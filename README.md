# Extract-8021xCert

Extract 802.1X machine certificates with private keys from Windows hosts using only native .NET and Windows APIs. No third-party tools required.

## Context

During PASSI pentests, after obtaining SYSTEM or local admin access on a domain-joined workstation, extracting the 802.1X machine certificate allows lateral movement on the wired network (NAC bypass via EAP-TLS impersonation).

This script extracts the certificate and its private key into a `.pfx` file, using three cascading methods that require **zero external dependencies**.

## Methods

| # | Technique | When it works |
|---|-----------|---------------|
| **1** | Direct .NET export (`X509Certificate2.Export`) | Key marked as exportable |
| **2** | CNG `NCryptSetProperty` export policy patch | CNG-backed key with non-exportable flag (most common) |
| **3** | Raw key file read + DPAPI `LocalMachine` decrypt | Fallback when NCrypt operations are blocked |

Methods are tried in order. The first success produces the `.pfx` and stops.

## Requirements

- **Windows** (PowerShell 5.1 / .NET Framework 4.x)
- **Administrator** or **SYSTEM** privileges
- Target host must have a machine certificate with EKU `1.3.6.1.5.5.7.3.2` (Client Authentication) or 802.1X-related template

## Usage

```powershell
# Basic - exports to current directory with default password
.\Extract-8021xCert.ps1

# Custom output directory and password
.\Extract-8021xCert.ps1 -OutputDir C:\Temp -PfxPassword "MyP@ss!"

# Target a specific certificate by thumbprint
.\Extract-8021xCert.ps1 -Thumbprint "A1B2C3D4..."
```

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-OutputDir` | `.` (current dir) | Directory for the exported `.pfx` |
| `-PfxPassword` | `Extract8021x!` | Password protecting the `.pfx` |
| `-Thumbprint` | *(auto-detect)* | Target a specific certificate thumbprint |

### Output

```
=============================================
  EXPORT SUCCESSFUL
=============================================
  Subject     : CN=YOURPC.domain.local
  Issuer      : CN=Corp-CA, DC=domain, DC=local
  Thumbprint  : A1B2C3D4E5F6...
  Template    : 802.1X Machine
  Not After   : 01/01/2027 00:00:00
  Method Used : Method 2 - CNG ExportPolicy Patch
  Output File : C:\Temp\YOURPC.domain.local.pfx
  PFX Password: Extract8021x!
=============================================
```

## Post-Exploitation

Once extracted, the `.pfx` can be used to authenticate on the wired network from an attacker-controlled machine:

```bash
# Linux - wpa_supplicant with EAP-TLS
wpa_supplicant -i eth0 -c eap-tls.conf

# Windows - import and configure NPS/802.1X profile
certutil -importpfx extracted.pfx
```

## Technical Details

### Method 2 - CNG Export Policy Patch

Uses P/Invoke to call `NCryptSetProperty` on the CNG key handle, changing `NCRYPT_EXPORT_POLICY_PROPERTY` from `0x00` (non-exportable) to `0x03` (exportable + plaintext). Then `NCryptExportKey` retrieves the `BCRYPT_RSAFULLPRIVATE_BLOB`.

### Method 3 - DPAPI Key File Decrypt

Locates the CNG/CAPI key file on disk (`ProgramData\Microsoft\Crypto\Keys\` or `RSA\MachineKeys\`), extracts the DPAPI-protected blob, decrypts it with `ProtectedData.Unprotect()` using `LocalMachine` scope, then parses the proprietary RSA2 blob format (20-byte header + padded components) and rebuilds a standard CAPI `PRIVATEKEYBLOB` for import.

## Disclaimer

This tool is provided for **authorized penetration testing and security research only**. Use of this tool against systems without explicit written authorization is illegal and unethical. The author assumes no liability for misuse or damage caused by this tool. Always ensure you have proper authorization before using this tool in any environment.

## License

See [LICENSE](LICENSE).
