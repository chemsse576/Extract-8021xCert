# Extract-8021xCert

Extract 802.1X machine certificates (EAP-TLS) with their private keys from Windows hosts. Outputs a ready-to-use Kali Linux package for network access impersonation during authorized penetration tests.

## What it does

This PowerShell script performs a **full DPAPI decryption chain** to export machine certificates that Windows normally marks as non-exportable:

```
LSA Secret (DPAPI_SYSTEM) → Master Key → CNG DPAPI Blob → RSA Private Key → PFX
```

It uses three extraction methods in cascade:

| Method | Technique | When it works |
|--------|-----------|---------------|
| **1** | Direct .NET PFX export | Certificate is marked exportable |
| **2** | NCrypt export policy patch | CNG key with modifiable export policy |
| **3** | Full DPAPI chain | Non-exportable CNG keys (most common in enterprise) |

## Output

The script creates a `8021x_kali/` folder containing everything needed to authenticate on the target 802.1X network from Kali Linux:

| File | Description |
|------|-------------|
| `<HOSTNAME>_<THUMBPRINT>.pfx` | Machine certificate + private key (PKCS#12) |
| `ca-radius.pem` | RADIUS server CA certificate(s) |
| `wpa_8021x.conf` | Pre-configured `wpa_supplicant` config |
| `commands.txt` | Step-by-step Kali commands |

## Usage

```powershell
# Basic (run as Administrator)
.\Extract-8021xCert.ps1

# Custom output directory and PFX password
.\Extract-8021xCert.ps1 -OutputDir C:\loot -PfxPassword "P@ss"

# Target a specific certificate by thumbprint
.\Extract-8021xCert.ps1 -Thumbprint "A1B2C3D4..."
```

### Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-OutputDir` | `.` (current dir) | Directory for output files |
| `-PfxPassword` | `exfiltrated` | Password to protect the PFX |
| `-Thumbprint` | *(auto-detect)* | Target a specific cert thumbprint |

## On Kali

```bash
# 1. Extract cert and key from PFX
openssl pkcs12 -in MACHINE_A1B2C3D4.pfx -clcerts -nokeys -out cert.pem -passin pass:exfiltrated
openssl pkcs12 -in MACHINE_A1B2C3D4.pfx -nocerts -nodes -out key.pem -passin pass:exfiltrated

# 2. Connect (replace eth0 with your interface)
sudo wpa_supplicant -i eth0 -c wpa_8021x.conf -D wired -d

# 3. Get an IP (in another terminal)
sudo dhclient eth0
```

## How it works

1. **Certificate discovery** — Scans `Cert:\LocalMachine\My` and identifies 802.1X candidates by template name and EKU (Client Authentication).

2. **Private key extraction** — Locates the CNG key file on disk, parses its DPAPI-encrypted blob, retrieves the `DPAPI_SYSTEM` LSA secret, decrypts the master key, then decrypts the RSA private key using the CNG-specific entropy value.

3. **RADIUS CA detection** — Parses wired 802.1X profile XML (`netsh lan export profile`) for `TrustedRootCA` thumbprints. Falls back to scanning root store for AD CS CAs matching the domain.

4. **Identity resolution** — Builds the EAP identity (`host/fqdn`) and collects Ethernet MAC addresses for optional spoofing.

5. **Package generation** — Produces all config files needed for immediate `wpa_supplicant` connection on Kali.

## Requirements

- **Windows** (tested on 10/11 and Server 2016+)
- **Administrator privileges** (required for LSA secret access and SYSTEM impersonation)
- **.NET Framework 4.5+** (uses `System.Numerics.BigInteger` for RSA math)
- No third-party tools — pure .NET and Windows API (P/Invoke)

## Limitations

- Only handles **RSA** keys (no ECDSA/EdDSA)
- Targets **machine** certificates only (not user certificates)
- DPAPI chain (Method 3) requires the SYSTEM master key to be in the default location

## Legal

This tool is intended for **authorized penetration testing** and **security auditing** only. Extracting certificates from systems you do not have authorization to test is illegal. Always obtain written permission before use.
