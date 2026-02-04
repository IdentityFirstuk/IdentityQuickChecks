# Free Code Signing for PowerShell Scripts

## Overview

This guide covers how to obtain a **free code signing certificate** and sign your PowerShell scripts for trusted distribution.

## Free Code Signing Options

### Option 1: Certum Open Source Code Signing (RECOMMENDED)

Certum (Poland) offers **free code signing certificates** for open source projects.

**Website:** https://certum.com/en/code-signing/code-signing-certificates/open-source/

**Requirements:**
- GitHub account with open source repository
- Proof of project ownership
- Valid email address

**Process:**
1. Register at Certum website
2. Verify your GitHub account
3. Download your certificate (.p12/.pfx file)

### Option 2: SSL.com Trial Certificate

SSL.com offers a 90-day trial code signing certificate.

**Website:** https://www.ssl.com/certificates/code-signing/

**Limitations:**
- 90-day validity
- Requires verification

### Option 3: Sectigo (formerly Comodo)

Free trial code signing certificates available.

**Website:** https://sectigo.com/ssl-certificates-tls

## Converting Certificate to PFX

If your certificate is issued in a different format (CER, PEM), convert to PFX:

```powershell
# Using OpenSSL (Linux/macOS)
openssl pkcs12 -export -out certificate.pfx -inkey private.key -in certificate.cer -certfile cacert.pem

# Using certutil (Windows)
certutil -mergePFX -pfx certificate.cer -outputFile certificate.pfx
```

## Sign Scripts Using PowerShell

Once you have your PFX certificate:

```powershell
# Run the signing script (enter password securely)
.\Sign-QuickChecks.ps1 -CertPath ".\certificate.pfx" -CertPassword (Read-Host "PFX password" -AsSecureString)

# Or provide a PSCredential
.\Sign-QuickChecks.ps1 -CertPath ".\certificate.pfx" -CertCredential (Get-Credential)

# Dry run (see what would be signed)
.\Sign-QuickChecks.ps1 -CertPath ".\certificate.pfx" -DryRun
```

## Verify Signatures

After signing, verify the scripts:

```powershell
# Check if a script is signed
Get-AuthenticodeSignature -Path ".\QuickChecks-Console.ps1"

# List all signed files
Get-ChildItem -Path . -Recurse -Include *.ps1, *.psm1 | 
    ForEach-Object { 
        $sig = Get-AuthenticodeSignature -Path $_.FullName
        if ($sig.Status -eq "Valid") {
            Write-Host "✓ $($_.Name) - Signed by $($sig.SignerCertificate.Subject)"
        } else {
            Write-Host "✗ $($_.Name) - $($sig.Status)"
        }
    }
```

## Distribute Signed Scripts

After signing:

1. **Test locally** - Run signed scripts to verify they work
2. **Package** - Create ZIP package: `.\Package-QuickChecks.ps1 -SignScripts`
3. **Publish** - Upload to GitHub Releases

## Users Trusting Your Certificate

When users run your signed scripts, they may see:

```
Security warning
Run only scripts that you trust. Only run scripts from sources that you trust.
```

To avoid this, users need to trust your certificate:

### Option 1: Install Certificate on User Machine

```powershell
# Import certificate to Trusted Publishers store
$cert = Import-Certificate -FilePath ".\your-certificate.cer" -CertStoreLocation Cert:\LocalMachine\Root

# Or for current user
$cert = Import-Certificate -FilePath ".\your-certificate.cer" -CertStoreLocation Cert:\CurrentUser\Root
```

### Option 2: Group Policy (Enterprise)

Distribute via GPO to all domain computers.

### Option 3: Include in Installer

Embed certificate in your installer script.

## Troubleshooting

### "The certificate is not trusted"

- Install certificate in Trusted Publishers store
- For full trust, install in Trusted Root Certification Authorities

### "The signature is corrupt or invalid"

- Re-sign the script
- Ensure certificate hasn't expired

### Certificate expired

- Renew certificate before expiration
- Re-sign all scripts with new certificate

## Best Practices

1. **Use EV certificate** for production - provides instant trust
2. **Timestamp signatures** - allows signature to remain valid after certificate expires
3. **Keep PFX secure** - password-protect and store securely
4. **Renew before expiry** - set calendar reminder
5. **Document the process** - save certificate details securely

## Alternative: Self-Signed Certificate (Internal Use Only)

For internal distribution (not for external users):

```powershell
# Create self-signed certificate
$cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "IdentityFirst QuickChecks" -KeyUsage DigitalSignature -FriendlyName "IdentityFirst Code Signing" -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddYears(5)

# Export PFX (enter password securely)
$pfxPath = ".\identityfirst-selfsigned.pfx"
$password = Read-Host "PFX export password" -AsSecureString
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $password

# Import to Trusted Publishers
Import-Certificate -FilePath ".\identityfirst-selfsigned.cer" -CertStoreLocation Cert:\CurrentUser\TrustedPublishers
```

**Warning:** Self-signed certificates won't be trusted by other computers.

## Summary

| Method | Cost | Trust Level | Best For |
|--------|------|-------------|----------|
| Certum Open Source | Free | Medium (review required) | Open source projects |
| SSL.com Trial | Free (90 days) | Medium | Testing |
| Commercial EV | Paid | High | Enterprise production |
| Self-Signed | Free | None | Internal use only |

For IdentityFirst QuickChecks (open source), **Certum Open Source** is the recommended free option.
