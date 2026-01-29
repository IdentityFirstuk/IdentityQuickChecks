# Free Code Signing Certificate - Registration Guide

## Quick Start: Get a Free Code Signing Certificate

Since Certum's free program may have changed, here are working alternatives:

### Option 1: SSL.com (Recommended - 90 day free trial)

1. Go to: https://www.ssl.com/certificates/code-signing/
2. Click "Free Trial" or "Buy Now"
3. Create account with: mark.ahearne@identityfirst.net
4. Select "Code Signing Certificate"
5. Complete verification (email + identity)
6. Download certificate (.p12/.pfx)

### Option 2: GitHub CLI (For GitHub Actions signing)

```powershell
# Install GitHub CLI
winget install gh

# Authenticate
gh auth login

# Generate code signing certificate
gh codesigning generate
```

### Option 3: KeyFactor Free Trial

1. Go to: https://www.keyfactor.com/free-code-signing/
2. Sign up for free trial
3. Complete verification
4. Download certificate

---

## Step-by-Step: SSL.com (Most Reliable)

### Step 1: Sign Up

1. Go to: **https://www.ssl.com/certificates/code-signing/**
2. Click **"Free Trial"** or **"Try for Free"**
3. Create account:
   - Email: **mark.ahearne@identityfirst.net**
   - Password: Create strong password
4. Verify email (check inbox)

### Step 2: Order Certificate

1. Log in to SSL.com account
2. Find "Code Signing" section
3. Order "Code Signing Certificate"
4. Select 90-day trial if available

### Step 3: Verify Identity

SSL.com may require:
- Email verification (automatic)
- Organization verification (if OV certificate)

### Step 4: Download Certificate

1. Go to "My Certificates"
2. Find your Code Signing certificate
3. Click **"Download"**
4. Choose format: **.PFX** (with private key)
5. Set password (remember it!)

### Step 5: Use the Certificate

```powershell
# Copy to QuickChecks folder
Copy-Item "C:\Downloads\certificate.pfx" "C:\IdentityFirst-Free\"

# Sign scripts
cd C:\IdentityFirst-Free
.\Sign-QuickChecks.ps1 -CertPath ".\certificate.pfx" -CertPassword "your-password"

# Package
.\Package-QuickChecks.ps1 -Version "1.0.0" -SignScripts
```

---

## Alternative: Generate Self-Signed Certificate (Free, No Verification)

For testing or internal use only (users will see warnings):

```powershell
# Create self-signed code signing certificate
$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject "IdentityFirst Ltd" `
    -KeyUsage DigitalSignature `
    -FriendlyName "IdentityFirst QuickChecks Code Signing" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -NotAfter (Get-Date).AddYears(3)

# Export to PFX
$pfxPath = ".\IdentityFirst-CodeSign.pfx"
$password = ConvertTo-SecureString -String "SecurePassword123!" -AsPlainText -Force
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $password

# Show certificate thumbprint
$cert | Select-Object Subject, Thumbprint, NotAfter
```

**Note:** Self-signed certificates show security warnings on users' computers. Not recommended for public distribution.

---

## What to Expect

| Provider | Timeline | Trust Level | Cost |
|----------|----------|-------------|------|
| SSL.com (trial) | 1-3 days | Medium | Free (90 days) |
| KeyFactor (trial) | 1-3 days | Medium | Free (90 days) |
| Self-signed | Immediate | None | Free |

---

## After You Get the Certificate

### 1. Secure Your Certificate

⚠️ **IMPORTANT:**
- Store `.pfx` file securely (not in GitHub!)
- Use strong password
- Back up to encrypted USB

### 2. Sign Scripts

```powershell
.\Sign-QuickChecks.ps1 -CertPath ".\certificate.pfx" -CertPassword "your-password"
```

### 3. Verify Signatures

```powershell
# Check a signed script
Get-AuthenticodeSignature -Path ".\QuickChecks-Console.ps1"

# List all signed files
Get-ChildItem -Path . -Include *.ps1, *.psm1 -Recurse | ForEach-Object {
    $sig = Get-AuthenticodeSignature -Path $_.FullName
    if ($sig.Status -eq "Valid") {
        Write-Host "✓ $($_.Name)" -ForegroundColor Green
    } else {
        Write-Host "✗ $($_.Name): $($sig.Status)" -ForegroundColor Red
    }
}
```

### 4. Package for Distribution

```powershell
.\Package-QuickChecks.ps1 -Version "1.0.0" -SignScripts
```

---

## Troubleshooting

### "Certificate not trusted"

- Users need to install your CA certificate
- Provide instructions in README

### "Signature invalid"

- Re-sign the script
- Check certificate hasn't expired

### "Cannot find certificate"

- Verify path is correct
- Check password is correct
- Ensure certificate includes private key

---

## Summary

| Method | Cost | Best For |
|--------|------|----------|
| SSL.com trial | Free (90 days) | ✅ Public distribution |
| KeyFactor trial | Free (90 days) | ✅ Public distribution |
| Self-signed | Free | Internal testing only |

**Recommended:** Use SSL.com free trial for initial signing, then purchase annual certificate when ready.

---

**Next Step:** Once you have a certificate, run:
```powershell
.\Sign-QuickChecks.ps1 -CertPath ".\your-certificate.pfx"
```
