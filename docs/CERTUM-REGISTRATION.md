# Certum Free Code Signing Certificate - Registration Guide

## Step-by-Step Registration

### Step 1: Visit Certum Website

Go to: https://certum.com/en/code-signing/code-signing-certificates/open-source/

### Step 2: Create Account

1. Click **"Register"** or **"Sign Up"**
2. Fill in your details:
   - **First Name:** Mark
   - **Last Name:** Ahearne
   - **Email:** mark.ahearne@identityfirst.net (use this email)
   - **Company:** IdentityFirst Ltd
   - **Country:** United Kingdom

3. Create a password (remember it - you'll need it later)

4. Accept terms and submit

### Step 3: Verify Email

1. Check your email (mark.ahearne@identityfirst.net)
2. Look for email from Certum with verification link
3. Click the link to verify your email

### Step 4: Complete Your Profile

After logging in:

1. Go to **"My Account"** or **"Profile"**
2. Complete company details:
   - **Organization Name:** IdentityFirst Ltd
   - **Address:** [Your business address]
   - **Phone:** [Your phone number]
   - **Website:** https://www.identityfirst.net

### Step 5: Request Open Source Certificate

1. Look for **"Code Signing Certificates"** section
2. Select **"Open Source"** or **"Free Code Signing"**
3. Fill in the application:
   - **Project Name:** IdentityFirst QuickChecks
   - **Project URL:** https://github.com/IdentityFirstuk/IdentityFirst-Free
   - **Project Description:** Free PowerShell modules for identity posture visibility
   - **License Type:** MIT or Custom (see EULA.txt)

4. Submit the application

### Step 6: Verify GitHub Repository

Certum may ask you to verify you own the GitHub repository:

1. They may ask you to:
   - Add a file to your repo
   - Or verify via email domain
   - Or provide proof of ownership

2. Follow their verification instructions

### Step 7: Download Certificate

Once approved (may take 1-2 business days):

1. Log in to Certum dashboard
2. Go to **"My Certificates"**
3. Find your **Code Signing Certificate**
4. Click **"Download"**
5. Save the file (usually `.p12` or `.pfx` format)

### Step 8: Install and Use

```powershell
# Copy certificate to QuickChecks folder
Copy-Item "C:\Downloads\certum-certificate.pfx" "C:\IdentityFirst-Free\"

# Sign your scripts
cd C:\IdentityFirst-Free
.\Sign-QuickChecks.ps1 -CertPath ".\certum-certificate.pfx" -CertPassword "your-cert-password"

# Package for distribution
.\Package-QuickChecks.ps1 -Version "1.0.0" -SignScripts
```

## What to Expect

| Stage | Timeline |
|-------|----------|
| Account creation | Immediate |
| Email verification | Immediate |
| Application review | 1-2 business days |
| GitHub verification | 1-2 business days |
| Certificate issuance | After approval |

## Certificate Details

After receiving your certificate:

- **Format:** .p12 or .pfx
- **Validity:** Typically 1-2 years
- **Key type:** RSA 2048-bit or ECC
- **Chain:** Includes intermediate CA certificate

## Common Issues

### "Application pending review"

- Certum manually reviews open source applications
- Be patient - they're verifying you're a legitimate organization
- Ensure your GitHub repo is public and well-documented

### "GitHub verification failed"

- Make sure repo name matches application exactly
- Ensure you have admin rights to the repo
- Try adding a verification file they request

### Certificate won't install

- Use correct password (from Certum, not your account)
- Try importing to Windows certificate store first
- Check file isn't corrupted (re-download if needed)

## After You Have the Certificate

1. **Secure it** - Store .pfx file securely, don't commit to Git
2. **Back it up** - Keep a secure backup
3. **Note expiry** - Set reminder to renew before expiration
4. **Sign scripts** - Run the signing script
5. **Test** - Verify signatures work on test machines

## Important Notes

⚠️ **Keep your PFX file secure!** It contains your private key.
- Don't commit it to GitHub
- Don't share it
- Use a strong password

⚠️ **Certificate validity** - Free certificates typically expire in 1-2 years. Set a reminder to renew.

⚠️ **Open Source requirement** - Certum may periodically verify your project is still open source.

## Support

If you have issues:
- Certum support: Check their website for contact info
- GitHub verification: https://docs.github.com/en/authentication/managing-commit-signature-verification

---

**Next:** Once you have the certificate, run:
```powershell
.\Sign-QuickChecks.ps1 -CertPath ".\your-certificate.pfx"
```
