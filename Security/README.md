# IdentityFirst Security Module

## Overview

The `IdentityFirst.Security.psm1` module provides security utilities for all IdentityFirst QuickChecks PowerShell scripts.

## Features

### 1. Secure Credential Handling
- `ConvertTo-SecureStringIfNeeded` - Safely converts passwords to secure strings
- `Get-CredentialFromInput` - Handles PSCredential, SecureString, or plain text

### 2. Input Validation
- `Test-ValidPath` - Prevents path traversal attacks
- `Test-ValidIdentifier` - Validates safe identifier format
- `Test-ValidCsvPath` / `Test-ValidJsonPath` / `Test-ValidHtmlPath` - Validates output paths

### 3. Secure Logging
- `Write-SecureLog` - Logs with automatic sensitive data redaction
- `New-SecureLogFile` - Creates log files with restricted permissions

### 4. HTML Output Security
- `Get-SecureHtmlContent` - HTML encoding to prevent XSS
- `New-SecureHtmlReport` - Creates reports with Content-Security-Policy headers

### 5. File Security
- `Set-OutputFileSecurity` - Applies owner-only ACLs
- `New-SecureOutputFile` - Creates files with secure permissions

### 6. Integrity Verification
- `Get-ScriptHash` - Computes SHA-256 hash
- `Test-ScriptIntegrity` - Verifies file hasn't been tampered

## Usage

```powershell
# Import the security module
Import-Module -Name "$PSScriptRoot/Security/IdentityFirst.Security.psm1"

# Use secure logging (redacts passwords/tokens)
Write-SecureLog -Message "Processing user password123" -Level INFO
# Output: [2026-01-29 20:40:00] [INFO] Processing user ***REDACTED***

# Validate paths
if (Test-ValidPath -Path $exportPath -AllowedRoots @($PSScriptRoot, $env:TEMP)) {
    # Safe to proceed
}

# Create secure output file
New-SecureOutputFile -FilePath ".\output\report.csv"

# HTML encode content
$safeContent = Get-SecureHtmlContent -Content $userInput
```

## Security Standards

| Feature | Standard |
|---------|----------|
| Key Size | 4096-bit RSA |
| Hash Algorithm | SHA-256 |
| PFX Encryption | AES-256 |
| File Permissions | Owner-only (ACL) |
| HTML Encoding | Full XSS protection |

## Manifest

See `IdentityFirst.Security.manifest.psd1` for:
- Security feature status
- Encryption standards
- Required modules
- Recommendations
- Known limitations

## Security Checklist

- [ ] Import Security module in all scripts
- [ ] Use `Write-SecureLog` instead of `Write-Host` for logging
- [ ] Validate all file paths before writing
- [ ] Use `Get-SecureHtmlContent` for HTML output
- [ ] Apply `Set-OutputFileSecurity` to exported files
- [ ] Rotate certificates annually

## Best Practices

1. **Least Privilege**: Run with minimum required permissions
2. **Input Validation**: Never trust user input
3. **Credential Handling**: Use SecureString, never plain text
4. **Logging**: Use `Write-SecureLog` to prevent credential exposure
5. **File Security**: Apply ACLs to sensitive output files
6. **Code Signing**: Sign all scripts before distribution

## Support

- Author: mark.ahearne@identityfirst.net
- Repository: https://github.com/IdentityFirstuk/IdentityFirst-Free
