# PowerShell Script Protection Guide

This guide covers free methods to protect your PowerShell scripts from unauthorized changes, reverse engineering, and tampering.

## Table of Contents

1. [Code Signing with Free Certificates](#code-signing)
2. [Execution Policy Configuration](#execution-policy)
3. [Constrained Language Mode](#constrained-language)
4. [Script Obfuscation](#obfuscation)
5. [File Integrity Monitoring](#integrity-monitoring)
6. [Repository Security](#repository-security)

---

## 1. Code Signing with Free Certificates {#code-signing}

### Option A: Self-Signed Certificates (Free)

You can create your own code signing certificate for free:

```powershell
# Create a self-signed code signing certificate
$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject "IdentityFirst QuickChecks Code Signing" `
    -KeyUsage DigitalSignature `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -FriendlyName "IdentityFirst Self-Signed Code Cert"

# Export the certificate with private key (for signing)
$password = ConvertTo-SecureString -String "YourStrongPassword123!" -AsPlainText -Force
Export-PfxCertificate -Cert $cert -FilePath ".\identityfirst-codesign.pfx" -Password $password

# Export the public key (for distribution)
Export-Certificate -Cert $cert -FilePath ".\identityfirst-codesign.cer"

# View certificate details
Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -match "Code Signing"}
```

### Option B: Let's Encrypt (Free SSL/TLS Certificates)

While primarily for HTTPS, you can use Let's Encrypt for Authenticode signing:

1. Get a free certificate from Let's Encrypt: https://letsencrypt.org
2. Convert to PFX using OpenSSL or certutil
3. Use for code signing

### Option C: Windows Built-in Certificate

Use the Windows certificate store for development:

```powershell
# Create a certificate for testing
$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject "CN=IdentityFirst Development" `
    -KeyUsage DigitalSignature `
    -CertStoreLocation "Cert:\LocalMachine\My"

# Trust the certificate for local testing
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
    [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPeople,
    [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
)
$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$store.Add($cert)
$store.Close()
```

### Signing Your Scripts

```powershell
# Sign a single script
$cert = Get-PfxCertificate -FilePath ".\identityfirst-codesign.pfx"
Set-AuthenticodeSignature `
    -FilePath ".\BreakGlassReality.ps1" `
    -Certificate $cert `
    -TimestampServer "http://timestamp.digicert.com"

# Sign all scripts in a directory
$cert = Get-PfxCertificate -FilePath ".\identityfirst-codesign.pfx"
Get-ChildItem -Path ".\IdentityQuickChecks\*.ps1" | ForEach-Object {
    Set-AuthenticodeSignature -FilePath $_.FullName -Certificate $cert
    Write-Host "Signed: $($_.Name)" -ForegroundColor Green
}
```

### Verifying Signatures

```powershell
# Check if a script is signed
Get-AuthenticodeSignature -FilePath ".\BreakGlassReality.ps1"

# Verify all scripts are signed
Get-ChildItem -Path ".\*.ps1" -Recurse | ForEach-Object {
    $sig = Get-AuthenticodeSignature -FilePath $_.FullName
    if ($sig.Status -eq 'Valid') {
        Write-Host "[SIGNED] $($_.FullName)" -ForegroundColor Green
    }
    else {
        Write-Host "[UNSIGNED] $($_.FullName)" -ForegroundColor Yellow
    }
}
```

---

## 2. Execution Policy Configuration {#execution-policy}

### Recommended Policies

| Policy | Security Level | Use Case |
|--------|---------------|----------|
| `AllSigned` | Highest | Production - requires all scripts signed |
| `RemoteSigned` | High | Default recommended - downloaded scripts must be signed |
| `Restricted` | Medium | Development - allows individual commands only |

### Setting Execution Policy

```powershell
# Set for current user (no admin required)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

# Set for all users (requires admin)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force

# Check current policy
Get-ExecutionPolicy -List
```

### Checking Before Execution

```powershell
function Test-ScriptExecutionPolicy {
    <#
    .SYNOPSIS
        Validates execution policy is set correctly.
    #>
    [CmdletBinding()]
    param()

    $policy = Get-ExecutionPolicy -Scope CurrentUser
    $localPolicy = Get-ExecutionPolicy -Scope LocalMachine

    $isSecure = $policy -in @('AllSigned', 'RemoteSigned') -or
                 $localPolicy -in @('AllSigned', 'RemoteSigned')

    return @{
        CurrentUserPolicy = $policy
        LocalMachinePolicy = $localPolicy
        IsSecure = $isSecure
    }
}

# Use in scripts
$policyCheck = Test-ScriptExecutionPolicy
if (-not $policyCheck.IsSecure) {
    Write-Warning "Execution policy may not provide adequate protection"
}
```

---

## 3. Constrained Language Mode {#constrained-language}

### What It Does

Constrained Language Mode restricts PowerShell to a basic feature set, preventing many attack techniques.

### Checking Current Mode

```powershell
# Check language mode
$ExecutionContext.SessionState.LanguageMode

# Or
$Host.LanguageMode
```

### Enabling Constrained Language Mode

```powershell
# For session only (temporary)
$ExecutionContext.SessionState.LanguageMode = 'ConstrainedLanguage'

# Permanent via Group Policy (AD environment)
# Computer Configuration > Administrative Templates >
# Windows Components > Windows PowerShell > Enable Language Mode = ConstrainedLanguage
```

### Checking in Scripts

```powershell
function Test-ConstrainedLanguage {
    <#
    .SYNOPSIS
        Checks if Constrained Language Mode is enabled.
    #>
    $mode = $ExecutionContext.SessionState.LanguageMode
    return $mode -eq 'ConstrainedLanguage'
}

if (Test-ConstrainedLanguage) {
    Write-Verbose "Constrained Language Mode is active" -Verbose
}
else {
    Write-Warning "Constrained Language Mode is not enabled"
}
```

---

## 4. Script Obfuscation {#obfuscation}

### Simple Obfuscation Techniques (Free)

#### Base64 Encoding

```powershell
# Encode a script
$scriptContent = Get-Content -Path ".\BreakGlassReality.ps1" -Raw
$encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($scriptContent))

# Save encoded version
$encoded | Out-File -Path ".\BreakGlassReality-encoded.ps1" -Encoding UTF8

# Create launcher script
$launcher = @"
`$encoded = @'
$encoded
'@
`$decoded = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(`$encoded))
Invoke-Expression ` `$decoded
"@
$launcher | Out-File -Path ".\BreakGlassReality.ps1" -Encoding UTF8
```

#### String Encryption

```powershell
# Simple string encryption for sensitive data
function Protect-String {
    param([string]$PlainText)
    $secure = ConvertTo-SecureString -String $PlainText -AsPlainText -Force
    $encrypted = ConvertFrom-SecureString -SecureString $secure
    return $encrypted
}

function Unprotect-String {
    param([string]$EncryptedText)
    $secure = ConvertTo-SecureString -String $EncryptedText -AsPlainText -Force
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    $decrypted = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    return $decrypted
}

# Usage
$encrypted = Protect-String "MySecretPassword"
$decrypted = Unprotect-String $encrypted
```

#### Advanced Obfuscation with open-source tools

1. **Invoke-Obfuscation** (Free - GitHub)
   - https://github.com/danielbohannon/Invoke-Obfuscation
   - Free open-source obfuscation tool

2. **PSPrettier** (Free - PowerShell formatting)
   - https://github.com/PoshCode/PSPrettier
   - Code formatting with some obfuscation options

3. **Carbon** (Free - Security toolkit)
   - https://get-carbon.org
   - Security-focused PowerShell module

---

## 5. File Integrity Monitoring {#integrity-monitoring}

### Create Hash Database

```powershell
function New-IntegrityBaseline {
    <#
    .SYNOPSIS
        Creates a hash baseline for script files.
    #>
    [CmdletBinding()]
    param(
        [string]$Path = ".",
        [string]$OutputFile = ".\integrity-baseline.json"
    )

    $baseline = @{
        Created = [datetime]::UtcNow
        Algorithm = "SHA256"
        Files = @{}
    }

    Get-ChildItem -Path $Path -Filter "*.ps1" -Recurse | ForEach-Object {
        $hash = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash
        $baseline.Files[$_.FullName] = @{
            Hash = $hash
            Size = $_.Length
            Modified = $_.LastWriteTimeUtc
        }
    }

    $baseline | ConvertTo-Json -Depth 10 | Out-File -Path $OutputFile -Encoding UTF8
    Write-Host "Baseline created: $OutputFile" -ForegroundColor Green
}

function Test-FileIntegrity {
    <#
    .SYNOPSIS
        Compares current file hashes against baseline.
    #>
    [CmdletBinding()]
    param(
        [string]$BaselineFile = ".\integrity-baseline.json"
    )

    if (-not (Test-Path $BaselineFile)) {
        Write-Warning "Baseline file not found. Run New-IntegrityBaseline first."
        return
    }

    $baseline = Get-Content -Path $BaselineFile | ConvertFrom-Json
    $violations = @()

    foreach ($file in $baseline.Files.PSObject.Properties) {
        $currentHash = (Get-FileHash -Path $file.Name -Algorithm SHA256).Hash
        $storedHash = $file.Value.Hash

        if ($currentHash -ne $storedHash) {
            $violations += @{
                File = $file.Name
                Status = "MODIFIED"
                OriginalHash = $storedHash
                CurrentHash = $currentHash
            }
        }
    }

    if ($violations) {
        Write-Host "[WARNING] $($violations.Count) file integrity violations detected:" -ForegroundColor Red
        foreach ($v in $violations) {
            Write-Host "  - $($v.File)" -ForegroundColor Yellow
        }
    }
    else {
        Write-Host "[OK] All files match baseline" -ForegroundColor Green
    }

    return $violations
}

# Usage
New-IntegrityBaseline -Path ".\IdentityQuickChecks" -OutputFile ".\integrity-baseline.json"
Test-FileIntegrity -BaselineFile ".\integrity-baseline.json"
```

### Git-Based Integrity

```powershell
# Verify all committed files match local files
function Test-GitIntegrity {
    git diff --stat --name-only | ForEach-Object {
        Write-Host "Modified: $_" -ForegroundColor Yellow
    }

    git status --short | Where-Object { $_ -match "^\s*M" } | ForEach-Object {
        $file = $_.Trim().Substring(3).Trim()
        $status = git diff "$file"
        if ($status) {
            Write-Host "Changes in: $file" -ForegroundColor Yellow
        }
    }
}
```

---

## 6. Repository Security {#repository-security}

### GitHub Protected Branches

1. Go to Repository Settings > Branches
2. Add branch protection rule for `main`
3. Enable:
   - Require pull request reviews
   - Require status checks
   - Require signed commits
   - Include administrators

### GitHub Security Features (Free)

| Feature | Description |
|---------|-------------|
| **Code Scanning** | Free automated security analysis |
| **Dependabot** | Automatic vulnerability alerts |
| **Secret Scanning** | Detect leaked credentials |
| **Security Advisories** | Private vulnerability reporting |

### Enable Security Features

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run GitHub Advanced Security Code Scanning
        uses: github/codeql-action/analyze@v3
        with:
          languages: powershell
          queries: security-extended

      - name: Check for secrets
        run: |
          # Basic secret pattern detection
          grep -r "password\s*=" --include="*.ps1" . || true
          grep -r "api[_-]key" --include="*.ps1" . || true
```

### File-Level Security

```powershell
# .gitignore for sensitive files
*.pfx
*.cer
*.pem
secrets.json
integrity-baseline.json
*.local
.vscode/
.idea/
*.log
```

---

## 7. Recommended Protection Stack {#recommended-stack}

For maximum protection at zero cost:

| Layer | Method | Cost |
|-------|--------|------|
| **Code Signing** | Self-signed certificate + timestamp | Free |
| **Execution Policy** | RemoteSigned via GPO | Free |
| **Language Mode** | ConstrainedLanguage via GPO | Free |
| **Integrity** | SHA256 hash baseline | Free |
| **Repository** | GitHub protected branches | Free |
| **Secrets** | Environment variables | Free |
| **Scanning** | GitHub Advanced Security (public repos free) | Free |

### Quick Setup Script

```powershell
# protect-scripts.ps1 - Quick protection setup

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  PowerShell Script Protection Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 1. Create code signing certificate
Write-Host "[1/4] Creating code signing certificate..." -ForegroundColor Yellow
$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject "CN=IdentityFirst Script Signing" `
    -KeyUsage DigitalSignature `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -FriendlyName "IdentityFirst Code Sign" `
    -ErrorAction Stop

$password = ConvertTo-SecureString -String "ChangeMe123!" -AsPlainText -Force
Export-PfxCertificate -Cert $cert -FilePath ".\identityfirst-codesign.pfx" -Password $password
Write-Host "  Certificate created: $($cert.Subject)" -ForegroundColor Green

# 2. Set execution policy
Write-Host "[2/4] Setting execution policy..." -ForegroundColor Yellow
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
Write-Host "  Execution policy: RemoteSigned" -ForegroundColor Green

# 3. Create integrity baseline
Write-Host "[3/4] Creating integrity baseline..." -ForegroundColor Yellow
$baseline = @{
    Created = [datetime]::UtcNow
    Files = @{}
}
Get-ChildItem -Path ".\*.ps1" -Recurse | ForEach-Object {
    $baseline.Files[$_.FullName] = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash
}
$baseline | ConvertTo-Json | Out-File -Path ".\integrity-baseline.json" -Encoding UTF8
Write-Host "  Baseline created with $($baseline.Files.Count) files" -ForegroundColor Green

# 4. Sign all scripts
Write-Host "[4/4] Signing scripts..." -ForegroundColor Yellow
Get-ChildItem -Path ".\*.ps1" -Recurse | ForEach-Object {
    $sig = Set-AuthenticodeSignature -FilePath $_.FullName -Certificate $cert
    Write-Host "  Signed: $($_.Name)" -ForegroundColor Gray
}
Write-Host "  All scripts signed" -ForegroundColor Green

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Protection Setup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  1. Back up your certificate: identityfirst-codesign.pfx" -ForegroundColor Gray
Write-Host "  2. Run integrity checks: Test-FileIntegrity" -ForegroundColor Gray
Write-Host "  3. Sign new scripts with: Set-AuthenticodeSignature" -ForegroundColor Gray
Write-Host ""
```

---

## Summary: Free Protection Tools

| Protection Type | Tool/Method | URL |
|----------------|-------------|-----|
| Code Signing | Self-signed certificate | Built into Windows |
| Code Scanning | GitHub CodeQL | github.com/features/security |
| Secret Scanning | GitHub Advanced Security | github.com/security/advisories |
| Obfuscation | Invoke-Obfuscation | github.com/danielbohannon/Invoke-Obfuscation |
| Integrity | PowerShell Get-FileHash | Built into PowerShell |
| Linting | PSScriptAnalyzer | Install-Module PSScriptAnalyzer |
| Testing | Pester | Install-Module Pester |

All of these methods are completely free and provide a solid security foundation for your PowerShell scripts.
