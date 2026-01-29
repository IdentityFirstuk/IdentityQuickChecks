# IdentityFirst Maximum Security Self-Signed Certificate Generator
# Creates 4096-bit RSA certificate with SHA-256 for strongest PowerShell signing

param(
    [string]$CertPassword = "ChangeThisPassword2024!@#$",
    [int]$CertYears = 3,
    [switch]$ReSignOnly = $false
)

$ErrorActionPreference = "Stop"
$CertSubject = "CN=IdentityFirst Code Signing, O=IdentityFirst Ltd, L=Northumberland, C=GB"
$CertFriendlyName = "IdentityFirst Code Signing Certificate (4096-bit RSA + SHA-256)"
$ScriptsPath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

function Write-Header {
    param([string]$Message)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host " $Message" -ForegroundColor White
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-Security {
    param([string]$Message)
    Write-Host "[🔒] $Message" -ForegroundColor Magenta
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[X] $Message" -ForegroundColor Red
}

# Display security settings
Write-Header "IdentityFirst Maximum Security Certificate Generator"

Write-Security "Security Configuration:"
Write-Host "  Key Algorithm:    RSA (4096-bit) - Maximum strength" -ForegroundColor White
Write-Host "  Hash Algorithm:   SHA-256 - Industry standard" -ForegroundColor White
Write-Host "  Key Usage:        Digital Signature only" -ForegroundColor White
Write-Host "  EKU:              Code Signing (1.3.6.1.5.5.7.3.3)" -ForegroundColor White
Write-Host "  Validity:         $CertYears years" -ForegroundColor White
Write-Host ""

# Step 1: Create self-signed certificate
if (-not $ReSignOnly) {
    Write-Step "Checking for existing certificate..."
    $existingCert = Get-ChildItem -Path "Cert:\CurrentUser\My" | Where-Object { $_.Subject -eq $CertSubject }
    
    if ($existingCert) {
        Write-Warning "Certificate already exists!"
        Write-Host "  Thumbprint:       $($existingCert.Thumbprint)" -ForegroundColor Yellow
        Write-Host "  Not After:        $($existingCert.NotAfter)" -ForegroundColor Yellow
        Write-Host "  Key Size:         $($existingCert.PublicKey.Key.KeySize) bits" -ForegroundColor Yellow
        
        $confirm = Read-Host "Replace existing certificate? (y/n)"
        if ($confirm -ne 'y' -and $confirm -ne 'Y') {
            Write-Host "Using existing certificate..." -ForegroundColor Cyan
            $cert = $existingCert
        } else {
            Write-Step "Removing existing certificate..."
            $existingCert | Remove-Item -Force
            Write-Step "Creating new certificate..."
            $cert = New-SelfSignedCertificate `
                -Type CodeSigningCert `
                -Subject $CertSubject `
                -KeyUsage DigitalSignature `
                -FriendlyName $CertFriendlyName `
                -CertStoreLocation "Cert:\CurrentUser\My" `
                -NotAfter (Get-Date).AddYears($CertYears) `
                -KeyLength 4096
        }
    } else {
        Write-Step "Creating new 4096-bit RSA certificate..."
        $cert = New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject $CertSubject `
            -KeyUsage DigitalSignature `
            -FriendlyName $CertFriendlyName `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -NotAfter (Get-Date).AddYears($CertYears) `
            -KeyLength 4096
    }
    
    Write-Security "Certificate Details:"
    Write-Host "  Thumbprint:       $($cert.Thumbprint)" -ForegroundColor White
    Write-Host "  Key Size:         $($cert.PublicKey.Key.KeySize) bits" -ForegroundColor White
    Write-Host "  Algorithm:        $($cert.SignatureAlgorithm)" -ForegroundColor White
    Write-Host "  Not Before:       $($cert.NotBefore)" -ForegroundColor White
    Write-Host "  Not After:        $($cert.NotAfter)" -ForegroundColor White
    Write-Host ""
    
    # Step 2: Export PFX with strong encryption
    Write-Step "Exporting to PFX with AES-256 encryption..."
    $pwd = ConvertTo-SecureString -String $CertPassword -Force -AsPlainText
    $pfxPath = Join-Path $ScriptsPath "identityfirst-codesign.pfx"
    Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pwd -CryptoAlgorithm AES256_AES -Force | Out-Null
    Write-Step "PFX exported: $pfxPath"
    
    # Step 3: Export public certificate
    Write-Step "Exporting public certificate (CER)..."
    $cerPath = Join-Path $ScriptsPath "identityfirst-codesign.cer"
    Export-Certificate -Cert $cert -FilePath $cerPath -Force | Out-Null
    Write-Step "CER exported: $cerPath"
}

# Step 4: Find and sign scripts
Write-Header "Signing PowerShell Scripts"

$signableExtensions = @('.ps1', '.psm1')
$signingScripts = @()

Get-ChildItem -Path $ScriptsPath -Recurse -File | ForEach-Object {
    if ($signableExtensions -contains $_.Extension.ToLower()) {
        $signingScripts += $_.FullName
    }
}

Write-Step "Found $($signingScripts.Count) scripts to sign"
Write-Security "Using SHA-256 for all signatures"
Write-Host ""

# Step 5: Sign all scripts
$signCount = 0
$skipCount = 0
$errorCount = 0

foreach ($scriptPath in $signingScripts) {
    try {
        $scriptName = Split-Path -Leaf $scriptPath
        $relativePath = $scriptPath.Replace($ScriptsPath, "").TrimStart("\/")
        
        # Check if already signed
        $signature = Get-AuthenticodeSignature -FilePath $scriptPath
        if ($signature.Status -eq 'Valid') {
            Write-Host "  [=] $relativePath" -ForegroundColor Gray
            $skipCount++
            continue
        }
        
        # Sign the script
        if (-not $ReSignOnly) {
            Set-AuthenticodeSignature -FilePath $scriptPath -Certificate $cert -HashAlgorithm SHA256 -TimestampServer "http://timestamp.digicert.com" | Out-Null
        } else {
            $pfxPath = Join-Path $ScriptsPath "identityfirst-codesign.pfx"
            $cert = Get-PfxCertificate -FilePath $pfxPath
            Set-AuthenticodeSignature -FilePath $scriptPath -Certificate $cert -HashAlgorithm SHA256 -TimestampServer "http://timestamp.digicert.com" | Out-Null
        }
        
        Write-Host "  [+] $relativePath" -ForegroundColor Green
        $signCount++
    }
    catch {
        Write-Host "  [X] $(Split-Path -Leaf $scriptPath): $($_.Exception.Message)" -ForegroundColor Red
        $errorCount++
    }
}

# Step 6: Summary
Write-Header "Signing Complete"

Write-Host "  Total scripts:   $($signingScripts.Count)"
Write-Host "  Signed:          $signCount" -ForegroundColor Green
Write-Host "  Already signed:  $skipCount" -ForegroundColor Cyan
Write-Host "  Errors:          $errorCount" -ForegroundColor $(if ($errorCount -gt 0) { "Red" } else { "White" })
Write-Host ""

Write-Security "Certificate Security:"
Write-Host "  Algorithm:       RSA 4096-bit + SHA-256" -ForegroundColor White
Write-Host "  Encryption:      AES-256 for PFX export" -ForegroundColor White
Write-Host "  Timestamp:       Included (DigiCert)" -ForegroundColor White
Write-Host ""

if (-not $ReSignOnly) {
    Write-Step "Files created:"
    Write-Host "  - identityfirst-codesign.pfx" -ForegroundColor White
    Write-Host "    (KEEP SECURE - contains private key)" -ForegroundColor Red
    Write-Host "  - identityfirst-codesign.cer" -ForegroundColor White
    Write-Host "    (safe to share with clients)" -ForegroundColor Green
    Write-Host ""
    
    Write-Warning "SECURITY RECOMMENDATIONS:"
    Write-Host "  1. Store PFX on encrypted drive" -ForegroundColor White
    Write-Host "  2. Use strong password (change default)" -ForegroundColor White
    Write-Host "  3. Limit access to authorized personnel only" -ForegroundColor White
    Write-Host "  4. Rotate certificate annually" -ForegroundColor White
    Write-Host "  5. Revoke and recreate if compromised" -ForegroundColor White
    Write-Host ""
    
    Write-Host "To re-sign scripts in future:" -ForegroundColor Cyan
    Write-Host "  .\Create-SelfSignedCert.ps1 -ReSignOnly" -ForegroundColor White
}

Write-Host ""
Write-Host "To verify signatures:" -ForegroundColor Cyan
Write-Host "  Get-AuthenticodeSignature .\scripts\*.ps1 | Format-Table Path, Status, SignerCertificate -Auto" -ForegroundColor White
