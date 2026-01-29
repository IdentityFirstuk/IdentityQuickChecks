# IdentityFirst Self-Signed Certificate Generator and Script Signer
# Run this script to create a self-signed code signing certificate and sign all QuickChecks scripts

param(
    [string]$CertPassword = "IdentityFirst2024!",
    [int]$CertYears = 3,
    [switch]$ReSignOnly = $false
)

$ErrorActionPreference = "Stop"
$CertSubject = "CN=IdentityFirst Code Signing, O=IdentityFirst Ltd, L=Northumberland, C=GB"
$CertFriendlyName = "IdentityFirst Code Signing Certificate"
$ScriptsPath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

function Write-Header {
    param([string]$Message)
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host " $Message" -ForegroundColor White
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[X] $Message" -ForegroundColor Red
}

# Step 1: Create self-signed certificate (unless re-signing only)
Write-Header "IdentityFirst Self-Signed Certificate Setup"

if (-not $ReSignOnly) {
    Write-Step "Checking for existing certificate..."
    $existingCert = Get-ChildItem -Path "Cert:\CurrentUser\My" | Where-Object { $_.Subject -eq $CertSubject }
    
    if ($existingCert) {
        Write-Warning "Certificate already exists with thumbprint: $($existingCert.Thumbprint)"
        $cert = $existingCert
    } else {
        Write-Step "Creating new self-signed code signing certificate..."
        $cert = New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject $CertSubject `
            -KeyUsage DigitalSignature `
            -FriendlyName $CertFriendlyName `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -NotAfter (Get-Date).AddYears($CertYears)
        
        Write-Step "Certificate created with thumbprint: $($cert.Thumbprint)"
    }
    
    # Step 2: Export PFX
    Write-Step "Exporting certificate to PFX..."
    $pwd = ConvertTo-SecureString -String $CertPassword -Force -AsPlainText
    $pfxPath = Join-Path $ScriptsPath "identityfirst-codesign.pfx"
    Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pwd -Force | Out-Null
    Write-Step "Certificate exported to: $pfxPath"
    
    # Step 3: Export public cer
    Write-Step "Exporting public certificate..."
    $cerPath = Join-Path $ScriptsPath "identityfirst-codesign.cer"
    Export-Certificate -Cert $cert -FilePath $cerPath -Force | Out-Null
    Write-Step "Public certificate exported to: $cerPath"
}

# Step 4: Find signing scripts
Write-Header "Signing PowerShell Scripts"

$signableExtensions = @('.ps1', '.psm1')
$signingScripts = @()

Get-ChildItem -Path $ScriptsPath -Recurse -File | ForEach-Object {
    if ($signableExtensions -contains $_.Extension.ToLower()) {
        $signingScripts += $_.FullName
    }
}

Write-Step "Found $($signingScripts.Count) scripts to sign"

# Step 5: Sign all scripts
$signCount = 0
$errorCount = 0

foreach ($scriptPath in $signingScripts) {
    try {
        $scriptName = Split-Path -Leaf $scriptPath
        
        # Check if already signed
        $signature = Get-AuthenticodeSignature -FilePath $scriptPath
        if ($signature.Status -eq 'Valid') {
            Write-Host "  [=] $scriptName (already signed)" -ForegroundColor Gray
            continue
        }
        
        # Sign the script
        if (-not $ReSignOnly) {
            Set-AuthenticodeSignature -FilePath $scriptPath -Certificate $cert -TimestampServer "http://timestamp.digicert.com" | Out-Null
        } else {
            # Load the PFX for re-signing
            $pfxPath = Join-Path $ScriptsPath "identityfirst-codesign.pfx"
            $cert = Get-PfxCertificate -FilePath $pfxPath
            Set-AuthenticodeSignature -FilePath $scriptPath -Certificate $cert -TimestampServer "http://timestamp.digicert.com" | Out-Null
        }
        
        Write-Host "  [+] $scriptName" -ForegroundColor Green
        $signCount++
    }
    catch {
        Write-Host "  [X] $(Split-Path -Leaf $scriptPath): $($_.Exception.Message)" -ForegroundColor Red
        $errorCount++
    }
}

# Step 6: Summary
Write-Header "Signing Complete"

Write-Host "  Total scripts:  $($signingScripts.Count)"
Write-Host "  Signed:         $signCount" -ForegroundColor Green
Write-Host "  Errors:         $errorCount" -ForegroundColor $(if ($errorCount -gt 0) { "Red" } else { "White" })
Write-Host ""

if (-not $ReSignOnly) {
    Write-Host "Files created:" -ForegroundColor Cyan
    Write-Host "  - identityfirst-codesign.pfx (use for future signing)"
    Write-Host "  - identityfirst-codesign.cer (share with clients)"
    Write-Host ""
    Write-Warning "SECURITY: Protect identityfirst-codesign.pfx - it contains the private key!"
    Write-Warning "If compromised, delete the certificate and create a new one."
    Write-Host ""
    Write-Host "To sign new scripts later, run:" -ForegroundColor Yellow
    Write-Host "  .\Create-SelfSignedCert.ps1 -ReSignOnly" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "To verify signatures:" -ForegroundColor Cyan
Write-Host "  Get-AuthenticodeSignature .\scripts\*.ps1 | Format-Table -Auto" -ForegroundColor White
