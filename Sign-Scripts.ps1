<#
.SYNOPSIS
    Sign all PowerShell scripts in a directory

.DESCRIPTION
    This script signs all .ps1 files in the specified directory using
    a code signing certificate. It also includes integrity checking
    and verification features.

.PARAMETER Path
    Root path to search for scripts (default: current directory)

.PARAMETER CertificatePath
    Path to PFX certificate file

.PARAMETER Password
    Password for PFX certificate (as SecureString)

.PARAMETER TimestampServer
    URL of timestamp server (default: http://timestamp.digicert.com)

.PARAMETER CheckOnly
    Only check signature status, do not sign

.PARAMETER CreateBaseline
    Create integrity baseline after signing

.EXAMPLE
    .\Sign-Scripts.ps1 -Path ".\IdentityQuickChecks" -CertificatePath ".\cert.pfx"

.EXAMPLE
    .\Sign-Scripts.ps1 -CheckOnly -Path ".\"

.NOTES
    This script is part of the IdentityFirst QuickChecks protection suite.
    All methods shown here are free to use.
#>

[CmdletBinding()]
param(
    [string]$Path = ".",
    [string]$CertificatePath,
    [SecureString]$Password,
    [string]$TimestampServer = "http://timestamp.digicert.com",
    [switch]$CheckOnly,
    [switch]$CreateBaseline
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  PowerShell Script Signer & Integrity" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Color definitions
$Green = [System.ConsoleColor]::Green
$Red = [System.ConsoleColor]::Red
$Yellow = [System.ConsoleColor]::Yellow
$Cyan = [System.ConsoleColor]::Cyan
$Gray = [System.ConsoleColor]::Gray

function Get-ScriptFiles {
    <#
    .SYNOPSIS
        Get all PowerShell script files recursively
    #>
    param([string]$SearchPath)
    Get-ChildItem -Path $SearchPath -Filter "*.ps1" -Recurse -ErrorAction SilentlyContinue
}

function Test-Certificate {
    <#
    .SYNOPSIS
        Test if certificate is valid for code signing
    #>
    param([string]$CertPath, [SecureString]$CertPassword)

    try {
        $cert = Get-PfxCertificate -FilePath $CertPath -Password $CertPassword -ErrorAction Stop

        # Check if certificate is valid for code signing
        $keyUsage = $cert.EnhancedKeyUsageList | Where-Object { $_.FriendlyName -eq "Code Signing" }

        if (-not $keyUsage) {
            Write-Host "  WARNING: Certificate may not be configured for code signing" -ForegroundColor $Yellow
        }

        return $cert
    }
    catch {
        Write-Host "  ERROR: Failed to load certificate: $($_.Exception.Message)" -ForegroundColor $Red
        return $null
    }
}

function Test-Signature {
    <#
    .SYNOPSIS
        Check if a file has a valid signature
    #>
    param([string]$FilePath)

    try {
        $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop

        if ($sig.Status -eq 'Valid') {
            return @{
                Signed = $true
                Signer = $sig.SignerCertificate.Subject
                Timestamp = $sig.TimeStamperCertificate.NotAfter
                Status = $sig.Status
            }
        }
        else {
            return @{
                Signed = $false
                Signer = $null
                Timestamp = $null
                Status = $sig.Status
            }
        }
    }
    catch {
        return @{
            Signed = $false
            Signer = $null
            Timestamp = $null
            Status = "Error: $($_.Exception.Message)"
        }
    }
}

function New-IntegrityBaseline {
    <#
    .SYNOPSIS
        Create SHA256 hash baseline for all scripts
    #>
    param([string]$BasePath, [string]$OutputFile)

    $baseline = @{
        Created = [datetime]::UtcNow
        Algorithm = "SHA256"
        Scripts = @{}
    }

    Get-ScriptFiles -SearchPath $BasePath | ForEach-Object {
        $hash = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash
        $baseline.Scripts[$_.FullName] = @{
            Hash = $hash
            Size = $_.Length
            LastModified = $_.LastWriteTimeUtc
            Signed = (Test-Signature -FilePath $_.FullName).Signed
        }
    }

    $baseline | ConvertTo-Json -Depth 5 | Out-File -Path $OutputFile -Encoding UTF8
    Write-Host "  Baseline created: $OutputFile" -ForegroundColor $Green
    Write-Host "  Scripts indexed: $($baseline.Scripts.Count)" -ForegroundColor $Gray
}

function Test-IntegrityBaseline {
    <#
    .SYNOPSIS
        Compare current files against baseline
    #>
    param([string]$BaselineFile)

    if (-not (Test-Path $BaselineFile)) {
        Write-Host "  ERROR: Baseline file not found" -ForegroundColor $Red
        return
    }

    $baseline = Get-Content -Path $BaselineFile | ConvertFrom-Json
    $violations = @()

    foreach ($script in $baseline.Scripts.PSObject.Properties) {
        $currentHash = (Get-FileHash -Path $script.Name -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        $storedHash = $script.Value.Hash

        if ($currentHash -ne $storedHash) {
            $violations += @{
                File = $script.Name
                Issue = "Hash mismatch"
                Original = $storedHash
                Current = $currentHash
            }
        }

        # Check if signature status changed
        $currentSigned = (Test-Signature -FilePath $script.Name).Signed
        if ($currentSigned -ne $script.Value.Signed) {
            $violations += @{
                File = $script.Name
                Issue = "Signature status changed"
                WasSigned = $script.Value.Signed
                IsSigned = $currentSigned
            }
        }
    }

    if ($violations) {
        Write-Host "  Found $($violations.Count) integrity violations:" -ForegroundColor $Red
        foreach ($v in $violations) {
            Write-Host "    - $($v.File): $($v.Issue)" -ForegroundColor $Yellow
        }
    }
    else {
        Write-Host "  All files pass integrity check" -ForegroundColor $Green
    }

    return $violations
}

function Sign-Script {
    <#
    .SYNOPSIS
        Sign a single PowerShell script
    #>
    param(
        [string]$FilePath,
        $Certificate,
        [string]$TimestampServer
    )

    try {
        $sig = Set-AuthenticodeSignature `
            -FilePath $FilePath `
            -Certificate $Certificate `
            -TimestampServer $TimestampServer `
            -ErrorAction Stop

        return @{
            Success = $true
            File = $FilePath
            Status = $sig.Status
        }
    }
    catch {
        return @{
            Success = $false
            File = $FilePath
            Error = $_.Exception.Message
        }
    }
}

# Main execution
Write-Host "[INFO] Scanning for PowerShell scripts in: $Path" -ForegroundColor $Gray
$scripts = Get-ScriptFiles -SearchPath $Path
Write-Host "[INFO] Found $($scripts.Count) scripts" -ForegroundColor $Gray
Write-Host ""

if ($scripts.Count -eq 0) {
    Write-Host "No PowerShell scripts found." -ForegroundColor $Yellow
    exit 0
}

if ($CheckOnly) {
    # Check-only mode: verify signatures
    Write-Host "========================================" -ForegroundColor $Cyan
    Write-Host "  Signature Verification Results" -ForegroundColor $Cyan
    Write-Host "========================================" -ForegroundColor $Cyan
    Write-Host ""

    $signed = 0
    $unsigned = 0
    $errors = 0

    foreach ($script in $scripts) {
        $result = Test-Signature -FilePath $script.FullName

        if ($result.Signed) {
            Write-Host "[SIGNED]   $($script.Name)" -ForegroundColor $Green
            Write-Host "           Signer: $($result.Signer)" -ForegroundColor $Gray
            $signed++
        }
        else {
            Write-Host "[UNSIGNED] $($script.Name)" -ForegroundColor $Yellow
            Write-Host "           Status: $($result.Status)" -ForegroundColor $Gray
            $unsigned++
        }
    }

    Write-Host ""
    Write-Host "========================================" -ForegroundColor $Cyan
    Write-Host "  Summary" -ForegroundColor $Cyan
    Write-Host "========================================" -ForegroundColor $Cyan
    Write-Host "  Signed:   $signed" -ForegroundColor $Green
    Write-Host "  Unsigned: $unsigned" -ForegroundColor $Yellow
    Write-Host "  Total:    $($scripts.Count)" -ForegroundColor $Gray
}
else {
    # Signing mode: require certificate
    if (-not $CertificatePath) {
        Write-Host "[ERROR] Certificate path required for signing" -ForegroundColor $Red
        Write-Host "        Use: .\Sign-Scripts.ps1 -CertificatePath '.\cert.pfx'" -ForegroundColor $Gray
        exit 1
    }

    if (-not $Password) {
        Write-Host "[ERROR] Certificate password required" -ForegroundColor $Red
        Write-Host "        Use: .\Sign-Scripts.ps1 -CertificatePath '.\cert.pfx' -Password (ConvertTo-SecureString 'password' -AsPlainText -Force)" -ForegroundColor $Gray
        exit 1
    }

    # Load certificate
    Write-Host "[INFO] Loading certificate: $CertificatePath" -ForegroundColor $Gray
    $cert = Test-Certificate -CertPath $CertificatePath -CertPassword $Password
    if (-not $cert) {
        exit 1
    }
    Write-Host "  Certificate loaded: $($cert.Subject)" -ForegroundColor $Green
    Write-Host "  Valid from: $($cert.NotBefore) to $($cert.NotAfter)" -ForegroundColor $Gray
    Write-Host ""

    # Sign all scripts
    Write-Host "========================================" -ForegroundColor $Cyan
    Write-Host "  Signing Scripts" -ForegroundColor $Cyan
    Write-Host "========================================" -ForegroundColor $Cyan
    Write-Host ""

    $success = 0
    $failed = 0

    foreach ($script in $scripts) {
        Write-Host "[SIGNING] $($script.Name)..." -ForegroundColor $Gray
        $result = Sign-Script `
            -FilePath $script.FullName `
            -Certificate $cert `
            -TimestampServer $TimestampServer

        if ($result.Success) {
            Write-Host "  [OK] Signed successfully" -ForegroundColor $Green
            $success++
        }
        else {
            Write-Host "  [FAILED] $($result.Error)" -ForegroundColor $Red
            $failed++
        }
    }

    Write-Host ""
    Write-Host "========================================" -ForegroundColor $Cyan
    Write-Host "  Signing Complete" -ForegroundColor $Cyan
    Write-Host "========================================" -ForegroundColor $Cyan
    Write-Host "  Success: $success" -ForegroundColor $Green
    Write-Host "  Failed:  $failed" -ForegroundColor $Red
    Write-Host "  Total:   $($scripts.Count)" -ForegroundColor $Gray
}

# Create integrity baseline if requested
if ($CreateBaseline -or (-not $CheckOnly)) {
    Write-Host ""
    Write-Host "[INFO] Creating integrity baseline..." -ForegroundColor $Gray
    $baselineFile = Join-Path $Path "integrity-baseline.json"
    New-IntegrityBaseline -BasePath $Path -OutputFile $baselineFile
}

Write-Host ""
Write-Host "Done!" -ForegroundColor $Green
