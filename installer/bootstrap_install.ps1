<#
.SYNOPSIS
Bootstrap installer that downloads a release ZIP from a URL, verifies integrity and signatures,
and installs files to a target directory.

.DESCRIPTION
Designed for customers to install the read-only IFQC release from a website. It:
- Downloads the release ZIP
- Extracts to a temporary folder
- Verifies file SHA256 checksums using `SHA256SUMS.txt` included in the release
- Verifies Authenticode signatures for PowerShell scripts unless `-AllowUnsigned` is set
- Installs files to the requested install path

.PARAMETER ReleaseUrl
URL to the release ZIP (required).
.PARAMETER InstallPath
Destination folder. Defaults to `%ProgramFiles%\IdentityFirst\IFQC`.
.PARAMETER AllowUnsigned
If set, the installer will allow unsigned PowerShell files (useful for trusted internal builds).
.PARAMETER KeepStaging
If set, keep the temporary staging folder for inspection.

USAGE
pwsh -NoProfile -ExecutionPolicy Bypass -File .\installer\bootstrap_install.ps1 -ReleaseUrl "https://example.com/releases/IFQC-free-20260131.zip"
#
# SECURITY
# - Verify HTTPS URL and validate SHA256SUMS.txt before running any extracted scripts.
# - Prefer signed releases; do not set -AllowUnsigned in production environments.
#
#>

[param(
    [Parameter(Mandatory=$true)] [string]$ReleaseUrl,
    [string]$InstallPath = (Join-Path ${env:ProgramFiles} 'IdentityFirst\IFQC'),
    [switch]$AllowUnsigned,
    [switch]$KeepStaging,
    [switch]$VerifyCosign,
    [string]$RekorUrl = 'https://rekor.sigstore.dev'
)]

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Info { param($m) Write-Host "[INFO] $m" -ForegroundColor Cyan }
function Write-Success { param($m) Write-Host "[OK] $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Write-Err { param($m) Write-Host "[ERR] $m" -ForegroundColor Red }

# Prepare staging
$staging = Join-Path $env:TEMP ("ifqc_install_{0}" -f ([System.Guid]::NewGuid().ToString()))
New-Item -ItemType Directory -Path $staging | Out-Null
$zipPath = Join-Path $staging 'release.zip'

Write-Info "Downloading release: $ReleaseUrl"
try {
    Invoke-WebRequest -Uri $ReleaseUrl -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
} catch {
    Write-Err "Failed to download release: $($_.Exception.Message)"; exit 2
}

# Optionally verify cosign signature (keyless + Rekor). Do this BEFORE extraction.
if ($VerifyCosign) {
    Write-Info "Verifying cosign signature (keyless) against Rekor: $RekorUrl"
    $cosignExe = Join-Path $env:TEMP 'cosign.exe'
    if (-not (Test-Path $cosignExe)) {
        Write-Info "Downloading cosign to: $cosignExe"
        try {
            Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/sigstore/cosign/releases/latest/download/cosign-windows-amd64.exe' -OutFile $cosignExe -ErrorAction Stop
        } catch {
            Write-Err "Failed to download cosign: $($_.Exception.Message)"; exit 10
        }
    }

    try {
        $verifyOutput = & $cosignExe verify --keyless --rekor $RekorUrl $zipPath 2>&1
        Write-Output $verifyOutput
        if ($LASTEXITCODE -ne 0) {
            Write-Err "cosign verification failed (exit $LASTEXITCODE). Aborting install."; exit 11
        } else {
            Write-Success "cosign verification succeeded."
        }
    } catch {
        Write-Err "cosign verification failed: $($_.Exception.Message)"; exit 12
    }
}

Write-Info "Extracting release"
try {
    Expand-Archive -Path $zipPath -DestinationPath $staging -Force
} catch {
    Write-Err "Failed to extract release: $($_.Exception.Message)"; exit 3
}

# Locate SHA256SUMS.txt inside staging
$hashFile = Get-ChildItem -Path $staging -Filter 'SHA256SUMS.txt' -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $hashFile) {
    Write-Warn 'No SHA256SUMS.txt found in release; integrity cannot be verified.'
} else {
    Write-Info "Verifying checksums using: $($hashFile.FullName)"
    $lines = Get-Content -LiteralPath $hashFile.FullName -ErrorAction Stop
    $fail = $false
    foreach ($line in $lines) {
        if ($line -match '^([A-Fa-f0-9]{64})\s+(.+)$') {
            $expected = $matches[1]
            $rel = $matches[2].Trim()
            $path = Join-Path $staging $rel
            if (-not (Test-Path $path)) { Write-Err "Missing file listed in checksums: $rel"; $fail = $true; continue }
            $h = Get-FileHash -Path $path -Algorithm SHA256
            if ($h.Hash -ne $expected) { Write-Err "Checksum mismatch: $rel"; $fail = $true }
        }
    }
    if ($fail) { Write-Err 'Checksum verification failed.'; exit 4 } else { Write-Success 'All checksums verified.' }
}

# Verify Authenticode for scripts
$scriptFiles = Get-ChildItem -Path $staging -Include *.ps1,*.psm1 -Recurse -File -ErrorAction SilentlyContinue
if ($scriptFiles.Count -gt 0) {
    Write-Info "Verifying Authenticode signatures for $($scriptFiles.Count) script files"
    $unsigned = @()
    foreach ($f in $scriptFiles) {
        $sig = Get-AuthenticodeSignature -FilePath $f.FullName
        if ($sig.Status -ne 'Valid') { $unsigned += $f }
    }
    if ($unsigned.Count -gt 0) {
        if ($AllowUnsigned) {
            Write-Warn "Found $($unsigned.Count) unsigned or invalid-signed files; proceeding due to -AllowUnsigned."
        } else {
            Write-Err "Found $($unsigned.Count) unsigned or invalid-signed files. Aborting install."
            foreach ($u in $unsigned) { Write-Err " - $($u.FullName)" }
            exit 5
        }
    } else { Write-Success 'All PowerShell scripts are Authenticode-signed and valid.' }
}

# Install files
Write-Info "Installing to: $InstallPath"
try {
    if (-not (Test-Path $InstallPath)) { New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null }
    # copy extracted root contents (excluding SHA256SUMS.txt)
    Get-ChildItem -Path $staging -Recurse -File | ForEach-Object {
        $rel = $_.FullName.Substring($staging.Length).TrimStart('\\','/')
        if ($rel -ieq 'SHA256SUMS.txt') { return }
        $dest = Join-Path $InstallPath $rel
        $dedir = Split-Path -Parent $dest
        if (-not (Test-Path $dedir)) { New-Item -ItemType Directory -Path $dedir -Force | Out-Null }
        Copy-Item -LiteralPath $_.FullName -Destination $dest -Force
    }
} catch {
    Write-Err "Install failed: $($_.Exception.Message)"; exit 6
}

Write-Success "Installed files to $InstallPath"

if (-not $KeepStaging) {
    try { Remove-Item -Path $staging -Recurse -Force -ErrorAction SilentlyContinue } catch {}
} else { Write-Info "Kept staging folder: $staging" }

Write-Success 'Installation complete.'
exit 0
