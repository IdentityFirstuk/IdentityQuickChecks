<#
.SYNOPSIS
    One-command script to build, sign, package, and install QuickChecks.

.DESCRIPTION
    This master script automates the entire process:
    - Creates/verifies code signing certificate
    - Signs all scripts
    - Creates distribution package
    - Optionally installs locally

.USAGE
    # Build and create distribution package:
    .\Build-And-Install.ps1 -Build

    # Build and install locally:
    .\Build-And-Install.ps1 -Build -Install

    # Install from existing package:
    .\Build-And-Install.ps1 -InstallFromPackage

.NOTES
    File Name      : Build-And-Install.ps1
    Prerequisite   : PowerShell 5.1 or 7+ (Windows)
    Author         : IdentityFirst Ltd
#>

param(
    # Build and sign all scripts
    [switch]$Build,

    # Install locally after building
    [switch]$Install,

    # Install from existing package
    [switch]$InstallFromPackage,

    # Package path for installation
    [string]$PackagePath,

    # Force rebuild even if already signed
    [switch]$Force
)

# Configuration
$Script:CertThumbprint = '602A77B6D1CAC3C6AD875CBED65A8D227BF77189'
$Script:CertSubject = 'CN=IdentityFirst Code Signing'
$Script:RootCAThumbprint = '602A77B6D1CAC3C6AD875CBED65A8D227BF77189'
$Script:RootCASubject = 'CN=IdentityFirst Root CA'
$Script:CertPassword = 'IdentityFirst2026!'
$Script:InstallPath = "$env:ProgramData\IdentityFirst\QuickChecks"
$Script:PackageName = 'IdentityFirst-QuickChecks'
$Script:ProjectRoot = $PSScriptRoot

function Write-Host {
    param([string]$Message, [string]$ForegroundColor)
    if ($ForegroundColor) {
        $host.UI.RawUI.ForegroundColor = $ForegroundColor
    }
    Write-Output $Message
    if ($ForegroundColor) {
        $host.UI.RawUI.ForegroundColor = $null
    }
}

function Get-OrCreateCertificate {
    Write-Host "[*] Checking for existing certificate..." -ForegroundColor Cyan

    $existingCert = Get-ChildItem -Path 'Cert:\CurrentUser\My' |
        Where-Object { $_.Subject -eq $CertSubject -and $_.Thumbprint -eq $CertThumbprint } |
        Select-Object -First 1

    if ($existingCert) {
        Write-Host "[+] Found existing certificate" -ForegroundColor Green
        return $existingCert
    }

    Write-Host "[*] Creating new self-signed certificate..." -ForegroundColor Cyan

    $rootCA = New-SelfSignedCertificate `
        -Subject $RootCASubject `
        -KeyUsage CertSign, CRLSign `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -NotAfter (Get-Date).AddYears(10)

    $codeCert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $CertSubject `
        -KeyUsage DigitalSignature `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -NotAfter (Get-Date).AddYears(5)

    $pwd = ConvertTo-SecureString -String $Script:CertPassword -AsPlainText -Force
    $certPfxPath = Join-Path -Path $Script:ProjectRoot -ChildPath 'IdentityFirst-CodeSign.pfx'
    $rootPfxPath = Join-Path -Path $Script:ProjectRoot -ChildPath 'IdentityFirst-Root.pfx'
    $rootCerPath = Join-Path -Path $Script:ProjectRoot -ChildPath 'IdentityFirst-Root-CA.cer'

    Export-PfxCertificate -Cert $codeCert -FilePath $certPfxPath -Password $pwd | Out-Null
    Export-PfxCertificate -Cert $rootCA -FilePath $rootPfxPath -Password $pwd | Out-Null
    Export-Certificate -Cert $rootCA -FilePath $rootCerPath | Out-Null

    Write-Host "[+] Certificate created and exported" -ForegroundColor Green
    return $codeCert
}

function Install-RootCA {
    Write-Host "[*] Installing Root CA..." -ForegroundColor Cyan

    $isAdmin = Test-AdministratorRole
    if (-not $isAdmin) {
        Write-Host "  WARNING: Administrator privileges required" -ForegroundColor Yellow
        return $false
    }

    $existing = Get-ChildItem -Path 'Cert:\LocalMachine\Root' |
        Where-Object { $_.Thumbprint -eq $RootCAThumbprint }

    if ($existing) {
        Write-Host "[+] Root CA already installed" -ForegroundColor Green
        return $true
    }

    $rootCerPath = Join-Path -Path $Script:ProjectRoot -ChildPath 'IdentityFirst-Root-CA.cer'
    if (-not (Test-Path $rootCerPath)) {
        Write-Host "  ERROR: Root CA certificate not found" -ForegroundColor Red
        return $false
    }

    Import-Certificate -FilePath $rootCerPath -CertStoreLocation 'Cert:\LocalMachine\Root' | Out-Null
    Write-Host "[+] Root CA installed to Local Machine store" -ForegroundColor Green
    return $true
}

function Sign-Scripts {
    param([switch]$Force)
    Write-Host "[*] Signing scripts..." -ForegroundColor Cyan

    $pwd = ConvertTo-SecureString -String $Script:CertPassword -AsPlainText -Force
    $cert = Get-PfxCertificate -FilePath (Join-Path -Path $Script:ProjectRoot -ChildPath 'IdentityFirst-CodeSign.pfx') -Password $pwd

    $scriptDirs = @(
        (Join-Path -Path $Script:ProjectRoot -ChildPath 'scripts'),
        (Join-Path -Path $Script:ProjectRoot -ChildPath 'scripts\Obfuscated')
    )

    $signedCount = 0
    $skipCount = 0

    foreach ($dir in $scriptDirs) {
        if (-not (Test-Path $dir)) { continue }

        $scripts = Get-ChildItem -Path $dir -Filter '*.ps1' -Recurse

        foreach ($script in $scripts) {
            if (-not $Force) {
                $sig = Get-AuthenticodeSignature -FilePath $script.FullName -ErrorAction SilentlyContinue
                if ($sig.Status -eq 'Valid') {
                    $skipCount++
                    continue
                }
            }

            $null = Set-AuthenticodeSignature `
                -FilePath $script.FullName `
                -Certificate $cert `
                -HashAlgorithm SHA256 `
                -TimestampServer 'http://timestamp.digicert.com' `
                -ErrorAction SilentlyContinue

            $signedCount++
            Write-Host "  Signed: $($script.Name)" -ForegroundColor Gray
        }
    }

    Write-Host "[+] Signed: $signedCount scripts" -ForegroundColor Green
    if ($skipCount -gt 0) {
        Write-Host "  Skipped: $skipCount already signed" -ForegroundColor Gray
    }
}

function New-DistributionPackage {
    Write-Host "[*] Creating distribution package..." -ForegroundColor Cyan

    $packageDir = Join-Path -Path $Script:ProjectRoot -ChildPath 'releases'
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $packageName = "$Script:PackageName-$timestamp"
    $packagePath = Join-Path -Path $packageDir -ChildPath $packageName

    New-Item -Path $packagePath -ItemType Directory -Force | Out-Null

    Write-Host "  Copying certificates..." -ForegroundColor Gray
    Copy-Item -Path (Join-Path -Path $Script:ProjectRoot -ChildPath 'IdentityFirst-Root-CA.cer') -Destination $packagePath
    Copy-Item -Path (Join-Path -Path $Script:ProjectRoot -ChildPath 'IdentityFirst-CodeSign.pfx') -Destination $packagePath

    Write-Host "  Copying install script..." -ForegroundColor Gray
    Copy-Item -Path (Join-Path -Path $Script:ProjectRoot -ChildPath 'scripts\Install-QuickChecks.ps1') -Destination $packagePath

    Write-Host "  Copying scripts..." -ForegroundColor Gray
    $scriptsDest = Join-Path -Path $packagePath -ChildPath 'scripts'
    Copy-Item -Path (Join-Path -Path $Script:ProjectRoot -ChildPath 'scripts\Obfuscated') -Destination $scriptsDest -Recurse

    Write-Host "  Copying modules..." -ForegroundColor Gray
    $moduleFolders = @('IdentityQuickChecks', 'IdentityAssumptionQuickChecks', 'IdentityBoundaryQuickChecks', 'IdentityTrustQuickChecks')
    foreach ($folder in $moduleFolders) {
        $src = Join-Path -Path $Script:ProjectRoot -ChildPath $folder
        if (Test-Path $src) {
            Copy-Item -Path $src -Destination $packagePath -Recurse
        }
    }

    Write-Host "  Copying documentation..." -ForegroundColor Gray
    Copy-Item -Path (Join-Path -Path $Script:ProjectRoot -ChildPath 'README.md') -Destination $packagePath

    Write-Host "  Creating ZIP archive..." -ForegroundColor Gray
    $zipPath = "$packagePath.zip"
    Compress-Archive -Path "$packagePath\*" -DestinationPath $zipPath -Force

    Write-Host "[+] Package created: $zipPath" -ForegroundColor Green
    Write-Host "    Size: $([math]::Round((Get-Item $zipPath).Length / 1MB, 2)) MB" -ForegroundColor Gray
    return $zipPath
}

function Install-Locally {
    Write-Host "[*] Installing QuickChecks locally..." -ForegroundColor Cyan

    $caResult = Install-RootCA

    New-Item -Path $Script:InstallPath -ItemType Directory -Force | Out-Null

    Write-Host "  Copying modules..." -ForegroundColor Gray
    $moduleFolders = @('IdentityQuickChecks', 'IdentityAssumptionQuickChecks', 'IdentityBoundaryQuickChecks', 'IdentityTrustQuickChecks')
    foreach ($folder in $moduleFolders) {
        $src = Join-Path -Path $Script:ProjectRoot -ChildPath $folder
        $dest = Join-Path -Path $Script:InstallPath -ChildPath $folder
        if (Test-Path $src) {
            Copy-Item -Path $src -Destination $dest -Recurse -Force
        }
    }

    Write-Host "  Copying scripts..." -ForegroundColor Gray
    $scriptsDest = Join-Path -Path $Script:InstallPath -ChildPath 'scripts'
    Copy-Item -Path (Join-Path -Path $Script:ProjectRoot -ChildPath 'scripts\Obfuscated') -Destination $scriptsDest -Recurse

    Copy-Item -Path (Join-Path -Path $Script:ProjectRoot -ChildPath 'IdentityFirst-Root-CA.cer') -Destination $Script:InstallPath
    Copy-Item -Path (Join-Path -Path $Script:ProjectRoot -ChildPath 'IdentityFirst-CodeSign.pfx') -Destination $Script:InstallPath
    Copy-Item -Path (Join-Path -Path $Script:ProjectRoot -ChildPath 'scripts\Install-QuickChecks.ps1') -Destination $Script:InstallPath

    Write-Host "[+] Installed to: $Script:InstallPath" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Usage:" -ForegroundColor Cyan
    Write-Host "    Import-Module IdentityQuickChecks" -ForegroundColor Gray
    Write-Host "    Get-Command -Module IdentityQuickChecks" -ForegroundColor Gray
}

function Install-FromPackage {
    param([string]$PackageFile)
    if (-not (Test-Path $PackageFile)) {
        Write-Host "ERROR: Package not found: $PackageFile" -ForegroundColor Red
        return $false
    }

    Write-Host "[*] Installing from package: $PackageFile" -ForegroundColor Cyan

    $tempDir = Join-Path -Path $Script:ProjectRoot -ChildPath 'temp-install'
    New-Item -Path $tempDir -ItemType Directory -Force | Out-Null

    Write-Host "  Extracting..." -ForegroundColor Gray
    Expand-Archive -Path $PackageFile -DestinationPath $tempDir -Force

    $installScript = Join-Path -Path $tempDir -ChildPath 'Install-QuickChecks.ps1'
    if (Test-Path $installScript) {
        & $installScript -InstallModules -TrustCertificate
    }

    Remove-Item -Path $tempDir -Recurse -Force
    Write-Host "[+] Installation complete" -ForegroundColor Green
}

function Test-AdministratorRole {
    $currentUser = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList (
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Main
Write-Host ""
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "  IdentityFirst QuickChecks - Build & Install  " -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ""

if ($Build) {
    $cert = Get-OrCreateCertificate
    Sign-Scripts -Force:$Force
    $packagePath = New-DistributionPackage

    if ($Install) {
        Install-Locally
    }

    Write-Host ""
    Write-Host "=================================================" -ForegroundColor Cyan
    Write-Host "  Package: $packagePath" -ForegroundColor Green
    Write-Host ""
    Write-Host "  To install on another machine:" -ForegroundColor Cyan
    Write-Host "    1. Copy the ZIP file" -ForegroundColor Gray
    Write-Host "    2. Extract and run Install-QuickChecks.ps1" -ForegroundColor Gray
    Write-Host "=================================================" -ForegroundColor Cyan
}

if ($InstallFromPackage) {
    if (-not $PackagePath) {
        $packages = Get-ChildItem -Path (Join-Path -Path $Script:ProjectRoot -ChildPath 'releases') -Filter '*.zip' | Sort-Object LastWriteTime -Descending
        if ($packages) {
            $PackagePath = $packages[0].FullName
        }
    }
    Install-FromPackage -PackageFile $PackagePath
}
