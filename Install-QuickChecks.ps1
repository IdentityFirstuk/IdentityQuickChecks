<#
.SYNOPSIS
    Install IdentityFirst QuickChecks module.

.DESCRIPTION
    Installs the QuickChecks module to the local PowerShell modules directory.
    Supports both per-user and all-users installation.

.OUTPUTS
    - Module installed to PowerShell modules folder

.NOTES
    Author: IdentityFirst Ltd
    Requirements: PowerShell 5.1+
    
.USAGE
    # Install for current user only
    .\Install-QuickChecks.ps1
    
    # Install for all users (requires admin)
    .\Install-QuickChecks.ps1 -AllUsers
    
    # Install from extracted ZIP
    .\Install-QuickChecks.ps1 -SourcePath "C:\Downloads\IdentityFirst.QuickChecks-v1.0.0"
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$SourcePath = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    
    [Parameter()]
    [switch]$AllUsers,
    
    [Parameter()]
    [switch]$Force,
    
    [Parameter()]
    [switch]$Help
)

if ($Help) {
    Write-Host @"
IdentityFirst QuickChecks - Installation Script
================================================

Installs the QuickChecks module to your PowerShell modules directory.

USAGE:
  .\Install-QuickChecks.ps1                    # Current user
  .\Install-QuickChecks.ps1 -AllUsers          # All users (admin required)
  .\Install-QuickChecks.ps1 -Force             # Overwrite existing
  .\Install-QuickChecks.ps1 -SourcePath ".\path"  # From specific location

INSTALLATION LOCATIONS:
  Current User:  %USERPROFILE%\Documents\WindowsPowerShell\Modules\IdentityFirst.QuickChecks
  All Users:     %ProgramFiles%\WindowsPowerShell\Modules\IdentityFirst.QuickChecks

AFTER INSTALLATION:
  Import-Module IdentityFirst.QuickChecks
  Get-Command -Module IdentityFirst.QuickChecks

TO RUN CHECKS:
  Import-Module IdentityFirst.QuickChecks
  Invoke-BreakGlassReality.ps1
  .\Run-AllQuickChecks.ps1

"@
    exit 0
}

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║       IdentityFirst QuickChecks - Installation            ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Determine installation path
$moduleName = "IdentityFirst.QuickChecks"
$moduleVersion = "1.0.0"

# Read version from file if exists
$versionFile = Join-Path $SourcePath "VERSION.txt"
if (Test-Path $versionFile) {
    $moduleVersion = (Get-Content $versionFile -Raw).Trim()
}

if ($AllUsers) {
    # All users installation
    $installPath = Join-Path $env:ProgramFiles "WindowsPowerShell\Modules\$moduleName"
} else {
    # Current user installation
    $documentsPath = [Environment]::GetFolderPath("MyDocuments")
    $installPath = Join-Path $documentsPath "WindowsPowerShell\Modules\$moduleName"
}

Write-Host "  Source:     $SourcePath" -ForegroundColor Gray
Write-Host "  Target:     $installPath" -ForegroundColor Gray
Write-Host "  Version:    $moduleVersion" -ForegroundColor Gray
Write-Host "  All Users:  $(if ($AllUsers) { 'Yes' } else { 'No' })" -ForegroundColor Gray
Write-Host ""

# Check if already installed
if (Test-Path $installPath) {
    $existingVersion = "Unknown"
    $existingVersionFile = Join-Path $installPath "VERSION.txt"
    if (Test-Path $existingVersionFile) {
        $existingVersion = (Get-Content $existingVersionFile -Raw).Trim()
    }
    
    Write-Host "  ⚠ Module already installed: v$existingVersion" -ForegroundColor Yellow
    
    if (-not $Force) {
        Write-Host ""
        Write-Host "  Use -Force to overwrite or -AllUsers for machine-wide install." -ForegroundColor Gray
        $response = Read-Host "  Continue with installation? (y/n)"
        if ($response.ToLower() -ne "y") {
            Write-Host "Installation cancelled." -ForegroundColor Gray
            exit 0
        }
    }
    
    Write-Host "  Removing existing installation..." -ForegroundColor Gray
    Remove-Item -Path $installPath -Recurse -Force
}

# Create installation directory
Write-Host "  Creating module directory..." -ForegroundColor Gray
New-Item -ItemType Directory -Path $installPath -Force | Out-Null

# Copy module files
Write-Host "  Copying module files..." -ForegroundColor Gray

$copyItems = @(
    @{ Source = "Module"; Target = "Module" }
    @{ Source = "Checks"; Target = "Checks" }
    @{ Source = "Run-AllQuickChecks.ps1"; Target = "Run-AllQuickChecks.ps1" }
    @{ Source = "README.md"; Target = "README.md" }
    @{ Source = "EULA.txt"; Target = "EULA.txt" }
    @{ Source = "VERSION.txt"; Target = "VERSION.txt" }
)

foreach ($item in $copyItems) {
    $src = Join-Path $SourcePath $item.Source
    $dst = Join-Path $installPath $item.Target
    
    if (Test-Path $src) {
        if (Test-Path $src -PathType Container) {
            Copy-Item -Path $src -Destination $dst -Recurse -Force
        } else {
            Copy-Item -Path $src -Destination $dst -Force
        }
        Write-Host "    ✓ $($item.Source)" -ForegroundColor Gray
    }
}

# Create version-specific directory (optional but good practice)
$versionedPath = Join-Path $installPath $moduleVersion
New-Item -ItemType Directory -Path $versionedPath -Force | Out-Null

# Copy files to versioned directory as well (PowerShellGet compatible)
Write-Host "  Setting up versioned directory..." -ForegroundColor Gray
foreach ($item in $copyItems) {
    $src = Join-Path $SourcePath $item.Source
    $dst = Join-Path $versionedPath $item.Target
    
    if (Test-Path $src) {
        if (Test-Path $src -PathType Container) {
            Copy-Item -Path $src -Destination $dst -Recurse -Force
        } else {
            Copy-Item -Path $src -Destination $dst -Force
        }
    }
}

# Verify installation
Write-Host ""
Write-Host "  Verifying installation..." -ForegroundColor Gray

$manifestPath = Join-Path $installPath "IdentityFirst.QuickChecks.psd1"
if (Test-Path $manifestPath) {
    try {
        $manifest = Import-PowerShellDataFile $manifestPath -ErrorAction Stop
        Write-Host "    ✓ Module manifest loaded successfully" -ForegroundColor Green
        Write-Host "    ✓ Version: $($manifest.ModuleVersion)" -ForegroundColor Gray
    } catch {
        Write-Host "    ⚠ Warning: Could not load manifest: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# Summary
Write-Host ""
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Installation Complete" -ForegroundColor White
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Module installed to:" -ForegroundColor Gray
Write-Host "  $installPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "  To use, run:" -ForegroundColor Gray
Write-Host "  Import-Module IdentityFirst.QuickChecks" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Or run individual checks:" -ForegroundColor Gray
Write-Host "  Import-Module '$installPath'" -ForegroundColor Yellow
Write-Host "  Invoke-BreakGlassReality.ps1" -ForegroundColor Yellow
