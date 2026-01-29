<#
.SYNOPSIS
    Package IdentityFirst QuickChecks for distribution.

.DESCRIPTION
    Creates a ZIP archive of all QuickChecks scripts for easy download
    and distribution. Optionally signs scripts before packaging.

.OUTPUTS
    - IdentityFirst.QuickChecks-v{version}.zip

.NOTES
    Author: IdentityFirst Ltd
    Requirements: PowerShell 5.1+
    
.USAGE
    # Create package
    .\Package-QuickChecks.ps1
    
    # Create package with signed scripts
    .\Package-QuickChecks.ps1 -SignScripts
    
    # Specify version
    .\Package-QuickChecks.ps1 -Version "1.0.1"
    
    # Skip README/EULA from package
    .\Package-QuickChecks.ps1 -NoDocumentation
    
    # Custom output directory
    .\Package-QuickChecks.ps1 -OutputPath ".\dist"
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ModulePath = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    
    [Parameter()]
    [string]$Version = "1.0.0",
    
    [Parameter()]
    [string]$OutputPath = ".\package",
    
    [Parameter()]
    [switch]$SignScripts,
    
    [Parameter()]
    [switch]$IncludeDocs = $true,
    
    [parameter()]
    [string]$CertPath,
    
    [parameter()]
    [securestring]$CertPassword,
    
    [Parameter()]
    [switch]$Help
)

if ($Help) {
    Write-Host @"
IdentityFirst QuickChecks - Packaging Script
=============================================

Creates a ZIP archive of all QuickChecks scripts for distribution.

USAGE:
  .\Package-QuickChecks.ps1                    # Basic package
  .\Package-QuickChecks.ps1 -Version "1.0.1"   # Custom version
  .\Package-QuickChecks.ps1 -SignScripts       # Sign before packaging
  .\Package-QuickChecks.ps1 -NoDocumentation   # Skip docs
  .\Package-QuickChecks.ps1 -OutputPath ".\dist"  # Custom output

OUTPUT:
  IdentityFirst.QuickChecks-v{version}.zip
  
CONTENTS:
  - Module/ (framework scripts)
  - Checks/ (all check scripts)
  - Run-AllQuickChecks.ps1 (launcher)
  - README.md (if included)
  - EULA.txt (if included)

AFTER PACKAGING:
1. Test the package by extracting and running
2. Upload to your website for download
3. Consider signing scripts for production use

"@
    exit 0
}

# Load version from module if not specified
if ($Version -eq "1.0.0") {
    $moduleFile = Join-Path $ModulePath "Module\IdentityFirst.QuickChecks.psd1"
    if (Test-Path $moduleFile) {
        $moduleData = Import-PowerShellDataFile $moduleFile -ErrorAction SilentlyContinue
        if ($moduleData.ModuleVersion) {
            $Version = $moduleData.ModuleVersion
        }
    }
}

$zipName = "IdentityFirst.QuickChecks-v$Version.zip"
$zipPath = Join-Path $OutputPath $zipName

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║       IdentityFirst QuickChecks - Packaging               ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Version:  $Version" -ForegroundColor Gray
Write-Host "  Output:   $zipPath" -ForegroundColor Gray
Write-Host "  Signing:  $(if ($SignScripts) { 'Yes' } else { 'No' })" -ForegroundColor Gray
Write-Host "  Docs:     $(if ($IncludeDocs) { 'Yes' } else { 'No' })" -ForegroundColor Gray
Write-Host ""

# Check for required files
$requiredPaths = @(
    "Module\IdentityFirst.QuickChecks.psm1",
    "Checks",
    "Run-AllQuickChecks.ps1"
)

foreach ($relPath in $requiredPaths) {
    $fullPath = Join-Path $ModulePath $relPath
    if (-not (Test-Path $fullPath)) {
        Write-Host "ERROR: Required path not found: $fullPath" -ForegroundColor Red
        exit 1
    }
}

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    Write-Host "Created output directory: $OutputPath" -ForegroundColor Gray
}

# Create temporary working directory
$tempDir = Join-Path $OutputPath "temp_$([guid]::NewGuid().ToString('N').Substring(0,8))"
New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
Write-Host "Created temp directory: $tempDir" -ForegroundColor Gray

try {
    # Copy module directory structure
    Write-Host ""
    Write-Host "Copying module files..." -ForegroundColor Gray
    
    $copySpec = @(
        @{ From = "Module"; To = "Module" }
        @{ From = "Checks"; To = "Checks" }
        @{ From = "Run-AllQuickChecks.ps1"; To = "Run-AllQuickChecks.ps1" }
    )
    
    if ($IncludeDocs) {
        $copySpec += @{ From = "README.md"; To = "README.md" }
        $copySpec += @{ From = "EULA.txt"; To = "EULA.txt" }
    }
    
    foreach ($item in $copySpec) {
        $src = Join-Path $ModulePath $item.From
        $dst = Join-Path $tempDir $item.To
        
        if (Test-Path $src) {
            if (Test-Path $src -PathType Container) {
                Copy-Item -Path $src -Destination $dst -Recurse -Force
            } else {
                Copy-Item -Path $src -Destination $dst -Force
            }
            Write-Host "  ✓ $($item.From)" -ForegroundColor Gray
        }
    }
    
    # Sign scripts if requested
    if ($SignScripts) {
        Write-Host ""
        Write-Host "Signing scripts..." -ForegroundColor Gray
        
        $signScript = Join-Path $ModulePath "Sign-QuickChecks.ps1"
        if (-not (Test-Path $signScript)) {
            Write-Host "ERROR: Sign-QuickChecks.ps1 not found" -ForegroundColor Red
            exit 1
        }
        
        $signArgs = @("-ModulePath", $tempDir)
        if ($CertPath) {
            $signArgs += "-CertPath", $CertPath
        }
        if ($CertPassword) {
            $signArgs += "-CertPassword", $CertPassword
        }
        
        # Run signing in temp directory context
        Push-Location $tempDir
        try {
            & $signScript @signArgs | Out-Host
        } finally {
            Pop-Location
        }
    }
    
    # Create ZIP file
    Write-Host ""
    Write-Host "Creating ZIP archive..." -ForegroundColor Gray
    
    # Remove existing ZIP
    if (Test-Path $zipPath) {
        Remove-Item $zipPath -Force
        Write-Host "  Removed existing: $zipName" -ForegroundColor Gray
    }
    
    # Create ZIP using .NET compression
    $zip = [System.IO.Compression.ZipFile]::Open($zipPath, [System.IO.Compression.ZipArchiveMode]::Create)
    
    try {
        # Get all files to add
        $files = Get-ChildItem -Path $tempDir -Recurse -File
        
        foreach ($file in $files) {
            # Calculate relative path within ZIP
            $relativePath = $file.FullName.Substring($tempDir.Length + 1).Replace('\', '/')
            
            # Add to ZIP
            $entry = $zip.CreateEntry($relativePath)
            $stream = $entry.Open()
            try {
                $file.OpenRead().CopyTo($stream)
            } finally {
                $stream.Close()
            }
            
            Write-Host "  ✓ $relativePath" -ForegroundColor Gray
        }
    } finally {
        $zip.Dispose()
    }
    
    # Get ZIP size
    $zipSize = (Get-Item $zipPath).Length
    $zipSizeStr = if ($zipSize -gt 1MB) { "{0:N1} MB" -f ($zipSize / 1MB) } else { "{0:N0} KB" -f ($zipSize / 1KB) }
    
    # Summary
    Write-Host ""
    Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Packaging Complete" -ForegroundColor White
    Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  File:    $zipName" -ForegroundColor Gray
    Write-Host "  Size:    $zipSizeStr" -ForegroundColor Gray
    Write-Host "  Scripts: $($files.Count)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Ready for distribution!" -ForegroundColor Green
    
} finally {
    # Clean up temp directory
    if (Test-Path $tempDir) {
        Remove-Item -Path $tempDir -Recurse -Force
        Write-Host ""
        Write-Host "Cleaned up temp directory" -ForegroundColor Gray
    }
}
