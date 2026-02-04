# ============================================================================
# IdentityFirst QuickChecks - Release Verification Script
# ============================================================================
# Verifies the integrity and authenticity of downloaded release
# ============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ReleasePath,
    
    [Parameter(Mandatory=$false)]
    [string]$ExpectedVersion = '1.0.0',
    
    [Parameter(Mandatory=$false)]
    [switch]$ExtractOnly,
    
    [Parameter(Mandatory=$false)]
    [switch]$Verbose
)

$ErrorActionPreference = 'Stop'

# ANSI colors
$Green = [char]27 + '[32m'
$Red = [char]27 + '[31m'
$Yellow = [char]27 + '[33m'
$Cyan = [char]27 + '[36m'
$Reset = [char]27 + '[0m'

function Write-Header {
    param([string]$Text)
    Write-Host "`n$('=' * 70)" -ForegroundColor $Cyan
    Write-Host " $Text" -ForegroundColor $Cyan
    Write-Host "$('=' * 70)`n" -ForegroundColor $Cyan
}

function Write-Status {
    param(
        [string]$Message,
        [string]$Status
    )
    $color = if ($Status -eq 'PASS') { $Green } elseif ($Status -eq 'FAIL') { $Red } else { $Yellow }
    Write-Host "[$color$Status$Reset] $Message"
}

function Write-VerboseMessage {
    param([string]$Message)
    if ($Verbose -or $ExtractOnly) {
        Write-Host "  → $Message" -ForegroundColor Gray
    }
}

Write-Header 'IdentityFirst QuickChecks - Release Verification'

# ============================================================================
# Step 1: Find release file
# ============================================================================

Write-Host 'Step 1: Locating release file...' -ForegroundColor White

if (-not $ReleasePath) {
    $ReleasePath = Get-ChildItem -Path . -Filter 'IdentityFirst.QuickChecks-*.zip' | Select-Object -First 1
    if (-not $ReleasePath) {
        Write-Status 'No release ZIP file found in current directory' 'FAIL'
        Write-Host "`nUsage:" -ForegroundColor White
        Write-Host "  .\Verify-Release.ps1 -ReleasePath '.\IdentityFirst.QuickChecks-1.0.0.zip'"
        Write-Host "  .\Verify-Release.ps1 -ReleasePath '.\IdentityFirst.QuickChecks-1.0.0.zip' -Verbose"
        exit 1
    }
    $ReleasePath = $ReleasePath.FullName
}

Write-VerboseMessage "Release file: $ReleasePath"

if (-not (Test-Path $ReleasePath)) {
    Write-Status "Release file not found: $ReleasePath" 'FAIL'
    exit 1
}

$zipInfo = Get-Item $ReleasePath
$zipName = $zipInfo.Name
$zipSize = $zipInfo.Length / 1MB
Write-VerboseMessage "File size: $('{0:N2}' -f $zipSize) MB"

# ============================================================================
# Step 2: Extract version from filename
# ============================================================================

Write-Host 'Step 2: Extracting version information...' -ForegroundColor White

$versionMatch = $zipName -match 'IdentityFirst\.QuickChecks-(.+)\.zip'
if (-not $versionMatch) {
    Write-Status 'Unable to extract version from filename' 'FAIL'
    exit 1
}

$extractedVersion = $Matches[1]
Write-VerboseMessage "Extracted version: $extractedVersion"

if ($ExpectedVersion -and $extractedVersion -ne $ExpectedVersion) {
    Write-Status "Version mismatch (expected: $ExpectedVersion, found: $extractedVersion)" 'WARN'
}
else {
    Write-Status "Version: $extractedVersion" 'PASS'
}

# ============================================================================
# Step 3: Verify SHA256 checksum
# ============================================================================

Write-Host 'Step 3: Verifying SHA256 checksum...' -ForegroundColor White

$checksumFile = $ReleasePath -replace '\.zip$', '.sha256'
if (Test-Path $checksumFile) {
    Write-VerboseMessage "Checksum file: $checksumFile"
    $expectedChecksum = (Get-Content $checksumFile | Select-Object -First 1).Trim()
    $expectedChecksum = $expectedChecksum -replace 'SHA256:\s*', ''
    
    $actualChecksum = (Get-FileHash $ReleasePath -Algorithm SHA256).Hash
    
    if ($actualChecksum -eq $expectedChecksum) {
        Write-Status 'SHA256 checksum verified' 'PASS'
        Write-VerboseMessage "Checksum: $actualChecksum"
    }
    else {
        Write-Status 'SHA256 checksum MISMATCH!' 'FAIL'
        Write-VerboseMessage "Expected: $expectedChecksum"
        Write-VerboseMessage "Actual:   $actualChecksum"
    }
}
else {
    Write-VerboseMessage "No SHA256 checksum file found"
    Write-Host "  → Computing SHA256 for reference..." -ForegroundColor Gray
    $actualChecksum = (Get-FileHash $ReleasePath -Algorithm SHA256).Hash
    Write-Host "  SHA256: $actualChecksum" -ForegroundColor White
}

# ============================================================================
# Step 4: Verify SHA512 checksum (if available)
# ============================================================================

Write-Host 'Step 4: Verifying SHA512 checksum...' -ForegroundColor White

$checksumsFile = $ReleasePath -replace '\.zip$', '.checksums.txt'
if (Test-Path $checksumsFile) {
    Write-VerboseMessage "Checksums file: $checksumsFile"
    $checksumsContent = Get-Content $checksumsFile -Raw
    
    if ($checksumsContent -match 'SHA512:\s*([A-Fa-f0-9]+)') {
        $expectedSha512 = $Matches[1]
        $actualSha512 = (Get-FileHash $ReleasePath -Algorithm SHA512).Hash
        
        if ($actualSha512 -eq $expectedSha512) {
            Write-Status 'SHA512 checksum verified' 'PASS'
        }
        else {
            Write-Status 'SHA512 checksum MISMATCH!' 'FAIL'
        }
    }
    else {
        Write-VerboseMessage "No SHA512 found in checksums file"
    }
}
else {
    Write-VerboseMessage "No checksums file found"
}

# ============================================================================
# Step 5: Verify catalog signature (if available)
# ============================================================================

Write-Host 'Step 5: Verifying Authenticode signature...' -ForegroundColor White

$signatureFile = $ReleasePath + '.sig'
if (Test-Path $signatureFile) {
    Write-VerboseMessage "Signature file: $signatureFile"
    
    try {
        # Read signature
        $signatureBytes = [System.IO.File]::ReadAllBytes($signatureFile)
        $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
        $cms.Decode($signatureBytes)
        
        # Verify signature
        $cms.CheckSignature($false)  # Don't check revocation for timestamp
        
        $signer = $cms.SignerInfos[0]
        Write-Status 'Digital signature verified' 'PASS'
        Write-VerboseMessage "Signed by: $($signer.Certificate.Subject)"
        
        if ($signer.TimestampInfos.Count -gt 0) {
            $ts = $signer.TimestampInfos[0]
            Write-VerboseMessage "Timestamp: $($ts.Timestamp)"
        }
    }
    catch {
        Write-Status 'Digital signature verification FAILED' 'FAIL'
        Write-VerboseMessage $_.Exception.Message
    }
}
else {
    Write-VerboseMessage "No signature file found (unsigned release)"
    Write-Status 'Release is NOT digitally signed' 'WARN'
}

# ============================================================================
# Step 6: Extract and inspect contents
# ============================================================================

Write-Host 'Step 6: Inspecting release contents...' -ForegroundColor White

$extractPath = $ReleasePath -replace '\.zip$', ''
if (Test-Path $extractPath) {
    Write-VerboseMessage "Removing existing extraction..."
    Remove-Item -Path $extractPath -Recurse -Force
}

New-Item -ItemType Directory -Path $extractPath -Force | Out-Null
Expand-Archive -Path $ReleasePath -DestinationPath $extractPath -Force

Write-VerboseMessage "Extracted to: $extractPath"

# Check for required files
$requiredFiles = @(
    'IdentityFirst.QuickChecks.psd1',
    'IdentityFirst.QuickChecks.psm1',
    'README.md',
    'CHANGELOG.md'
)

$modulePath = Join-Path $extractPath 'IdentityFirst.QuickChecks'
if (Test-Path $modulePath) {
    foreach ($file in $requiredFiles) {
        $fullPath = Join-Path $modulePath $file
        if (Test-Path $fullPath) {
            Write-VerboseMessage "Found: $file"
        }
        else {
            Write-Status "Missing required file: $file" 'FAIL'
        }
    }
    
    # Count check files
    $psmFiles = Get-ChildItem -Path $modulePath -Filter '*.psm1' -Recurse | Measure-Object | Select-Object -ExpandProperty Count
    Write-VerboseMessage "PSM files: $psmFiles"
    
    $psdFiles = Get-ChildItem -Path $modulePath -Filter '*.psd1' | Measure-Object | Select-Object -ExpandProperty Count
    Write-VerboseMessage "PSD files: $psdFiles"
}
else {
    Write-Status 'Module directory not found' 'FAIL'
}

# ============================================================================
# Step 7: Validate module manifest
# ============================================================================

Write-Host 'Step 7: Validating module manifest...' -ForegroundColor White

$manifestPath = Join-Path $modulePath 'IdentityFirst.QuickChecks.psd1'
if (Test-Path $manifestPath) {
    try {
        $manifest = Import-PowerShellDataFile -Path $manifestPath -ErrorAction Stop
        
        # Check required fields
        $requiredFields = @('ModuleVersion', 'GUID', 'Author', 'Description')
        foreach ($field in $requiredFields) {
            if ($manifest.ContainsKey($field)) {
                Write-VerboseMessage "$field present"
            }
            else {
                Write-Status "Missing field in manifest: $field" 'FAIL'
            }
        }
        
        Write-VerboseMessage "Module Version: $($manifest.ModuleVersion)"
        Write-VerboseMessage "Functions Exported: $($manifest.FunctionsToExport.Count)"
        
        # Verify GUID
        if ($manifest.GUID -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
            Write-VerboseMessage "Valid GUID format"
        }
        else {
            Write-Status 'Invalid GUID format' 'FAIL'
        }
        
        Write-Status 'Module manifest valid' 'PASS'
    }
    catch {
        Write-Status "Failed to parse manifest: $($_.Exception.Message)" 'FAIL'
    }
}
else {
    Write-Status 'Module manifest not found' 'FAIL'
}

# ============================================================================
# Step 8: Verify PowerShell script signatures (if on Windows with SignTool)
# ============================================================================

if ($IsWindows -or $PSVersionTable.PSVersion.Major -eq 5) {
    Write-Host 'Step 8: Verifying PowerShell script signatures...' -ForegroundColor White
    
    $psFiles = Get-ChildItem -Path $extractPath -Filter '*.ps1' -Recurse
    $signedCount = 0
    $unsignedCount = 0
    
    foreach ($psFile in $psFiles) {
        try {
            $sig = Get-AuthenticodeSignature -Path $psFile.FullName -ErrorAction Stop
            if ($sig.Status -eq 'Valid') {
                $signedCount++
            }
            else {
                $unsignedCount++
            }
        }
        catch {
            $unsignedCount++
        }
    }
    
    if ($signedCount -gt 0) {
        Write-Status "Scripts signed: $signedCount" 'PASS'
    }
    if ($unsignedCount -gt 0) {
        Write-Status "Scripts unsigned: $unsignedCount" 'WARN'
    }
}
else {
    Write-VerboseMessage "Script signature verification not available on this platform"
}

# ============================================================================
# Summary
# ============================================================================

Write-Header 'Verification Complete'

Write-Host "Release: $zipName" -ForegroundColor White
Write-Host "Size: $('{0:N2}' -f $zipSize) MB" -ForegroundColor White
Write-Host "Version: $extractedVersion" -ForegroundColor White
Write-Host "`nExtraction location: $extractPath" -ForegroundColor White

Write-Host "`nTo install:" -ForegroundColor White
Write-Host "  1. Copy 'IdentityFirst.QuickChecks' folder to:" -ForegroundColor Gray
Write-Host "     - User:   `$Home\Documents\WindowsPowerShell\Modules\" -ForegroundColor Gray
Write-Host "     - System: `$env:ProgramFiles\WindowsPowerShell\Modules\" -ForegroundColor Gray
Write-Host ""
Write-Host "  2. Or use the install script:" -ForegroundColor Gray
Write-Host "     .\scripts\Install-Release.ps1" -ForegroundColor Gray

Write-Host "`nTo verify after installation:" -ForegroundColor White
Write-Host "  Import-Module IdentityFirst.QuickChecks" -ForegroundColor Gray
Write-Host "  Get-Module IdentityFirst.QuickChecks" -ForegroundColor Gray
