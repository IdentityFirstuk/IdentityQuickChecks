# ============================================================================
# ATTRIBUTION
# ============================================================================
# Author: Mark Ahearne
# Email: mark.ahearne@identityfirst.net
# Company: IdentityFirst Ltd
#
# This script is provided by IdentityFirst Ltd for identity security assessment.
# All rights reserved.
#
# License: See EULA.txt for license terms.
# ============================================================================
<#
.SYNOPSIS
    Obfuscate PowerShell scripts to prevent reverse engineering

.DESCRIPTION
    This script provides basic obfuscation techniques to protect your
    PowerShell scripts. For advanced protection, consider commercial tools.

.PARAMETER Path
    Path to script or directory to obfuscate

.PARAMETER OutputPath
    Output path for obfuscated scripts

.PARAMETER Level
    Obfuscation level: 1 (Basic), 2 (Medium), 3 (Advanced)

.PARAMETER EncryptStrings
    Encrypt sensitive strings (passwords, API keys)

.EXAMPLE
    .\Obfuscate-Scripts.ps1 -Path ".\MyScript.ps1" -Level 2

.NOTES
    Obfuscation is NOT a security feature - it can be reversed.
    Use signing for integrity, obfuscation for intellectual property.
#>

[CmdletBinding()]
param(
    [string]$Path = ".",
    [string]$OutputPath = ".\Obfuscated",
    [ValidateSet(1, 2, 3)]
    [int]$Level = 2,
    [switch]$EncryptStrings
)

# Get the directory where this script is located
$scriptDir = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition

# Resolve the input path to absolute path based on current directory, not script directory
if (-not $Path.Contains(':')) {
    $Path = Join-Path -Path (Get-Location) -ChildPath $Path
}

# Resolve the output path to absolute path
if (-not $OutputPath.Contains(':')) {
    $OutputPath = Join-Path -Path (Get-Location) -ChildPath $OutputPath
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  PowerShell Script Obfuscation" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------

function Invoke-Base64Encode {
    <#
    .SYNOPSIS
        Encode script content to Base64
    #>
    param([string]$Content)
    [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Content))
}

function New-ObfuscatedLauncher {
    <#
    .SYNOPSIS
        Create an obfuscated launcher script that decodes and executes the payload
    #>
    param(
        [string]$EncodedContent,
        [string]$OriginalName,
        [int]$Level
    )

    if ($Level -ge 3) {
        # Advanced: Multiple layers of encoding
        return @"
`$encoded = @'
$EncodedContent
'@

`$decoded1 = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(`$encoded))
`$bytes = [System.Convert]::FromBase64String(`$decoded1)
`$final = [System.Text.Encoding]::Unicode.GetString(`$bytes)

Invoke-Expression ` `$final
"@
    }
    else {
        # Medium/Basic: Base64 encoding with launcher
        return @"
`$encoded = @'
$EncodedContent
'@
`$decoded = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(`$encoded))
Invoke-Expression ` `$decoded
"@
    }
}

function Get-ObfuscatedName {
    <#
    .SYNOPSIS
        Generate random obfuscated name
    #>
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $name = ""
    for ($i = 0; $i -lt 8; $i++) {
        $name += $chars[(Get-Random -Maximum $chars.Length)]
    }
    return "Invoke-$name"
}

function Invoke-StringObfuscation {
    <#
    .SYNOPSIS
        Obfuscate string literals in script
    #>
    param([string]$Content)

    # Replace common sensitive patterns
    $patterns = @{
        'password\s*=\s*["''][^"'']+["'']' = 'password="ENCRYPTED"'
        'api[_-]?key\s*=\s*["''][^"'']+["'']' = 'api_key="ENCRYPTED"'
        'secret\s*=\s*["''][^"'']+["'']' = 'secret="ENCRYPTED"'
        'connection[_-]?string\s*=\s*["''][^"'']+["'']' = 'connection_string="ENCRYPTED"'
    }

    foreach ($pattern in $patterns.Keys) {
        $Content = $Content -replace $pattern, $patterns[$pattern]
    }

    return $Content
}

function Invoke-VariableObfuscation {
    <#
    .SYNOPSIS
        Rename variables to random names
    #>
    param([string]$Content)

    $variablePatterns = @(
        '\$Findings',
        '\$findings',
        '\$context',
        '\$Context',
        '\$report',
        '\$Report',
        '\$users',
        '\$User',
        '\$groups',
        '\$Groups'
    )

    foreach ($pattern in $variablePatterns) {
        $newName = Get-ObfuscatedName
        $Content = $Content -replace $pattern, $newName
    }

    return $Content
}

function Invoke-CommentRemoval {
    <#
    .SYNOPSIS
        Remove comments from script
    #>
    param([string]$Content)

    # Remove single-line comments
    $Content = $Content -replace '#.*$', ''

    # Remove multi-line comments
    $Content = $Content -replace '<#.*?#>', ''

    return $Content
}

function Invoke-FunctionRenaming {
    <#
    .SYNOPSIS
        Rename functions to random names
    #>
    param([string]$Content)

    $functionPatterns = @(
        'function\s+Invoke-\w+',
        'function\s+\w+-\w+'
    )

    foreach ($pattern in $functionPatterns) {
        $matches = [regex]::Matches($Content, $pattern)
        foreach ($match in $matches) {
            $oldName = $match.Value -replace 'function\s+', ''
            $newName = Get-ObfuscatedName
            $Content = $Content -replace $match.Value, "function $newName"
            # Also rename calls to the function
            $Content = $Content -replace $oldName, $newName
        }
    }

    return $Content
}

# -----------------------------------------------------------------------------
# Main Obfuscation Logic
# -----------------------------------------------------------------------------

Write-Host "[INFO] Starting obfuscation..." -ForegroundColor Yellow
Write-Host "  Input:  $Path" -ForegroundColor Gray
Write-Host "  Output: $OutputPath" -ForegroundColor Gray
Write-Host "  Level:  $Level" -ForegroundColor Gray
Write-Host ""

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Get files to process
if (Test-Path $Path -PathType Container) {
    $files = Get-ChildItem -Path $Path -Filter "*.ps1" -Recurse
    Write-Host "[INFO] Found $($files.Count) scripts to obfuscate" -ForegroundColor Yellow
}
elseif (Test-Path $Path -PathType Leaf) {
    $files = Get-Item $Path
    Write-Host "[INFO] Obfuscating single file: $($files.Name)" -ForegroundColor Yellow
}
else {
    Write-Host "[ERROR] Path not found: $Path" -ForegroundColor Red
    exit 1
}

$obfuscated = 0
$errors = 0

foreach ($file in $files) {
    try {
        Write-Host "[OBFUSCATING] $($file.FullName)" -ForegroundColor Gray

        # Read original content - PS 5.1 compatible
        $content = [System.IO.File]::ReadAllText($file.FullName)
        
        # Apply obfuscation based on level
        if ($Level -ge 1) {
            $content = Invoke-CommentRemoval -Content $content
        }

        if ($Level -ge 2 -and $EncryptStrings) {
            $content = Invoke-StringObfuscation -Content $content
        }

        if ($Level -ge 3) {
            $content = Invoke-VariableObfuscation -Content $content
            $content = Invoke-FunctionRenaming -Content $content
        }

        # Base64 encode the content
        $encoded = Invoke-Base64Encode -Content $content

        # Create obfuscated launcher
        $launcher = New-ObfuscatedLauncher -EncodedContent $encoded -OriginalName $file.Name -Level $Level

        # Save obfuscated script - PS 5.1 compatible
        $outputFile = Join-Path $OutputPath $file.Name
        [System.IO.File]::WriteAllText($outputFile, $launcher, [System.Text.Encoding]::UTF8)

        Write-Host "  [OK] Saved: $outputFile" -ForegroundColor Green
        $obfuscated++
    }
    catch {
        Write-Host "  [ERROR] $($_.Exception.Message)" -ForegroundColor Red
        $errors++
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Obfuscation Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Obfuscated: $obfuscated" -ForegroundColor Green
Write-Host "  Errors:     $errors" -ForegroundColor $(if ($errors -gt 0) { 'Red' } else { 'Green' })
Write-Host ""
Write-Host "[WARNING] Obfuscation is NOT a security feature!" -ForegroundColor Yellow
Write-Host "          Scripts can still be reverse-engineered." -ForegroundColor Gray
Write-Host "          Use code signing for integrity protection." -ForegroundColor Gray

Write-Host ""
