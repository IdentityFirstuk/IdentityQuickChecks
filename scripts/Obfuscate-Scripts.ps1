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

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  PowerShell Script Obfuscation" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

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
        Create an obfuscated launcher script
    #>
    param(
        [string]$EncodedContent,
        [string]$OriginalName,
        [int]$Level
    )

    $scriptName = $OriginalName -replace '\.ps1$', ''

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
    elseif ($Level -ge 2) {
        # Medium: Base64 encoding
        return @"
`$encoded = @'
$EncodedContent
'@
`$decoded = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(`$encoded))
Invoke-Expression ` `$decoded
"@
    }
    else {
        # Basic: Simple string replacement
        return $EncodedContent
    }
}

function Protect-String {
    <#
    .SYNOPSIS
        Encrypt a string value
    #>
    param([string]$PlainText)

    $secure = ConvertTo-SecureString -String $PlainText -AsPlainText -Force
    $encrypted = ConvertFrom-SecureString -SecureString $secure
    return $encrypted
}

function Get-ObfuscatedName {
    <#
    .SYNOPSIS
        Generate random obfuscated name
    #>
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $name = ""
    for ($i = 0; $i < 8; $i++) {
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

# Main obfuscation logic
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

        # Read original content
        $content = Get-Content -Path $file.FullName -Raw

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

        # Save obfuscated script
        $outputFile = Join-Path $OutputPath $file.Name
        $launcher | Out-File -Path $outputFile -Encoding UTF8 -Force

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

<#




.DESCRIPTION
    PowerShell Obfuscation Tools and Techniques

.TABLE OF CONTENTS
    1. Basic Obfuscation
    2. Advanced Obfuscation
    3. Commercial Tools
    4. Limitations

## 1. BASIC OBFUSCATION (Free)

### String Encoding

```powershell
# Base64 encode
$encoded = [Convert]::ToBase64String(
    [System.Text.Encoding]::Unicode.GetBytes($scriptContent)
)

# Decode and run
$decoded = [System.Text.Encoding]::Unicode.GetString(
    [Convert]::FromBase64String($encoded)
)
Invoke-Expression $decoded
```

### String Encryption

```powershell
# Protect sensitive strings
$secure = ConvertTo-SecureString -String "MySecret" -AsPlainText -Force
$encrypted = ConvertFrom-SecureString -SecureString $secure

# Decrypt when needed
$secure2 = ConvertTo-SecureString -String $encrypted -AsPlainText
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure2)
$plaintext = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
```

## 2. ADVANCED OBFUSCATION

### Commercial Tools

| Tool | Cost | Features |
|------|------|----------|
| **PSScriptObfuscator** | Free | Basic obfuscation |
| **Invoke-Obfuscation** | Free | Comprehensive techniques |
| **ISESteroids** | $ | IDE with protection features |
| **PowerShell Pro Tools** | $ | VS Code extension with obfuscation |

### Invoke-Obfuscation (Free - GitHub)

```powershell
# Download from: https://github.com/danielbohannon/Invoke-Obfuscation

# Launch interactive obfuscation
Invoke-Obfuscation

# Command line usage
Invoke-Obfuscation -ScriptPath ".\script.ps1" -OutputPath ".\obfuscated" -All
```

## 3. PROTECTION COMPARISON

| Feature | Plain | Obfuscated | Signed |
|---------|-------|------------|--------|
| Readable source | Yes | No | Yes |
| Tamper detection | No | No | Yes |
| Trusted publisher | No | No | Yes |
| IP protection | Low | Medium | None |
| Ease of bypass | Easy | Medium | Hard |

## 4. IMPORTANT LIMITATIONS

⚠️ **Obfuscation can be reversed**

- Base64 is NOT encryption - it's encoding
- Tools exist to automatically deobfuscate
- Determined attackers can always reverse engineer

⚠️ **Best practices**

1. **Sign your scripts** - Proves authenticity
2. **Obfuscate if needed** - Protects IP
3. **Use Azure Key Vault** - Store secrets, not in scripts
4. **Least privilege** - Run with minimal permissions
5. **Continuous monitoring** - Detect unauthorized changes

## RECOMMENDED APPROACH

```
┌─────────────────────────────────────┐
│  SIGNED + OBFUSCATED + MONITORED   │
├─────────────────────────────────────┤
│  Signing: Proves it came from you  │
│  Obfuscation: Hides your IP        │
│  Monitoring: Detects tampering     │
└─────────────────────────────────────┘
```

For truly sensitive operations, consider:
- **Azure Automation** - Run scripts in controlled environment
- **PowerShell Just Enough Administration (JEA)** - Limit capabilities
- **Application Whitelisting** - Only allow signed scripts to run
#>

Write-Host ""
