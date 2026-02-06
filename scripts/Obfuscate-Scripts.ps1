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

# SIG # Begin signature block
# MIIcFwYJKoZIhvcNAQcCoIIcCDCCHAQCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAeoUriXyhLSRdp
# xMX/1lHfeLjB5Gi+kczkSswYk9etlqCCFlgwggMaMIICAqADAgECAhBf+irPCn8a
# h0egI+kXM/O8MA0GCSqGSIb3DQEBCwUAMCUxIzAhBgNVBAMMGklkZW50aXR5Rmly
# c3QgQ29kZSBTaWduaW5nMB4XDTI2MDIwNjEzMzQ1NloXDTMxMDIwNjEzNDQ1Nlow
# JTEjMCEGA1UEAwwaSWRlbnRpdHlGaXJzdCBDb2RlIFNpZ25pbmcwggEiMA0GCSqG
# SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDeIxBFnRbFAFXNkoZ2ZGEfjKtc5nqrodwc
# cKV2S7cpHmKT3usCJnHbzQv0tE220IOuSWO7d/Od2q6k+J5osRngkWu5+4ujklFa
# AZP2pXCxLQBYT4fhB+C7p6ULFYMYPmvaKaSsd/5RplW+LPuIaHr+YdnZDabHVvZR
# hWz84cKSm1S2I8ekeZF7JDHMlQvWWW1z7mzY+uCtmoiTKEvWfr7O1baBXwyq40uI
# oRoR4IV4l9z59rT8HG6jsD39h30e7r33cnbP9AJR8max8ocOlSaWsx6Ey2djT/ft
# CI/PYHZPqdr3HwmAZxRT//8Q5mDtt5Bk3iYA64x696V9vo7tyHAhAgMBAAGjRjBE
# MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQU
# AApdetN2wXAWY01eV4BKyETsUgowDQYJKoZIhvcNAQELBQADggEBAAqUQnXgw+B/
# 38QTmxTiTCTBDIsQCYxAl88wraWtISY+w4xVc9Z5pST4OovkTZK2qRKp8RS6kpND
# gGnaRlN5KvIp3hwkXFQrlHp1W9KYSKzer1/w80CcuWwGu6TSp2LaFf7pwDGodC+2
# wFXD3qlGiePZPqz4TlGugouYZ6giii4E7g9q+vAxhMTZ7zB/q4WS5iW49ikWBVNu
# PethyeI3GMZTIq0s1R7k5BkNixZ97LILmfWzYkWkc5cawOwb3bhpg8d4bsBrHb+M
# JY2czc8knu7iJI0KXjXk+G4vQ0Lh1uWOnxm5ptBKsK5uve0qFH60b3MHN7RRlazB
# zqcr2XUvIdMwggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3
# DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAX
# BgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3Vy
# ZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIx
# CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3
# dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBH
# NDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIw
# aTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLK
# EdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4Tm
# dDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembu
# d8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnD
# eMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1
# XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVld
# QnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTS
# YW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSm
# M9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzT
# QRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6Kx
# fgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/
# MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv
# 9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBr
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUH
# MAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJ
# RFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYG
# BFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72a
# rKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFID
# yE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/o
# Wajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv
# 76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30
# fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQwgga0MIIE
# nKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0y
# NTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqG
# SIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51N
# rY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5ba
# p+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf7
# 7S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF
# 2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80Fio
# cSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzV
# yhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl
# 92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGP
# RdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//
# Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4O
# Lu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM
# 7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E
# FgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5n
# P+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcG
# CCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQu
# Y29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGln
# aUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8v
# Y3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNV
# HSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIB
# ABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM
# 0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqW
# Gd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr
# 0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35
# k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKq
# MVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiy
# fTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDU
# phPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTj
# d6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2Z
# yJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWC
# nb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQ
# CoDvGEuN8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0
# ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1
# MDYwNDAwMDAwMFoXDTM2MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNV
# BAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNB
# NDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMy
# qJnfFNZx+wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4Q
# KpVD7dvNZh6wW2R6kSu9RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8
# SOhPUWlLnh00Cll8pjrUcCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtU
# DVHRXdmncOOMA3CoB/iUSROUINDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5KqCv
# pSduSwhwUmotuQhcg9tw2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1
# Hf2JNMVL4Q1OpbybpMe46YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdoRORV
# bPR1VVnDuSeHVZlc4seAO+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUoHLWn
# qWU3dCCyFG1roSrgHjSHlq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7rlRyT
# laCCfw7aSUROwnu7zER6EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K096V1hE0
# yZIXe+giAwW00aHzrDchIc2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8+3mn
# AgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39/dfz
# kXFjGVBDz2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNV
# HQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEB
# BIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYI
# KwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNV
# HR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYD
# VR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4IC
# AQBlKq3xHCcEua5gQezRCESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fN
# aNmFj6Eh8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim
# 8/9yJmZSe2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUqW4da
# IqToXFE/JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMnxYOX
# 8VBRKe1uNnzQVTeLni2nHkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1
# d0IbX6Wq8/gVutDojBIFeRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AWcIQf
# VjnzrvwiCZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJgddJ3
# 5XTxfUlQ+8Hggt8l2Yv7roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV1S3C
# rWqZzBt1R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVccAvlK
# V9jEnstrniLvUxxVZE/rptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8atufk
# +EMF/cWuiC7POGT75qaL6vdCvHlshtjdNXOCIUjsarfNZzGCBRUwggURAgEBMDkw
# JTEjMCEGA1UEAwwaSWRlbnRpdHlGaXJzdCBDb2RlIFNpZ25pbmcCEF/6Ks8KfxqH
# R6Aj6Rcz87wwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAA
# oQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4w
# DAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgMevMRxBQnEet9frKe7QrYl0x
# FW1WG1SF6sexBABMj0wwDQYJKoZIhvcNAQEBBQAEggEAYIddHUX4ElChq6Pk3Ho7
# IjQqDs9j1HKml59WF9E3VM5Fo22NPjClepnt3MB0zDVAwNbcrk9J9jnJbbkl0C9n
# LJk/P/hDdgCniHPT8Z0UQF2MURxBSQ7w7Ntj8nKg0Ubobft603Nqerk4DbzSRrSJ
# Eh2ockqcVyMFdVPy4dB8bEOYFdAZxUCGHCXW8W9Fjd3JS4Gx1jVOJvqpYTvWN8Hm
# b6JWzzJoHsCIj2/x3RaKKyeIfbJYqYeQh5DEDp1EkZsmA4kmBm9BRQD5e/ieppbp
# 4yRBxtmFjxXcDTB6vADt+0SXNsdb/d8hyvvdnI4nYaEtD22o3vUnu3beQ3Rh1W1j
# xKGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVT
# MRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1
# c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA
# 7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJ
# KoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAyMDYxMzQ0NTZaMC8GCSqGSIb3
# DQEJBDEiBCB5Rk2DUv2xo/kgGAcxxQ1gokz4dKutuiuGMqZDa1KURjANBgkqhkiG
# 9w0BAQEFAASCAgBkgpILjAN1fOcZFvdO4EjRlV8B0tYl5E7g/WqK5eg+SjsJSb9C
# +9x934msyRi+LCCwcypP79T49fTMqFJhiX8GlA1/lKFjI5mtGhqjU3Gc3zmTfH4E
# TNP/AoA+AcgG81BlBdkqI070Ihuzl5ucakZiN3rzKZLs3LjMhk413DEagFU4YMYP
# y+f5hXpExdITcga4FxSFGdTtHSnhQO4XSN8ApRg25/DKrVOIbKSJ2gpqLeNnlumJ
# lSlGLTDBC0dMboaxU+QtqmDNeShhThz0jSb4JRTygZKupCy6DPgUpx7KVPjYNS84
# SyTtzdDJ5NF9l5/20C48qT3s/JGaracj+eDg1yxxX8PCkLtN5J44cdK8Bci52Ww8
# fJ0YTDYIu0TlDAgAhK5bS/LbCT3ilM1L264WzRHPIUrgQ+p+h1Uc4xP9Mr1EhcCs
# sQJEyBQvOyFCoD1NkevqTGdrfHMMAvZB7KQrCWRW+ErauqRYuo1Hx5ZAwwuTKyNa
# YalGRXcy6bug1kiGL8EC8iFNpFNtsWIyWSdFrgUFSIlY1nqayOhtxNpz2iIF5fz7
# ntZJlXaPICs2QUQv2G18MV6kq74Gw0ydBSFrQXGRYhNlUKgTutPzODt7fZ06jnUJ
# fircVFT3ObK0nQ1uosHmlTO3yM5pT5k3NhEz5j/VJF28627DiYoXVeFP/A==
# SIG # End signature block
