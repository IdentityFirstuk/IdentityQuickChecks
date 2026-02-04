<#
    IdentityFirst QuickChecks - Main Launcher
    Runs all available quick checks and generates combined report
#>

param(
    [string]$OutputPath = ".\QuickChecks_Report",
    [switch]$CoreOnly,
    [switch]$Help
)

if ($Help) {
    Write-Output @"
IdentityFirst QuickChecks Launcher
===================================

Usage: .\Run-AllQuickChecks.ps1 [-OutputPath <path>] [-CoreOnly]

Options:
  -OutputPath  Path for report output (default: .\QuickChecks_Report)
  -CoreOnly    Run only Core modules (IdentityQuickChecks, IdentityTrustQuickChecks)
  -Help        Show this help message

Modules:
  Core:     IdentityQuickChecks, IdentityTrustQuickChecks
  Advanced: IdentityBoundaryQuickChecks, IdentityAssumptionQuickChecks

Examples:
  .\Run-AllQuickChecks.ps1
  .\Run-AllQuickChecks.ps1 -OutputPath "C:\Reports\Identity" -CoreOnly

"@
    exit 0
}

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$scriptRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

Write-Output ""
Write-Output "IdentityFirst QuickChecks - Complete Suite"
Write-Output "-------------------------------------------"
Write-Output ""
Write-Output "  Output: $OutputPath"
Write-Output "  Time:   $timestamp"
Write-Output ""

# Define module paths
$coreModules = @(
    @{ Name = "IdentityQuickChecks"; Path = Join-Path $scriptRoot "IdentityQuickChecks" },
    @{ Name = "IdentityTrustQuickChecks"; Path = Join-Path $scriptRoot "IdentityTrustQuickChecks" }
)

$advancedModules = @(
    @{ Name = "IdentityBoundaryQuickChecks"; Path = Join-Path $scriptRoot "IdentityBoundaryQuickChecks" },
    @{ Name = "IdentityAssumptionQuickChecks"; Path = Join-Path $scriptRoot "IdentityAssumptionQuickChecks" }
)

$modulesToRun = if ($CoreOnly) { $coreModules } else { $coreModules + $advancedModules }

$results = @{
    timestamp = $timestamp
    modules = @()
}

foreach ($module in $modulesToRun) {
    Write-Output "────────────────────────────────────────────────────────────"
    Write-Output "  Module: $($module.Name)"
    Write-Output "────────────────────────────────────────────────────────────"
    Write-Output ""

    $moduleResult = @{
        name = $module.Name
        checks = @()
        issuesFound = 0
    }

    $psFiles = Get-ChildItem -Path $module.Path -Filter "*.ps1" -ErrorAction SilentlyContinue

    if (-not $psFiles) {
        Write-Output "  ⚠ No scripts found in $($module.Path)"
    }

    foreach ($psFile in $psFiles) {
        Write-Output "  → Running: $($psFile.Name)"

        $checkResult = @{
            script = $psFile.Name
            status = "success"
            issues = 0
        }

        try {
            $output = & $psFile.FullName -OutputPath $OutputPath 2>&1 | Out-String

            $issueCount = ($output | Select-String "⚠ Found" -AllMatches).Matches.Count
            $checkResult.issues = $issueCount
            $moduleResult.issuesFound += $issueCount
        }
        catch {
            $checkResult.status = "error"
            $checkResult.error = $_.Exception.Message
            Write-Output "    ✗ Error: $($_.Exception.Message)"
        }

        $moduleResult.checks += $checkResult
    }

    $results.modules += $moduleResult

    $issueText = if ($moduleResult.issuesFound -gt 0) {
        "⚠ $($moduleResult.issuesFound) potential issues"
    } else {
        "✓ No issues detected"
    }
    Write-Output ""
    Write-Output "  $($module.Name): $issueText"
    Write-Output ""
}

# Generate summary report
$summaryPath = Join-Path $OutputPath "QuickChecks_Summary_$timestamp.json"
$results | ConvertTo-Json -Depth 10 | Out-File -FilePath $summaryPath -Encoding UTF8

Write-Output "════════════════════════════════════════════════════════════"
Write-Output "  QuickChecks Complete"
Write-Output "════════════════════════════════════════════════════════════"
Write-Output ""
Write-Output "  Summary report: $summaryPath"
Write-Output ""

$totalIssues = ($results.modules | Measure-Object -Property issuesFound -Sum).Sum

if ($totalIssues -gt 0) {
    Write-Output "  ℹ Total: $totalIssues potential issues found"
} else {
    Write-Output "  ✓ No issues detected across all checks"
}

Write-Output ""
Write-Output "  ─────────────────────────────────────────────────────────────"
Write-Output "  ℹ  These scripts show identity conditions."
Write-Output "     For governance analysis, run IdentityHealthCheck."
Write-Output "  ─────────────────────────────────────────────────────────────"

# SIG # Begin signature block
# MIIJyAYJKoZIhvcNAQcCoIIJuTCCCbUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDAXsJ2U9+i/sGH
# DbQJgweMvgA/eugb5FbQu5JRVSjm8aCCBdYwggXSMIIDuqADAgECAhAxVnqog0nQ
# oULr1YncnW59MA0GCSqGSIb3DQEBCwUAMIGAMQswCQYDVQQGEwJHQjEXMBUGA1UE
# CAwOTm9ydGh1bWJlcmxhbmQxFzAVBgNVBAcMDk5vcnRodW1iZXJsYW5kMRowGAYD
# VQQKDBFJZGVudGl0eUZpcnN0IEx0ZDEjMCEGA1UEAwwaSWRlbnRpdHlGaXJzdCBD
# b2RlIFNpZ25pbmcwHhcNMjYwMTI5MjExMDU3WhcNMzEwMTI5MjEyMDU2WjCBgDEL
# MAkGA1UEBhMCR0IxFzAVBgNVBAgMDk5vcnRodW1iZXJsYW5kMRcwFQYDVQQHDA5O
# b3J0aHVtYmVybGFuZDEaMBgGA1UECgwRSWRlbnRpdHlGaXJzdCBMdGQxIzAhBgNV
# BAMMGklkZW50aXR5Rmlyc3QgQ29kZSBTaWduaW5nMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAtrU2HprgcHe9mxlmt5X72OsSk7cXDyUhoOAcLE9f4lS2
# rOx7VbZSMSi0r4lt8a/S5m/JIWCdYO+GrWZCgS2S73H3KNDszR5HDPbMhv+leoWA
# qLT7C0awpjcTnvWIDxnHyHHane/TNl3ehY9Jek5qrbiNgJDatV6SEYVFlK8Nk9kE
# 3TiveVvRKokNT2xY4/h1rohFCHnF+g7dCn06xAZwoGnFVlmPop3jItAlZdUQz3zR
# /xSNW01sQXgW6/TYd2VzXXuQihMQ3ikjoNGX1L8SlcV4ih2J+r2kSHjhkZ8c+wJE
# v2iiUHqpwmch31UwQOb4qklGKg1A+SAUGdf0cTTc6ApSFsqrol1euObreoy0zdAA
# k47NELuGhKA4N0Dk9Ar616JGFt/03s1waukNisnH/sk9PmPGUo9QtKH1IQpBtwWw
# uKel0w3MmgTwi2vBwfyh2/oTDkTfic7AT3+wh6O/9mFxxu2Fsq6VSlYRpSTSpgxF
# c/YsVlQZaueZs6WB6/HzftGzv1Mmz7is8DNnnhkADTEMj+NDo4wq+lUCE7XNDnnH
# KBN8MkDh4IljXVSkP/xwt4wLLd9g7oAOW91SDA2wJniyjSUy9c+auW3lbA8ybSfL
# TrQgZiSoepcCjW2otZIXrmDnJ7BtqmmiRff4CCacdJXxqNWdFnv6y7Yy6DQmECEC
# AwEAAaNGMEQwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0G
# A1UdDgQWBBQBfqZy0Xp6lbG6lqI+cAlT7ardlTANBgkqhkiG9w0BAQsFAAOCAgEA
# IwBi/lJTGag5ac5qkMcnyholdDD6H0OaBSFtux1vPIDqNd35IOGYBsquL0BZKh8O
# AHiuaKbo2Ykevpn5nzbXDBVHIW+gN1yu5fWCXSezCPN/NgVgdH6CQ6vIuKNq4BVm
# E8AEhm7dy4pm4WPLqEzWT2fwJhnJ8JYBnPbuUVE8F8acyqG8l3QMcGICG26NWgGs
# A28YvlkzZsny+HAzLvmJn/IhlfWte1kGu0h0G7/KQG6hei5afsn0HxWHKqxI9JsG
# EF3SsMVQW3YJtDzAiRkNtII5k0PyywjrgzIGViVNOrKMT9dKlsTev6Ca/xQX13xM
# 0prtnvxiTXGtT031EBGXAUhOzvx2Hp1WFnZTEIJyX1J2qI+DQsPb9Y1jWcdGBwv3
# /m1nAHE7FpPGsSv+UIP3QQFD/j6nLl5zUoWxqAZMcV4K4t4WkPQjPAXzomoRaqc6
# toXHlXhKHKZ0kfAIcPCFlMwY/Rho82GiATIxHXjB/911VRcpv+xBoPCZkXDnsr9k
# /aRuPNt9DDSrnocJIoTtqIdel/GJmD0D75Lg4voUX9J/1iBuUzta2hoBA8fSVPS5
# 6plrur3Sn5QQG2kJt9I4z5LS3UZSfT+29+xJz7WSyp8+LwU7jaNUuWr3lpUnY2nS
# pohDlw2BFFNGT6/DZ0loRJrUMt58UmfdUX8FPB7uNuIxggNIMIIDRAIBATCBlTCB
# gDELMAkGA1UEBhMCR0IxFzAVBgNVBAgMDk5vcnRodW1iZXJsYW5kMRcwFQYDVQQH
# DA5Ob3J0aHVtYmVybGFuZDEaMBgGA1UECgwRSWRlbnRpdHlGaXJzdCBMdGQxIzAh
# BgNVBAMMGklkZW50aXR5Rmlyc3QgQ29kZSBTaWduaW5nAhAxVnqog0nQoULr1Ync
# nW59MA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAw
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIIlxfR1P2enThErAheY55zBgMyGoiVJ9
# nQqmZWS4qMccMA0GCSqGSIb3DQEBAQUABIICAHF3f5KiaDq9W9RWwrWRPbGka8Zx
# Eh180scFHRphaAHL9AEeyk6i3xdNxNTEJJOXAub9Ob60BuKPPvfe6ta3MRcZxvkh
# ASKYeh6sD0MMAz8w4wRxPBaKt8hivlXzfAP/LAFT0F+KxFapj4hQXkbnfe08XvZA
# 0a8IeNTF3yfRUz5gvN9Ia299SrpJZqu8zdIa+NrEPCI/ocbB4ts3jnCDIeHcKY21
# TCpTtuvgU2taLmTN4Zdpa3oTK9PfHOhr7tMrN1NLDMhJHxbX9iWt4o/h+sS0vOgo
# KAtLRDPEfIB3alRnNzjwn5P+fH7UbAXd6q+V0j+3gEC/v86OQrZRM2PTZKBCAf7n
# HLftRtcgG3IXzIB0vfghGMbmUjKxFoQevNyOzMMIkd53H1nFXvTJfa/Au+PykimG
# YUHS8hGzsVANqA0ZI52hSzoaWwvxPQOOAu4/PVk7hdZrVrwH/L+fHBJvO55X+aKD
# lRIXsptXIRyitM47lDsVixMAxZqoYu71g6OQRaPfRY00f0ADVrCZKQ/gAF+ayye/
# z+/LD5mzyteFUqlNe+Q2OUg0ixXZxKk4HUKni+a780Ek+OY/PdOU2bDQecbwUw2e
# V0ACyXutr396PWEfvtOSau8Ms6gpt0RwpHk2PBa6D6POjXAGBSWORCkeJWRyOoQU
# OdXoNU+mQPo4SlK/
# SIG # End signature block

