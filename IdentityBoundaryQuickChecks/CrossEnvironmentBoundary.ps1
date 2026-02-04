<#
    Cross-Environment Boundary Check
    Identifies identities existing in multiple environments without coordination
#>

param(
    [string]$OutputPath = "."
)

Write-IFQC -Message "════════════════════════════════════════════════════════════" -Level Info
Write-IFQC -Message "  Cross-Environment Boundary Check" -Level Info
Write-IFQC -Message "════════════════════════════════════════════════════════════" -Level Info
Write-IFQC -Message "" -Level Info
Write-IFQC -Message "  Checking for identities in multiple environments..." -Level Info
Write-IFQC -Message "" -Level Info

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-IFQC -Message "  ✗ ActiveDirectory module not available" -Level Error
    exit 1
}

$users = Get-ADUser -Filter * -Properties SamAccountName,UserPrincipalName,DisplayName,Description

# Check for same UPN pattern in multiple naming conventions
$upnSuffixes = $users | ForEach-Object {
    if ($_.UserPrincipalName -match "@(.+)$") { $matches[1] }
} | Sort-Object -Unique

Write-IFQC -Message "  Detected UPN Suffixes:" -Level Info
$upnSuffixes | ForEach-Object { Write-IFQC -Message ("     " + $_) -Level Info }
Write-IFQC -Message "" -Level Info

# Flag potential cross-environment issues
$boundaryViolations = @()

# Check for service accounts with human-like names
$humanLikeService = $users | Where-Object {
    $_.SamAccountName -notmatch "^(svc-|adm-|usr-|app-)" -and
    $_.DisplayName -match "^[A-Z][a-z]+(\s+[A-Z][a-z]+)?$" -and
    $_.Description -match "service|app|system|automation"
}

if ($humanLikeService) {
    Write-IFQC -Message "  ⚠ Human-named accounts used as service identities:" -Level Warning
    $humanLikeService | Select-Object SamAccountName,DisplayName,Description | Format-Table -AutoSize
}

# Check for duplicate samaccountname patterns
$duplicatePatterns = $users | Group-Object { $_.SamAccountName -replace "\d+$", "" } |
    Where-Object { $_.Count -gt 1 }

if ($duplicatePatterns) {
    Write-IFQC -Message "" -Level Info
    Write-IFQC -Message "  Potential duplicate identity patterns:" -Level Info
    $duplicatePatterns | Select-Object -First 10 | Format-Table -AutoSize
}

# Export report
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$jsonPath = Join-Path $OutputPath "CrossEnvironmentBoundary-$timestamp.json"
$report = @{
    check = "Cross-Environment Boundary Check"
    timestamp = (Get-Date).ToString("o")
    upnSuffixes = $upnSuffixes
    humanLikeServiceAccounts = $humanLikeService
    duplicatePatterns = $duplicatePatterns | Select-Object -First 10
}
$report | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
Write-IFQC -Message "" -Level Info
Write-IFQC -Message "  📄 Report saved: $jsonPath" -Level Info

Write-IFQC -Message "" -Level Info
Write-IFQC -Message "  ─────────────────────────────────────────────────────────────" -Level Info
Write-IFQC -Message "  ℹ  Cross-environment identities need authoritative ownership." -Level Info
Write-IFQC -Message "     For boundary governance, run IdentityHealthCheck." -Level Info
Write-IFQC -Message "  ─────────────────────────────────────────────────────────────" -Level Info

# SIG # Begin signature block
# MIIJyAYJKoZIhvcNAQcCoIIJuTCCCbUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAu33MuWdqSQ9Ik
# Sc9GvZAknMbKZVtXHmkm1D1icwNMwqCCBdYwggXSMIIDuqADAgECAhAxVnqog0nQ
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
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIAMPR+KHiuNAvdrBbDpb8eAmDIsBLNzp
# sx3nT7Mh803IMA0GCSqGSIb3DQEBAQUABIICAED2wlqX/Ou9FPOFd8oAGJhdq+G/
# YV1nbzvbOj/fKfrYYSUJIR0atUPPFCdgatiK0sQV58qJDHL7W6pjYbN2pomZHj8K
# kvg1OPBqLjbGiA8o+KvgCKtKeij1dYBpCeBoEzyZHKmClTBAor54rFDiQqFbAGug
# wjekR4dHq2NayfeDzIknsO7qrE8mkWjux6+0l4Un0U6wiLZDgp9lGzaiED2YhRT9
# XawvZmXxkoe/FHSkS62uHaoXuwwoDptiqoZtonzwf34lEhq6ndr9MAMIXjOAVUY5
# bC/zFtJ7yev7gmlwig1wMyJaIq+wAwL7FJzqJY+5eXDzmxt7QNihMZvv+0O9jrvf
# GYfihLj5+a6mAS9rD5zkiJsGf43odtwUd7uIuxv8bFjbIcZZZIid9dB4n8gk3uEz
# iGG9VE+jU52gAAf4OpOnsCwzo7oCEM2/mqBaxjxnWcF4TAzhhKW8N8S7UNILuys9
# 8MnYBl1n8VaKnYNHMBMtk4w/nHMssu5tDH09Hi4l8KqPYSBUfInSFHstpaY/CmR9
# m5znR2f81eH8EEKH65ARldjLnZE28QaYEEjOBDu2EWC6cCGedQV2ohix8IrtZ/FE
# 2zxjmq5XsusoXwGzYAPNm84slnIOYgas4Y40QmItULFHYoIDCqcoP5MqAjGxLzKT
# SGJTXvJIBXWduNKQ
# SIG # End signature block

