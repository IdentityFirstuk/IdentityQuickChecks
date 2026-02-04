<#
.SYNOPSIS
    Checks for external guest lifecycle issues in Entra ID.

.DESCRIPTION
    Identifies guest accounts and their age. Requires Microsoft Graph.
    Does NOT change Conditional Access or guest policies.

.OUTPUTS
    - JSON report
    - HTML report
    - Log file

.NOTES
    Author: IdentityFirst Ltd
    Safety: Read-only. No changes are made.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path $PWD "IFQC-Output"),

    [Parameter()]
    [ValidateSet("Normal","Detailed")]
    [string]$DetailLevel = "Normal",

    [Parameter()]
    [int]$GuestAgeDays = 180
)

$modulePath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $modulePath "Module\IdentityFirst.QuickChecks.psm1") -Force

$ctx = New-IFQCContext -ToolName "GuestCreep" -OutputDirectory $OutputDirectory -DetailLevel $DetailLevel
Add-IFQCNote -Context $ctx -Note "Requires Microsoft Graph PowerShell SDK. Licensing/permissions may limit what can be retrieved."
Add-IFQCNote -Context $ctx -Note "This does not change Conditional Access or guest policies."

function Get-EvidenceLimit {
    param([string]$DetailLevel)
    if ($DetailLevel -eq "Detailed") { return 250 }
    return 40
}

Invoke-IFQCSafe -Context $ctx -Name "Entra guest access checks" -Block {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw "Microsoft Graph SDK not found. Install-Module Microsoft.Graph -Scope CurrentUser"
    }

    Import-Module Microsoft.Graph.Authentication
    Import-Module Microsoft.Graph.Users

    $scopes = @("User.Read.All","Directory.Read.All")
    Connect-MgGraph -Scopes $scopes | Out-Null
    $mg = Get-MgContext
    $ctx.Data.entra = [ordered]@{ tenantId=$mg.TenantId; account=$mg.Account }

    $cutoff = (Get-Date).AddDays(-$GuestAgeDays)

    $guests = Get-MgUser -Filter "userType eq 'Guest'" -All -Property DisplayName,UserPrincipalName,AccountEnabled,CreatedDateTime,ExternalUserState |
        Select-Object DisplayName, UserPrincipalName, AccountEnabled, CreatedDateTime, ExternalUserState

    $oldGuests = $guests | Where-Object { $_.CreatedDateTime -and $_.CreatedDateTime -lt $cutoff }

    $evidenceLimit = Get-EvidenceLimit -DetailLevel $DetailLevel

    # 1) All guests
    Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
        -Id "ENTRA-GUESTS-ALL" `
        -Title "Guest users present" `
        -Severity "Medium" `
        -Description "Guest accounts expand the trust boundary and often outlive their purpose." `
        -Count ($guests.Count) `
        -Evidence ($guests | Select-Object -First $evidenceLimit) `
        -Recommendation "Implement guest lifecycle, expiry, sponsorship and periodic review. Apply Conditional Access for externals."
    )

    # 2) Old guests
    Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
        -Id "ENTRA-GUESTS-OLD" `
        -Title "Guest users older than threshold" `
        -Severity "High" `
        -Description "Long-lived guests are a frequent source of 'permanent external access' risk." `
        -Count ($oldGuests.Count) `
        -Evidence ($oldGuests | Select-Object -First $evidenceLimit) `
        -Recommendation "Expire unused guests, validate sponsorship and access purpose, and enforce review cadence."
    )
}

$output = Save-IFQCReport -Context $ctx

# Emit structured report saved event
$reportEvent = [PSCustomObject]@{
    Timestamp = (Get-Date).ToString('o')
    Level = 'Info'
    Action = 'ReportSaved'
    Tool = $ctx.ToolName
    Json = $output.Json
    Html = $output.Html
}
Write-IFQC -InputObject $reportEvent

# SIG # Begin signature block
# MIIJyAYJKoZIhvcNAQcCoIIJuTCCCbUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA4yGjnqycDd2s/
# lYlvrzKkYjfalVR4VjzcIsB3mziFR6CCBdYwggXSMIIDuqADAgECAhAxVnqog0nQ
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
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIG14l6b8oYRvedxbVtE0lHHVyEfDd8ML
# tN3lMR1RD7OqMA0GCSqGSIb3DQEBAQUABIICAKNaVuy5XWq/5x1SZAM5WJQp7XZo
# w+D/E/Hqg/NE2eJ2zZoT0aDTrxWwQSh09mVqXkx/DYHASXkoVVuX5u+OH1Xi7aHD
# 8l87rrCGDmr8U8/JHvxpUF1aJ8yzOfkjl6EWPJdfdMeffabdSzhTBfSJ/U5Nq11z
# RVDuTrwbyKqpgCkWajpIAW2m33J8OQ/q2e50LOIfKagBJSFtweaoiYuWEk4pQr3f
# O7xwvYVDsNsiEqvAeOODgBrtfMVjYlInKPLfAqCqoj0Xkf/+0RExu8OE4NXxDY+u
# G2+YbgK8GDs8j9eq/wayS6wfzgt7K4KG0d//Z+UOHHwDqHDnEZlmrkfxoy+FMJON
# zKlEasBWn6iJ5h1Wy7ZH6UAFZbFsUPPtj4+L7OAS1CsM86T5a6dmBXQGvVrqpAw+
# Nt3KaqYRWPCRDrFDIHZH/cot5MYt151yxPmSqm17sWB1I2pzUI0GIsFbiveI7ClZ
# 8YQm/SSI4X77PQiQQxWT1uYi4qk+N27c7rPHK8N3UaiTI33htVZufO2k1T5LeqQ/
# wWTGvil9QDB6Jbm2swcEmCj2TimduChbBLxwBw0+J7hExNwEKRqhXdln2tvEooLW
# dcLN0zuCBkBm9C+1ti6FLu5bHkEljbaEfHvdSZDKTp75+hWS8/FOZPTSa8JgQ/qm
# rXKS8B7ur7Wks3gl
# SIG # End signature block

