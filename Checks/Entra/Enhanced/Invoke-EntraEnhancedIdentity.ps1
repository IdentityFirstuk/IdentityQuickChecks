<#
.SYNOPSIS
    Entra ID PIM Role Eligibility and Conditional Access visibility.

.DESCRIPTION
    Reads PIM-eligible roles and Conditional Access policies (read-only).

.OUTPUTS
    - JSON report
    - HTML report
    - Log file

.NOTES
    Author: mark.ahearne@identityfirst.net | Owner: IdentityFirst Ltd
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path $PWD "IFQC-Output"),

    [Parameter()]
    [ValidateSet("Normal","Detailed")]
    [string]$DetailLevel = "Normal"
)

$modulePath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $modulePath "Module\IdentityFirst.QuickChecks.psm1") -Force

$ctx = New-IFQCContext -ToolName "EntraEnhancedIdentity" -OutputDirectory $OutputDirectory -DetailLevel $DetailLevel
Add-IFQCNote -Context $ctx -Note "Read-only Entra ID PIM and Conditional Access visibility."

function Get-EvidenceLimit {
    if ($DetailLevel -eq "Detailed") { return 200 }
    return 40
}

Invoke-IFQCSafe -Context $ctx -Name "Entra PIM and CA inventory" -Block {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw "Microsoft Graph SDK not found."
    }

    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Identity.Governance -ErrorAction Stop

    $scopes = @("RoleManagement.Read.Directory", "Policy.Read.ConditionalAccess", "User.Read.All")
    Connect-MgGraph -Scopes $scopes | Out-Null

    $mgCtx = Get-MgContext
    $ctx.Data.tenantId = $mgCtx.TenantId

    $eligibleAssignments = @()
    try {
        $assignments = Get-MgIdentityGovernanceRoleEligibilitySchedule -All -ErrorAction SilentlyContinue
        foreach ($a in $assignments) {
            $eligibleAssignments += [PSCustomObject]@{
                PrincipalId = $a.PrincipalId
                RoleId = $a.RoleDefinitionId
                MemberType = $a.MemberType
                EndDateTime = $a.EndDateTime
            }
        }
    } catch {
        Write-IFQCLog -Context $ctx -Level WARN -Message "PIM not accessible"
    }

    $caPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue |
        Select-Object DisplayName, State, Id

    $ctx.Data.eligibleAssignmentCount = ($eligibleAssignments | Measure-Object).Count
    $ctx.Data.caPolicyCount = ($caPolicies | Measure-Object).Count

    $evidenceLimit = Get-EvidenceLimit

    $permanentEligible = $eligibleAssignments | Where-Object {
        $_.MemberType -eq "Eligible" -and (-not $_.EndDateTime)
    }

    Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
        -Id "ENTRA-PIM-PERMANENT" `
        -Title "PIM eligible assignments without expiration" `
        -Severity "High" `
        -Description "Permanent PIM eligibility removes time-bound access control." `
        -Count ($permanentEligible.Count) `
        -Evidence ($permanentEligible | Select-Object -First $evidenceLimit) `
        -Recommendation "Configure assignment expiry for PIM roles."
    )
}

$output = Save-IFQCReport -Context $ctx
Write-IFQCLog -Context $ctx -Level INFO -Message "EntraEnhancedIdentity complete."
Write-IFQCLog -Context $ctx -Level INFO -Message "Report files: JSON: $($output.Json); HTML: $($output.Html)"
Write-Output $output

# SIG # Begin signature block
# MIIJyAYJKoZIhvcNAQcCoIIJuTCCCbUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD87Vl59CAyePyI
# p+Q4vy0qq6gyMfO7USVUm8HMmKWPdKCCBdYwggXSMIIDuqADAgECAhAxVnqog0nQ
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
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIBvTKVABfuJhY5NXDGkhkuJfOMPKwuD3
# cgxqYb0ubhyDMA0GCSqGSIb3DQEBAQUABIICABUIDUuMSXE+fbLn33rF7lHbbv8v
# hvBdo6YtFwY1Ov/X7t90+fI7F7645ARroaeu18QDmceh8RqlJj0Ys1FVwHNMCIJS
# waptLcEKdjfwRBXsQC1yiJKZMMdx7RyXuEnVOVuBXT/HL9eanPBSbgd5xIUGZzOK
# 7nWxM12x2L6apL9W60tkYUrz9+wtaHQNmn7k6GLo5RiWaWvAG6K3bWw9ImynRllh
# mHT+JVL1jvBMliWMdPbnr5FyJjcbCixd4WluaN1Yby1CBi8MG32oskRrtVtT1O94
# d+Y4ag6WJtO2mylD3pMlw6YO0S1MRIU3ulwqLQpGSpfHA05fya+ppCMmOsudgWN3
# BaBejaok5BQBOtUDYZt8bBy9IEgEQneRfmRFNqMocMFAEoDpJMB75Ma2Z5IDYJnV
# yoOlalpdYVW25eUF2SoVYE0vZjdJXRDSDiV+1D9bSkDA60KcEvRRkwDo1PvPu76D
# 76dbQP5g/pgEcgqWpkvMHKAgWMx3YgQ+erG3uIR2mZA1OfYXecVn1OLtFNAdns1r
# m3yoxbgUkM9OetKOTkEdf5FSPvzOAb9iSoCE3TsKQma8xcphrr+ME8xHfZBf6qsS
# 7S4GnxxIcXPGpj6rHyMqEDGIF49hsd9Wk2MqYXQUjzT/QmHZjGbJ6gIcX006+jOR
# YIl1sSbsk61NOx93
# SIG # End signature block

