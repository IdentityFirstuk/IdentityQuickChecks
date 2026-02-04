<#
.SYNOPSIS
    Checks for MFA registration gaps in Entra ID.

.DESCRIPTION
    Attempts to identify users without registered authentication methods.
    MFA state retrieval varies by tenant and API capabilities.

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
    [string]$DetailLevel = "Normal"
)

$modulePath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $modulePath "Module\IdentityFirst.QuickChecks.psm1") -Force

$ctx = New-IFQCContext -ToolName "MfaCoverageGap" -OutputDirectory $OutputDirectory -DetailLevel $DetailLevel
Add-IFQCNote -Context $ctx -Note "MFA state retrieval varies by tenant and API. This attempts best-effort visibility."
Add-IFQCNote -Context $ctx -Note "Full enforcement design belongs in IdentityHealthCheck."

Invoke-IFQCSafe -Context $ctx -Name "Graph MFA coverage (best effort)" -Block {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw "Microsoft Graph SDK not found."
    }

    Import-Module Microsoft.Graph.Authentication
    Import-Module Microsoft.Graph.Users
    Import-Module Microsoft.Graph.Identity.SignIns

    $scopes = @("User.Read.All","Reports.Read.All","Directory.Read.All")
    Connect-MgGraph -Scopes $scopes | Out-Null
    $mg = Get-MgContext
    $ctx.Data.entra = [ordered]@{ tenantId=$mg.TenantId; account=$mg.Account }

    $noMethods = @()
    try {
        Import-Module Microsoft.Graph.Identity.SignIns
        $scopes2 = @("User.Read.All","Directory.Read.All","UserAuthenticationMethod.Read.All")
        Connect-MgGraph -Scopes $scopes2 | Out-Null

        $users = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,AccountEnabled | Where-Object AccountEnabled -eq $true
        $sampleLimit = 5000
        $i = 0

        foreach ($u in $users) {
            $i++
            if ($i -gt $sampleLimit) { break }
            $methods = Get-MgUserAuthenticationMethod -UserId $u.Id -ErrorAction Stop
            if (-not $methods -or $methods.Count -eq 0) {
                $noMethods += [PSCustomObject]@{ DisplayName=$u.DisplayName; UPN=$u.UserPrincipalName }
            }
        }
    } catch {
        Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
            -Id "ENTRA-MFA-TELEMETRY-UNAVAILABLE" `
            -Title "Cannot enumerate authentication methods" `
            -Severity "Medium" `
            -Description "Authentication method visibility could not be retrieved." `
            -Count 1 `
            -Evidence @(@{ note = $_.Exception.Message }) `
            -Recommendation "Grant least-privileged read scopes for auth methods."
        )
        return
    }

    $evidenceLimit = if ($DetailLevel -eq "Detailed") { 200 } else { 40 }
    Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
        -Id "ENTRA-NO-AUTH-METHODS" `
        -Title "Users with no registered authentication methods (sampled)" `
        -Severity "High" `
        -Description "Users with no registered auth methods indicate weak MFA coverage." `
        -Count $noMethods.Count `
        -Evidence ($noMethods | Select-Object -First $evidenceLimit) `
        -Recommendation "Enforce registration, require MFA for privileged accounts first."
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
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDWk1dhOQpbr9/S
# O3SS2/RwdHGkJBuVVDla1NPIkgP4i6CCBdYwggXSMIIDuqADAgECAhAxVnqog0nQ
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
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIMpn9vjkhW1N9KMFq0Oa56F0p+JdzRaQ
# 4ZMxM3+1o+Y9MA0GCSqGSIb3DQEBAQUABIICAGhbm4LFA8KU8e+mp73DVcXwIfOA
# oX3wft4a4PJEzVCK8SsMic++XFZfIY2iCoThJw9vUCgLbRFh9kTSM0qt0bVcZcjS
# 94iJAZYKgDe/i09ks12PPpG5hDKs9hri8asdq9MkWw3ZaqcLHoL9xMxH5BXDkfcm
# 4M4BIz36BFNT2e0K++9JcGKvoZ/et1LzQ7O8Tit2FP+Bb50/3MDvInSOcLqka55u
# pePiVcnOrgAk87Ff4YZ1puVGyjHWSuESZhKSUDE5CuwEUqrnKRmhE39niVKBytxq
# O9tmhNzElrP2tbX3+Caokm+h/c0R+CmGA8RvlPbWX8B59jQTOqLCBz0218kl6S18
# JIGPbAR9BZM6Hg/8USp6zc4PzsicDYc8AArQVbQHCiq40b8f/hG1tUEhChxM/op0
# Cgozf4+IixkWXitxWsSr3VZVoIknUnDuVbrx+uMaJBdTIOCAURnt9nIsFMrOAGJu
# Gkg2s8LJJHz0VSPlxdM66UYiq0axfJ4iHDr5jN5vXn2tLLIzIcnw5DvNfmuvnc3j
# yjZ5WtYbCTywXUZILUpOLchudLwKCRjFdvVp0wEv7ma99UneUyDi08qPPVHiYZXP
# b6G1hh+/UHbNCPHA/eaUQN8wcOlkquN9hgMfMyBGnKbKKuafiYNNYQHJFJnTtQ/5
# hJWWS/R4wBxnF0Ir
# SIG # End signature block

