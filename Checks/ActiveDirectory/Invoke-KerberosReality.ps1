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
    Checks for Kerberos misconfigurations and security issues.

.DESCRIPTION
    Identifies common Kerberos misconfigurations including:
    - Duplicate SPNs
    - Kerberoastable accounts
    - Constrained delegation issues
    - Unconstrained delegation
    - Resource-based constrained delegation

.OUTPUTS
    - JSON report
    - HTML report
    - Log file

.NOTES
    Author: IdentityFirst Ltd
    Safety: Read-only. No changes are made.
    Requirements: ActiveDirectory module
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

$ctx = New-IFQCContext -ToolName "KerberosReality" -OutputDirectory $OutputDirectory -DetailLevel $DetailLevel
Add-IFQCNote -Context $ctx -Note "Kerberos assessment requires ActiveDirectory module."
Add-IFQCNote -Context $ctx -Note "Full attack path analysis available in IdentityHealthCheck."

Invoke-IFQCSafe -Context $ctx -Name "Kerberos Security Assessment" -Block {
    # Check if AD module is available
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
        throw "ActiveDirectory module not available"
    }

    Import-Module ActiveDirectory -ErrorAction Stop

    $domain = Get-ADDomain -ErrorAction SilentlyContinue
    if (-not $domain) {
        throw "Could not retrieve domain information"
    }
    $ctx.Data.domain = $domain.DnsRoot

    $evidenceLimit = if ($DetailLevel -eq "Detailed") { 100 } else { 30 }
    $findings = @()

    # =========================================================================
    # Check 1: Duplicate SPNs (Kerberoast target)
    # =========================================================================
    Write-Host "[INFO] Checking for duplicate SPNs..." -ForegroundColor Gray
    try {
        # Get all user accounts with SPN set
        $spnUsers = Get-ADUser -Filter { ServicePrincipalName -like '*' } `
            -Properties ServicePrincipalName, Name, SamAccountName, DistinguishedName `
            -ErrorAction SilentlyContinue

        $spnCounts = @{}
        foreach ($user in $spnUsers) {
            foreach ($spn in $user.ServicePrincipalName) {
                $spnCounts[$spn] = @($spnCounts[$spn] ?? @()) + $user.DistinguishedName
            }
        }

        $duplicateSpns = $spnCounts.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 }

        if ($duplicateSpns) {
            $dupEvidence = foreach ($dup in $duplicateSpns | Select-Object -First $evidenceLimit) {
                [PSCustomObject]@{
                    SPN = $dup.Key
                    Count = $dup.Value.Count
                }
            }

            $findings += @{
                Id = "KERB-DUPLICATE-SPN"
                Title = "Duplicate Service Principal Names"
                Severity = "High"
                Description = "$($duplicateSpns.Count) SPN(s) are assigned to multiple accounts. This can cause authentication failures."
                Count = $duplicateSpns.Count
                Evidence = $dupEvidence
                Recommendation = "Identify and fix duplicate SPNs. Kerberos authentication may fail for affected services."
            }
        }
    }
    catch {
        Add-IFQCNote -Context $ctx -Note "Could not check duplicate SPNs: $($_.Exception.Message)"
    }

    # =========================================================================
    # Check 2: Kerberoastable accounts
    # =========================================================================
    Write-Host "[INFO] Checking for Kerberoastable accounts..." -ForegroundColor Gray
    try {
        # Accounts with SPN but not requiring pre-auth
        $kerberoastable = Get-ADUser -Filter { (ServicePrincipalName -like '*') -and (DoesNotRequirePreAuth -eq $false) } `
            -Properties ServicePrincipalName, Name, SamAccountName, DistinguishedName, DoesNotRequirePreAuth `
            -ErrorAction SilentlyContinue

        if ($kerberoastable) {
            $krEvidence = foreach ($account in $kerberoastable | Select-Object -First $evidenceLimit) {
                [PSCustomObject]@{
                    Account = $account.SamAccountName
                    SPNs = ($account.ServicePrincipalName -join ', ').Substring(0, 50)
                }
            }

            $findings += @{
                Id = "KERB-KERBEROASTABLE"
                Title = "Accounts Susceptible to Kerberoasting"
                Severity = "High"
                Description = "$($kerberoastable.Count) account(s) have SPNs set but are not configured to require pre-authentication."
                Count = $kerberoastable.Count
                Evidence = $krEvidence
                Recommendation = "Enable 'Do not require Kerberos pre-authentication' should be avoided. Enable UF_DONT_REQUIRE_PREAUTH where possible."
            }
        }
    }
    catch {
        Add-IFQCNote -Context $ctx -Note "Could not check Kerberoastable accounts: $($_.Exception.Message)"
    }

    # =========================================================================
    # Check 3: Unconstrained delegation
    # =========================================================================
    Write-Host "[INFO] Checking for unconstrained delegation..." -ForegroundColor Gray
    try {
        # Accounts with TRUSTED_FOR_DELEGATION
        $unconstrained = Get-ADUser -Filter { TrustedForDelegation -eq $true } `
            -Properties TrustedForDelegation, Name, SamAccountName, DistinguishedName `
            -ErrorAction SilentlyContinue

        # Computers with unconstrained delegation
        $unconstrainedComputers = Get-ADComputer -Filter { TrustedForDelegation -eq $true } `
            -Properties TrustedForDelegation, Name, SamAccountName, DistinguishedName `
            -ErrorAction SilentlyContinue

        $allUnconstrained = @()
        $allUnconstrained += $unconstrained
        $allUnconstrained += $unconstrainedComputers

        if ($allUnconstrained) {
            $unconEvidence = foreach ($obj in $allUnconstrained | Select-Object -First $evidenceLimit) {
                [PSCustomObject]@{
                    Type = if ($obj.ObjectClass -eq 'user') { "User" } else { "Computer" }
                    Name = $obj.SamAccountName
                }
            }

            $findings += @{
                Id = "KERB-UNCONSTRAINED"
                Title = "Unconstrained Delegation Enabled"
                Severity = "High"
                Description = "$($allUnconstrained.Count) account(s)/computer(s) have unconstrained delegation enabled."
                Count = $allUnconstrained.Count
                Evidence = $unconEvidence
                Recommendation = "Avoid unconstrained delegation. Use Constrained Delegation or RBCD instead."
            }
        }
    }
    catch {
        Add-IFQCNote -Context $ctx -Note "Could not check unconstrained delegation: $($_.Exception.Message)"
    }

    # =========================================================================
    # Check 4: Constrained delegation configured
    # =========================================================================
    Write-Host "[INFO] Checking for constrained delegation..." -ForegroundColor Gray
    try {
        # Accounts with msDS-AllowedToDelegateTo - use quotes for hyphenated property
        $constrainedUsers = Get-ADUser -Filter { "msDS-AllowedToDelegateTo" -like '*' } `
            -Properties "msDS-AllowedToDelegateTo", Name, SamAccountName, DistinguishedName `
            -ErrorAction SilentlyContinue

        $constrainedComputers = Get-ADComputer -Filter { "msDS-AllowedToDelegateTo" -like '*' } `
            -Properties "msDS-AllowedToDelegateTo", Name, SamAccountName, DistinguishedName `
            -ErrorAction SilentlyContinue

        $allConstrained = @()
        $allConstrained += $constrainedUsers
        $allConstrained += $constrainedComputers

        if ($allConstrained) {
            $conEvidence = foreach ($obj in $allConstrained | Select-Object -First $evidenceLimit) {
                $delegationValue = if ($null -ne $obj."msDS-AllowedToDelegateTo") {
                    ($obj."msDS-AllowedToDelegateTo" -join ', ').Substring(0, 50)
                } else { "None" }
                [PSCustomObject]@{
                    Type = $obj.ObjectClass
                    Name = $obj.SamAccountName
                    DelegatesTo = $delegationValue
                }
            }

            $findings += @{
                Id = "KERB-CONSTRAINED"
                Title = "Constrained Delegation Configured"
                Severity = "Medium"
                Description = "$($allConstrained.Count) account(s) have constrained delegation configured."
                Count = $allConstrained.Count
                Evidence = $conEvidence
                Recommendation = "Review delegation targets. Ensure only necessary services are allowed."
            }
        }
    }
    catch {
        Add-IFQCNote -Context $ctx -Note "Could not check constrained delegation: $($_.Exception.Message)"
    }

    # =========================================================================
    # Check 5: Resource-based constrained delegation (RBCD)
    # =========================================================================
    Write-Host "[INFO] Checking for RBCD..." -ForegroundColor Gray
    try {
        # msDS-AllowedToActOnBehalfOfOtherIdentity
        $rbcdUsers = Get-ADUser -Filter { "msDS-AllowedToActOnBehalfOfOtherIdentity" -like '*' } `
            -Properties "msDS-AllowedToActOnBehalfOfOtherIdentity", Name, SamAccountName `
            -ErrorAction SilentlyContinue

        $rbcdComputers = Get-ADComputer -Filter { "msDS-AllowedToActOnBehalfOfOtherIdentity" -like '*' } `
            -Properties "msDS-AllowedToActOnBehalfOfOtherIdentity", Name, SamAccountName `
            -ErrorAction SilentlyContinue

        $allRbcd = @()
        $allRbcd += $rbcdUsers
        $allRbcd += $rbcdComputers

        if ($allRbcd) {
            $rbcdEvidence = foreach ($obj in $allRbcd | Select-Object -First $evidenceLimit) {
                [PSCustomObject]@{
                    Type = $obj.ObjectClass
                    Name = $obj.SamAccountName
                    RBCD = "Configured"
                }
            }

            $findings += @{
                Id = "KERB-RBCD"
                Title = "Resource-Based Constrained Delegation Configured"
                Severity = "Medium"
                Description = "$($allRbcd.Count) account(s)/computer(s) have RBCD configured."
                Count = $allRbcd.Count
                Evidence = $rbcdEvidence
                Recommendation = "Review RBCD assignments. Attackers can abuse this for privilege escalation."
            }
        }
    }
    catch {
        Add-IFQCNote -Context $ctx -Note "Could not check RBCD: $($_.Exception.Message)"
    }

    # =========================================================================
    # Check 6: Pre-auth not required (AS-REP roasting)
    # =========================================================================
    Write-Host "[INFO] Checking for AS-REP roastable accounts..." -ForegroundColor Gray
    try {
        $asrepRoastable = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } `
            -Properties DoesNotRequirePreAuth, Name, SamAccountName, DistinguishedName `
            -ErrorAction SilentlyContinue

        if ($asrepRoastable) {
            $asrepEvidence = foreach ($account in $asrepRoastable | Select-Object -First $evidenceLimit) {
                [PSCustomObject]@{
                    Account = $account.SamAccountName
                    Enabled = $account.Enabled
                }
            }

            $findings += @{
                Id = "KERB-ASREP-ROAST"
                Title = "Accounts Vulnerable to AS-REP Roasting"
                Severity = "High"
                Description = "$($asrepRoastable.Count) account(s) have 'Do not require Kerberos pre-authentication' enabled."
                Count = $asrepRoastable.Count
                Evidence = $asrepEvidence
                Recommendation = "AS-REP roasting extracts account hashes. Only enable this setting when absolutely required."
            }
        }
    }
    catch {
        Add-IFQCNote -Context $ctx -Note "Could not check AS-REP roasting: $($_.Exception.Message)"
    }

    # =========================================================================
    # Output findings
    # =========================================================================
    foreach ($finding in $findings) {
        Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
            -Id $finding.Id `
            -Title $finding.Title `
            -Severity $finding.Severity `
            -Description $finding.Description `
            -Count $finding.Count `
            -Evidence $finding.Evidence `
            -Recommendation $finding.Recommendation
        )
    }
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
# MIIf3QYJKoZIhvcNAQcCoIIfzjCCH8oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB1u2zp97QIB/W2
# PaSmAFViwR6rYlI5b6vl0b+BFd2eqqCCGNwwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggWeMIIDhqADAgECAhAfb4XAeia2j0f08ahQbRKXMA0GCSqG
# SIb3DQEBCwUAMGcxCzAJBgNVBAYTAkdCMRcwFQYDVQQHDA5Ob3J0aHVtYmVybGFu
# ZDEaMBgGA1UECgwRSWRlbnRpdHlGaXJzdCBMdGQxIzAhBgNVBAMMGklkZW50aXR5
# Rmlyc3QgQ29kZSBTaWduaW5nMB4XDTI2MDEyOTIwNTAyM1oXDTI5MDEyOTIxMDAy
# M1owZzELMAkGA1UEBhMCR0IxFzAVBgNVBAcMDk5vcnRodW1iZXJsYW5kMRowGAYD
# VQQKDBFJZGVudGl0eUZpcnN0IEx0ZDEjMCEGA1UEAwwaSWRlbnRpdHlGaXJzdCBD
# b2RlIFNpZ25pbmcwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDV9YyY
# z49V2ipI5ePMgWVHs5h89pYHRk60XSkSOUrCXYH+83sOhTgzKnpvwo7Mzuchbf6f
# q4+85DpydvkLD1L/ZMAF3x1oP74iZ28JZYv/3PwrwLsUDAAiqFQlZk7YrDxgMhdO
# Z90dXpnK+xLTfbaRGLaqB40xnCMAozxHwIm1ClEOOlhC/I+BoPZqG6GRCcOXIdzU
# UQFWRGw8o33e2YyvDfCpwZlFHTgbD1Zmsx/SE7x9LiKi3UdnAyOMlrfHgSeJRIss
# omIVDKheB5MuAHlZQm//DMNBV7o+jO3prF4MJJygD+scND5ZImw+3L2BJEPYyBLZ
# Jum+fnKp4obGnMafQWyEk77bR+ebX3hIyglqcEwalVFdPQsIMeNQ7ervsFy7NOU0
# wBPIuEgLifGWwTVPHy70T2Ci+rz5+93qSljOWvOeT4LdQ/hpqH9JS4Eu4SpJrJ+U
# 6pwdbB3rZnFLax57w/Uh/ayZ74FZDvZhCg8KaV5sJo7XgbwZ44b3OPo6bXAWV7Jl
# yIWrO4h1q3QbgSXVWui3fWxfNmHgW3CEPTzKJlRM88wCvcPe/gQYx4aDFUKtEoiE
# JKmbuDFWoHyDAEuVo+ohUt03eRdEv73XZR/hwg9imN6NbaaR9aG1TV8C3/uMD5ET
# jBmdlUcGEztyHDLzVyIad+RQGh3nDmq2vhGLfQIDAQABo0YwRDAOBgNVHQ8BAf8E
# BAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFHZkS4haGPdZn+Um
# 4fJ/zeQU7kJzMA0GCSqGSIb3DQEBCwUAA4ICAQAnWa5k8D/hKdPn9IIZNY15hX6B
# NQylhSEPNRl4PT4vR1KKyX7Wl6c55c57z3egOC23wjOC6n0Nzt0JzZwgor9Do2V8
# 7R7APMQbXVMU2N1wDugVMNBsXbDbcS4AJz2IxRPmcW+CbMo32BoFeVbc6AODLhEr
# 1PEcAydxANk7E3rxXd1TD7pCLgp1XtRmZPx87SVJgYrRvr7J3VG0As/2KOO6Eu8n
# QTAwiyOZaRXh8MGmI/kd8SUZzFzwRpcafvSgjGqbQK6s4Tkvyxo9rkLKcS9xOww7
# hyEB6mmmV9Z0kPRBMk7llIKebFzN3exzhU8Jrdsnoas4dHl/O78VOl7nZEAbujhF
# l2IL+wFTicwrwCe9s4ZVtEhFZogUAxgGk6Ut00axJF5DgRuvc06YSRrrG7DvMKZw
# vSLWeeT9u+gbwmwEFLIjaEuF+PG0HQ2EgEaNxOKXP7xjJzLo58f5GWoFk+AKealG
# 8E1TuUfHLGJSl4m30vmenyjTlWtpcgbX5XBAb7BbYv3BrIsTiPwoqKY/X9orSDK8
# owFCw1x3Gy+K2DnaVR8JMtGv5KfC2hSobmjnc3nsryd0Bf0iEO/rcwtNbhAzjNEi
# rEKDng+bz5WEJ5HXVg3SXB7v73m+Q4xNVPfBT4WVV0YHxlbwtIk/Jpbsls43n5Uv
# 6aqzWFEZtlMMLRwTezCCBrQwggScoAMCAQICEA3HrFcF/yGZLkBDIgw6SYYwDQYJ
# KoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IElu
# YzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQg
# VHJ1c3RlZCBSb290IEc0MB4XDTI1MDUwNzAwMDAwMFoXDTM4MDExNDIzNTk1OVow
# aTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQD
# EzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1
# NiAyMDI1IENBMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALR4MdMK
# mEFyvjxGwBysddujRmh0tFEXnU2tjQ2UtZmWgyxU7UNqEY81FzJsQqr5G7A6c+Gh
# /qm8Xi4aPCOo2N8S9SLrC6Kbltqn7SWCWgzbNfiR+2fkHUiljNOqnIVD/gG3SYDE
# Ad4dg2dDGpeZGKe+42DFUF0mR/vtLa4+gKPsYfwEu7EEbkC9+0F2w4QJLVSTEG8y
# AR2CQWIM1iI5PHg62IVwxKSpO0XaF9DPfNBKS7Zazch8NF5vp7eaZ2CVNxpqumzT
# CNSOxm+SAWSuIr21Qomb+zzQWKhxKTVVgtmUPAW35xUUFREmDrMxSNlr/NsJyUXz
# dtFUUt4aS4CEeIY8y9IaaGBpPNXKFifinT7zL2gdFpBP9qh8SdLnEut/GcalNeJQ
# 55IuwnKCgs+nrpuQNfVmUB5KlCX3ZA4x5HHKS+rqBvKWxdCyQEEGcbLe1b8Aw4wJ
# khU1JrPsFfxW1gaou30yZ46t4Y9F20HHfIY4/6vHespYMQmUiote8ladjS/nJ0+k
# 6MvqzfpzPDOy5y6gqztiT96Fv/9bH7mQyogxG9QEPHrPV6/7umw052AkyiLA6tQb
# Zl1KhBtTasySkuJDpsZGKdlsjg4u70EwgWbVRSX1Wd4+zoFpp4Ra+MlKM2baoD6x
# 0VR4RjSpWM8o5a6D8bpfm4CLKczsG7ZrIGNTAgMBAAGjggFdMIIBWTASBgNVHRMB
# Af8ECDAGAQH/AgEAMB0GA1UdDgQWBBTvb1NK6eQGfHrK4pBW9i/USezLTjAfBgNV
# HSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYD
# VR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1Ud
# HwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwH
# ATANBgkqhkiG9w0BAQsFAAOCAgEAF877FoAc/gc9EXZxML2+C8i1NKZ/zdCHxYga
# MH9Pw5tcBnPw6O6FTGNpoV2V4wzSUGvI9NAzaoQk97frPBtIj+ZLzdp+yXdhOP4h
# CFATuNT+ReOPK0mCefSG+tXqGpYZ3essBS3q8nL2UwM+NMvEuBd/2vmdYxDCvwzJ
# v2sRUoKEfJ+nN57mQfQXwcAEGCvRR2qKtntujB71WPYAgwPyWLKu6RnaID/B0ba2
# H3LUiwDRAXx1Neq9ydOal95CHfmTnM4I+ZI2rVQfjXQA1WSjjf4J2a7jLzWGNqNX
# +DF0SQzHU0pTi4dBwp9nEC8EAqoxW6q17r0z0noDjs6+BFo+z7bKSBwZXTRNivYu
# ve3L2oiKNqetRHdqfMTCW/NmKLJ9M+MtucVGyOxiDf06VXxyKkOirv6o02OoXN4b
# FzK0vlNMsvhlqgF2puE6FndlENSmE+9JGYxOGLS/D284NHNboDGcmWXfwXRy4kbu
# 4QFhOm0xJuF2EZAOk5eCkhSxZON3rGlHqhpB/8MluDezooIs8CVnrpHMiD2wL40m
# m53+/j7tFaxYKIqL0Q4ssd8xHZnIn/7GELH3IdvG2XlM9q7WP/UwgOkw/HQtyRN6
# 2JK4S1C8uw3PdBunvAZapsiI5YKdvlarEvf8EA+8hcpSM9LHJmyrxaFtoza2zNaQ
# 9k+5t1wwggbtMIIE1aADAgECAhAKgO8YS43xBYLRxHanlXRoMA0GCSqGSIb3DQEB
# CwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8G
# A1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBT
# SEEyNTYgMjAyNSBDQTEwHhcNMjUwNjA0MDAwMDAwWhcNMzYwOTAzMjM1OTU5WjBj
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMT
# MkRpZ2lDZXJ0IFNIQTI1NiBSU0E0MDk2IFRpbWVzdGFtcCBSZXNwb25kZXIgMjAy
# NSAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0EasLRLGntDqrmBW
# sytXum9R/4ZwCgHfyjfMGUIwYzKomd8U1nH7C8Dr0cVMF3BsfAFI54um8+dnxk36
# +jx0Tb+k+87H9WPxNyFPJIDZHhAqlUPt281mHrBbZHqRK71Em3/hCGC5KyyneqiZ
# 7syvFXJ9A72wzHpkBaMUNg7MOLxI6E9RaUueHTQKWXymOtRwJXcrcTTPPT2V1D/+
# cFllESviH8YjoPFvZSjKs3SKO1QNUdFd2adw44wDcKgH+JRJE5Qg0NP3yiSyi5Mx
# gU6cehGHr7zou1znOM8odbkqoK+lJ25LCHBSai25CFyD23DZgPfDrJJJK77epTwM
# P6eKA0kWa3osAe8fcpK40uhktzUd/Yk0xUvhDU6lvJukx7jphx40DQt82yepyekl
# 4i0r8OEps/FNO4ahfvAk12hE5FVs9HVVWcO5J4dVmVzix4A77p3awLbr89A90/nW
# GjXMGn7FQhmSlIUDy9Z2hSgctaepZTd0ILIUbWuhKuAeNIeWrzHKYueMJtItnj2Q
# +aTyLLKLM0MheP/9w6CtjuuVHJOVoIJ/DtpJRE7Ce7vMRHoRon4CWIvuiNN1Lk9Y
# +xZ66lazs2kKFSTnnkrT3pXWETTJkhd76CIDBbTRofOsNyEhzZtCGmnQigpFHti5
# 8CSmvEyJcAlDVcKacJ+A9/z7eacCAwEAAaOCAZUwggGRMAwGA1UdEwEB/wQCMAAw
# HQYDVR0OBBYEFOQ7/PIx7f391/ORcWMZUEPPYYzoMB8GA1UdIwQYMBaAFO9vU0rp
# 5AZ8esrikFb2L9RJ7MtOMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggr
# BgEFBQcDCDCBlQYIKwYBBQUHAQEEgYgwgYUwJAYIKwYBBQUHMAGGGGh0dHA6Ly9v
# Y3NwLmRpZ2ljZXJ0LmNvbTBdBggrBgEFBQcwAoZRaHR0cDovL2NhY2VydHMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNI
# QTI1NjIwMjVDQTEuY3J0MF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly9jcmwzLmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZT
# SEEyNTYyMDI1Q0ExLmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1s
# BwEwDQYJKoZIhvcNAQELBQADggIBAGUqrfEcJwS5rmBB7NEIRJ5jQHIh+OT2Ik/b
# NYulCrVvhREafBYF0RkP2AGr181o2YWPoSHz9iZEN/FPsLSTwVQWo2H62yGBvg7o
# uCODwrx6ULj6hYKqdT8wv2UV+Kbz/3ImZlJ7YXwBD9R0oU62PtgxOao872bOySCI
# LdBghQ/ZLcdC8cbUUO75ZSpbh1oipOhcUT8lD8QAGB9lctZTTOJM3pHfKBAEcxQF
# oHlt2s9sXoxFizTeHihsQyfFg5fxUFEp7W42fNBVN4ueLaceRf9Cq9ec1v5iQMWT
# FQa0xNqItH3CPFTG7aEQJmmrJTV3Qhtfparz+BW60OiMEgV5GWoBy4RVPRwqxv7M
# k0Sy4QHs7v9y69NBqycz0BZwhB9WOfOu/CIJnzkQTwtSSpGGhLdjnQ4eBpjtP+XB
# 3pQCtv4E5UCSDag6+iX8MmB10nfldPF9SVD7weCC3yXZi/uuhqdwkgVxuiMFzGVF
# wYbQsiGnoa9F5AaAyBjFBtXVLcKtapnMG3VH3EmAp/jsJ3FVF3+d1SVDTmjFjLbN
# FZUWMXuZyvgLfgyPehwJVxwC+UpX2MSey2ueIu9THFVkT+um1vshETaWyQo8gmBt
# o/m3acaP9QsuLj3FNwFlTxq25+T4QwX9xa6ILs84ZPvmpovq90K8eWyG2N01c4Ih
# SOxqt81nMYIGVzCCBlMCAQEwezBnMQswCQYDVQQGEwJHQjEXMBUGA1UEBwwOTm9y
# dGh1bWJlcmxhbmQxGjAYBgNVBAoMEUlkZW50aXR5Rmlyc3QgTHRkMSMwIQYDVQQD
# DBpJZGVudGl0eUZpcnN0IENvZGUgU2lnbmluZwIQH2+FwHomto9H9PGoUG0SlzAN
# BglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqG
# SIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3
# AgEVMC8GCSqGSIb3DQEJBDEiBCCRVBczrbMg+cqN7SxAh47/9rt50wflarLMAPUi
# 4ao7mjANBgkqhkiG9w0BAQEFAASCAgBtnp/qmQSc5G3pOk9Sx6IH0ksEFAbmsyak
# Xt2c9TTFpohtoNgvpzGS9gmrQ7XB7vFQLYL388q89xUQQhy1520LMRd1mX3DhNW2
# 3bJaHDmihsZ/X1PxOMKoaeMenADUAQua23Mxwovd/HBnAa19sE5jrGcaacPqRiKv
# 28qGfkV/IeZ6a5zVtUjGnk7WvQ5jFc4VaRvnT07MD/Oqb0L3yi8R+vYtNCXs6A+K
# 4tmF5KY2tExbDCJWlKcmJ6eMH77qoSOc24MO18u3VSzojm3rS3dtCJG8+fiS3FPl
# GeUENGHjYMHYhLtu5qQjhiZ2Cds8MXxHPyGrGF6YksnOBSd+ZUb7pXccuM6tGujb
# X0YMu96SDS67oiv13QiOC/2qkUf6N+seHNngxoKyst3ZLy6aHmRI/Pj7LM/B+/nf
# cWVohzTouvAoVXvOMJolEclo3X94Z7tL5pp5t98VgNufCgdh9K5ASDcy7m1nRzyx
# EWnki/ZR27M/yIAqXhNy309d2iORtAxOeeIWBg42/Md5xI+exR070jzmzplX7hJo
# gSrvoOPmRAAWxNpCk2LkYQBnUpwZO8ENSaJ0O9SXpo1Dhb6fNZwGbMiG9IJUrJPf
# oN88oKc/CP2x5k83Ncv404nEMd6jLS01dNpCHGsz8e93pgINIKnVhez/fs6qdLSy
# 7qko0pl12qGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAyMDUxNzEzMDFaMC8G
# CSqGSIb3DQEJBDEiBCAbKq7aMUkeTTdy5xiNWKcfm4N+sAmHkme0GOw34td2PTAN
# BgkqhkiG9w0BAQEFAASCAgCNOEROjYOQ8cvvjUCUnoyi+MwZYKzebTBVGqdb+zCN
# LBqF6yyjK0ZuFp8Y1kga+kOHX1u6LW0QV/3BPKHkErEJblzTfmFRTrpjYSmyP0dx
# YDRBdpFj+FrcMW1dxm1MVPhHP/f8HynTgGdJk7coxy/ftlmpIVdbPDnAd8NWf4/a
# 5CsIMKjYM56KtHcqN7I9r6MQb0r4wwdw+yWGV46hU59wZuvLWIvMfSXT3axveUB4
# Cj/G/McCojt8uHkZlWa5lwI5eaqkmBxfz90i/ACaHXocAkmNyi2tAuBj2Ac7Xal9
# 9kdpPuhbxP7HT8rSsMyxyKs1Bqg9gYvof1nH8J3k7CQZQoQKWNsRnUh8DKjF7hwS
# ndY6R0qgTkNgHRu8rbnvycAxE4FL14OnkOcYXhYFvV8GCUvK2F4EV3F0tS+BgZ6t
# cP4yJnv8RXsJXiQ3d7MPC/V29KnxeUppReEBuoR656r4ZqAiF3die/zLcP2kH8h/
# sfMMUuMzldLT/IF8yS5z5NEpnVbjN37Q9qHNf6g4Ala9NisHf8Y87/zqvugaILQp
# BKpe+oDpafo8o7IQzpJlsGgdRE/amB/EzHJBZ6dHVRjcgcxzVlPFYtuDetntBXZt
# kaGijfMjxjY82NJE19VGuxbcOj9k3V9vUln0eFrMrPCAEtTDx9KtO6bgNXx58IIb
# zw==
# SIG # End signature block
