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
    Microsoft 365 App Consent Patterns Detection.

.DESCRIPTION
    Detects applications that users have consented to in Entra ID.
    Identifies over-privileged apps, admin vs user consent patterns,
    and risky permission scopes granted to third-party applications.

.OUTPUTS
    - JSON report
    - HTML report
    - Log file

.NOTES
    Author: mark.ahearne@identityfirst.net | Owner: IdentityFirst Ltd
    Safety: Read-only. No changes to app registrations or consent grants.
    Requires: Microsoft Graph with "Directory.Read.All", "User.Read.All", "Application.Read.All"
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

$ctx = New-IFQCContext -ToolName "AppConsentReality" -OutputDirectory $OutputDirectory -DetailLevel $DetailLevel
Add-IFQCNote -Context $ctx -Note "Read-only detection of application consent patterns."
Add-IFQCNote -Context $ctx -Note "Does not modify or revoke any application permissions."
Add-IFQCNote -Context $ctx -Note "Shows which apps users have consented to and their permission scopes."

function Get-EvidenceLimit {
    param([string]$DetailLevel)
    if ($DetailLevel -eq "Detailed") { return 50 }
    return 15
}

Invoke-IFQCSafe -Context $ctx -Name "App consent patterns detection" -Block {
    try {
        Import-Module Microsoft.Graph.Applications -Force -ErrorAction Stop
        Import-Module Microsoft.Graph.Identity.DirectoryManagement -Force -ErrorAction Stop
        Connect-MgGraph -Scopes "Directory.Read.All", "User.Read.All", "Application.Read.All" -ErrorAction Stop | Out-Null
    } catch {
        throw "Microsoft Graph modules required. Install Microsoft.Graph and connect first."
    }

    $ctx.Data.connected = $true

    # High-risk permission scopes to watch for
    $highRiskScopes = @(
        "User.ReadWrite.All",           # Write to all user accounts
        "Directory.ReadWrite.All",      # Full directory access
        "Files.ReadWrite.All",          # All file access
        "Mail.ReadWrite",               # Read/write all mail
        "Sites.ReadWrite.All",          # All SharePoint sites
        "Teamwork.ReadWrite.All",       # Teams management
        "Calendars.ReadWrite",          # Modify calendars
        "Contacts.ReadWrite",           # Modify contacts
        "Directory.AccessAsUser.All"    # Act as directory
    )

    $moderateRiskScopes = @(
        "User.Read",                    # Sign in and read profile
        "User.ReadBasic.All",           # Read basic profiles
        "Mail.Read",                    # Read mail
        "Files.Read",                   # Read files
        "Sites.Read.All"                # Read SharePoint sites
    )

    # Collect consent grants
    $consentGrants = @{
        byUser = @{}      # User consents
        byApp = @{}       # Aggregated by app
        totalGrants = 0
        highRiskApps = @()
        adminConsents = @()
        userConsents = @()
    }

    Write-IFQCLog -Context $ctx -Level INFO -Message "Fetching service principal consent grants..."

    # Get all service principals with oauth2 permission grants
    try {
        $servicePrincipals = Get-MgServicePrincipal -All -ErrorAction SilentlyContinue

        foreach ($sp in $servicePrincipals) {
            $appId = $sp.AppId
            $displayName = $sp.DisplayName

            # Get app owner
            $owners = Get-MgServicePrincipalOwner -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue
            $ownerCount = ($owners | Measure-Object).Count

            # Check for admin consent (permissions that don't require user assignment)
            $hasHighRiskPermissions = $false
            $permissionDetails = @()

            if ($sp.Oauth2PermissionScopes) {
                foreach ($scope in $sp.Oauth2PermissionScopes) {
                    $scopeId = $scope.Id
                    $scopeValue = $scope.Value
                    $isAdminConsentRequired = $scope.IsAdminConsentRequired

                    $permInfo = [PSCustomObject]@{
                        Scope = $scopeValue
                        AdminConsentRequired = $isAdminConsentRequired
                        IsEnabled = $scope.IsEnabled
                    }
                    $permissionDetails += $permInfo

                    if ($scopeValue -in $highRiskScopes -and $scope.IsEnabled) {
                        $hasHighRiskPermissions = $true
                    }
                }
            }

            # Check delegated permissions used
            $delegatedPermissions = @()
            if ($sp.AppRoles | Where-Object { $_.AllowedMemberTypes -contains "User" }) {
                foreach ($role in $sp.AppRoles | Where-Object { $_.AllowedMemberTypes -contains "User" }) {
                    $delegatedPermissions += [PSCustomObject]@{
                        Role = $role.DisplayName
                        Value = $role.Value
                        Description = $role.Description
                    }
                }
            }

            # Store app info
            $consentGrants.byApp[$appId] = [PSCustomObject]@{
                AppId = $appId
                DisplayName = $displayName
                Owners = $ownerCount
                HasHighRiskPermissions = $hasHighRiskPermissions
                PermissionDetails = $permissionDetails
                DelegatedPermissions = $delegatedPermissions
            }

            if ($hasHighRiskPermissions) {
                $consentGrants.highRiskApps += [PSCustomObject]@{
                    AppId = $appId
                    DisplayName = $displayName
                    Owners = $ownerCount
                    Permissions = ($permissionDetails | Where-Object { $_.Scope -in $highRiskScopes } | ForEach-Object { $_.Scope })
                }
            }
        }
    } catch {
        Write-IFQCLog -Context $ctx -Level WARN -Message "Failed to fetch service principals: $($_.Exception.Message)"
    }

    # Get user consent requests (if available)
    Write-IFQCLog -Context $ctx -Level INFO -Message "Fetching user consent requests..."
    try {
        $consentRequests = Get-MgUserConsentRequest -All -ExpandProperty "app" -ErrorAction SilentlyContinue
        foreach ($req in $consentRequests) {
            $consentGrants.userConsents += [PSCustomObject]@{
                UserId = $req.UserId
                AppDisplayName = $req.AppDisplayName
                AppId = $req.AppId
                Status = $req.Status
                CreatedDateTime = $req.CreatedDateTime
            }
        }
    } catch {
        Write-IFQCLog -Context $ctx -Level WARN -Message "Failed to fetch consent requests: $($_.Exception.Message)"
    }

    # Get oauth2 permission grants (specific consent grants)
    Write-IFQCLog -Context $ctx -Level INFO -Message "Fetching oauth2 permission grants..."
    try {
        $oauthGrants = Get-MgOauth2PermissionGrant -All -ErrorAction SilentlyContinue
        foreach ($grant in $oauthGrants) {
            $consentGrants.byUser[$grant.Id] = [PSCustomObject]@{
                ClientId = $grant.ClientId
                ResourceId = $grant.ResourceId
                Scope = $grant.Scope
                ConsentType = $grant.ConsentType  # Principal, Global, or Specific
                PrincipalId = $grant.PrincipalId
            }

            if ($grant.ConsentType -eq "Global") {
                $sp = Get-MgServicePrincipal -Filter "AppId eq '$($grant.ClientId)'" -ErrorAction SilentlyContinue
                $consentGrants.adminConsents += [PSCustomObject]@{
                    GrantId = $grant.Id
                    ClientId = $grant.ClientId
                    ClientName = $sp.DisplayName
                    Scope = $grant.Scope
                }
            }
        }
    } catch {
        Write-IFQCLog -Context $ctx -Level WARN -Message "Failed to fetch oauth2 grants: $($_.Exception.Message)"
    }

    $consentGrants.totalGrants = ($consentGrants.byUser.Keys | Measure-Object).Count

    $ctx.Data.consents = $consentGrants

    # ---------------------------
    # Findings
    # ---------------------------
    $evidenceLimit = Get-EvidenceLimit -DetailLevel $DetailLevel

    # Finding: Apps with high-risk permissions
    if ($consentGrants.highRiskApps.Count -gt 0) {
        Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
            -Id "APP-CONSENT-HIGHRISK" `
            -Title "Applications with high-risk permissions detected" `
            -Severity "High" `
            -Description "$($consentGrants.highRiskApps.Count) applications have been granted high-risk permission scopes (User.ReadWrite.All, Directory.ReadWrite.All, etc.)." `
            -Count $consentGrants.highRiskApps.Count `
            -Evidence ($consentGrants.highRiskApps | Select-Object -First $evidenceLimit) `
            -Recommendation "Review each high-risk application. Verify business need. Remove unnecessary permissions. Consider restricting to specific users."
        )
    }

    # Finding: Global admin consents
    if ($consentGrants.adminConsents.Count -gt 0) {
        Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
            -Id "APP-CONSENT-ADMIN" `
            -Title "Global admin consent grants detected" `
            -Severity "Medium" `
            -Description "$($consentGrants.adminConsents.Count) applications have been granted admin consent for the entire organisation." `
            -Count $consentGrants.adminConsents.Count `
            -Evidence ($consentGrants.adminConsents | Select-Object -First $evidenceLimit) `
            -Recommendation "Review global consent grants. Ensure they are documented and approved. Consider shifting to specific user/group consent."
        )
    }

    # Finding: Apps with no owners
    $orphanApps = $consentGrants.byApp.Values | Where-Object { $_.Owners -eq 0 }
    if ($orphanApps.Count -gt 0) {
        Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
            -Id "APP-CONSENT-ORPHAN" `
            -Title "Applications with no owners detected" `
            -Severity "Low" `
            -Description "$($orphanApps.Count) applications have no assigned owners. These may be orphaned or shadow IT." `
            -Count $orphanApps.Count `
            -Evidence ($orphanApps | Select-Object -First $evidenceLimit) `
            -Recommendation "Assign owners to all applications. Remove applications that are no longer needed."
        )
    }

    # Summary stats
    $ctx.Data.summary = @{
        totalServicePrincipals = ($consentGrants.byApp.Keys | Measure-Object).Count
        highRiskApps = $consentGrants.highRiskApps.Count
        adminConsents = $consentGrants.adminConsents.Count
        userConsentRequests = $consentGrants.userConsents.Count
        oauthGrants = $consentGrants.totalGrants
    }
}

$output = Save-IFQCReport -Context $ctx

# Emit structured logs for automation and keep the report object on the pipeline
Write-IFQCLog -Context $ctx -Level INFO -Message "AppConsentReality check complete."
Write-IFQCLog -Context $ctx -Level INFO -Message "Report files: JSON: $($output.Json); HTML: $($output.Html)"
Write-Output $output

# Cleanup
try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
# SIG # Begin signature block
# MIIf3QYJKoZIhvcNAQcCoIIfzjCCH8oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCDwG40bJ2aidaH
# ykG+FtY7PDrCjzjcBpyN0VUlcZ+BfqCCGNwwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# AgEVMC8GCSqGSIb3DQEJBDEiBCDtFxkLx2gXnhx1w+DPXhtTYukwKdrZWY5GJyfq
# KCqURTANBgkqhkiG9w0BAQEFAASCAgB6Zn0CClxgkx7ipnevpFPECa6kP585HwKk
# iklF3NECIbo+12gMxIP1U4nj4L2Ia4bKrUQED+/7jJno2lQqwXs7YU0UZYz2/IEx
# Kw7ik6VDAHBPQmXehRfLjK/4JHIfTzaTARzrCcrgyczKOcdCCogMD+xbIne/Fo1z
# 8P9JRDLuyAWneohwa6SW6vDiI31ulLQjq8zOppYZ9ypiwQyLAGwj5N1CIll4yCce
# d4jLz1H+O3faBmk67ftvJAvcBsqxRvQ28cgGOrQy8BRJycUfxQSZcrh8JJorJtPC
# SKGB4ytKEMBiTpMgGNjUVwPhBAgQrPFeAZO2RyQF3PsnseyCJHXfkgHGnCr2KisC
# lnEi8PFdW2mMPnOtORBlA8+5g3sDM/fo3RUxLZ1EkEqPc4MIX5HJLKebgYynOeGR
# Q0V3zRPIZvzke/DdDAMZ2BUdKrZsChqiJA3P0TIEcYERXZ0cVoFXbsF9TQhME8Lw
# Q5+/4UqXGCsinvdJEPGC4qD1L6hglUHwUmz3XaVff1rWmOawTGhE4WbV3RRonLxP
# L+jYljc16uKNfF/KP102CnryO8OP8eNQ3pZ/CyPfDACjvFj+BbMWU5/dJrze0kc+
# TSInkduefeWFCgAIrOeCwa2NIWBs5QxAGJtVQDUNcNgo5zgU6+krB/dlD+J6dFDA
# bfwMly+LY6GCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAyMDUxNzEzMDdaMC8G
# CSqGSIb3DQEJBDEiBCBOMphaABYGQxA0S1DGN6QMEFjC6rnQ5qWPeIpBAdQmtjAN
# BgkqhkiG9w0BAQEFAASCAgCZqwBHVVz8N/2KB0be8qLEY+GdCVsxyFReeydC2laX
# wbMGT4nYP5IW0uiKDMPX+qvtnrZbyo7MBZMDZKz9CkQFICxHhxEPtOCK1COoiOZp
# Di5mTujIogTwZutJ+bjCWgb1wpgK4l54cOyQbMWxF3KdNas9B50L9E9ln5lWBfqV
# FiG72sZzaL0h2aCwf4WmsWdODc98VwivHLN3Luq5WeVg6E+9p53YZMaVaJl52uHg
# ZCEwCehtftxfFMhvvtlo1UHkIU4Eixc1rs2hlSIKsnXaceII3pMlZQq39XJBvpc0
# bfvahi96lmumSRkbl0rte+0Zb9OzKgt3/dByO65ZqzybK9s/JR03lljlqGDng4Wa
# NlWNd5ka7EC9KMe67lKGvJxVXGs+67EosxBPAoa6m0rsQB/V/NWC+3DO7VqZbdG8
# ELZc5zGRLPzXGvdczcxuzNPcmZAbPCJ2zZnu2SgzQV/w20g/QmiF1vkhSAQ2xaGv
# 86pptpdrLkb3f0juds5qCM6JKmmja4YcKnongLs/utmB8nOOM+JVV6BC9jQgsJXO
# VqeFVW2WcuaCbLCl342biSULdqMwtUZJrEvNwVZI5cPMkMUn6R1oZ0LyHBp6wIkw
# PA3ET3nwOQf9L2BC8v1ivOWUWbqcqHVDulhKC2mBjRtDdUCJcjhxJ++pQo6YbHtJ
# +g==
# SIG # End signature block
