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
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDJKlyVv+gwGP90
# CNRSYWwadaOST3ar9D4sWC0aFLOToaCCFlIwggMUMIIB/KADAgECAhBDR0HvMFNE
# lkJ70azsYRwnMA0GCSqGSIb3DQEBCwUAMCIxIDAeBgNVBAMMF0lkZW50aXR5Rmly
# c3QgQ29kZSBTaWduMB4XDTI2MDIwNDE2NDE0OFoXDTI3MDIwNDE3MDE0OFowIjEg
# MB4GA1UEAwwXSWRlbnRpdHlGaXJzdCBDb2RlIFNpZ24wggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQDWJrlUCUN9yoS4qyJUFIIrjVVnfoFqTXwze3ijNE5q
# wUAAiypU86tc6ct9/wQ9Q9qOn6gjKU3vDhq8XojyQhi/q0ffxG1pP8bHfCQtrMFc
# kTOKLZRgQO73caKFxunCuRdAGxdDxy94NNjwITySkaaLFb3gULH1wbfmu5l2v9ga
# CgpRJGoofRbYbjBS5B7TTNVXlyxl5I3toq9cYRwauWq0Fqj2h6gZ/8izDVU6nMGX
# k+ZfsQwTsVSxfiiWHozhjU7Rt8ckxfVt1YLyPamewESLxw4ijFgHYZUrxNtbm2DP
# QUUG4ekzdDQlBLBzjdIJh8hIz+gcqvyXIQpoFjF2xyoFAgMBAAGjRjBEMA4GA1Ud
# DwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQU0LvUry7V
# 3WlfTmidD6yCOpbcmSQwDQYJKoZIhvcNAQELBQADggEBAAWDzEqYgCCQHZwHCMlU
# ob2Jkqcbk6GYylmfTwW9EQ7iJjyKHFJlbUGuDJxClDwDteBCVpxhfbi0fJjkib8r
# b4Fbk9Rex5rJxEMidBYbnASWnLuJD7dsHbwf6N4SM/LsYhiEtllGb0UsKET6PyuO
# f1sYdDY+UcTssCzDAElCrlVIl4Z4/JBlXOhInMD7AnP6Xx2r4hCAVEWhHtJ+ahY/
# bFAJ7v+EsTET2Pa34kiymxJ7yYRNSxwxyb1umUx/Q6pui0lYjyNXt8AAg4A0ybyj
# ABLNYct6zilczJ6JqPCBJLL0ZbCDpg8SkmAn3G3Y+bSztlOIUo4eXpjXV1DE7oB/
# kuAwggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUA
# MGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsT
# EHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQg
# Um9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqcl
# LskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YF
# PFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceIt
# DBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZX
# V59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1
# ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2Tox
# RJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdp
# ekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF
# 30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9
# t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQ
# UOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXk
# aS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud
# DgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEt
# UYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsG
# AQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0
# dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RD
# QS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAw
# DQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72arKGHLOyF
# XqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFIDyE7QKt76
# LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8L
# punyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2
# CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si
# /xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQwgga0MIIEnKADAgEC
# AhANx6xXBf8hmS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcw
# MDAwMDBaFw0zODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1l
# U3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZ
# loMsVO1DahGPNRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM
# 2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj
# 7GH8BLuxBG5AvftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQ
# Sku2Ws3IfDReb6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZ
# lDwFt+cVFBURJg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+
# 8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRx
# ykvq6gbylsXQskBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yG
# OP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqI
# MRvUBDx6z1ev+7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm
# 1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBj
# UwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729T
# SunkBnx6yuKQVvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4c
# D08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUF
# BwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEG
# CCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAX
# MAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaA
# HP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQ
# M2qEJPe36zwbSI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt
# 6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7
# bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmS
# Nq1UH410ANVko43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69
# M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnF
# RsjsYg39OlV8cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmM
# Thi0vw9vODRzW6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oa
# Qf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx
# 9yHbxtl5TPau1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3
# /BAPvIXKUjPSxyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN
# 8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQg
# VGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAw
# MDAwMFoXDTM2MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBU
# aW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx
# +wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvN
# Zh6wW2R6kSu9RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlL
# nh00Cll8pjrUcCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmn
# cOOMA3CoB/iUSROUINDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5KqCvpSduSwhw
# UmotuQhcg9tw2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL
# 4Q1OpbybpMe46YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdoRORVbPR1VVnD
# uSeHVZlc4seAO+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCy
# FG1roSrgHjSHlq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7rlRyTlaCCfw7a
# SUROwnu7zER6EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K096V1hE0yZIXe+gi
# AwW00aHzrDchIc2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGj
# ggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39/dfzkXFjGVBD
# z2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8E
# BAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGF
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUH
# MAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRH
# NFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBW
# MFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVk
# RzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkw
# FzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3x
# HCcEua5gQezRCESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh
# 8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim8/9yJmZS
# e2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUqW4daIqToXFE/
# JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMnxYOX8VBRKe1u
# NnzQVTeLni2nHkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq
# 8/gVutDojBIFeRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AWcIQfVjnzrvwi
# CZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJgddJ35XTxfUlQ
# +8Hggt8l2Yv7roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1
# R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVccAvlKV9jEnstr
# niLvUxxVZE/rptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8atufk+EMF/cWu
# iC7POGT75qaL6vdCvHlshtjdNXOCIUjsarfNZzGCBRIwggUOAgEBMDYwIjEgMB4G
# A1UEAwwXSWRlbnRpdHlGaXJzdCBDb2RlIFNpZ24CEENHQe8wU0SWQnvRrOxhHCcw
# DQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkq
# hkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGC
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgzFbdqLg+8ziptrUIULkaWJepwmNwoQ70xneb
# pkcdIsYwDQYJKoZIhvcNAQEBBQAEggEAtqSFipIvJ2I2Yo99hkwg0eb03SKT59Na
# veTA9vATA7ZRbGInYI2qvW7SnPPT2s/hsA/28nxBhleRZJQZv4erv7wozKpdyFru
# aVWPWaM57RhB24ideYyA3XCJjtr1N5AHfjqAVNIKZHwVOjzHIwqm8qcJTQjCa5n5
# zpa69IWEC7Fdh7DgyJzLTJVBegy4GMgBPK8B83wXwdFT/LJqwRCGe5jTf0698dUR
# d7LiFvombw3/dJ1BsuO//jxBfQzbDe8cCtzqH0hTIgFxcMkwCi4bDCH7NXJNIRxg
# AVTQ0+DTVL16V/YJNCsh2yMWF2niPgElV6MchDMwZ9p2+l0XwFmWQ6GCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjAyMDQxNjUyMTRaMC8GCSqGSIb3DQEJBDEiBCDo
# d2FBE8eX2DTbxvFFPYt24qfbo2KwPXpZejnsGdhDRDANBgkqhkiG9w0BAQEFAASC
# AgA0rXLyaofCz9lLhdt+O4EnCPfH8697Cd2srMUON4bjaNS7OWvkiYYgV1oFNwV3
# 6BByC/Nnnhvo+XGoiLQvVZcmdSX9Y2fVCZf8p/I1qf4j294JLQIyd6FXaYelvIlX
# FluXGpvCEUrwzTIAo4X3HcvFBsE/gdc6mJwgR5wiuXZrAvi+dXqX+tw1X3bZYOq4
# fGLV5qyxE02LtO1wGhFAt/7815kidBq4S4vorQvyAiwTzr8b/H58vF509YMOUneO
# LwfcsW+wS8a1lp8P0ennJMNdF9kghvDDb3DXSamzOCiLNv5Ql31KabNzaAJivB9R
# ylXUsFvBP2SYusTXrxCYtL6b9H/yWKWsIw1QZGFRRhr2gckbRdtMX4lZhLykJhkR
# nkaJDJKhNxdVyuLuNhJC8q4TllBVEsAaY/bT8Jt2FOT4Au4XORvJ6Y2T0KgOv4b3
# iDcEd/f2uMn52DMhniQmP2v5vWboiInLJP8varUDwYYb8gMBNDt+QTy9OsccasfU
# iT+TRW1B3ZxhN4sCvL2alln1X9CtJWgO4/Qa+jMIxqjF2ub/Tb/mqT6xV/yYc7jz
# g+mzCqp/ASAn4VCGtsp2x87ciCWXVgdHY9ZFcwKLv0yV6ka1PkGb4hkvEdy8aOA4
# EU8RgqBUKuTL6TsU+NG7KdVIsYJj2lWh1P6S+ubRikRveQ==
# SIG # End signature block
