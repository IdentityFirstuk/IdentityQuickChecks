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
    Pester tests for EntraID and Azure QuickChecks

.DESCRIPTION
    This test suite validates EntraID and Azure-specific functionality
    including guest accounts, legacy auth, MFA coverage, and hybrid sync.

.NOTES
    Requirements: Pester 5.0+
    PowerShell: 5.1+
#>

Describe "IdentityFirst.QuickChecks EntraID Tests" -Tag "EntraID", "Unit" {
    BeforeAll {
        # Mock module availability for testing without actual Graph connection
        $script:MockModuleAvailable = @{
            MicrosoftGraph = $true
            AzAccounts = $true
        }
    }

    Context "Guest Account Detection" -Tag "EntraID", "Guest" {
        It "Should define guest finding structure" -Tag "Guest" {
            $finding = @{
                Id = "ENTRA-GUEST-001"
                Title = "Guest Account Found"
                Description = "External guest account detected in tenant"
                Severity = "Medium"
                Category = "EntraID_GuestAccounts"
                Timestamp = [datetime]::UtcNow
                AffectedObjects = @()
                Evidence = @()
                RemediationSteps = @()
                IsResolved = $false
                Confidence = "High"
                RuleId = "ENTRA-GUEST-001"
                Source = "EntraID"
                CheckName = "GuestAccountDetection"
                AffectedCount = 0
                Remediation = "Review guest account necessity"
            }

            $finding.Id | Should -Be "ENTRA-GUEST-001"
            $finding.Severity | Should -Be "Medium"
            $finding.Category | Should -Be "EntraID_GuestAccounts"
        }

        It "Should filter guest accounts by age" -Tag "Guest" {
            $guests = @(
                @{ UserPrincipalName = "guest1#ext#contoso.com"; CreatedDateTime = (Get-Date).AddDays(-90) }
                @{ UserPrincipalName = "guest2#ext#contoso.com"; CreatedDateTime = (Get-Date).AddDays(-30) }
                @{ UserPrincipalName = "guest3#ext#contoso.com"; CreatedDateTime = (Get-Date).AddDays(-365) }
            )

            $thresholdDays = 180
            $staleGuests = $guests | Where-Object {
                $daysOld = ((Get-Date) - $_.CreatedDateTime).Days
                $daysOld -gt $thresholdDays
            }

            $staleGuests.Count | Should -Be 1
            $staleGuests[0].UserPrincipalName | Should -Be "guest3#ext#contoso.com"
        }

        It "Should detect external domain guests" -Tag "Guest" {
            $users = @(
                @{ UserPrincipalName = "user@contoso.com"; UserType = "Member" }
                @{ UserPrincipalName = "guest@otherdomain.com"; UserType = "Guest" }
                @{ UserPrincipalName = "external#EXT#tenant.onmicrosoft.com"; UserType = "Guest" }
            )

            $guests = $users | Where-Object UserType -eq "Guest"

            $guests.Count | Should -Be 2
        }

        It "Should categorize guest by invitation method" -Tag "Guest" {
            $guests = @(
                @{ UserPrincipalName = "guest1#ext#"; InvitationState = "Accepted" }
                @{ UserPrincipalName = "guest2#ext#"; InvitationState = "Pending" }
            )

            $accepted = ($guests | Where-Object InvitationState -eq "Accepted").Count
            $pending = ($guests | Where-Object InvitationState -eq "Pending").Count

            $accepted | Should -Be 1
            $pending | Should -Be 1
        }
    }

    Context "Legacy Authentication Detection" -Tag "EntraID", "LegacyAuth" {
        It "Should define legacy auth finding structure" -Tag "LegacyAuth" {
            $finding = @{
                Id = "ENTRA-LEGACY-001"
                Title = "Legacy Authentication Detected"
                Description = "User has logged in using legacy authentication protocols"
                Severity = "High"
                Category = "EntraID_LegacyAuth"
                Timestamp = [datetime]::UtcNow
                AffectedObjects = @()
                Evidence = @()
                RemediationSteps = @()
                IsResolved = $false
                Confidence = "High"
                RuleId = "ENTRA-LEGACY-001"
                Source = "EntraID"
                CheckName = "LegacyAuthReality"
                AffectedCount = 0
                Remediation = "Block legacy authentication in Conditional Access"
            }

            $finding.Id | Should -Be "ENTRA-LEGACY-001"
            $finding.Severity | Should -Be "High"
        }

        It "Should identify legacy auth protocols" -Tag "LegacyAuth" {
            $protocols = @(
                @{ Name = "BasicAuth"; IsLegacy = $true }
                @{ Name = "OAuth"; IsLegacy = $false }
                @{ Name = "SMTP"; IsLegacy = $true }
                @{ Name = "IMAP"; IsLegacy = $true }
                @{ Name = "POP3"; IsLegacy = $true }
                @{ Name = "EAS"; IsLegacy = $true }
                @{ Name = "EWS"; IsLegacy = $true }
                @{ Name = "ModernAuth"; IsLegacy = $false }
            )

            $legacyCount = ($protocols | Where-Object IsLegacy).Count
            $legacyCount | Should -Be 5
        }

        It "Should filter users by last legacy auth date" -Tag "LegacyAuth" {
            $users = @(
                @{ UPN = "user1@contoso.com"; LastLegacyAuth = (Get-Date).AddDays(-10) }
                @{ UPN = "user2@contoso.com"; LastLegacyAuth = (Get-Date).AddDays(-90) }
                @{ UPN = "user3@contoso.com"; LastLegacyAuth = $null }
            )

            $thresholdDays = 30
            $recentLegacy = $users | Where-Object {
                $_.LastLegacyAuth -and ((Get-Date) - $_.LastLegacyAuth).Days -le $thresholdDays
            }

            $recentLegacy.Count | Should -Be 1
        }
    }

    Context "MFA Coverage Detection" -Tag "EntraID", "MFA" {
        It "Should define MFA finding structure" -Tag "MFA" {
            $finding = @{
                Id = "ENTRA-MFA-001"
                Title = "MFA Not Enabled"
                Description = "User does not have MFA registration"
                Severity = "Critical"
                Category = "EntraID_MFACoverage"
                Timestamp = [datetime]::UtcNow
                AffectedObjects = @()
                Evidence = @()
                RemediationSteps = @()
                IsResolved = $false
                Confidence = "High"
                RuleId = "ENTRA-MFA-001"
                Source = "EntraID"
                CheckName = "MfaCoverageGap"
                AffectedCount = 0
                Remediation = "Enforce MFA registration via Conditional Access"
            }

            $finding.Id | Should -Be "ENTRA-MFA-001"
            $finding.Severity | Should -Be "Critical"
        }

        It "Should identify users without MFA" -Tag "MFA" {
            $users = @(
                @{ UPN = "user1@contoso.com"; MFARegistered = $true; MFAEnabled = $true }
                @{ UPN = "user2@contoso.com"; MFARegistered = $false; MFAEnabled = $false }
                @{ UPN = "user3@contoso.com"; MFARegistered = $true; MFAEnabled = $true }
                @{ UPN = "user4@contoso.com"; MFARegistered = $false; MFAEnabled = $false }
            )

            $noMFA = $users | Where-Object { -not $_.MFAEnabled }

            $noMFA.Count | Should -Be 2
        }

        It "Should calculate MFA coverage percentage" -Tag "MFA" {
            $users = @(
                @{ UPN = "user1@contoso.com"; MFAEnabled = $true }
                @{ UPN = "user2@contoso.com"; MFAEnabled = $true }
                @{ UPN = "user3@contoso.com"; MFAEnabled = $false }
                @{ UPN = "user4@contoso.com"; MFAEnabled = $true }
            )

            $total = $users.Count
            $enabled = ($users | Where-Object MFAEnabled).Count
            $coverage = [math]::Round(($enabled / $total) * 100, 2)

            $coverage | Should -Be 75
        }

        It "Should prioritize privileged users without MFA" -Tag "MFA" {
            $users = @(
                @{ UPN = "admin@contoso.com"; Role = "Global Administrator"; MFAEnabled = $false }
                @{ UPN = "user@contoso.com"; Role = "User"; MFAEnabled = $false }
                @{ UPN = "privileged@contoso.com"; Role = "Security Administrator"; MFAEnabled = $false }
            )

            $privilegedNoMFA = $users | Where-Object {
                $_.Role -match "Administrator" -and -not $_.MFAEnabled
            }

            $privilegedNoMFA.Count | Should -Be 2
        }
    }

    Context "Hybrid Sync Detection" -Tag "EntraID", "HybridSync" {
        It "Should define hybrid sync finding structure" -Tag "HybridSync" {
            $finding = @{
                Id = "ENTRA-HYBRID-001"
                Title = "Hybrid Identity Sync Issue"
                Description = "Azure AD Connect synchronization delay or failure detected"
                Severity = "High"
                Category = "EntraID_HybridSync"
                Timestamp = [datetime]::UtcNow
                AffectedObjects = @()
                Evidence = @()
                RemediationSteps = @()
                IsResolved = $false
                Confidence = "High"
                RuleId = "ENTRA-HYBRID-001"
                Source = "EntraID"
                CheckName = "HybridSyncReality"
                AffectedCount = 0
                Remediation = "Verify Azure AD Connect health and event logs"
            }

            $finding.Id | Should -Be "ENTRA-HYBRID-001"
            $finding.Category | Should -Be "EntraID_HybridSync"
        }

        It "Should detect sync service status" -Tag "HybridSync" {
            $connectors = @(
                @{ Name = "Azure AD Connect Sync"; LastSyncSuccess = $true; LastExecutionTime = (Get-Date).AddMinutes(-30) }
                @{ Name = "Password Writeback"; LastSyncSuccess = $false; LastExecutionTime = (Get-Date).AddHours(-2) }
            )

            $healthy = ($connectors | Where-Object LastSyncSuccess).Count
            $unhealthy = ($connectors | Where-Object { -not $_.LastSyncSuccess }).Count

            $healthy | Should -Be 1
            $unhealthy | Should -Be 1
        }

        It "Should identify stale synced objects" -Tag "HybridSync" {
            $users = @(
                @{ UPN = "user1@contoso.com"; OnPremisesSyncEnabled = $true; LastDirSyncTime = (Get-Date).AddMinutes(-30) }
                @{ UPN = "user2@contoso.com"; OnPremisesSyncEnabled = $true; LastDirSyncTime = (Get-Date).AddDays(-3) }
                @{ UPN = "user3@contoso.com"; OnPremisesSyncEnabled = $false; LastDirSyncTime = $null }
            )

            $thresholdHours = 24
            $stale = $users | Where-Object {
                $_.OnPremisesSyncEnabled -and $_.LastDirSyncTime -and
                ((Get-Date) - $_.LastDirSyncTime).Hours -gt $thresholdHours
            }

            $stale.Count | Should -Be 1
        }
    }

    Context "App Consent Patterns" -Tag "EntraID", "AppConsent" {
        It "Should define app consent finding structure" -Tag "AppConsent" {
            $finding = @{
                Id = "ENTRA-CONSENT-001"
                Title = "High-Risk App Consent Granted"
                Description = "Application with sensitive permissions consented by user"
                Severity = "High"
                Category = "EntraID_AppConsent"
                Timestamp = [datetime]::UtcNow
                AffectedObjects = @()
                Evidence = @()
                RemediationSteps = @()
                IsResolved = $false
                Confidence = "High"
                RuleId = "ENTRA-CONSENT-001"
                Source = "EntraID"
                CheckName = "AppConsentReality"
                AffectedCount = 0
                Remediation = "Review and revoke unnecessary app consents"
            }

            $finding.Id | Should -Be "ENTRA-CONSENT-001"
            $finding.CheckName | Should -Be "AppConsentReality"
        }

        It "Should identify high-privilege app permissions" -Tag "AppConsent" {
            $permissions = @(
                @{ Name = "Mail.Read"; RiskLevel = "Low" }
                @{ Name = "User.ReadWrite.All"; RiskLevel = "High" }
                @{ Name = "Directory.Read.All"; RiskLevel = "High" }
                @{ Name = "Files.Read"; RiskLevel = "Low" }
            )

            $highRisk = $permissions | Where-Object RiskLevel -eq "High"

            $highRisk.Count | Should -Be 2
        }

        It "Should detect admin consent granted apps" -Tag "AppConsent" {
            $apps = @(
                @{ AppId = "app1"; ConsentType = "AllPrincipals"; Permissions = "High" }
                @{ AppId = "app2"; ConsentType = "Specific"; Permissions = "Low" }
                @{ AppId = "app3"; ConsentType = "AllPrincipals"; Permissions = "High" }
            )

            $adminConsented = $apps | Where-Object ConsentType -eq "AllPrincipals"

            $adminConsented.Count | Should -Be 2
        }
    }
}

Describe "IdentityFirst.QuickChecks Azure Tests" -Tag "Azure", "Unit" {
    Context "Azure RBAC Assessment" -Tag "Azure", "RBAC" {
        It "Should define RBAC finding structure" -Tag "Azure", "RBAC" {
            $finding = @{
                Id = "AZ-RBAC-001"
                Title = "Overly Permissive Role Assignment"
                Description = "Role assignment grants excessive permissions"
                Severity = "High"
                Category = "Azure_RBAC"
                Timestamp = [datetime]::UtcNow
                AffectedObjects = @()
                Evidence = @()
                RemediationSteps = @()
                IsResolved = $false
                Confidence = "High"
                RuleId = "AZ-RBAC-001"
                Source = "Azure"
                CheckName = "AzureRBACCheck"
                AffectedCount = 0
                Remediation = "Review and reduce role scope"
            }

            $finding.Id | Should -Be "AZ-RBAC-001"
            $finding.Severity | Should -Be "High"
        }

        It "Should identify high-privilege roles" -Tag "Azure", "RBAC" {
            $roles = @(
                @{ RoleName = "Reader"; IsHighPrivilege = $false }
                @{ RoleName = "Contributor"; IsHighPrivilege = $false }
                @{ RoleName = "Owner"; IsHighPrivilege = $true }
                @{ RoleName = "User Access Administrator"; IsHighPrivilege = $true }
                @{ RoleName = "Global Administrator"; IsHighPrivilege = $true }
            )

            $highPriv = $roles | Where-Object IsHighPrivilege

            $highPriv.Count | Should -Be 3
        }

        It "Should detect role assignments at management group scope" -Tag "Azure", "RBAC" {
            $assignments = @(
                @{ Scope = "/subscriptions/sub1"; Role = "Contributor" }
                @{ Scope = "/providers/Microsoft.Management/managementGroups/mg1"; Role = "Owner" }
                @{ Scope = "/providers/Microsoft.Management/managementGroups/mg1"; Role = "Reader" }
            )

            $mgmtGroupScope = $assignments | Where-Object Scope -match "managementGroups"

            $mgmtGroupScope.Count | Should -Be 2
        }
    }

    Context "Azure AD Integration" -Tag "Azure", "AAD" {
        It "Should check conditional access policies" -Tag "Azure", "AAD" {
            $policies = @(
                @{ Name = "Block Legacy Auth"; State = "Enabled"; Conditions = "LegacyAuth" }
                @{ Name = "Require MFA"; State = "Enabled"; Conditions = "AllUsers" }
                @{ Name = "Require MFA"; State = "ReportOnly"; Conditions = "AllUsers" }
            )

            $enabled = $policies | Where-Object State -eq "Enabled"
            $enabled.Count | Should -Be 2
        }

        It "Should detect missing security defaults" -Tag "Azure", "AAD" {
            $tenant = @{
                SecurityDefaultsEnabled = $false
                ConditionalAccessEnabled = $true
                HasMFAPolicy = $true
            }

            $securityGaps = @()
            if (-not $tenant.SecurityDefaultsEnabled -and -not $tenant.ConditionalAccessEnabled) {
                $securityGaps += "No conditional access or security defaults"
            }

            $securityGaps.Count | Should -Be 1
        }
    }
}

Describe "IdentityFirst.QuickChecks Finding Aggregation" -Tag "Aggregation", "Unit" {
    Context "Finding Severity Summary" -Tag "Aggregation" {
        It "Should aggregate findings by severity" -Tag "Aggregation" {
            $findings = @(
                @{ Severity = "Critical"; Id = "1" }
                @{ Severity = "Critical"; Id = "2" }
                @{ Severity = "High"; Id = "3" }
                @{ Severity = "High"; Id = "4" }
                @{ Severity = "High"; Id = "5" }
                @{ Severity = "Medium"; Id = "6" }
                @{ Severity = "Low"; Id = "7" }
                @{ Severity = "Low"; Id = "8" }
            )

            $bySeverity = $findings | Group-Object Severity

            $critical = ($bySeverity | Where-Object Name -eq 'Critical').Count
            $high = ($bySeverity | Where-Object Name -eq 'High').Count
            $medium = ($bySeverity | Where-Object Name -eq 'Medium').Count
            $low = ($bySeverity | Where-Object Name -eq 'Low').Count

            $critical | Should -Be 2
            $high | Should -Be 3
            $medium | Should -Be 1
            $low | Should -Be 2
        }

        It "Should calculate overall health score" -Tag "Aggregation" {
            $findings = @(
                @{ Severity = "Critical"; Count = 1 }
                @{ Severity = "High"; Count = 2 }
                @{ Severity = "Medium"; Count = 5 }
                @{ Severity = "Low"; Count = 10 }
            )

            $critical = ($findings | Where-Object Severity -eq 'Critical').Count
            $high = ($findings | Where-Object Severity -eq 'High').Count

            $healthScore = if ($critical -gt 0) { 0 }
            elseif ($high -gt 0) { 50 }
            else { 100 }

            $healthScore | Should -Be 50
        }

        It "Should prioritize remediation actions" -Tag "Aggregation" {
            $findings = @(
                @{ Severity = "Low"; Title = "Minor issue"; Priority = 4 }
                @{ Severity = "Medium"; Title = "Moderate issue"; Priority = 3 }
                @{ Severity = "High"; Title = "Serious issue"; Priority = 2 }
                @{ Severity = "Critical"; Title = "Critical issue"; Priority = 1 }
            )

            $sorted = $findings | Sort-Object Priority

            $sorted[0].Title | Should -Be "Critical issue"
            $sorted[1].Title | Should -Be "Serious issue"
        }
    }

    Context "Report Generation" -Tag "Report" {
        It "Should generate JSON report" -Tag "Report" {
            $findings = @(
                @{ Severity = "High"; Title = "Test 1" }
                @{ Severity = "Medium"; Title = "Test 2" }
            )

            $report = @{
                Timestamp = [datetime]::UtcNow
                Summary = @{
                    TotalFindings = $findings.Count
                    BySeverity = @{
                        High = ($findings | Where-Object Severity -eq 'High').Count
                        Medium = ($findings | Where-Object Severity -eq 'Medium').Count
                    }
                }
                Findings = $findings
            }

            $json = $report | ConvertTo-Json -Depth 5

            $json | Should -Not -BeNullOrEmpty
            $json | Should -Contain '"Title": "Test 1"'
        }

        It "Should format executive summary" -Tag "Report" {
            $summary = @{
                Total = 10
                Critical = 1
                High = 2
                Medium = 3
                Low = 4
            }

            $formatted = @"
EXECUTIVE SUMMARY
=================
Total Findings: $($summary.Total)
Critical: $($summary.Critical)
High: $($summary.High)
Medium: $($summary.Medium)
Low: $($summary.Low)
"@

            $formatted | Should -Contain "Total Findings: 10"
            $formatted | Should -Contain "Critical: 1"
        }
    }
}

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBKan83Fvmadema
# OBo49yq+BhMfERkBGRZY3n/8+Yf+/KCCFlIwggMUMIIB/KADAgECAhBDR0HvMFNE
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgoPTrvte7s8v7CVoWgQtDAKdzHNL0IXSuBldK
# HWuIT2wwDQYJKoZIhvcNAQEBBQAEggEAY6QMZvwkFfqu2s/16hIARhIuAEq29Tsg
# qJJf5wJEKKvE6KsDbXcHQS+KEMDNmdqIup+1HnnI4JDwE7Z22JckAD2tQLFDzDjw
# g6y6oXoAmxp3FRqUCsS0noKUTdFo9MKOnKd8DzVjCBEjJbtIu7QnF08JuK6yz2jF
# k7d5PjcRhSsakVELMY/uCdYiD5j2fJ3Bgo63O4zSiqrYUWndVoPb8FdBAmJq3sy9
# gAaSxisoRt3j7rlSfrYMS1uWBCFZr0HHxQizWjbGjGFyxfEX9BCMmyOiok+SscYg
# uTxGzoWQhMbBp/JsXnRauRGswySLn+6nJoz0LvJ6HJFTkuSfJp2g+KGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjAyMDQxNjUyMjBaMC8GCSqGSIb3DQEJBDEiBCAL
# 2ysBPZfkfbkpK+/lVttKZn22gCfRg9kC0JQhFirlSjANBgkqhkiG9w0BAQEFAASC
# AgCBWH+tX20/hCYKe9EbNFUkBpPGMnv0vJR+ECkPLLZcFWZlmbMvsA0OSyMZ3r5r
# A5SG6y+DkNs2rdz4NuqL2EhAyVMIGOOQBVhMRgrCh+cGJjX0g7Msal8YRPcSuoRk
# TmRpYsbq5+A5InKr3OBzagMQW/3/DDtzmOzCtfSbf+jSbzMhFAo8rWev43cR/9gb
# 0URf0yLxtTq6Dzfq8KEQv2nbQW+p6CIBLJlWyKGReB0Tnh+D6mN1LvsK7O7yEIHG
# mT6z8aM3F4SuyhvwtLX2x76dagC6+jdb3UJ28Sm0BhXqjIiglx3X/9KBzWuKKcBm
# Cz/FXBPUnmQCeI11oatCg47E4dyWOGkERBgXqOwGkNYNxcz7hJkNsQCo5A5/ZowV
# a1EWeOLD3cTHwrpRe6TUexfx5bYC3E08dVj7R3tgTtLHbx5TLDHoNjPggtHckzXs
# S8caD3ykEBZinoY6V9W7VzWyrE0GSRDlVkmcV32OtqsJ8VwekR9BRYNn2Z0u6+nI
# VuCWEClQRgcdhzTsmiOWSHSe93sjWxkc7gZGIy+mQ3jGkKO89NebWfQy5K7+TWuV
# yOZ8ZrVbnKs4UJ9L2987StaPuIz9WOSTMSdN+4HrejmJ0HjgmcjLLVDO6KuNHjAL
# XZxv02I0z8QVKt21k6XuaxBNo6CLywyogOMdwoe0iuCUaw==
# SIG # End signature block
