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
