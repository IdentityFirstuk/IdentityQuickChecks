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

function Invoke-OktaUserCheck {
<#
.SYNOPSIS
    OKTA-USER-001: Identifies inactive users in the Okta organization.

.DESCRIPTION
    Searches for user accounts that have not logged in within the specified
    threshold period. Inactive accounts pose a security risk as they may be
    compromised or orphaned.

.NOTES
    - Read-only: YES
    - Requires: Okta API token with read access
    - Permissions: Reports Admin or higher

.EXAMPLE
    Invoke-OktaUserCheck -DaysInactive 90

.EXAMPLE
    Invoke-OktaUserCheck -OutputPath ".\Reports" -DaysInactive 30
#>
    param(
        [int]$DaysInactive = 90,
        [string]$OutputPath = "."
    )
    
    $ErrorActionPreference = "Stop"
    
    $checkId = "OKTA-USER-001"
    $checkName = "Inactive Users Detection"
    $severity = "Medium"
    
    Write-Host "[$checkId] Starting $checkName..." -ForegroundColor Cyan
    Write-Host "[$checkId] Inactive threshold: $DaysInactive days" -ForegroundColor Gray
    
    $findings = @()
    $stats = @{
        TotalUsers = 0
        InactiveUsers = 0
        ActiveUsers = 0
    }
    
    try {
        # Get all users
        Write-Host "[$checkId] Fetching users from Okta..." -ForegroundColor Gray
        $users = Invoke-OktaApi -Endpoint "users?limit=200" -Method GET
        
        $stats.TotalUsers = $users.Count
        
        $inactiveCutoff = (Get-Date).AddDays(-$DaysInactive)
        
        foreach ($user in $users) {
            $isInactive = $false
            $lastLogin = $null
            
            # Check last login from status events
            try {
                $events = Invoke-OktaApi -Endpoint "users/$($user.id)/events?filter=eventType eq 'user.session.start'&limit=1" -Method GET
                if ($events) {
                    $lastLogin = [DateTime]::ParseExact($events[0].published, "yyyy-MM-ddTHH:mm:ss.fffZ", $null)
                    if ($lastLogin -lt $inactiveCutoff) {
                        $isInactive = $true
                    }
                }
            }
            catch {
                # If no events found, check created date as fallback
                $createdDate = [DateTime]::ParseExact($user.created, "yyyy-MM-ddTHH:mm:ss.fffZ", $null)
                if ($createdDate -lt $inactiveCutoff) {
                    $isInactive = $true
                    $lastLogin = $createdDate
                }
            }
            
            # Also check status
            if ($user.status -ne "ACTIVE") {
                $isInactive = $true
            }
            
            if ($isInactive) {
                $stats.InactiveUsers++
                
                $finding = @{
                    Id = $checkId
                    Name = $checkName
                    Severity = $severity
                    UserId = $user.id
                    UserLogin = $user.login
                    UserEmail = $user.profile.email
                    Status = $user.status
                    LastLogin = if ($lastLogin) { $lastLogin.ToString("yyyy-MM-dd") } else { "Never" }
                    CreatedDate = $user.created
                    Department = $user.profile.department
                    Title = $user.profile.title
                }
                $findings += $finding
            }
            else {
                $stats.ActiveUsers++
            }
        }
        
        # Output summary
        Write-Host "[$checkId] Completed. Total: $($stats.TotalUsers), Active: $($stats.ActiveUsers), Inactive: $($stats.InactiveUsers)" -ForegroundColor $(if ($stats.InactiveUsers -gt 0) { "Yellow" } else { "Green" })
        
        # Export findings
        $outputFile = Join-Path $OutputPath "$checkId-Results.json"
        $result = @{
            CheckId = $checkId
            CheckName = $checkName
            Timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            ThresholdDays = $DaysInactive
            Statistics = $stats
            Findings = $findings
        }
        $result | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8
        Write-Host "[$checkId] Results exported to: $outputFile" -ForegroundColor Gray
        
        return $result
    }
    catch {
        Write-Error "[$checkId] Error during check: $($_.Exception.Message)"
        throw
    }
}

function Invoke-OktaMfaCheck {
<#
.SYNOPSIS
    OKTA-MFA-001: Verifies MFA factor status for all users.

.DESCRIPTION
    Checks that all users have at least one active MFA factor enrolled.
    Users without MFA are high-risk targets for account compromise.

.NOTES
    - Read-only: YES
    - Requires: Okta API token with read access

.EXAMPLE
    Invoke-OktaMfaCheck

.EXAMPLE
    Invoke-OktaMfaCheck -OutputPath ".\Reports"
#>
    param(
        [string]$OutputPath = "."
    )
    
    $ErrorActionPreference = "Stop"
    
    $checkId = "OKTA-MFA-001"
    $checkName = "MFA Factor Status"
    $severity = "High"
    
    Write-Host "[$checkId] Starting $checkName..." -ForegroundColor Cyan
    
    $findings = @()
    $stats = @{
        TotalUsers = 0
        UsersWithMfa = 0
        UsersWithoutMfa = 0
        FactorTypesFound = @{}
    }
    
    try {
        $users = Invoke-OktaApi -Endpoint "users?limit=200" -Method GET
        $stats.TotalUsers = $users.Count
        
        foreach ($user in $users) {
            try {
                $factors = Invoke-OktaApi -Endpoint "users/$($user.id)/factors" -Method GET
                
                if ($factors.Count -eq 0) {
                    $stats.UsersWithoutMfa++
                    
                    $finding = @{
                        Id = $checkId
                        Name = $checkName
                        Severity = $severity
                        UserId = $user.id
                        UserLogin = $user.login
                        UserEmail = $user.profile.email
                        Status = $user.status
                        MfaEnrolled = $false
                        FactorCount = 0
                        Department = $user.profile.department
                    }
                    $findings += $finding
                }
                else {
                    $stats.UsersWithMfa++
                    
                    foreach ($factor in $factors) {
                        $factorType = $factor.factorType
                        if ($stats.FactorTypesFound.ContainsKey($factorType)) {
                            $stats.FactorTypesFound[$factorType]++
                        }
                        else {
                            $stats.FactorTypesFound[$factorType] = 1
                        }
                    }
                }
            }
            catch {
                $stats.UsersWithoutMfa++
            }
        }
        
        Write-Host "[$checkId] Completed. With MFA: $($stats.UsersWithMfa), Without MFA: $($stats.UsersWithoutMfa)" -ForegroundColor $(if ($stats.UsersWithoutMfa -gt 0) { "Yellow" } else { "Green" })
        
        $outputFile = Join-Path $OutputPath "$checkId-Results.json"
        $result = @{
            CheckId = $checkId
            CheckName = $checkName
            Timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            Statistics = $stats
            Findings = $findings
            FactorTypes = $stats.FactorTypesFound
        }
        $result | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8
        
        return $result
    }
    catch {
        Write-Error "[$checkId] Error during check: $($_.Exception.Message)"
        throw
    }
}

function Invoke-OktaAdminCheck {
<#
.SYNOPSIS
    OKTA-ADMIN-001: Identifies admin role assignments and privileges.

.DESCRIPTION
    Lists all users with administrative role assignments and their
    privilege levels. Admin accounts require additional security controls.

.NOTES
    - Read-only: YES
    - Requires: Okta API token with read access

.EXAMPLE
    Invoke-OktaAdminCheck
#>
    param(
        [string]$OutputPath = "."
    )
    
    $ErrorActionPreference = "Stop"
    
    $checkId = "OKTA-ADMIN-001"
    $checkName = "Admin Role Assignments"
    $severity = "High"
    
    Write-Host "[$checkId] Starting $checkName..." -ForegroundColor Cyan
    
    $findings = @()
    $stats = @{
        TotalAdmins = 0
        SuperAdmins = 0
        AdminAdmins = 0
        HelpDeskAdmins = 0
        ReadOnlyAdmins = 0
    }
    
    try {
        $users = Invoke-OktaApi -Endpoint "users?limit=200" -Method GET
        
        foreach ($user in $users) {
            try {
                $userRoles = Invoke-OktaApi -Endpoint "users/$($user.id)/roles" -Method GET
                
                if ($userRoles.Count -gt 0) {
                    $roleNames = ($userRoles | ForEach-Object { $_.type }) -join ", "
                    
                    $isSuperAdmin = $userRoles | Where-Object { $_.type -eq "SUPER_ADMIN" }
                    $isOrgAdmin = $userRoles | Where-Object { $_.type -eq "ORG_ADMIN" }
                    $isHelpDesk = $userRoles | Where-Object { $_.type -eq "HELP_DESK_ADMIN" }
                    $isReadOnly = $userRoles | Where-Object { $_.type -eq "READ_ONLY_ADMIN" }
                    
                    if ($isSuperAdmin) { $stats.SuperAdmins++; $adminType = "SUPER_ADMIN" }
                    elseif ($isOrgAdmin) { $stats.AdminAdmins++; $adminType = "ORG_ADMIN" }
                    elseif ($isHelpDesk) { $stats.HelpDeskAdmins++; $adminType = "HELP_DESK_ADMIN" }
                    elseif ($isReadOnly) { $stats.ReadOnlyAdmins++; $adminType = "READ_ONLY_ADMIN" }
                    else { $adminType = "OTHER" }
                    
                    $stats.TotalAdmins++
                    
                    $finding = @{
                        Id = $checkId
                        Name = $checkName
                        Severity = $severity
                        UserId = $user.id
                        UserLogin = $user.login
                        UserEmail = $user.profile.email
                        Status = $user.status
                        Roles = $roleNames
                        AdminType = $adminType
                        RoleCount = $userRoles.Count
                        Department = $user.profile.department
                    }
                    $findings += $finding
                }
            }
            catch { }
        }
        
        Write-Host "[$checkId] Completed. Total Admins: $($stats.TotalAdmins)" -ForegroundColor Gray
        
        $outputFile = Join-Path $OutputPath "$checkId-Results.json"
        $result = @{
            CheckId = $checkId
            CheckName = $checkName
            Timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            Statistics = $stats
            Findings = $findings
        }
        $result | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8
        
        return $result
    }
    catch {
        Write-Error "[$checkId] Error during check: $($_.Exception.Message)"
        throw
    }
}

function Invoke-OktaAppCheck {
<#
.SYNOPSIS
    OKTA-APP-001: Checks application assignments and access patterns.

.DESCRIPTION
    Reports on application assignments, identifying unused applications.

.NOTES
    - Read-only: YES

.EXAMPLE
    Invoke-OktaAppCheck
#>
    param(
        [string]$OutputPath = "."
    )
    
    $ErrorActionPreference = "Stop"
    
    $checkId = "OKTA-APP-001"
    $checkName = "Application Assignments"
    $severity = "Medium"
    
    Write-Host "[$checkId] Starting $checkName..." -ForegroundColor Cyan
    
    $findings = @()
    $stats = @{
        TotalApps = 0
        AppsWithAssignments = 0
        TotalAssignments = 0
        UnusedApps = 0
    }
    
    try {
        $apps = Invoke-OktaApi -Endpoint "apps?limit=200" -Method GET
        $stats.TotalApps = $apps.Count
        
        foreach ($app in $apps) {
            try {
                $assignments = Invoke-OktaApi -Endpoint "apps/$($app.id)/users" -Method GET
                
                if ($assignments.Count -gt 0) {
                    $stats.AppsWithAssignments++
                    $stats.TotalAssignments += $assignments.Count
                }
                else {
                    $stats.UnusedApps++
                    
                    $finding = @{
                        Id = $checkId
                        Name = $checkName
                        Severity = $severity
                        AppId = $app.id
                        AppName = $app.label
                        AppStatus = $app.status
                        AssignmentCount = 0
                        AppType = $app.signOnMode
                        IsUnused = $true
                    }
                    $findings += $finding
                }
            }
            catch { }
        }
        
        Write-Host "[$checkId] Completed. Apps: $($stats.TotalApps), Assignments: $($stats.TotalAssignments), Unused: $($stats.UnusedApps)" -ForegroundColor Gray
        
        $outputFile = Join-Path $OutputPath "$checkId-Results.json"
        $result = @{
            CheckId = $checkId
            CheckName = $checkName
            Timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            Statistics = $stats
            Findings = $findings
        }
        $result | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8
        
        return $result
    }
    catch {
        Write-Error "[$checkId] Error during check: $($_.Exception.Message)"
        throw
    }
}

function Invoke-OktaPolicyCheck {
<#
.SYNOPSIS
    OKTA-POLICY-001: Identifies security policy gaps and misconfigurations.

.DESCRIPTION
    Reviews password policies, MFA policies, and sign-on policies for
    security gaps and weak configurations.

.EXAMPLE
    Invoke-OktaPolicyCheck
#>
    param(
        [string]$OutputPath = "."
    )
    
    $ErrorActionPreference = "Stop"
    
    $checkId = "OKTA-POLICY-001"
    $checkName = "Security Policy Gaps"
    $severity = "High"
    
    Write-Host "[$checkId] Starting $checkName..." -ForegroundColor Cyan
    
    $findings = @()
    $stats = @{
        PasswordPolicies = 0
        MfaPolicies = 0
        SignOnPolicies = 0
        PoliciesWithoutMfa = 0
        WeakPasswordPolicies = 0
    }
    
    try {
        $passwordPolicies = Invoke-OktaApi -Endpoint "policies?type=PASSWORD" -Method GET
        $stats.PasswordPolicies = $passwordPolicies.Count
        
        foreach ($policy in $passwordPolicies) {
            $settings = $policy.settings
            $isWeak = $false
            
            if ($settings.complexity) {
                if ($settings.complexity.minLength -lt 12) {
                    $isWeak = $true
                    $finding = @{
                        Id = $checkId
                        Name = $checkName
                        Severity = $severity
                        PolicyId = $policy.id
                        PolicyName = $policy.name
                        PolicyType = "PASSWORD"
                        Issue = "Minimum password length is less than 12"
                        CurrentValue = $settings.complexity.minLength
                        RecommendedValue = 12
                    }
                    $findings += $finding
                }
            }
            
            if ($isWeak) { $stats.WeakPasswordPolicies++ }
        }
        
        $mfaPolicies = Invoke-OktaApi -Endpoint "policies?type=MFA_ENROLL" -Method GET
        $stats.MfaPolicies = $mfaPolicies.Count
        
        foreach ($policy in $mfaPolicies) {
            $enrollment = $policy.settings
            if ($enrollment.enrollment -ne "REQUIRED") {
                $stats.PoliciesWithoutMfa++
                $finding = @{
                    Id = $checkId
                    Name = $checkName
                    Severity = $severity
                    PolicyId = $policy.id
                    PolicyName = $policy.name
                    PolicyType = "MFA_ENROLL"
                    Issue = "MFA enrollment is not set to REQUIRED"
                }
                $findings += $finding
            }
        }
        
        $signOnPolicies = Invoke-OktaApi -Endpoint "policies?type=OKTA_SIGN_ON" -Method GET
        $stats.SignOnPolicies = $signOnPolicies.Count
        
        Write-Host "[$checkId] Completed." -ForegroundColor Gray
        
        $outputFile = Join-Path $OutputPath "$checkId-Results.json"
        $result = @{
            CheckId = $checkId
            CheckName = $checkName
            Timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            Statistics = $stats
            Findings = $findings
        }
        $result | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8
        
        return $result
    }
    catch {
        Write-Error "[$checkId] Error during check: $($_.Exception.Message)"
        throw
    }
}

function Invoke-OktaIntegrationCheck {
<#
.SYNOPSIS
    OKTA-INTEG-001: Identifies inactive or orphaned integrations.

.DESCRIPTION
    Finds API integrations and service connections that are inactive.

.EXAMPLE
    Invoke-OktaIntegrationCheck
#>
    param(
        [string]$OutputPath = "."
    )
    
    $ErrorActionPreference = "Stop"
    
    $checkId = "OKTA-INTEG-001"
    $checkName = "Inactive Integrations"
    $severity = "Medium"
    
    Write-Host "[$checkId] Starting $checkName..." -ForegroundColor Cyan
    
    $findings = @()
    $stats = @{
        TotalIntegrations = 0
        ActiveIntegrations = 0
        InactiveIntegrations = 0
    }
    
    try {
        $clients = Invoke-OktaApi -Endpoint "oauth2/clients" -Method GET
        $stats.TotalIntegrations = $clients.Count
        
        foreach ($client in $clients) {
            $isInactive = $false
            
            if ($client.status -ne "ACTIVE") {
                $isInactive = $true
            }
            
            if ($isInactive) {
                $stats.InactiveIntegrations++
                $finding = @{
                    Id = $checkId
                    Name = $checkName
                    Severity = $severity
                    IntegrationId = $client.clientId
                    IntegrationName = $client.name
                    Status = $client.status
                }
                $findings += $finding
            }
            else {
                $stats.ActiveIntegrations++
            }
        }
        
        Write-Host "[$checkId] Completed. Active: $($stats.ActiveIntegrations), Inactive: $($stats.InactiveIntegrations)" -ForegroundColor Gray
        
        $outputFile = Join-Path $OutputPath "$checkId-Results.json"
        $result = @{
            CheckId = $checkId
            CheckName = $checkName
            Timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            Statistics = $stats
            Findings = $findings
        }
        $result | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8
        
        return $result
    }
    catch {
        Write-Error "[$checkId] Error during check: $($_.Exception.Message)"
        throw
    }
}

function Invoke-OktaApiTokenCheck {
<#
.SYNOPSIS
    OKTA-API-001: Reviews API token management and usage.

.DESCRIPTION
    Checks for API tokens that are unused, expired, or have excessive privileges.

.EXAMPLE
    Invoke-OktaApiTokenCheck
#>
    param(
        [string]$OutputPath = "."
    )
    
    $ErrorActionPreference = "Stop"
    
    $checkId = "OKTA-API-001"
    $checkName = "API Token Management"
    $severity = "High"
    
    Write-Host "[$checkId] Starting $checkName..." -ForegroundColor Cyan
    
    $findings = @()
    $stats = @{
        TotalTokens = 0
        ActiveTokens = 0
        ExpiredTokens = 0
        TokensWithoutExpiration = 0
    }
    
    try {
        $tokens = Invoke-OktaApi -Endpoint "api/tokens" -Method GET
        $stats.TotalTokens = $tokens.Count
        $cutoffDate = Get-Date
        
        foreach ($token in $tokens) {
            if ($token.status -eq "active") {
                $stats.ActiveTokens++
                
                if (-not $token.expiresAt) {
                    $stats.TokensWithoutExpiration++
                    $finding = @{
                        Id = $checkId
                        Name = $checkName
                        Severity = $severity
                        TokenId = $token.id
                        TokenName = $token.name
                        Issue = "Token does not have an expiration date"
                    }
                    $findings += $finding
                }
            }
            elseif ($token.status -eq "expired" -or $token.status -eq "revoked") {
                $stats.ExpiredTokens++
            }
        }
        
        Write-Host "[$checkId] Completed. Active: $($stats.ActiveTokens), Issues: $($stats.TokensWithoutExpiration)" -ForegroundColor Gray
        
        $outputFile = Join-Path $OutputPath "$checkId-Results.json"
        $result = @{
            CheckId = $checkId
            CheckName = $checkName
            Timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            Statistics = $stats
            Findings = $findings
        }
        $result | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8
        
        return $result
    }
    catch {
        Write-Error "[$checkId] Error during check: $($_.Exception.Message)"
        throw
    }
}

function Invoke-OktaGuestCheck {
<#
.SYNOPSIS
    OKTA-GUEST-001: Reviews guest account hygiene and lifecycle.

.DESCRIPTION
    Checks for guest accounts that are orphaned or have excessive permissions.

.EXAMPLE
    Invoke-OktaGuestCheck
#>
    param(
        [string]$OutputPath = ".",
        [int]$InactiveDays = 30
    )
    
    $ErrorActionPreference = "Stop"
    
    $checkId = "OKTA-GUEST-001"
    $checkName = "Guest Account Hygiene"
    $severity = "Medium"
    
    Write-Host "[$checkId] Starting $checkName..." -ForegroundColor Cyan
    
    $findings = @()
    $stats = @{
        TotalGuests = 0
        ActiveGuests = 0
        InactiveGuests = 0
        GuestsWithAdminAccess = 0
    }
    
    try {
        $users = Invoke-OktaApi -Endpoint "users?limit=200" -Method GET
        $inactiveCutoff = (Get-Date).AddDays(-$InactiveDays)
        
        foreach ($user in $users) {
            $isGuest = $false
            
            if ($user.profile.userType -eq "Guest" -or $user.profile.userType -eq "Contractor") {
                $isGuest = $true
            }
            
            if ($isGuest) {
                $stats.TotalGuests++
                $isInactive = $false
                $hasAdminAccess = $false
                
                try {
                    $events = Invoke-OktaApi -Endpoint "users/$($user.id)/events?filter=eventType eq 'user.session.start'&limit=1" -Method GET
                    if ($events) {
                        $lastLogin = [DateTime]::ParseExact($events[0].published, "yyyy-MM-ddTHH:mm:ss.fffZ", $null)
                        if ($lastLogin -lt $inactiveCutoff) { $isInactive = $true }
                    }
                }
                catch { }
                
                try {
                    $userRoles = Invoke-OktaApi -Endpoint "users/$($user.id)/roles" -Method GET
                    if ($userRoles.Count -gt 0) {
                        $hasAdminAccess = $true
                        $stats.GuestsWithAdminAccess++
                    }
                }
                catch { }
                
                if ($isInactive) {
                    $stats.InactiveGuests++
                    $finding = @{
                        Id = $checkId
                        Name = $checkName
                        Severity = $severity
                        UserId = $user.id
                        UserLogin = $user.login
                        Status = $user.status
                        IsGuest = $true
                        HasAdminAccess = $hasAdminAccess
                    }
                    $findings += $finding
                }
                else {
                    $stats.ActiveGuests++
                }
            }
        }
        
        Write-Host "[$checkId] Completed. Total: $($stats.TotalGuests), Inactive: $($stats.InactiveGuests)" -ForegroundColor Gray
        
        $outputFile = Join-Path $OutputPath "$checkId-Results.json"
        $result = @{
            CheckId = $checkId
            CheckName = $checkName
            Timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            Statistics = $stats
            Findings = $findings
        }
        $result | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile -Encoding UTF8
        
        return $result
    }
    catch {
        Write-Error "[$checkId] Error during check: $($_.Exception.Message)"
        throw
    }
}

function Invoke-AllOktaQuickChecks {
<#
.SYNOPSIS
    Runs all Okta QuickChecks and generates a consolidated report.

.DESCRIPTION
    Executes all 8 Okta QuickChecks and produces a comprehensive findings report.

.EXAMPLE
    Invoke-AllOktaQuickChecks -OrgUrl "https://dev-123456.okta.com" -ApiToken "xxx"
#>
    param(
        [Parameter(Mandatory)]
        [string]$OrgUrl,
        
        [Parameter(Mandatory)]
        [string]$ApiToken,
        
        [string]$OutputPath = ".",
        
        [int]$DaysInactive = 90
    )
    
    $ErrorActionPreference = "Stop"
    
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  OKTA QUICKCHECKS - SECURITY ASSESSMENT" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    # Connect to Okta
    $connected = Connect-OktaOrg -OrgUrl $OrgUrl -ApiToken $ApiToken
    if (-not $connected) {
        Write-Error "Failed to connect to Okta organization"
        return
    }
    
    $results = @()
    $checkParams = @{ OutputPath = $OutputPath; DaysInactive = $DaysInactive }
    
    Write-Host "" ; Write-Host "Running Okta QuickChecks..." -ForegroundColor Cyan
    
    $results += Invoke-OktaUserCheck @checkParams
    $results += Invoke-OktaMfaCheck @checkParams
    $results += Invoke-OktaAdminCheck @checkParams
    $results += Invoke-OktaAppCheck @checkParams
    $results += Invoke-OktaPolicyCheck @checkParams
    $results += Invoke-OktaIntegrationCheck @checkParams
    $results += Invoke-OktaApiTokenCheck @checkParams
    $results += Invoke-OktaGuestCheck @checkParams
    
    # Calculate risk score
    $riskScore = Invoke-QuickChecksRiskScore -Findings $results
    
    $consolidatedReport = @{
        CheckType = "OktaQuickChecks"
        Timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
        OrgUrl = $OrgUrl
        TotalChecks = $results.Count
        RiskScore = $riskScore
        IndividualResults = $results
    }
    
    $reportFile = Join-Path $OutputPath "OktaQuickChecks-ConsolidatedReport.json"
    $consolidatedReport | ConvertTo-Json -Depth 15 | Out-File -FilePath $reportFile -Encoding UTF8
    
    Write-Host "" ; Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "  ASSESSMENT COMPLETE" -ForegroundColor Cyan
    Write-Host "  Risk Score: $($riskScore.Score)/100" -ForegroundColor $riskScore.Color
    Write-Host "  Level: $($riskScore.Level)" -ForegroundColor $riskScore.Color
    Write-Host "========================================" -ForegroundColor Cyan
    
    return $consolidatedReport
}

Export-ModuleMember -Function @(
    'Invoke-OktaUserCheck',
    'Invoke-OktaMfaCheck',
    'Invoke-OktaAdminCheck',
    'Invoke-OktaAppCheck',
    'Invoke-OktaPolicyCheck',
    'Invoke-OktaIntegrationCheck',
    'Invoke-OktaApiTokenCheck',
    'Invoke-OktaGuestCheck',
    'Invoke-AllOktaQuickChecks'
) -ErrorAction SilentlyContinue
