<#
.SYNOPSIS
    IdentityFirst QuickChecks - Entra ID & Azure Security Assessment
    
.DESCRIPTION
    Comprehensive Entra ID and Azure security checks:
    - Entra ID: MFA, Privileged Identity Management, Guest Users, App Registrations
    - Azure RBAC: Role assignments, Scope analysis, Classic administrators
    - Azure PBAC: Policy assignments, Exemptions, Compliance
    - Azure ABAC: Conditional Access, Claims policies, Token policies
    
.NOTES
    Author: mark.ahearne@identityfirst.net
    Requirements: PowerShell 5.1+, Microsoft.Graph module, Az module
#>

# =============================================================================
# DEFAULT THRESHOLDS - Configurable Security Thresholds
# =============================================================================

$script:DefaultThresholds = @{
    # MFA Thresholds
    MfaRegistrationThreshold = 10                        # Max % users without MFA
    MfaPolicyRequired = $true                           # MFA policy must exist
    
    # Privileged Access Thresholds
    PermanentAdminThreshold = 5                         # Max permanent admin assignments
    HighPrivRoleCount = 0                               # Should be 0 for critical roles
    
    # Guest User Thresholds
    GuestUserLimit = 50                                 # Max guest users before warning
    GuestInPrivGroupThreshold = 0                       # Guests in privileged groups
    
    # Application Thresholds
    AppPermissionLimit = 10                              # Max permissions per app
    AppConsentThreshold = 0                             # Apps with admin consent
    
    # Device Thresholds
    DeviceInactivityDays = 90                           # Days before device is stale
    
    # Scoring Thresholds
    HealthyScoreThreshold = 80
    CriticalThreshold = 1
    HighThreshold = 5
    
    # Finding Weights (score deductions)
    CriticalWeight = 25
    HighWeight = 10
    MediumWeight = 5
    LowWeight = 2
}

# Severity definitions
$script:FindingSeverity = @{ Critical = "Critical"; High = "High"; Medium = "Medium"; Low = "Low"; Info = "Info" }
$script:HealthStatus = @{ Healthy = "Healthy"; Warning = "Warning"; Critical = "Critical" }

# =============================================================================
# FINDING HELPER FUNCTIONS
# =============================================================================

function New-Finding {
    <#
    .SYNOPSIS
        Creates a new security finding object.
    
    .DESCRIPTION
        Creates a standardized finding object that represents a security issue
        discovered during an assessment. The finding includes all metadata
        needed for reporting and remediation tracking.
    
    .PARAMETER Id
        Unique identifier for the finding (e.g., 'ENTRA-MFA-001').
    
    .PARAMETER Title
        Brief, descriptive title of the finding.
    
    .PARAMETER Description
        Detailed explanation of the security issue.
    
    .PARAMETER Severity
        Severity level: Critical, High, Medium, Low, or Info.
    
    .PARAMETER Category
        Category classification for the finding.
    
    .EXAMPLE
        New-Finding -Id "ENTRA-MFA-001" -Title "Users without MFA" `
            -Description "Users lack MFA registration" `
            -Severity High -Category "Entra_MFARegistration"
    
    .OUTPUTS
        Hashtable representing the finding object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Unique finding identifier")]
        [ValidateNotNullOrEmpty()]
        [string]$Id,
        
        [Parameter(Mandatory = $true, HelpMessage = "Brief finding title")]
        [ValidateNotNullOrEmpty()]
        [string]$Title,
        
        [Parameter(Mandatory = $true, HelpMessage = "Detailed description")]
        [ValidateNotNullOrEmpty()]
        [string]$Description,
        
        [Parameter(Mandatory = $true, HelpMessage = "Severity level")]
        [ValidateSet("Critical", "High", "Medium", "Low", "Info")]
        [string]$Severity,
        
        [Parameter(Mandatory = $true, HelpMessage = "Category classification")]
        [ValidateNotNullOrEmpty()]
        [string]$Category
    )
    
    return @{
        Id = $Id
        Title = $Title
        Description = $Description
        Severity = $Severity
        Category = $Category
        Timestamp = [datetime]::UtcNow
        AffectedObjects = @()
        Evidence = @()
        RemediationSteps = @()
        IsResolved = $false
        Confidence = "Medium"
        RuleId = $Id
        Source = "EntraID"
        CheckName = ""
        AffectedCount = 0
        Remediation = ""
        RemediationUrl = ""
    }
}

function Add-FindingObject {
    <#
    .SYNOPSIS
        Adds an affected object to a finding.
    
    .DESCRIPTION
        Appends an affected object to the finding's AffectedObjects collection
        and updates the AffectedCount property.
    
    .PARAMETER Finding
        The finding object to modify.
    
    .PARAMETER Object
        The object affected by this finding.
    
    .EXAMPLE
        $finding = New-Finding -Id "TEST-001" -Title "Test" -Description "Test" -Severity Low -Category "Test"
        Add-FindingObject -Finding $finding -Object "User123"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Finding,
        
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Object
    )
    
    $Finding.AffectedObjects += $Object
    $Finding.AffectedCount = $Finding.AffectedObjects.Count
}

function Add-FindingEvidence {
    <#
    .SYNOPSIS
        Adds evidence to a finding.
    
    .DESCRIPTION
        Appends evidence details to the finding's Evidence collection,
        including the source, detailed information, and confidence level.
    
    .PARAMETER Finding
        The finding object to modify.
    
    .PARAMETER Source
        The data source or cmdlet that provided this evidence.
    
    .PARAMETER Detail
        Detailed description of the evidence.
    
    .PARAMETER Confidence
        Confidence level in the evidence (Low, Medium, High). Default is Medium.
    
    .EXAMPLE
        Add-FindingEvidence -Finding $finding -Source "Get-MgUser" -Detail "Found 10 users" -Confidence "High"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Finding,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Source,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Detail,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Low", "Medium", "High")]
        [string]$Confidence = "Medium"
    )
    
    $Finding.Evidence += @{
        Source = $Source
        Detail = $Detail
        Confidence = $Confidence
        Timestamp = [datetime]::UtcNow
    }
}

# =============================================================================
# ENTRA ID CHECKS - MFA
# =============================================================================

function Invoke-EntraMfaRegistrationCheck {
    <#
    .SYNOPSIS
        Checks for users without MFA registered.
    
    .DESCRIPTION
        Retrieves all users and checks their authentication methods to
        identify accounts without MFA registration. These accounts are
        vulnerable to credential-based attacks.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = @{ Log = @{} }
        $findings = Invoke-EntraMfaRegistrationCheck -Context $context
    
    .OUTPUTS
        Array of finding objects for users without MFA.
    
    .NOTES
        Requires: Microsoft.Graph with User.Read.All and Policy.Read.All scopes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    try {
        Connect-MgGraph -Scopes "User.Read.All, Policy.Read.All" -ErrorAction Stop | Out-Null
        $users = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, CreatedDateTime -ErrorAction Stop
        
        $usersWithoutMfa = @()
        foreach ($user in $users) {
            $mfaMethods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
            if (-not $mfaMethods -or $mfaMethods.Count -eq 0) {
                $usersWithoutMfa += $user
            }
        }
        Disconnect-MgGraph | Out-Null
        
        if ($usersWithoutMfa.Count -gt 0) {
            $pct = [math]::Round(($usersWithoutMfa.Count / $users.Count) * 100, 1)
            $threshold = $script:DefaultThresholds.MfaRegistrationThreshold
            
            $f = New-Finding -Id "ENTRA-MFA-001" -Title "Users without MFA registered" `
                -Description "$($usersWithoutMfa.Count) of $($users.Count) users ($pct%) have no MFA methods registered" `
                -Severity $script:FindingSeverity.Critical -Category "Entra_MFARegistration"
            
            if ($pct -gt 20) { $f.Severity = $script:FindingSeverity.Critical }
            elseif ($pct -gt 10) { $f.Severity = $script:FindingSeverity.High }
            else { $f.Severity = $script:FindingSeverity.Medium }
            
            $f.CheckName = "MfaRegistrationCheck"
            $f.Remediation = "Enable MFA for all users via Conditional Access or Security Defaults."
            $f.RemediationSteps = @(
                "Enable Security Defaults (simplest option)",
                "Or create Conditional Access policy requiring MFA",
                "Exclude break-glass accounts",
                "Enable combined registration experience"
            )
            $f.RemediationUrl = "https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-userdevices"
            
            foreach ($u in $usersWithoutMfa | Select-Object -First 20) {
                Add-FindingObject -Finding $f -Object "$($u.DisplayName) ($($u.UserPrincipalName))"
            }
            if ($usersWithoutMfa.Count -gt 20) {
                Add-FindingObject -Finding $f -Object "... and $($usersWithoutMfa.Count - 20) more users"
            }
            Add-FindingEvidence -Finding $f -Source "Get-MgUserAuthenticationMethod" `
                -Detail "$($usersWithoutMfa.Count) users without MFA" -Confidence "High"
            $findings += $f
        }
    }
    catch {
        if ($Context) { $Context.Log("MFA check failed: $($_.Exception.Message)", "Error") }
        Write-Warning "MFA check failed: $($_.Exception.Message)"
    }
    return $findings
}

function Invoke-EntraMfaPolicyCheck {
    <#
    .SYNOPSIS
        Checks if MFA is required via Conditional Access.
    
    .DESCRIPTION
        Verifies that Conditional Access policies require multi-factor
        authentication for users. Missing MFA policies leave the
        organization vulnerable to credential attacks.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = @{ Log = @{} }
        $findings = Invoke-EntraMfaPolicyCheck -Context $context
    
    .OUTPUTS
        Array of finding objects for missing MFA policies.
    
    .NOTES
        Requires: Microsoft.Graph with ConditionalAccess.Read.All scope.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    try {
        Connect-MgGraph -Scopes "ConditionalAccess.Read.All" -ErrorAction Stop | Out-Null
        $policies = Get-MgIdentityConditionalAccessPolicy -ErrorAction Stop
        
        $mfaPolicies = $policies | Where-Object {
            $_.State -eq 'Enabled' -and $_.GrantControls -and
            ($_.GrantControls.BuiltInControls -contains 'mfa' -or $_.GrantControls.CustomControls)
        }
        
        # Check if any policy requires MFA for all users
        $comprehensiveMfa = $policies | Where-Object {
            $_.State -eq 'Enabled' -and $_.Conditions -and
            ($_.Conditions.Users -eq 'All') -and $_.GrantControls -and
            ($_.GrantControls.BuiltInControls -contains 'mfa')
        }
        
        $requiresPolicy = $script:DefaultThresholds.MfaPolicyRequired
        
        if ($requiresPolicy -and (-not $comprehensiveMfa) -and ($mfaPolicies.Count -eq 0)) {
            $f = New-Finding -Id "ENTRA-MFA-002" -Title "No comprehensive MFA policy found" `
                -Description "No Conditional Access policy requires MFA for all users" `
                -Severity $script:FindingSeverity.High -Category "Entra_MFAPolicy"
            $f.CheckName = "MfaPolicyCheck"
            $f.Remediation = "Create a Conditional Access policy requiring MFA for all users."
            $f.RemediationSteps = @(
                "Create new Conditional Access policy",
                "Apply to All users and All cloud apps",
                "Require MFA as grant control",
                "Enable in Report-only mode first",
                "Exclude break-glass accounts"
            )
            Add-FindingObject -Finding $f -Object "No comprehensive MFA policy"
            Add-FindingEvidence -Finding $f -Source "Get-MgIdentityConditionalAccessPolicy" `
                -Detail "0 MFA policies" -Confidence "High"
            $findings += $f
        }
        
        Disconnect-MgGraph | Out-Null
    }
    catch {
        if ($Context) { $Context.Log("MFA policy check failed: $($_.Exception.Message)", "Error") }
    }
    return $findings
}

# =============================================================================
# ENTRA ID CHECKS - PRIVILEGED ACCESS
# =============================================================================

function Invoke-EntraPermanentAdminCheck {
    <#
    .SYNOPSIS
        Checks for permanent privileged role assignments.
    
    .DESCRIPTION
        Identifies directory role assignments that are permanently active
        rather than eligible through Privileged Identity Management (PIM).
        Permanent assignments increase the attack surface.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = @{ Log = @{} }
        $findings = Invoke-EntraPermanentAdminCheck -Context $context
    
    .OUTPUTS
        Array of finding objects for permanent admin assignments.
    
    .NOTES
        Requires: Microsoft.Graph with RoleManagement.Read.Directory scope.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    $threshold = $script:DefaultThresholds.PermanentAdminThreshold
    
    try {
        Connect-MgGraph -Scopes "RoleManagement.Read.Directory" -ErrorAction Stop | Out-Null
        
        $roles = Get-MgDirectoryRole -ErrorAction Stop
        foreach ($role in $roles) {
            $assignments = Get-MgDirectoryRoleAssignment -DirectoryRoleId $role.Id -ErrorAction Stop | Where-Object {
                $_.AssignmentState -eq 'Active' -and -not $_.EndDateTime
            }
            
            if ($assignments.Count -gt $threshold) {
                $f = New-Finding -Id "ENTRA-PIM-001" -Title "Permanent $($role.DisplayName) assignments" `
                    -Description "$($assignments.Count) users have permanent $($role.DisplayName) role instead of eligible/just-in-time" `
                    -Severity $script:FindingSeverity.High -Category "Entra_PrivilegedAccess"
                $f.CheckName = "PermanentAdminCheck"
                $f.Remediation = "Enable Privileged Identity Management for this role."
                $f.RemediationSteps = @(
                    "Enable PIM for $($role.DisplayName)",
                    "Convert permanent assignments to eligible",
                    "Set activation duration and approval",
                    "Require MFA for activation",
                    "Configure alerting"
                )
                foreach ($a in $assignments | Select-Object -First 10) {
                    Add-FindingObject -Finding $f -Object $a.DisplayName
                }
                if ($assignments.Count -gt 10) {
                    Add-FindingObject -Finding $f -Object "... and $($assignments.Count - 10) more"
                }
                Add-FindingEvidence -Finding $f -Source "Get-MgDirectoryRoleAssignment" `
                    -Detail "$($assignments.Count) permanent assignments" -Confidence "High"
                $findings += $f
            }
        }
        
        Disconnect-MgGraph | Out-Null
    }
    catch {
        if ($Context) { $Context.Log("PIM check failed: $($_.Exception.Message)", "Error") }
    }
    return $findings
}

function Invoke-EntraHighPrivilegeRoleCheck {
    <#
    .SYNOPSIS
        Checks for assignments to highest privilege roles.
    
    .DESCRIPTION
        Identifies users with highly privileged roles like Global Administrator,
        Privileged Role Administrator, and other critical roles that grant
        extensive access across the tenant.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = @{ Log = @{} }
        $findings = Invoke-EntraHighPrivilegeRoleCheck -Context $context
    
    .OUTPUTS
        Array of finding objects for high-privilege role assignments.
    
    .NOTES
        Requires: Microsoft.Graph with RoleManagement.Read.Directory scope.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    try {
        Connect-MgGraph -Scopes "RoleManagement.Read.Directory" -ErrorAction Stop | Out-Null
        
        $criticalRoles = @(
            "Global Administrator",
            "Privileged Role Administrator",
            "Security Administrator",
            "Exchange Administrator",
            "SharePoint Administrator",
            "User Administrator",
            "Billing Administrator"
        )
        
        $allAssignments = @()
        $roles = Get-MgDirectoryRole -ErrorAction Stop
        foreach ($role in $roles) {
            if ($role.DisplayName -in $criticalRoles) {
                $assignments = Get-MgDirectoryRoleAssignment -DirectoryRoleId $role.Id -ErrorAction Stop
                foreach ($a in $assignments) {
                    $allAssignments += @{ Role = $role.DisplayName; User = $a.DisplayName }
                }
            }
        }
        
        $threshold = $script:DefaultThresholds.HighPrivRoleCount
        
        if ($allAssignments.Count -gt $threshold) {
            $f = New-Finding -Id "ENTRA-PRIV-001" -Title "High-privilege role assignments found" `
                -Description "$($allAssignments.Count) users have critical role assignments" `
                -Severity $script:FindingSeverity.Medium -Category "Entra_PrivilegedAccess"
            $f.CheckName = "HighPrivilegeRoleCheck"
            $f.Remediation = "Review and reduce high-privilege role assignments. Use least-privilege."
            $f.RemediationSteps = @(
                "Review all $($criticalRoles -join ', ') assignments",
                "Remove unnecessary permanent assignments",
                "Enable PIM for all critical roles",
                "Implement tiered admin model",
                "Monthly access reviews"
            )
            foreach ($a in $allAssignments | Select-Object -First 15) {
                Add-FindingObject -Finding $f -Object "$($a.User) -> $($a.Role)"
            }
            if ($allAssignments.Count -gt 15) {
                Add-FindingObject -Finding $f -Object "... and $($allAssignments.Count - 15) more"
            }
            Add-FindingEvidence -Finding $f -Source "Get-MgDirectoryRoleAssignment" `
                -Detail "$($allAssignments.Count) critical role assignments" -Confidence "High"
            $findings += $f
        }
        
        Disconnect-MgGraph | Out-Null
    }
    catch {
        if ($Context) { $Context.Log("High privilege check failed: $($_.Exception.Message)", "Error") }
    }
    return $findings
}

# =============================================================================
# ENTRA ID CHECKS - GUEST USERS
# =============================================================================

function Invoke-EntraGuestUserCheck {
    <#
    .SYNOPSIS
        Checks for guest user proliferation and access.
    
    .DESCRIPTION
        Identifies excessive guest users in the tenant and checks for
        guest users in privileged groups, which represents a significant
        security risk.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = @{ Log = @{} }
        $findings = Invoke-EntraGuestUserCheck -Context $context
    
    .OUTPUTS
        Array of finding objects for guest user issues.
    
    .NOTES
        Requires: Microsoft.Graph with User.Read.All and GroupMember.Read.All scopes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    $guestLimit = $script:DefaultThresholds.GuestUserLimit
    
    try {
        Connect-MgGraph -Scopes "User.Read.All, GroupMember.Read.All" -ErrorAction Stop | Out-Null
        
        $allUsers = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, UserType -ErrorAction Stop
        $guests = $allUsers | Where-Object { $_.UserType -eq 'Guest' }
        
        if ($guests.Count -gt $guestLimit) {
            $pct = [math]::Round(($guests.Count / $allUsers.Count) * 100, 1)
            $f = New-Finding -Id "ENTRA-GUEST-001" -Title "High number of guest users" `
                -Description "$($guests.Count) guest users ($pct% of total) in the tenant" `
                -Severity $script:FindingSeverity.Medium -Category "Entra_GuestAccess"
            $f.CheckName = "GuestUserCheck"
            $f.Remediation = "Review and reduce guest user access. Implement guest access reviews."
            $f.RemediationSteps = @(
                "Run guest access review in Azure AD Access Reviews",
                "Remove guests no longer needing access",
                "Configure guest restrictions in Conditional Access",
                "Set guest invite restrictions",
                "Review B2B collaboration settings"
            )
            Add-FindingObject -Finding $f -Object "$($guests.Count) guest users"
            Add-FindingEvidence -Finding $f -Source "Get-MgUser" `
                -Detail "$($guests.Count) guests, $($allUsers.Count) total users" -Confidence "Medium"
            $findings += $f
        }
        
        # Check for guests in privileged groups
        $privilegedGroups = @("Global Administrators", "Privileged Role Administrators", "Security Administrators")
        $guestPrivThreshold = $script:DefaultThresholds.GuestInPrivGroupThreshold
        
        foreach ($groupName in $privilegedGroups) {
            $group = Get-MgGroup -Filter "DisplayName eq '$groupName'" -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($group) {
                $members = Get-MgGroupMember -GroupId $group.Id -All -ErrorAction Stop
                $guestMembers = $members | Where-Object { $_.AdditionalProperties.userType -eq 'Guest' }
                if ($guestMembers.Count -gt $guestPrivThreshold) {
                    $f2 = New-Finding -Id "ENTRA-GUEST-002" -Title "Guest user in $($groupName)" `
                        -Description "$($guestMembers.Count) guest users are members of $groupName" `
                        -Severity $script:FindingSeverity.Critical -Category "Entra_GuestAccess"
                    $f2.CheckName = "GuestInPrivilegeGroupCheck"
                    $f2.Remediation = "Remove guest users from privileged groups immediately."
                    $f2.RemediationSteps = @(
                        "Identify guest members of $groupName",
                        "Remove from group immediately",
                        "Create equivalent account in home tenant",
                        "Configure guest restrictions"
                    )
                    foreach ($g in $guestMembers) {
                        Add-FindingObject -Finding $f2 -Object $g.DisplayName
                    }
                    Add-FindingEvidence -Finding $f2 -Source "Get-MgGroupMember" `
                        -Detail "Guests in privileged group" -Confidence "High"
                    $findings += $f2
                }
            }
        }
        
        Disconnect-MgGraph | Out-Null
    }
    catch {
        if ($Context) { $Context.Log("Guest check failed: $($_.Exception.Message)", "Error") }
    }
    return $findings
}

# =============================================================================
# ENTRA ID CHECKS - APPLICATION REGISTRATIONS
# =============================================================================

function Invoke-EntraAppRegistrationCheck {
    <#
    .SYNOPSIS
        Checks for application security issues.
    
    .DESCRIPTION
        Analyzes application registrations for excessive permissions and
        application (admin consent) permissions that may pose security risks.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = @{ Log = @{} }
        $findings = Invoke-EntraAppRegistrationCheck -Context $context
    
    .OUTPUTS
        Array of finding objects for application security issues.
    
    .NOTES
        Requires: Microsoft.Graph with Application.Read.All and AppRoleAssignment.Read.All scopes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    $permissionLimit = $script:DefaultThresholds.AppPermissionLimit
    
    try {
        Connect-MgGraph -Scopes "Application.Read.All, AppRoleAssignment.Read.All" -ErrorAction Stop | Out-Null
        
        $apps = Get-MgApplication -All -Property Id, DisplayName, AppId, RequiredResourceAccess -ErrorAction Stop
        
        # Check for apps with excessive permissions
        $highPermissionApps = @()
        foreach ($app in $apps) {
            if ($app.RequiredResourceAccess) {
                $totalPerms = ($app.RequiredResourceAccess | Measure-Object).Count
                if ($totalPerms -gt $permissionLimit) {
                    $highPermissionApps += @{ App = $app.DisplayName; Perms = $totalPerms }
                }
            }
        }
        
        if ($highPermissionApps.Count -gt 0) {
            $f = New-Finding -Id "ENTRA-APP-001" -Title "Applications with excessive permissions" `
                -Description "$($highPermissionApps.Count) applications request more than $permissionLimit permissions" `
                -Severity $script:FindingSeverity.Low -Category "Entra_ApplicationSecurity"
            $f.CheckName = "AppRegistrationCheck"
            $f.Remediation = "Review application permissions and apply least-privilege principle."
            $f.RemediationSteps = @(
                "Review each application's required permissions",
                "Remove unnecessary delegated and application permissions",
                "Use Microsoft Graph permissions instead of Azure AD Graph",
                "Document permission justification"
            )
            foreach ($a in $highPermissionApps | Select-Object -First 10) {
                Add-FindingObject -Finding $f -Object "$($a.App) ($($a.Perms) permissions)"
            }
            if ($highPermissionApps.Count -gt 10) {
                Add-FindingObject -Finding $f -Object "... and $($highPermissionApps.Count - 10) more"
            }
            Add-FindingEvidence -Finding $f -Source "Get-MgApplication" `
                -Detail "$($highPermissionApps.Count) high-permission apps" -Confidence "Medium"
            $findings += $f
        }
        
        # Check for apps with admin consent granted
        $appsWithConsent = $apps | Where-Object {
            $_.RequiredResourceAccess -and
            ($_.RequiredResourceAccess | Where-Object { $_.ResourceAccess -and
                ($_.ResourceAccess | Where-Object { $_.Type -eq 'Role' }) })
        }
        
        $consentThreshold = $script:DefaultThresholds.AppConsentThreshold
        
        if ($appsWithConsent.Count -gt $consentThreshold) {
            $f2 = New-Finding -Id "ENTRA-APP-002" -Title "Applications with application permissions" `
                -Description "$($appsWithConsent.Count) applications have application permissions (admin consent required)" `
                -Severity $script:FindingSeverity.Medium -Category "Entra_ApplicationSecurity"
            $f2.CheckName = "AppConsentCheck"
            $f2.Remediation = "Review and revoke unnecessary application permissions."
            $f2.RemediationSteps = @(
                "Review all applications with application permissions",
                "Verify business justification",
                "Remove unnecessary app-only access",
                "Use delegated permissions with user context when possible"
            )
            foreach ($a in $appsWithConsent | Select-Object -First 10) {
                Add-FindingObject -Finding $f2 -Object $a.DisplayName
            }
            $findings += $f2
        }
        
        Disconnect-MgGraph | Out-Null
    }
    catch {
        if ($Context) { $Context.Log("App registration check failed: $($_.Exception.Message)", "Error") }
    }
    return $findings
}

function Invoke-EntraServicePrincipalCheck {
    <#
    .SYNOPSIS
        Checks for service principal security issues.
    
    .DESCRIPTION
        Identifies disabled service principals that still have active
        credentials, representing a security risk and potential attack vector.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = @{ Log = @{} }
        $findings = Invoke-EntraServicePrincipalCheck -Context $context
    
    .OUTPUTS
        Array of finding objects for service principal issues.
    
    .NOTES
        Requires: Microsoft.Graph with Application.Read.All scope.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    try {
        Connect-MgGraph -Scopes "Application.Read.All" -ErrorAction Stop | Out-Null
        
        $sp = Get-MgServicePrincipal -All -Property Id, DisplayName, AppId, AccountEnabled -ErrorAction Stop
        
        # Check for disabled service principals with key credentials
        $disabledWithKeys = $sp | Where-Object {
            $_.AccountEnabled -eq $false -and
            ($_.KeyCredentials.Count -gt 0 -or $_.PasswordCredentials.Count -gt 0)
        }
        
        if ($disabledWithKeys.Count -gt 0) {
            $f = New-Finding -Id "ENTRA-SP-001" -Title "Disabled service principals with active credentials" `
                -Description "$($disabledWithKeys.Count) disabled service principals still have active key/password credentials" `
                -Severity $script:FindingSeverity.High -Category "Entra_ServicePrincipalSecurity"
            $f.CheckName = "ServicePrincipalCheck"
            $f.Remediation = "Remove credentials from disabled service principals."
            $f.RemediationSteps = @(
                "Identify disabled service principals",
                "Remove key and password credentials",
                "Delete service principals if no longer needed",
                "Audit service principals quarterly"
            )
            foreach ($s in $disabledWithKeys | Select-Object -First 10) {
                Add-FindingObject -Finding $f -Object $s.DisplayName
            }
            Add-FindingEvidence -Finding $f -Source "Get-MgServicePrincipal" `
                -Detail "$($disabledWithKeys.Count) disabled SPs" -Confidence "High"
            $findings += $f
        }
        
        Disconnect-MgGraph | Out-Null
    }
    catch {
        if ($Context) { $Context.Log("Service principal check failed: $($_.Exception.Message)", "Error") }
    }
    return $findings
}

# =============================================================================
# ENTRA ID CHECKS - AUTHENTICATION
# =============================================================================

function Invoke-EntraLegacyAuthCheck {
    <#
    .SYNOPSIS
        Checks if legacy authentication is blocked.
    
    .DESCRIPTION
        Verifies that Conditional Access policies block legacy authentication
        methods like Exchange ActiveSync and Basic Auth, which can bypass MFA.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = @{ Log = @{} }
        $findings = Invoke-EntraLegacyAuthCheck -Context $context
    
    .OUTPUTS
        Array of finding objects for missing legacy auth blocking.
    
    .NOTES
        Requires: Microsoft.Graph with ConditionalAccess.Read.All scope.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    try {
        Connect-MgGraph -Scopes "ConditionalAccess.Read.All" -ErrorAction Stop | Out-Null
        
        $policies = Get-MgIdentityConditionalAccessPolicy -ErrorAction Stop
        
        # Check for legacy auth blocking
        $blocksLegacy = $policies | Where-Object {
            $_.State -eq 'Enabled' -and $_.Conditions -and $_.Conditions.ClientApplications -and
            ($_.Conditions.ClientApplications -contains 'exchangeActiveSync' -or
             $_.Conditions.ClientApplications -contains 'otherClients' -or
             $_.Conditions.Applications -contains 'all')
        }
        
        if (-not $blocksLegacy -and $policies.Count -gt 0) {
            $f = New-Finding -Id "ENTRA-AUTH-001" -Title "Legacy authentication not blocked" `
                -Description "No Conditional Access policy blocks legacy authentication (Exchange ActiveSync, Basic auth)" `
                -Severity $script:FindingSeverity.High -Category "Entra_AuthenticationSecurity"
            $f.CheckName = "LegacyAuthCheck"
            $f.Remediation = "Create Conditional Access policy to block legacy authentication."
            $f.RemediationSteps = @(
                "Create new Conditional Access policy",
                "Target all users and all cloud apps",
                "Block access for 'Other clients' and 'Exchange ActiveSync'",
                "Enable in Report-only mode first",
                "Monitor sign-in logs for legacy auth usage",
                "Plan phased rollout"
            )
            Add-FindingObject -Finding $f -Object "Legacy auth not blocked"
            Add-FindingEvidence -Finding $f -Source "Get-MgIdentityConditionalAccessPolicy" `
                -Detail "No blocking policy" -Confidence "High"
            $findings += $f
        }
        
        Disconnect-MgGraph | Out-Null
    }
    catch {
        if ($Context) { $Context.Log("Legacy auth check failed: $($_.Exception.Message)", "Error") }
    }
    return $findings
}

function Invoke-EntraPasswordWritebackCheck {
    <#
    .SYNOPSIS
        Checks if password writeback is enabled.
    
    .DESCRIPTION
        Verifies that Azure AD Connect is configured for password writeback,
        which allows password changes in the cloud to be written back to on-premises AD.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = @{ Log = @{} }
        $findings = Invoke-EntraPasswordWritebackCheck -Context $context
    
    .OUTPUTS
        Array of finding objects for missing password writeback.
    
    .NOTES
        Requires: Microsoft.Graph with appropriate scopes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    try {
        Connect-MgDirectoryConfiguration -ErrorAction Stop | Out-Null
        
        $config = Get-MgDirectoryConfiguration -ErrorAction Stop
        $directorySettings = $config | Where-Object { $_.DisplayName -eq 'Directory Settings' }
        
        $writebackEnabled = $false
        if ($directorySettings -and $directorySettings.Settings) {
            $setting = $directorySettings.Settings | Where-Object { $_.Name -eq 'EnableCloudPasswordWriteback' }
            if ($setting -and $setting.Value -eq 'True') {
                $writebackEnabled = $true
            }
        }
        
        if (-not $writebackEnabled) {
            $f = New-Finding -Id "ENTRA-AUTH-002" -Title "Password writeback not enabled" `
                -Description "Azure AD Connect is not configured for password writeback" `
                -Severity $script:FindingSeverity.Low -Category "Entra_AuthenticationSecurity"
            $f.CheckName = "PasswordWritebackCheck"
            $f.Remediation = "Enable password writeback in Azure AD Connect."
            $f.RemediationSteps = @(
                "Open Azure AD Connect",
                "Navigate to Optional Features",
                "Enable Password writeback",
                "Verify configuration in Azure AD"
            )
            Add-FindingObject -Finding $f -Object "Password writeback disabled"
            Add-FindingEvidence -Finding $f -Source "Get-MgDirectoryConfiguration" `
                -Detail "Writeback not enabled" -Confidence "Medium"
            $findings += $f
        }
        
        Disconnect-MgGraph | Out-Null
    }
    catch {
        if ($Context) { $Context.Log("Password writeback check failed: $($_.Exception.Message)", "Warning") }
        # This check may fail due to permissions, not a finding
    }
    return $findings
}

# =============================================================================
# ENTRA ID CHECKS - SIGN-IN & RISK
# =============================================================================

function Invoke-EntraSignInRiskPolicyCheck {
    <#
    .SYNOPSIS
        Checks for Identity Protection risk policies.
    
    .DESCRIPTION
        Verifies that sign-in risk and user risk-based Conditional Access
        policies are configured to respond to detected risks.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = @{ Log = @{} }
        $findings = Invoke-EntraSignInRiskPolicyCheck -Context $context
    
    .OUTPUTS
        Array of finding objects for missing risk policies.
    
    .NOTES
        Requires: Microsoft.Graph with Policy.Read.All scope.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    try {
        Connect-MgGraph -Scopes "Policy.Read.All" -ErrorAction Stop | Out-Null
        
        $signInRiskPolicies = Get-MgIdentityProtectionSignInPolicy -ErrorAction SilentlyContinue
        $userRiskPolicies = Get-MgIdentityProtectionUserRiskPolicy -ErrorAction SilentlyContinue
        
        if (-not $signInRiskPolicies -or $signInRiskPolicies.Count -eq 0) {
            $f = New-Finding -Id "ENTRA-RISK-001" -Title "No sign-in risk policy configured" `
                -Description "No sign-in risk-based Conditional Access policy is configured" `
                -Severity $script:FindingSeverity.Medium -Category "Entra_RiskManagement"
            $f.CheckName = "SignInRiskPolicyCheck"
            $f.Remediation = "Configure sign-in risk-based Conditional Access policy."
            $f.RemediationSteps = @(
                "Enable Azure AD Identity Protection",
                "Create Conditional Access policy based on sign-in risk",
                "Require MFA for medium and high risk",
                "Block access for high risk"
            )
            Add-FindingObject -Finding $f -Object "No sign-in risk policy"
            Add-FindingEvidence -Finding $f -Source "Get-MgIdentityProtectionSignInPolicy" `
                -Detail "No policies" -Confidence "Medium"
            $findings += $f
        }
        
        if (-not $userRiskPolicies -or $userRiskPolicies.Count -eq 0) {
            $f2 = New-Finding -Id "ENTRA-RISK-002" -Title "No user risk policy configured" `
                -Description "No user risk-based Conditional Access policy is configured" `
                -Severity $script:FindingSeverity.Medium -Category "Entra_RiskManagement"
            $f2.CheckName = "UserRiskPolicyCheck"
            $f2.Remediation = "Configure user risk-based Conditional Access policy."
            $f2.RemediationSteps = @(
                "Enable Azure AD Identity Protection",
                "Create Conditional Access policy based on user risk",
                "Require password change for high risk"
            )
            Add-FindingObject -Finding $f2 -Object "No user risk policy"
            $findings += $f2
        }
        
        Disconnect-MgGraph | Out-Null
    }
    catch {
        if ($Context) { $Context.Log("Risk policy check failed: $($_.Exception.Message)", "Error") }
    }
    return $findings
}

# =============================================================================
# ENTRA ID CHECKS - ADMIN CONSENT
# =============================================================================

function Invoke-EntraAdminConsentCheck {
    <#
    .SYNOPSIS
        Checks for admin consent workflow configuration.
    
    .DESCRIPTION
        Verifies that admin consent is required for applications requesting
        sensitive permissions, preventing users from granting excessive access.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = @{ Log = @{} }
        $findings = Invoke-EntraAdminConsentCheck -Context $context
    
    .OUTPUTS
        Array of finding objects for missing admin consent requirements.
    
    .NOTES
        Requires: Microsoft.Graph with Policy.Read.All scope.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    try {
        Connect-MgGraph -Scopes "Policy.Read.All" -ErrorAction Stop | Out-Null
        
        $consentSettings = Get-MgPolicyConsentPolicy -ErrorAction SilentlyContinue
        
        $requiresAdminConsent = $false
        if ($consentSettings) {
            $requiresAdminConsent = $consentSettings.AllowedToConsent -eq $false
        }
        
        if (-not $requiresAdminConsent) {
            $f = New-Finding -Id "ENTRA-CONSENT-001" -Title "Admin consent not required for all apps" `
                -Description "Users may be able to consent to applications without admin approval" `
                -Severity $script:FindingSeverity.Low -Category "Entra_ConsentManagement"
            $f.CheckName = "AdminConsentCheck"
            $f.Remediation = "Configure admin consent workflow for sensitive permissions."
            $f.RemediationSteps = @(
                "Review current consent settings",
                "Enable 'Admin consent request' workflow",
                "Require admin consent for sensitive permissions",
                "Notify admins when new apps request consent"
            )
            Add-FindingObject -Finding $f -Object "Users can consent to apps"
            Add-FindingEvidence -Finding $f -Source "Get-MgPolicyConsentPolicy" `
                -Detail "Consent policy not restrictive" -Confidence "Medium"
            $findings += $f
        }
        
        Disconnect-MgGraph | Out-Null
    }
    catch {
        if ($Context) { $Context.Log("Admin consent check failed: $($_.Exception.Message)", "Error") }
    }
    return $findings
}

# =============================================================================
# ENTRA ID CHECKS - EXTERNAL COLLABORATION
# =============================================================================

function Invoke-EntraB2BCollaborationCheck {
    <#
    .SYNOPSIS
        Checks for B2B collaboration settings.
    
    .DESCRIPTION
        Verifies that guest invitation settings are appropriately restricted
        to prevent unauthorized external user creation.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = @{ Log = @{} }
        $findings = Invoke-EntraB2BCollaborationCheck -Context $context
    
    .OUTPUTS
        Array of finding objects for B2B collaboration issues.
    
    .NOTES
        Requires: Microsoft.Graph with Policy.Read.All scope.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    try {
        Connect-MgGraph -Scopes "Policy.Read.All" -ErrorAction Stop | Out-Null
        
        $orgSettings = Get-MgOrganization -ErrorAction Stop | Select-Object -First 1
        
        # Check B2B settings
        $b2bSettings = $orgSettings.AllowInvites
        $allowExternalUsers = $b2bSettings -eq 'True'
        
        # Check for unrestricted external collaboration
        $inviteGuests = $orgSettings.InviteGuestsEnabled
        
        if ($inviteGuests -eq 'True') {
            $f = New-Finding -Id "ENTRA-B2B-001" -Title "Guest invitations enabled for all users" `
                -Description "Any user can invite guest users without restriction" `
                -Severity $script:FindingSeverity.Low -Category "Entra_ExternalCollaboration"
            $f.CheckName = "B2BCollaborationCheck"
            $f.Remediation = "Restrict guest invitations to specific users or groups."
            $f.RemediationSteps = @(
                "Enable 'Member can invite' setting only",
                "Configure guest invite restrictions",
                "Require justification for guest invitations",
                "Set up guest access reviews"
            )
            Add-FindingObject -Finding $f -Object "Anyone can invite guests"
            Add-FindingEvidence -Finding $f -Source "Get-MgOrganization" `
                -Detail "Guest inviting enabled" -Confidence "Medium"
            $findings += $f
        }
        
        Disconnect-MgGraph | Out-Null
    }
    catch {
        if ($Context) { $Context.Log("B2B check failed: $($_.Exception.Message)", "Error") }
    }
    return $findings
}

# =============================================================================
# ENTRA ID CHECKS - DEVICE MANAGEMENT
# =============================================================================

function Invoke-EntraDeviceManagementCheck {
    <#
    .SYNOPSIS
        Checks for device management configuration.
    
    .DESCRIPTION
        Identifies registered devices that haven't signed in for an extended
        period, indicating stale devices that should be reviewed or removed.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = @{ Log = @{} }
        $findings = Invoke-EntraDeviceManagementCheck -Context $context
    
    .OUTPUTS
        Array of finding objects for inactive devices.
    
    .NOTES
        Requires: Microsoft.Graph with Device.Read.All and Policy.Read.All scopes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    $inactiveDays = $script:DefaultThresholds.DeviceInactivityDays
    
    try {
        Connect-MgGraph -Scopes "Device.Read.All, Policy.Read.All" -ErrorAction Stop | Out-Null
        
        $devices = Get-MgDevice -All -Property Id, DisplayName, ApproximateLastSignInDateTime -ErrorAction Stop
        $registeredDevices = $devices | Where-Object { $_.DeviceId }
        
        $inactiveDevices = $registeredDevices | Where-Object {
            $_.ApproximateLastSignInDateTime -and
            $_.ApproximateLastSignInDateTime -lt (Get-Date).AddDays(-$inactiveDays)
        }
        
        if ($inactiveDevices.Count -gt 0) {
            $f = New-Finding -Id "ENTRA-DEV-001" -Title "Inactive registered devices" `
                -Description "$($inactiveDevices.Count) devices haven't signed in for $inactiveDays+ days" `
                -Severity $script:FindingSeverity.Low -Category "Entra_DeviceManagement"
            $f.CheckName = "DeviceManagementCheck"
            $f.Remediation = "Remove or disable stale devices."
            $f.RemediationSteps = @(
                "Export list of inactive devices",
                "Contact device owners for status",
                "Remove devices no longer in use",
                "Configure automatic device cleanup"
            )
            foreach ($d in $inactiveDevices | Select-Object -First 10) {
                Add-FindingObject -Finding $f -Object $d.DisplayName
            }
            Add-FindingEvidence -Finding $f -Source "Get-MgDevice" `
                -Detail "$($inactiveDevices.Count) inactive devices" -Confidence "Medium"
            $findings += $f
        }
        
        Disconnect-MgGraph | Out-Null
    }
    catch {
        if ($Context) { $Context.Log("Device management check failed: $($_.Exception.Message)", "Error") }
    }
    return $findings
}

# =============================================================================
# ENTRA ID CHECKS - DOMAIN SECURITY
# =============================================================================

function Invoke-EntraDomainSecurityCheck {
    <#
    .SYNOPSIS
        Checks for federated domain security.
    
    .DESCRIPTION
        Verifies that federated domains require MFA for authentication,
        preventing federated users from bypassing cloud-based security controls.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = @{ Log = @{} }
        $findings = Invoke-EntraDomainSecurityCheck -Context $context
    
    .OUTPUTS
        Array of finding objects for federated domain security issues.
    
    .NOTES
        Requires: Microsoft.Graph with Domain.Read.All scope.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    try {
        Connect-MgGraph -Scopes "Domain.Read.All" -ErrorAction Stop | Out-Null
        
        $domains = Get-MgDomain -ErrorAction Stop
        
        foreach ($domain in $domains) {
            # Check for federated domains
            if ($domain.IsVerified -and $domain.AuthenticationType -eq 'Federated') {
                $federationSettings = Get-MgDomainFederationConfiguration -DomainId $domain.Id -ErrorAction SilentlyContinue
                
                if ($federationSettings) {
                    foreach ($fs in $federationSettings) {
                        # Check if MFA is required for federation
                        if (-not $fs.IsMfaEnabled) {
                            $f = New-Finding -Id "ENTRA-DOM-001" -Title "Federation without MFA required: $($domain.Id)" `
                                -Description "Federated domain $($domain.Id) does not require MFA for federation users" `
                                -Severity $script:FindingSeverity.High -Category "Entra_DomainSecurity"
                            $f.CheckName = "DomainSecurityCheck"
                            $f.Remediation = "Enable MFA requirement in federation settings or move to Passthrough/PTA."
                            $f.RemediationSteps = @(
                                "Review federation configuration",
                                "Enable 'Require MFA' in ADFS or IdP",
                                "Consider migrating to Passthrough Authentication",
                                "Monitor federated sign-ins"
                            )
                            Add-FindingObject -Finding $f -Object $domain.Id
                            Add-FindingEvidence -Finding $f -Source "Get-MgDomainFederationConfiguration" `
                                -Detail "MFA not required" -Confidence "High"
                            $findings += $f
                        }
                    }
                }
            }
        }
        
        Disconnect-MgGraph | Out-Null
    }
    catch {
        if ($Context) { $Context.Log("Domain security check failed: $($_.Exception.Message)", "Error") }
    }
    return $findings
}

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

function Invoke-EntraSecurityAssessment {
    <#
    .SYNOPSIS
        Runs comprehensive Entra ID security assessment.
    
    .DESCRIPTION
        Main entry point for the Entra ID security assessment module.
        Executes all enabled security checks and generates a comprehensive report.
    
    .PARAMETER OutputDir
        Directory path for output files. Default is ".\Entra-Security-Output".
    
    .PARAMETER Format
        Output format: Console or Json. Default is Console.
    
    .PARAMETER CriticalThreshold
        Number of critical findings to trigger Critical status. Default is 1.
    
    .PARAMETER HighThreshold
        Number of high findings to trigger Warning status. Default is 5.
    
    .PARAMETER SkipMFA
        Skip MFA-related checks.
    
    .PARAMETER SkipPrivilegedAccess
        Skip privileged access checks.
    
    .PARAMETER SkipGuestUsers
        Skip guest user checks.
    
    .PARAMETER SkipApplications
        Skip application registration checks.
    
    .PARAMETER SkipAuthentication
        Skip authentication checks.
    
    .PARAMETER SkipRisk
        Skip risk management checks.
    
    .PARAMETER SkipAll
        Skip all checks.
    
    .PARAMETER Help
        Display help information and exit.
    
    .EXAMPLE
        Invoke-EntraSecurityAssessment -Format All -OutputDir ".\Results"
    
    .EXAMPLE
        Invoke-EntraSecurityAssessment -SkipMFA -SkipGuestUsers
    
    .OUTPUTS
        Hashtable containing the assessment results.
    
    .NOTES
        Requires: Microsoft.Graph module with appropriate permissions.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, HelpMessage = "Output directory for reports")]
        [ValidateNotNullOrEmpty()]
        [string]$OutputDir = ".\Entra-Security-Output",
        
        [Parameter(Mandatory = $false, HelpMessage = "Output format")]
        [ValidateSet('Console', 'Json')]
        [string]$Format = 'Console',
        
        [Parameter(Mandatory = $false, HelpMessage = "Critical findings threshold")]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$CriticalThreshold = 1,
        
        [Parameter(Mandatory = $false, HelpMessage = "High findings threshold")]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$HighThreshold = 5,
        
        [Parameter(Mandatory = $false, HelpMessage = "Skip MFA checks")]
        [switch]$SkipMFA,
        
        [Parameter(Mandatory = $false, HelpMessage = "Skip privileged access checks")]
        [switch]$SkipPrivilegedAccess,
        
        [Parameter(Mandatory = $false, HelpMessage = "Skip guest user checks")]
        [switch]$SkipGuestUsers,
        
        [Parameter(Mandatory = $false, HelpMessage = "Skip application checks")]
        [switch]$SkipApplications,
        
        [Parameter(Mandatory = $false, HelpMessage = "Skip authentication checks")]
        [switch]$SkipAuthentication,
        
        [Parameter(Mandatory = $false, HelpMessage = "Skip risk management checks")]
        [switch]$SkipRisk,
        
        [Parameter(Mandatory = $false, HelpMessage = "Skip all checks")]
        [switch]$SkipAll,
        
        [Parameter(Mandatory = $false, HelpMessage = "Display help information")]
        [switch]$Help
    )
    
    if ($Help) {
        Write-Host @"
IdentityFirst QuickChecks - Entra ID Security Assessment
=====================================================
Comprehensive Entra ID security checks including MFA, PIM, Conditional Access,
guest users, application registrations, and authentication security.

USAGE:
    Invoke-EntraSecurityAssessment [-OutputDir <path>] [-Format <format>]
                                   [-CriticalThreshold <n>] [-HighThreshold <n>]
                                   [-SkipMFA] [-SkipPrivilegedAccess] [-SkipGuestUsers]
                                   [-SkipApplications] [-SkipAuthentication] [-SkipRisk]
                                   [-SkipAll] [-Help]

CHECK CATEGORIES:
    MFA:                  MFA registration, MFA policies
    Privileged Access:    PIM, high-privilege roles
    Guest Users:          Guest proliferation, guests in privileged groups
    Applications:         App registrations, service principals
    Authentication:      Legacy auth, password writeback
    Risk:                 Sign-in risk policies, user risk policies
    Device Management:    Stale devices
    Domain Security:      Federated domain MFA

PARAMETERS:
    -OutputDir           Output directory (default: .\Entra-Security-Output)
    -Format              Console or JSON output (default: Console)
    -CriticalThreshold   Critical findings for Critical status (default: 1)
    -HighThreshold       High findings for Warning status (default: 5)
    -SkipMFA             Skip MFA checks
    -SkipPrivilegedAccess Skip privileged access checks
    -SkipGuestUsers      Skip guest user checks
    -SkipApplications    Skip application checks
    -SkipAuthentication  Skip authentication checks
    -SkipRisk            Skip risk management checks
    -SkipAll             Skip all checks
    -Help                Show this help message

EXIT CODES:
    0 = Healthy
    1 = Warning
    2 = Critical
    3 = Error

REQUIREMENTS:
    - PowerShell 5.1+
    - Microsoft.Graph module with appropriate scopes
"@
        return
    }
    
    Write-Host "`n" -ForegroundColor Cyan
    Write-Host "  IdentityFirst QuickChecks - Entra ID Security Assessment                  " -ForegroundColor Cyan
    Write-Host "" -ForegroundColor Cyan
    
    $context = @{ Configuration = @{}; Log = @(); StartTime = [datetime]::UtcNow }
    
    $allFindings = @()
    
    if (-not $SkipAll -and -not $SkipMFA) {
        Write-Host "`n[ENTRA-MFA] Checking MFA configuration..." -ForegroundColor Yellow
        $allFindings += Invoke-EntraMfaRegistrationCheck -Context $context
        $allFindings += Invoke-EntraMfaPolicyCheck -Context $context
    }
    
    if (-not $SkipAll -and -not $SkipPrivilegedAccess) {
        Write-Host "`n[ENTRA-PRIV] Checking privileged access..." -ForegroundColor Yellow
        $allFindings += Invoke-EntraPermanentAdminCheck -Context $context
        $allFindings += Invoke-EntraHighPrivilegeRoleCheck -Context $context
    }
    
    if (-not $SkipAll -and -not $SkipGuestUsers) {
        Write-Host "`n[ENTRA-GUEST] Checking guest users..." -ForegroundColor Yellow
        $allFindings += Invoke-EntraGuestUserCheck -Context $context
    }
    
    if (-not $SkipAll -and -not $SkipApplications) {
        Write-Host "`n[ENTRA-APP] Checking applications..." -ForegroundColor Yellow
        $allFindings += Invoke-EntraAppRegistrationCheck -Context $context
        $allFindings += Invoke-EntraServicePrincipalCheck -Context $context
    }
    
    if (-not $SkipAll -and -not $SkipAuthentication) {
        Write-Host "`n[ENTRA-AUTH] Checking authentication..." -ForegroundColor Yellow
        $allFindings += Invoke-EntraLegacyAuthCheck -Context $context
        $allFindings += Invoke-EntraPasswordWritebackCheck -Context $context
    }
    
    if (-not $SkipAll -and -not $SkipRisk) {
        Write-Host "`n[ENTRA-RISK] Checking risk policies..." -ForegroundColor Yellow
        $allFindings += Invoke-EntraSignInRiskPolicyCheck -Context $context
    }
    
    Write-Host "`n[ENTRA-OTHER] Additional checks..." -ForegroundColor Yellow
    $allFindings += Invoke-EntraAdminConsentCheck -Context $context
    $allFindings += Invoke-EntraB2BCollaborationCheck -Context $context
    $allFindings += Invoke-EntraDeviceManagementCheck -Context $context
    $allFindings += Invoke-EntraDomainSecurityCheck -Context $context
    
    # Calculate score
    $score = 100
    foreach ($f in $allFindings) {
        switch ($f.Severity) {
            "Critical" { $score -= $script:DefaultThresholds.CriticalWeight }
            "High" { $score -= $script:DefaultThresholds.HighWeight }
            "Medium" { $score -= $script:DefaultThresholds.MediumWeight }
            "Low" { $score -= $script:DefaultThresholds.LowWeight }
        }
    }
    $score = [Math]::Max(0, [Math]::Min(100, $score))
    
    $crit = ($allFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $high = ($allFindings | Where-Object { $_.Severity -eq 'High' }).Count
    
    $healthyThreshold = $script:DefaultThresholds.HealthyScoreThreshold
    
    $status = if ($crit -ge $CriticalThreshold) { "Critical" }
              elseif ($high -ge $HighThreshold) { "Warning" }
              elseif ($score -lt 60) { "Critical" }
              elseif ($score -lt $healthyThreshold) { "Warning" }
              else { "Healthy" }
    
    $scoreColor = if ($status -eq 'Healthy') { 'Green' } elseif ($status -eq 'Warning') { 'Yellow' } else { 'Red' }
    
    Write-Host "`n" -ForegroundColor Cyan
    Write-Host " ENTRA ID SECURITY ASSESSMENT RESULTS " -ForegroundColor White
    Write-Host "" -ForegroundColor Cyan
    Write-Host "`n  Score:  $score/100 - " -NoNewline
    Write-Host $status -ForegroundColor $scoreColor
    Write-Host "`n  Findings:"
    Write-Host "    Critical: $crit" -ForegroundColor Red
    Write-Host "    High:     $high" -ForegroundColor DarkRed
    Write-Host "    Medium:   $(($allFindings | Where-Object { $_.Severity -eq 'Medium' }).Count)" -ForegroundColor Yellow
    Write-Host "    Low:      $(($allFindings | Where-Object { $_.Severity -eq 'Low' }).Count)" -ForegroundColor Cyan
    
    if ($crit -gt 0) {
        Write-Host "`n CRITICAL FINDINGS" -ForegroundColor Red
        foreach ($f in $allFindings | Where-Object { $_.Severity -eq 'Critical' }) {
            Write-Host "`n  [!] $($f.Title)" -ForegroundColor Red
            Write-Host "      $($f.Description)"
            if ($f.Remediation) {
                Write-Host "      - $($f.Remediation)" -ForegroundColor Yellow
            }
        }
    }
    
    Write-Host "`n" -ForegroundColor Cyan
    
    $exitCode = switch ($status) { 'Healthy' { 0 } 'Warning' { 1 } 'Critical' { 2 } default { 3 } }
    Write-Host "Exit Code: $exitCode" -ForegroundColor Gray
    
    return @{
        OverallScore = $score
        HealthStatus = $status
        Findings = $allFindings
        CriticalCount = $crit
        HighCount = $high
    }
}

Export-ModuleMember -Function Invoke-EntraSecurityAssessment
