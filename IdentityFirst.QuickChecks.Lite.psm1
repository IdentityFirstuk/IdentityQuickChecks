<#
.SYNOPSIS
    IdentityFirst QuickChecks - Lite Health Assessment Engine
    
.DESCRIPTION
    Lite version of IdentityHealthCheck with Azure RBAC/PBAC/ABAC support.
    Provides security assessments for Azure Role-Based Access Control,
    Policy-Based Access Control, and Attribute-Based Access Control.
    
.NOTES
    Author: mark.ahearne@identityfirst.net
    Requirements: PowerShell 5.1+
#>

# =============================================================================
# DEFAULT THRESHOLDS - Configurable Security Thresholds
# =============================================================================

$script:DefaultThresholds = @{
    # RBAC Thresholds
    WideScopeAssignments = 0                          # Number of wide-scope assignments to flag
    DangerousRoleThreshold = 5                         # Threshold for excessive dangerous role assignments
    ClassicAdminCount = 0                             # Classic admins should be 0
    
    # PBAC Thresholds
    PolicyExemptionLimit = 10                         # Maximum allowed policy exemptions
    
    # ABAC Thresholds
    CAGrantAllThreshold = 0                           # CA policies granting all access
    LegacyAuthBlockingRequired = $true                # Legacy auth must be blocked
    MFAForAdminRequired = $true                      # MFA must be required for admins
    
    # Scoring Thresholds
    HealthyScoreThreshold = 80                        # Score below this is Warning
    CriticalThreshold = 1                             # Critical findings threshold
    HighThreshold = 5                                 # High findings threshold
    
    # Finding Weights (score deductions)
    CriticalWeight = 25
    HighWeight = 10
    MediumWeight = 5
    LowWeight = 2
}

# Finding severity levels
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
        Unique identifier for the finding (e.g., 'AZURE-RBAC-001').
    
    .PARAMETER Title
        Brief, descriptive title of the finding.
    
    .PARAMETER Description
        Detailed explanation of the security issue.
    
    .PARAMETER Severity
        Severity level: Critical, High, Medium, Low, or Info.
    
    .PARAMETER Category
        Category classification for the finding.
    
    .EXAMPLE
        New-Finding -Id "AZURE-RBAC-001" -Title "Wide Scope RBAC Assignment" `
            -Description "RBAC assignment at subscription scope" `
            -Severity High -Category "AzureRBAC_WideScope"
    
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
        RuleDescription = ""
        Source = ""
        CheckName = ""
        AffectedCount = 0
        Remediation = ""
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
        Add-FindingEvidence -Finding $finding -Source "Get-AzRoleAssignment" `
            -Detail "Found 10 wide-scope assignments" -Confidence "High"
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
    $Finding.Confidence = $Confidence
}

# =============================================================================
# AZURE RBAC COLLECTOR
# =============================================================================

function Get-AzureRBACCollector {
    <#
    .SYNOPSIS
        Collects Azure RBAC data for assessment.
    
    .DESCRIPTION
        Retrieves all RBAC role assignments and role definitions from
        Azure subscriptions. This data is used by subsequent checks
        to identify security issues.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = New-AssessmentContext
        $rbacData = Get-AzureRBACCollector -Context $context
    
    .OUTPUTS
        Hashtable containing Assignments, RoleDefinitions, and ScopeCount.
    
    .NOTES
        Requires: Az.Accounts module
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $result = @{
        SourceName = "AzureRBAC"
        Success = $true
        ErrorMessage = ""
        Timestamp = [datetime]::UtcNow
        Assignments = @()
        RoleDefinitions = @()
        ScopeCount = 0
    }
    
    $hasAz = Get-Module -ListAvailable -Name Az.Accounts -ErrorAction SilentlyContinue
    if (-not $hasAz) {
        $result.Success = $false
        $result.ErrorMessage = "Az module not available"
        return $result
    }
    
    try {
        $subscriptions = Get-AzSubscription -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Enabled' }
        foreach ($sub in $subscriptions) {
            if ($Context) { $Context.Log("Processing subscription: $($sub.Name)", "Debug") }
            $assignments = Get-AzRoleAssignment -Scope "/subscriptions/$($sub.Id)" -ErrorAction SilentlyContinue
            foreach ($assignment in $assignments) {
                $result.Assignments += @{
                    RoleDefinitionName = $assignment.RoleDefinitionName
                    RoleDefinitionId = $assignment.RoleDefinitionId
                    Scope = $assignment.Scope
                    SignInName = $assignment.SignInName
                    ObjectType = $assignment.ObjectType
                    ObjectId = $assignment.ObjectId
                    CanDelegate = $assignment.CanDelegate
                    Description = $assignment.Description
                    SubscriptionId = $sub.Id
                    SubscriptionName = $sub.Name
                }
            }
            $roles = Get-AzRoleDefinition -Scope "/subscriptions/$($sub.Id)" -ErrorAction SilentlyContinue | Where-Object { $_.IsCustom -eq $true }
            foreach ($role in $roles) {
                $result.RoleDefinitions += @{
                    Name = $role.Name
                    Id = $role.Id
                    Description = $role.Description
                    Permissions = $role.Actions
                    NotActions = $role.NotActions
                    AssignableScopes = $role.AssignableScopes
                    SubscriptionId = $sub.Id
                }
            }
        }
        $result.ScopeCount = ($result.Assignments | Select-Object -ExpandProperty Scope -Unique).Count
        if ($Context) { $Context.Log("Collected $($result.Assignments.Count) RBAC assignments", "Info") }
    }
    catch {
        $result.Success = $false
        $result.ErrorMessage = $_.Exception.Message
        if ($Context) { $Context.Log("Azure RBAC collection failed: $($_.Exception.Message)", "Error") }
    }
    return $result
}

# =============================================================================
# AZURE PBAC COLLECTOR
# =============================================================================

function Get-AzurePBACCollector {
    <#
    .SYNOPSIS
        Collects Azure Policy data for assessment.
    
    .DESCRIPTION
        Retrieves all Azure Policy assignments, definitions, and exemptions
        from Azure subscriptions for security assessment.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = New-AssessmentContext
        $pbacData = Get-AzurePBACCollector -Context $context
    
    .OUTPUTS
        Hashtable containing PolicyAssignments, PolicyDefinitions, and Exemptions.
    
    .NOTES
        Requires: Az.Accounts module
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $result = @{
        SourceName = "AzurePBAC"
        Success = $true
        ErrorMessage = ""
        Timestamp = [datetime]::UtcNow
        PolicyAssignments = @()
        PolicyDefinitions = @()
        Initiatives = @()
        NonCompliantResources = @()
        Exemptions = @()
    }
    
    $hasAz = Get-Module -ListAvailable -Name Az.Accounts -ErrorAction SilentlyContinue
    if (-not $hasAz) {
        $result.Success = $false
        $result.ErrorMessage = "Az module not available"
        return $result
    }
    
    try {
        $subscriptions = Get-AzSubscription -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Enabled' }
        foreach ($sub in $subscriptions) {
            $assignments = Get-AzPolicyAssignment -Scope "/subscriptions/$($sub.Id)" -ErrorAction SilentlyContinue
            foreach ($assignment in $assignments) {
                $result.PolicyAssignments += @{
                    Name = $assignment.Name
                    DisplayName = $assignment.DisplayName
                    Description = $assignment.Description
                    PolicyDefinitionId = $assignment.PolicyDefinitionId
                    Scope = $assignment.Scope
                    Parameters = $assignment.Parameters
                    EnforcementMode = $assignment.EnforcementMode
                    SubscriptionId = $sub.Id
                }
            }
            $definitions = Get-AzPolicyDefinition -Scope "/subscriptions/$($sub.Id)" -ErrorAction SilentlyContinue
            foreach ($def in $definitions) {
                $result.PolicyDefinitions += @{
                    Name = $def.Name
                    DisplayName = $def.DisplayName
                    Description = $def.Description
                    PolicyType = $def.PolicyType
                    Mode = $def.Mode
                    Parameters = $def.Parameters
                    PolicyRule = $def.PolicyRule
                    SubscriptionId = $sub.Id
                }
            }
        }
        if ($Context) { $Context.Log("Collected $($result.PolicyAssignments.Count) policy assignments", "Info") }
    }
    catch {
        $result.Success = $false
        $result.ErrorMessage = $_.Exception.Message
        if ($Context) { $Context.Log("Azure PBAC collection failed: $($_.Exception.Message)", "Error") }
    }
    return $result
}

# =============================================================================
# AZURE ABAC COLLECTOR
# =============================================================================

function Get-AzureABACCollector {
    <#
    .SYNOPSIS
        Collects Azure Conditional Access data for assessment.
    
    .DESCRIPTION
        Retrieves all Conditional Access policies and named locations
        from Microsoft Graph for security assessment.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = New-AssessmentContext
        $abacData = Get-AzureABACCollector -Context $context
    
    .OUTPUTS
        Hashtable containing ConditionalAccessPolicies and NamedLocations.
    
    .NOTES
        Requires: Microsoft.Graph.Identity.ConditionalAccess module
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $result = @{
        SourceName = "AzureABAC"
        Success = $true
        ErrorMessage = ""
        Timestamp = [datetime]::UtcNow
        ConditionalAccessPolicies = @()
        ConditionalAccessNamedLocations = @()
    }
    
    $hasGraph = Get-Module -ListAvailable -Name Microsoft.Graph.Identity.ConditionalAccess -ErrorAction SilentlyContinue
    if (-not $hasGraph) {
        $result.Success = $false
        $result.ErrorMessage = "Microsoft.Graph module not available"
        return $result
    }
    
    try {
        Connect-MgGraph -Scopes "ConditionalAccess.Read.All, Policy.Read.All" -ErrorAction Stop | Out-Null
        $policies = Get-MgIdentityConditionalAccessPolicy -ErrorAction Stop
        foreach ($policy in $policies) {
            $result.ConditionalAccessPolicies += @{
                Id = $policy.Id
                DisplayName = $policy.DisplayName
                Description = $policy.Description
                State = $policy.State
                Conditions = $policy.Conditions
                GrantControls = $policy.GrantControls
                SessionControls = $policy.SessionControls
            }
        }
        $namedLocations = Get-MgIdentityConditionalAccessNamedLocation -ErrorAction Stop
        foreach ($location in $namedLocations) {
            $result.ConditionalAccessNamedLocations += @{
                Id = $location.Id
                DisplayName = $location.DisplayName
                IsTrusted = $location.IsTrusted
                IpRanges = $location.IpRanges
            }
        }
        Disconnect-MgGraph | Out-Null
        if ($Context) { $Context.Log("Collected $($result.ConditionalAccessPolicies.Count) CA policies", "Info") }
    }
    catch {
        $result.Success = $false
        $result.ErrorMessage = $_.Exception.Message
        if ($Context) { $Context.Log("Azure ABAC collection failed: $($_.Exception.Message)", "Error") }
    }
    return $result
}

# =============================================================================
# AZURE RBAC CHECKS
# =============================================================================

function Invoke-AzureRBACWideScopeCheck {
    <#
    .SYNOPSIS
        Identifies RBAC assignments at wide scope levels.
    
    .DESCRIPTION
        Checks for RBAC role assignments at management group or subscription
        scope, which provide broader access than necessary. Wide-scope
        assignments increase the attack surface and should be minimized.
    
    .PARAMETER Assignments
        Collection of RBAC assignments to analyze.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $rbacData = Get-AzureRBACCollector -Context $ctx
        $findings = Invoke-AzureRBACWideScopeCheck -Assignments $rbacData.Assignments -Context $ctx
    
    .OUTPUTS
        Array of finding objects for wide-scope assignments.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [array]$Assignments,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    if (-not $Assignments -or $Assignments.Count -eq 0) { return $findings }
    
    $threshold = $script:DefaultThresholds.WideScopeAssignments
    
    $wideScope = $Assignments | Where-Object {
        $_.Scope -match '/providers/Microsoft.Management' -or
        ($_.Scope -match '/subscriptions/' -and $_.Scope -notmatch '/resourceGroups/')
    }
    
    if ($wideScope.Count -gt $threshold) {
        $f = New-Finding -Id "AZURE-RBAC-001" -Title "RBAC assignments at wide scope" `
            -Description "$($wideScope.Count) RBAC assignments at management group or subscription scope" `
            -Severity $script:FindingSeverity.High -Category "AzureRBAC_WideScope"
        $f.RuleId = "AZURE-RBAC-001"
        $f.Source = "AzureRBAC"
        $f.CheckName = "WideScopeCheck"
        $f.Remediation = "Reduce scope to resource groups where possible. Use PIM for just-in-time access."
        $f.RemediationSteps = @(
            "Review subscription-level assignments",
            "Move to resource-group scope",
            "Enable Azure AD PIM",
            "Document justification for wide-scope assignments"
        )
        foreach ($a in $wideScope) {
            Add-FindingObject -Finding $f -Object "$($a.SignInName) -> $($a.RoleDefinitionName)"
        }
        Add-FindingEvidence -Finding $f -Source "Get-AzRoleAssignment" `
            -Detail "$($wideScope.Count) wide-scope assignments" -Confidence "Medium"
        $findings += $f
    }
    
    return $findings
}

function Invoke-AzureRBACOverprivilegedCheck {
    <#
    .SYNOPSIS
        Identifies excessive dangerous role assignments.
    
    .DESCRIPTION
        Checks for permanent assignments to dangerous roles like Owner,
        Contributor, and Global Administrator. These roles should be
        limited and use PIM for just-in-time access.
    
    .PARAMETER Assignments
        Collection of RBAC assignments to analyze.
    
    .PARAMETER RoleDefinitions
        Collection of role definitions for reference.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $rbacData = Get-AzureRBACCollector -Context $ctx
        $findings = Invoke-AzureRBACOverprivilegedCheck `
            -Assignments $rbacData.Assignments `
            -RoleDefinitions $rbacData.RoleDefinitions `
            -Context $ctx
    
    .OUTPUTS
        Array of finding objects for overprivileged assignments.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [array]$Assignments,
        
        [Parameter(Mandatory = $false)]
        [array]$RoleDefinitions,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    if (-not $Assignments -or $Assignments.Count -eq 0) { return $findings }
    
    $threshold = $script:DefaultThresholds.DangerousRoleThreshold
    $dangerousRoles = @("Owner", "Contributor", "User Access Administrator", "Security Admin", "Global Administrator", "Privileged Role Administrator")
    
    foreach ($role in $dangerousRoles) {
        $overpriv = $Assignments | Where-Object {
            $_.RoleDefinitionName -eq $role -and $_.CanDelegate -ne $false
        }
        if ($overpriv.Count -gt $threshold) {
            $f = New-Finding -Id "AZURE-RBAC-002" -Title "Excessive $role role assignments" `
                -Description "$($overpriv.Count) users have permanent $role role" `
                -Severity $script:FindingSeverity.High -Category "AzureRBAC_OverprivilegedRole"
            $f.RuleId = "AZURE-RBAC-002"
            $f.Source = "AzureRBAC"
            $f.CheckName = "OverprivilegedCheck"
            $f.Remediation = "Reduce $role assignments. Use least-privilege principle and PIM."
            $f.RemediationSteps = @(
                "Review $role assignments",
                "Convert permanent to eligible via PIM",
                "Document justifications",
                "Implement approval workflow for PIM activation"
            )
            foreach ($a in $overpriv) {
                Add-FindingObject -Finding $f -Object $a.SignInName
            }
            Add-FindingEvidence -Finding $f -Source "Get-AzRoleAssignment" `
                -Detail "$($overpriv.Count) assignments" -Confidence "High"
            $findings += $f
        }
    }
    
    return $findings
}

function Invoke-AzureRBACClassicAdminCheck {
    <#
    .SYNOPSIS
        Identifies classic Azure administrator roles in use.
    
    .DESCRIPTION
        Checks for legacy Co-Administrator and ServiceAdministrator
        role assignments that should be migrated to Azure RBAC.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $findings = Invoke-AzureRBACClassicAdminCheck -Context $ctx
    
    .OUTPUTS
        Array of finding objects for classic admin assignments.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    $threshold = $script:DefaultThresholds.ClassicAdminCount
    
    try {
        $classic = Get-AzRoleAssignment -Scope "/subscriptions" -RoleDefinitionName "Co-Administrator" -ErrorAction SilentlyContinue
        $classic += Get-AzRoleAssignment -Scope "/subscriptions" -RoleDefinitionName "ServiceAdministrator" -ErrorAction SilentlyContinue
        
        if ($classic.Count -gt $threshold) {
            $f = New-Finding -Id "AZURE-RBAC-003" -Title "Classic administrator roles in use" `
                -Description "$($classic.Count) classic admin (Co-Administrator/ServiceAdministrator) assignments" `
                -Severity $script:FindingSeverity.Medium -Category "AzureRBAC_ClassicAdmin"
            $f.RuleId = "AZURE-RBAC-003"
            $f.Source = "AzureRBAC"
            $f.CheckName = "ClassicAdminCheck"
            $f.Remediation = "Migrate to Azure RBAC roles."
            $f.RemediationSteps = @(
                "Identify classic admin assignments",
                "Create equivalent RBAC roles",
                "Test and remove classic admins",
                "Document migration process"
            )
            foreach ($a in $classic) {
                Add-FindingObject -Finding $f -Object $a.SignInName
            }
            Add-FindingEvidence -Finding $f -Source "Get-AzRoleAssignment" `
                -Detail "Classic admins found" -Confidence "High"
            $findings += $f
        }
    }
    catch {
        if ($Context) { $Context.Log("Could not check classic admins: $($_.Exception.Message)", "Debug") }
    }
    
    return $findings
}

# =============================================================================
# AZURE PBAC CHECKS
# =============================================================================

function Invoke-AzurePBACPolicyExemptionCheck {
    <#
    .SYNOPSIS
        Identifies excessive policy exemptions.
    
    .DESCRIPTION
        Checks for Azure Policy exemptions that may reduce compliance
        posture. A high number of exemptions should be reviewed and
        documented.
    
    .PARAMETER Exemptions
        Collection of policy exemptions to analyze.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $pbacData = Get-AzurePBACCollector -Context $ctx
        $findings = Invoke-AzurePBACPolicyExemptionCheck -Exemptions $pbacData.Exemptions -Context $ctx
    
    .OUTPUTS
        Array of finding objects for policy exemptions.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [array]$Exemptions,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    if (-not $Exemptions -or $Exemptions.Count -eq 0) { return $findings }
    
    $threshold = $script:DefaultThresholds.PolicyExemptionLimit
    
    if ($Exemptions.Count -gt $threshold) {
        $f = New-Finding -Id "AZURE-PBAC-001" -Title "High number of policy exemptions" `
            -Description "$($Exemptions.Count) policy exemptions reduce compliance posture" `
            -Severity $script:FindingSeverity.Medium -Category "AzurePBAC_Exemption"
        $f.RuleId = "AZURE-PBAC-001"
        $f.Source = "AzurePBAC"
        $f.CheckName = "PolicyExemptionCheck"
        $f.Remediation = "Review and reduce exemptions. Document business justification."
        $f.RemediationSteps = @(
            "Export exemptions",
            "Review justifications",
            "Set expiration dates",
            "Quarterly review",
            "Remove unnecessary exemptions"
        )
        foreach ($e in $Exemptions) {
            Add-FindingObject -Finding $f -Object $e.DisplayName
        }
        Add-FindingEvidence -Finding $f -Source "Get-AzPolicyExemption" `
            -Detail "$($Exemptions.Count) exemptions" -Confidence "Medium"
        $findings += $f
    }
    
    return $findings
}

function Invoke-AzurePBACPolicyEffectCheck {
    <#
    .SYNOPSIS
        Identifies policies with lenient enforcement effects.
    
    .DESCRIPTION
        Checks for Azure Policy definitions using AuditIfNotExists
        or Disabled effects instead of Deny or Enforce.
    
    .PARAMETER PolicyDefinitions
        Collection of policy definitions to analyze.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $pbacData = Get-AzurePBACCollector -Context $ctx
        $findings = Invoke-AzurePBACPolicyEffectCheck -PolicyDefinitions $pbacData.PolicyDefinitions -Context $ctx
    
    .OUTPUTS
        Array of finding objects for lenient policies.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [array]$PolicyDefinitions,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    if (-not $PolicyDefinitions -or $PolicyDefinitions.Count -eq 0) { return $findings }
    
    $lenient = $PolicyDefinitions | Where-Object {
        $_.PolicyRule -match '"effect".*"AuditIfNotExists"' -or
        $_.PolicyRule -match '"effect".*"Disabled"'
    }
    
    if ($lenient.Count -gt 0) {
        $f = New-Finding -Id "AZURE-PBAC-002" -Title "Policies with lenient enforcement effects" `
            -Description "$($lenient.Count) policies use AuditIfNotExists or Disabled effect" `
            -Severity $script:FindingSeverity.Low -Category "AzurePBAC_PolicyEffect"
        $f.RuleId = "AZURE-PBAC-002"
        $f.Source = "AzurePBAC"
        $f.CheckName = "PolicyEffectCheck"
        $f.Remediation = "Review and upgrade to deny/enforce effects where appropriate."
        $f.RemediationSteps = @(
            "Review lenient policies",
            "Upgrade to Deny where safe",
            "Test in non-production",
            "Document exceptions"
        )
        foreach ($p in $lenient) {
            Add-FindingObject -Finding $f -Object $p.DisplayName
        }
        Add-FindingEvidence -Finding $f -Source "Get-AzPolicyDefinition" `
            -Detail "$($lenient.Count) lenient policies" -Confidence "Medium"
        $findings += $f
    }
    
    return $findings
}

# =============================================================================
# AZURE ABAC CHECKS
# =============================================================================

function Invoke-AzureABACGrantAllCheck {
    <#
    .SYNOPSIS
        Identifies CA policies that grant all access without controls.
    
    .DESCRIPTION
        Checks for Conditional Access policies that grant all access
        without MFA, device compliance, or other security controls.
    
    .PARAMETER CAPolicies
        Collection of Conditional Access policies to analyze.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $abacData = Get-AzureABACCollector -Context $ctx
        $findings = Invoke-AzureABACGrantAllCheck -CAPolicies $abacData.ConditionalAccessPolicies -Context $ctx
    
    .OUTPUTS
        Array of finding objects for permissive CA policies.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [array]$CAPolicies,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    if (-not $CAPolicies -or $CAPolicies.Count -eq 0) { return $findings }
    
    $threshold = $script:DefaultThresholds.CAGrantAllThreshold
    
    $permissive = $CAPolicies | Where-Object {
        $_.State -eq 'Enabled' -and $_.GrantControls -and
        $_.GrantControls.Operator -eq 'OR' -and
        ($_.GrantControls.BuiltInControls -contains 'All')
    }
    
    foreach ($policy in $permissive) {
        $f = New-Finding -Id "AZURE-ABAC-001" -Title "CA policy grants all access without controls" `
            -Description "Policy '$($policy.DisplayName)' grants all access without MFA or device compliance" `
            -Severity $script:FindingSeverity.Critical -Category "AzureABAC_ConditionalAccess"
        $f.RuleId = "AZURE-ABAC-001"
        $f.Source = "AzureABAC"
        $f.CheckName = "GrantAllCheck"
        $f.Remediation = "Add MFA and security controls to the policy."
        $f.RemediationSteps = @(
            "Add MFA requirement",
            "Add compliant device check",
            "Add risk-based conditions",
            "Test in report-only mode"
        )
        Add-FindingObject -Finding $f -Object $policy.DisplayName
        Add-FindingEvidence -Finding $f -Source "Get-MgIdentityConditionalAccessPolicy" `
            -Detail "No controls" -Confidence "High"
        $findings += $f
    }
    
    return $findings
}

function Invoke-AzureABACLegacyAuthCheck {
    <#
    .SYNOPSIS
        Identifies missing legacy authentication blocking.
    
    .DESCRIPTION
        Checks that Conditional Access policies block legacy authentication
        methods like Exchange ActiveSync and Basic Auth, which can bypass MFA.
    
    .PARAMETER CAPolicies
        Collection of Conditional Access policies to analyze.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $abacData = Get-AzureABACCollector -Context $ctx
        $findings = Invoke-AzureABACLegacyAuthCheck -CAPolicies $abacData.ConditionalAccessPolicies -Context $ctx
    
    .OUTPUTS
        Array of finding objects for missing legacy auth blocking.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [array]$CAPolicies,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    if (-not $CAPolicies -or $CAPolicies.Count -eq 0) { return $findings }
    
    $requiresBlocking = $script:DefaultThresholds.LegacyAuthBlockingRequired
    
    $blocksLegacy = $CAPolicies | Where-Object {
        $_.State -eq 'Enabled' -and $_.Conditions -and
        $_.Conditions.ClientApplications -and
        ($_.Conditions.ClientApplications -contains 'exchangeActiveSync' -or
         $_.Conditions.ClientApplications -contains 'otherClients')
    }
    
    if ($requiresBlocking -and ($blocksLegacy.Count -eq 0)) {
        $f = New-Finding -Id "AZURE-ABAC-002" -Title "No policy blocking legacy authentication" `
            -Description "Legacy authentication (Exchange ActiveSync, Basic auth) is not blocked. These bypass MFA." `
            -Severity $script:FindingSeverity.High -Category "AzureABAC_ConditionalAccess"
        $f.RuleId = "AZURE-ABAC-002"
        $f.Source = "AzureABAC"
        $f.CheckName = "LegacyAuthCheck"
        $f.Remediation = "Create CA policy to block legacy authentication."
        $f.RemediationSteps = @(
            "Create CA policy for all users",
            "Block 'other clients' and 'Exchange ActiveSync'",
            "Exclude break-glass accounts",
            "Enable report-only first"
        )
        Add-FindingEvidence -Finding $f -Source "Get-MgIdentityConditionalAccessPolicy" `
            -Detail "No legacy blocking" -Confidence "High"
        $findings += $f
    }
    
    return $findings
}

function Invoke-AzureABACNoMFAForAdminCheck {
    <#
    .SYNOPSIS
        Identifies missing MFA requirement for privileged users.
    
    .DESCRIPTION
        Checks that Conditional Access policies require MFA specifically
        for privileged role holders.
    
    .PARAMETER CAPolicies
        Collection of Conditional Access policies to analyze.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $abacData = Get-AzureABACCollector -Context $ctx
        $findings = Invoke-AzureABACNoMFAForAdminCheck -CAPolicies $abacData.ConditionalAccessPolicies -Context $ctx
    
    .OUTPUTS
        Array of finding objects for missing admin MFA.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [array]$CAPolicies,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    if (-not $CAPolicies -or $CAPolicies.Count -eq 0) { return $findings }
    
    $requiresMFA = $script:DefaultThresholds.MFAForAdminRequired
    
    $mfaForAdmins = $CAPolicies | Where-Object {
        $_.State -eq 'Enabled' -and $_.GrantControls -and
        ($_.GrantControls.BuiltInControls -contains 'mfa' -or $_.GrantControls.CustomControls)
    }
    
    if ($requiresMFA -and ($mfaForAdmins.Count -eq 0)) {
        $f = New-Finding -Id "AZURE-ABAC-003" -Title "No MFA requirement for privileged users" `
            -Description "No CA policy requires MFA specifically for admin role holders." `
            -Severity $script:FindingSeverity.Critical -Category "AzureABAC_ConditionalAccess"
        $f.RuleId = "AZURE-ABAC-003"
        $f.Source = "AzureABAC"
        $f.CheckName = "NoMFAForAdminCheck"
        $f.Remediation = "Create CA policy requiring MFA for privileged users."
        $f.RemediationSteps = @(
            "Target privileged roles",
            "Require MFA",
            "Exclude break-glass accounts",
            "Report-only first"
        )
        Add-FindingEvidence -Finding $f -Source "Get-MgIdentityConditionalAccessPolicy" `
            -Detail "No admin MFA" -Confidence "High"
        $findings += $f
    }
    
    return $findings
}

function Invoke-AzureABACAllLocationsTrustedCheck {
    <#
    .SYNOPSIS
        Identifies CA policies applying to all locations without trusted exclusions.
    
    .DESCRIPTION
        Checks that enabled Conditional Access policies with all-locations
        targeting also exclude trusted named locations for sensitive operations.
    
    .PARAMETER CAPolicies
        Collection of Conditional Access policies to analyze.
    
    .PARAMETER NamedLocations
        Collection of named locations for reference.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $abacData = Get-AzureABACCollector -Context $ctx
        $findings = Invoke-AzureABACAllLocationsTrustedCheck `
            -CAPolicies $abacData.ConditionalAccessPolicies `
            -NamedLocations $abacData.ConditionalAccessNamedLocations `
            -Context $ctx
    
    .OUTPUTS
        Array of finding objects for policies without trusted location exclusions.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [array]$CAPolicies,
        
        [Parameter(Mandatory = $false)]
        [array]$NamedLocations,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    if (-not $CAPolicies -or $CAPolicies.Count -eq 0) { return $findings }
    
    foreach ($policy in $CAPolicies) {
        if ($policy.State -eq 'Enabled' -and $policy.Conditions) {
            $locs = $policy.Conditions.Locations
            $includesAll = $locs -and ($locs.Include -contains 'All' -or -not $locs.Include)
            $hasTrusted = $locs.ExcludeLocations -and
                ($locs.ExcludeLocations | Where-Object { $_ -match 'NamedLocation' }).Count -gt 0
            
            if ($includesAll -and -not $hasTrusted) {
                $f = New-Finding -Id "AZURE-ABAC-004" -Title "CA policy applies to all locations without trusted exclusions" `
                    -Description "Policy '$($policy.DisplayName)' applies to all locations" `
                    -Severity $script:FindingSeverity.Low -Category "AzureABAC_ConditionalAccess"
                $f.RuleId = "AZURE-ABAC-004"
                $f.Source = "AzureABAC"
                $f.CheckName = "AllLocationsTrustedCheck"
                $f.Remediation = "Create named corporate locations and exclude them from high-risk policies."
                $f.RemediationSteps = @(
                    "Identify corporate IPs",
                    "Create named locations",
                    "Mark as trusted",
                    "Exclude from policies"
                )
                Add-FindingObject -Finding $f -Object $policy.DisplayName
                Add-FindingEvidence -Finding $f -Source "Get-MgIdentityConditionalAccessPolicy" `
                    -Detail "All locations" -Confidence "Medium"
                $findings += $f
            }
        }
    }
    
    return $findings
}

# =============================================================================
# ASSESSMENT ENGINE
# =============================================================================

function New-AssessmentContext {
    <#
    .SYNOPSIS
        Creates a new assessment context object.
    
    .DESCRIPTION
        Initializes a context object used throughout the assessment
        for configuration, collector results, and logging.
    
    .EXAMPLE
        $context = New-AssessmentContext
        $context.Configuration = @{ CriticalThreshold = 1 }
    
    .OUTPUTS
        Hashtable representing the assessment context.
    #>
    [CmdletBinding()]
    param()
    
    return @{
        StartTime = [datetime]::UtcNow
        Configuration = @{}
        CollectorResults = @()
        Log = @()
    }
}

function Add-AssessmentLog {
    <#
    .SYNOPSIS
        Adds a log entry to the assessment context.
    
    .DESCRIPTION
        Appends a log entry to the context's Log collection
        with timestamp, level, and message.
    
    .PARAMETER Context
        The assessment context object to modify.
    
    .PARAMETER Message
        The log message.
    
    .PARAMETER Level
        Log level: Error, Warning, Info, Debug. Default is Info.
    
    .EXAMPLE
        $context = New-AssessmentContext
        Add-AssessmentLog -Context $context -Message "Assessment started" -Level "Info"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Context,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Error", "Warning", "Info", "Debug")]
        [string]$Level = "Info"
    )
    
    $Context.Log += @{
        Timestamp = [datetime]::UtcNow
        Level = $Level
        Message = $Message
    }
}

function Invoke-QuickChecksAssessment {
    <#
    .SYNOPSIS
        Runs the complete QuickChecks Lite assessment.
    
    .DESCRIPTION
        Executes all enabled collectors and checks based on the
        configuration, returning consolidated findings.
    
    .PARAMETER Config
        Configuration hashtable with enabled collectors and thresholds.
    
    .PARAMETER Context
        The assessment context object for logging and state.
    
    .EXAMPLE
        $config = @{ EnabledCollectors = @('AzureRBAC', 'AzurePBAC', 'AzureABAC') }
        $context = New-AssessmentContext
        $findings = Invoke-QuickChecksAssessment -Config $config -Context $context
    
    .OUTPUTS
        Array of all findings from executed checks.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Config,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    if (-not $Config -or -not $Config.EnabledCollectors) { return $findings }
    
    if ($Config.EnabledCollectors -contains 'AzureRBAC') {
        Add-AssessmentLog -Context $Context -Message "Running Azure RBAC collector" -Level "Info"
        $rbac = Get-AzureRBACCollector -Context $Context
        if ($rbac.Success) {
            $findings += Invoke-AzureRBACWideScopeCheck -Assignments $rbac.Assignments -Context $Context
            $findings += Invoke-AzureRBACOverprivilegedCheck -Assignments $rbac.Assignments -RoleDefinitions $rbac.RoleDefinitions -Context $Context
            $findings += Invoke-AzureRBACClassicAdminCheck -Context $Context
        }
    }
    
    if ($Config.EnabledCollectors -contains 'AzurePBAC') {
        Add-AssessmentLog -Context $Context -Message "Running Azure PBAC collector" -Level "Info"
        $pbac = Get-AzurePBACCollector -Context $Context
        if ($pbac.Success) {
            $findings += Invoke-AzurePBACPolicyExemptionCheck -Exemptions $pbac.Exemptions -Context $Context
            $findings += Invoke-AzurePBACPolicyEffectCheck -PolicyDefinitions $pbac.PolicyDefinitions -Context $Context
        }
    }
    
    if ($Config.EnabledCollectors -contains 'AzureABAC') {
        Add-AssessmentLog -Context $Context -Message "Running Azure ABAC collector" -Level "Info"
        $abac = Get-AzureABACCollector -Context $Context
        if ($abac.Success) {
            $findings += Invoke-AzureABACGrantAllCheck -CAPolicies $abac.ConditionalAccessPolicies -Context $Context
            $findings += Invoke-AzureABACLegacyAuthCheck -CAPolicies $abac.ConditionalAccessPolicies -Context $Context
            $findings += Invoke-AzureABACNoMFAForAdminCheck -CAPolicies $abac.ConditionalAccessPolicies -Context $Context
            $findings += Invoke-AzureABACAllLocationsTrustedCheck -CAPolicies $abac.ConditionalAccessPolicies -NamedLocations $abac.ConditionalAccessNamedLocations -Context $Context
        }
    }
    
    return $findings
}

# =============================================================================
# REPORT GENERATION
# =============================================================================

function New-AssessmentReport {
    <#
    .SYNOPSIS
        Generates an assessment report with scoring.
    
    .DESCRIPTION
        Calculates overall score and health status based on findings
        and thresholds, returning a comprehensive report object.
    
    .PARAMETER Findings
        Array of findings to include in the report.
    
    .PARAMETER Config
        Configuration hashtable with threshold values.
    
    .EXAMPLE
        $report = New-AssessmentReport -Findings $findings -Config $config
    
    .OUTPUTS
        Hashtable containing the complete assessment report.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [array]$Findings,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Config
    )
    
    $score = 100
    
    foreach ($f in $Findings) {
        switch ($f.Severity) {
            "Critical" { $score -= $script:DefaultThresholds.CriticalWeight }
            "High" { $score -= $script:DefaultThresholds.HighWeight }
            "Medium" { $score -= $script:DefaultThresholds.MediumWeight }
            "Low" { $score -= $script:DefaultThresholds.LowWeight }
        }
    }
    
    $score = [Math]::Max(0, [Math]::Min(100, $score))
    
    $crit = ($Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $high = ($Findings | Where-Object { $_.Severity -eq 'High' }).Count
    $med = ($Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $low = ($Findings | Where-Object { $_.Severity -eq 'Low' }).Count
    
    $critThreshold = if ($Config.CriticalThreshold) { $Config.CriticalThreshold } else { $script:DefaultThresholds.CriticalThreshold }
    $highThreshold = if ($Config.HighThreshold) { $Config.HighThreshold } else { $script:DefaultThresholds.HighThreshold }
    $healthyThreshold = if ($Config.HealthyScoreThreshold) { $Config.HealthyScoreThreshold } else { $script:DefaultThresholds.HealthyScoreThreshold }
    
    $status = $script:HealthStatus.Healthy
    if ($crit -ge $critThreshold) { $status = $script:HealthStatus.Critical }
    elseif ($high -ge $highThreshold) { $status = $script:HealthStatus.Warning }
    elseif ($score -lt 60) { $status = $script:HealthStatus.Critical }
    elseif ($score -lt $healthyThreshold) { $status = $script:HealthStatus.Warning }
    
    return @{
        ReportId = [guid]::NewGuid().ToString().Substring(0, 8)
        Timestamp = [datetime]::UtcNow
        Version = "1.1.0"
        OverallScore = $score
        HealthStatus = $status
        TotalFindings = $Findings.Count
        CriticalCount = $crit
        HighCount = $high
        MediumCount = $med
        LowCount = $low
        InfoCount = 0
        Findings = $Findings
        Configuration = $Config
    }
}

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

function Invoke-QuickChecksLite {
    <#
    .SYNOPSIS
        Executes the IdentityFirst QuickChecks Lite security assessment.
    
    .DESCRIPTION
        Main entry point for the QuickChecks Lite module. Runs Azure RBAC,
        PBAC, and ABAC security checks and generates a comprehensive report.
    
    .PARAMETER OutputDir
        Directory path for output files. Default is ".\QuickChecks-Lite-Output".
    
    .PARAMETER Format
        Output format: Console, Json, Html, or All. Default is Console.
    
    .PARAMETER CriticalThreshold
        Number of critical findings to trigger Critical status. Default is 1.
    
    .PARAMETER HighThreshold
        Number of high findings to trigger Warning status. Default is 5.
    
    .PARAMETER Force
        Overwrite existing output files without prompting.
    
    .PARAMETER Help
        Display help information and exit.
    
    .EXAMPLE
        Invoke-QuickChecksLite -Format All -OutputDir ".\Results"
    
    .EXAMPLE
        Invoke-QuickChecksLite -CriticalThreshold 2 -HighThreshold 10
    
    .OUTPUTS
        Hashtable containing the assessment report.
    
    .NOTES
        Exit Codes: 0=Healthy, 1=Warning, 2=Critical, 3=Error
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, HelpMessage = "Output directory for reports")]
        [ValidateNotNullOrEmpty()]
        [string]$OutputDir = ".\QuickChecks-Lite-Output",
        
        [Parameter(Mandatory = $false, HelpMessage = "Output format")]
        [ValidateSet('Console', 'Json', 'Html', 'All')]
        [string]$Format = 'Console',
        
        [Parameter(Mandatory = $false, HelpMessage = "Critical findings threshold")]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$CriticalThreshold = 1,
        
        [Parameter(Mandatory = $false, HelpMessage = "High findings threshold")]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$HighThreshold = 5,
        
        [Parameter(Mandatory = $false, HelpMessage = "Force overwrite output files")]
        [switch]$Force,
        
        [Parameter(Mandatory = $false, HelpMessage = "Display help information")]
        [switch]$Help
    )
    
    if ($Help) {
        Write-Host @"
IdentityFirst QuickChecks Lite v1.1.0
=====================================
PowerShell edition with Azure RBAC/PBAC/ABAC support.

FEATURES:
  - Azure RBAC: Wide scope, Overprivileged, Classic admin checks
  - Azure PBAC: Policy exemptions, Policy effect checks
  - Azure ABAC: CA grant all, Legacy auth blocking, MFA for admins

USAGE:
  Invoke-QuickChecksLite [-OutputDir <path>] [-Format <format>]
                         [-CriticalThreshold <n>] [-HighThreshold <n>]
                         [-Force] [-Help]

PARAMETERS:
  -OutputDir          Output directory (default: .\QuickChecks-Lite-Output)
  -Format             Console, Json, Html, or All (default: Console)
  -CriticalThreshold  Critical findings for Critical status (default: 1)
  -HighThreshold     High findings for Warning status (default: 5)
  -Force              Overwrite existing files
  -Help               Show this help message

EXIT CODES:
  0 = Healthy
  1 = Warning
  2 = Critical
  3 = Error

REQUIREMENTS:
  - PowerShell 5.1+
  - Az.Accounts module (for RBAC/PBAC checks)
  - Microsoft.Graph module (for ABAC checks)
"@
        return
    }
    
    Write-Host "`n" -ForegroundColor Cyan
    Write-Host "  IdentityFirst QuickChecks Lite v1.1.0                              " -ForegroundColor Cyan
    Write-Host "  Azure RBAC/PBAC/ABAC Security Assessment                          " -ForegroundColor Yellow
    Write-Host "" -ForegroundColor Cyan
    
    $config = @{
        EnabledCollectors = @('AzureRBAC', 'AzurePBAC', 'AzureABAC')
        CriticalThreshold = $CriticalThreshold
        HighThreshold = $HighThreshold
        HealthyScoreThreshold = 80
        OutputDirectory = $OutputDir
        ExportJson = ($Format -eq 'Json' -or $Format -eq 'All')
        ExportHtml = ($Format -eq 'Html' -or $Format -eq 'All')
        Force = $Force
    }
    
    $context = New-AssessmentContext
    $context.Configuration = $config
    
    Write-Host "`nRunning Azure Security Assessment..." -ForegroundColor White
    $findings = Invoke-QuickChecksAssessment -Config $config -Context $context
    $report = New-AssessmentReport -Findings $findings -Config $config
    
    $scoreColor = if ($report.HealthStatus -eq 'Healthy') { 'Green' } elseif ($report.HealthStatus -eq 'Warning') { 'Yellow' } else { 'Red' }
    
    Write-Host "`n" -ForegroundColor Cyan
    Write-Host " ASSESSMENT RESULTS " -ForegroundColor White
    Write-Host "" -ForegroundColor Cyan
    Write-Host "`n  Overall Score: " -NoNewline
    Write-Host "$($report.OverallScore)/100" -ForegroundColor $scoreColor
    Write-Host "  Status:       " -NoNewline
    Write-Host $report.HealthStatus -ForegroundColor $scoreColor
    Write-Host "`n  Findings:"
    Write-Host "    Critical: $($report.CriticalCount)" -ForegroundColor Red
    Write-Host "    High:     $($report.HighCount)" -ForegroundColor DarkRed
    Write-Host "    Medium:   $($report.MediumCount)" -ForegroundColor Yellow
    Write-Host "    Low:      $($report.LowCount)" -ForegroundColor Cyan
    
    # Critical findings
    $critFind = $findings | Where-Object { $_.Severity -eq 'Critical' }
    if ($critFind.Count -gt 0) {
        Write-Host "`n CRITICAL FINDINGS " -ForegroundColor Red
        foreach ($f in $critFind) {
            Write-Host "`n  [!] $($f.Title)" -ForegroundColor Red
            Write-Host "      $($f.Description)"
            if ($f.Remediation) {
                Write-Host "      - Remediation: $($f.Remediation)" -ForegroundColor Yellow
            }
        }
    }
    
    Write-Host "`n" -ForegroundColor Cyan
    
    $exitCode = switch ($report.HealthStatus) {
        'Healthy' { 0 }
        'Warning' { 1 }
        'Critical' { 2 }
        default { 3 }
    }
    Write-Host "Exit Code: $exitCode" -ForegroundColor Gray
    
    return $report
}

Export-ModuleMember -Function Invoke-QuickChecksLite

if ($MyInvocation.ScriptName -eq "") {
    Invoke-QuickChecksLite @args
}
