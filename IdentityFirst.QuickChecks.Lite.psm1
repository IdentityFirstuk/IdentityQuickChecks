<#
.SYNOPSIS
    IdentityFirst QuickChecks - Lite Health Assessment Engine
    
.DESCRIPTION
    Lite version of IdentityHealthCheck with Azure RBAC/PBAC/ABAC support.
    
.NOTES
    Author: mark.ahearne@identityfirst.net
    Requirements: PowerShell 5.1+
#>

# Finding severity levels
$script:FindingSeverity = @{ Critical = "Critical"; High = "High"; Medium = "Medium"; Low = "Low"; Info = "Info" }
$script:HealthStatus = @{ Healthy = "Healthy"; Warning = "Warning"; Critical = "Critical" }

function New-Finding {
    param([string]$Id, [string]$Title, [string]$Description, [string]$Severity, [string]$Category)
    return @{ Id = $Id; Title = $Title; Description = $Description; Severity = $Severity; Category = $Category; 
              Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @(); RemediationSteps = @(); 
              IsResolved = $false; Confidence = "Medium"; RuleId = ""; RuleDescription = ""; 
              Source = ""; CheckName = ""; AffectedCount = 0; Remediation = "" }
}

function Add-FindingObject { param($Finding, $Object) 
    $Finding.AffectedObjects += $Object; $Finding.AffectedCount = $Finding.AffectedObjects.Count }

function Add-FindingEvidence { param($Finding, $Source, $Detail, $Confidence = "Medium") 
    $Finding.Evidence += @{ Source = $Source; Detail = $Detail; Confidence = $Confidence; Timestamp = [datetime]::UtcNow }
    $Finding.Confidence = $Confidence }

# =============================================================================
# Azure RBAC Collector
# =============================================================================

function Get-AzureRBACCollector {
    param($Context)
    $result = @{ SourceName = "AzureRBAC"; Success = $true; ErrorMessage = ""; Timestamp = [datetime]::UtcNow; 
                 Assignments = @(); RoleDefinitions = @(); ScopeCount = 0 }
    $hasAz = Get-Module -ListAvailable -Name Az.Accounts -ErrorAction SilentlyContinue
    if (-not $hasAz) { $result.Success = $false; $result.ErrorMessage = "Az module not available"; return $result }
    try {
        $subscriptions = Get-AzSubscription -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Enabled' }
        foreach ($sub in $subscriptions) {
            $Context.Log("Processing subscription: $($sub.Name)", "Debug")
            $assignments = Get-AzRoleAssignment -Scope "/subscriptions/$($sub.Id)" -ErrorAction SilentlyContinue
            foreach ($assignment in $assignments) {
                $result.Assignments += @{ RoleDefinitionName = $assignment.RoleDefinitionName; RoleDefinitionId = $assignment.RoleDefinitionId;
                                          Scope = $assignment.Scope; SignInName = $assignment.SignInName; ObjectType = $assignment.ObjectType;
                                          ObjectId = $assignment.ObjectId; CanDelegate = $assignment.CanDelegate; Description = $assignment.Description;
                                          SubscriptionId = $sub.Id; SubscriptionName = $sub.Name }
            }
            $roles = Get-AzRoleDefinition -Scope "/subscriptions/$($sub.Id)" -ErrorAction SilentlyContinue | Where-Object { $_.IsCustom -eq $true }
            foreach ($role in $roles) {
                $result.RoleDefinitions += @{ Name = $role.Name; Id = $role.Id; Description = $role.Description; 
                                              Permissions = $role.Actions; NotActions = $role.NotActions; 
                                              AssignableScopes = $role.AssignableScopes; SubscriptionId = $sub.Id }
            }
        }
        $result.ScopeCount = ($result.Assignments | Select-Object -ExpandProperty Scope -Unique).Count
        $Context.Log("Collected $($result.Assignments.Count) RBAC assignments", "Info")
    }
    catch { $result.Success = $false; $result.ErrorMessage = $_.Exception.Message; $Context.Log("Azure RBAC collection failed", "Error") }
    return $result
}

# =============================================================================
# Azure PBAC Collector
# =============================================================================

function Get-AzurePBACCollector {
    param($Context)
    $result = @{ SourceName = "AzurePBAC"; Success = $true; ErrorMessage = ""; Timestamp = [datetime]::UtcNow;
                 PolicyAssignments = @(); PolicyDefinitions = @(); Initiatives = @(); NonCompliantResources = @(); Exemptions = @() }
    $hasAz = Get-Module -ListAvailable -Name Az.Accounts -ErrorAction SilentlyContinue
    if (-not $hasAz) { $result.Success = $false; $result.ErrorMessage = "Az module not available"; return $result }
    try {
        $subscriptions = Get-AzSubscription -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Enabled' }
        foreach ($sub in $subscriptions) {
            $assignments = Get-AzPolicyAssignment -Scope "/subscriptions/$($sub.Id)" -ErrorAction SilentlyContinue
            foreach ($assignment in $assignments) {
                $result.PolicyAssignments += @{ Name = $assignment.Name; DisplayName = $assignment.DisplayName; 
                                                Description = $assignment.Description; PolicyDefinitionId = $assignment.PolicyDefinitionId;
                                                Scope = $assignment.Scope; Parameters = $assignment.Parameters;
                                                EnforcementMode = $assignment.EnforcementMode; SubscriptionId = $sub.Id }
            }
            $definitions = Get-AzPolicyDefinition -Scope "/subscriptions/$($sub.Id)" -ErrorAction SilentlyContinue
            foreach ($def in $definitions) {
                $result.PolicyDefinitions += @{ Name = $def.Name; DisplayName = $def.DisplayName; Description = $def.Description;
                                              PolicyType = $def.PolicyType; Mode = $def.Mode; Parameters = $def.Parameters;
                                              PolicyRule = $def.PolicyRule; SubscriptionId = $sub.Id }
            }
        }
        $Context.Log("Collected $($result.PolicyAssignments.Count) policy assignments", "Info")
    }
    catch { $result.Success = $false; $result.ErrorMessage = $_.Exception.Message; $Context.Log("Azure PBAC collection failed", "Error") }
    return $result
}

# =============================================================================
# Azure ABAC Collector
# =============================================================================

function Get-AzureABACCollector {
    param($Context)
    $result = @{ SourceName = "AzureABAC"; Success = $true; ErrorMessage = ""; Timestamp = [datetime]::UtcNow;
                 ConditionalAccessPolicies = @(); ConditionalAccessNamedLocations = @() }
    $hasGraph = Get-Module -ListAvailable -Name Microsoft.Graph.Identity.ConditionalAccess -ErrorAction SilentlyContinue
    if (-not $hasGraph) { $result.Success = $false; $result.ErrorMessage = "Microsoft.Graph module not available"; return $result }
    try {
        Connect-MgGraph -Scopes "ConditionalAccess.Read.All, Policy.Read.All" -ErrorAction Stop | Out-Null
        $policies = Get-MgIdentityConditionalAccessPolicy -ErrorAction Stop
        foreach ($policy in $policies) {
            $result.ConditionalAccessPolicies += @{ Id = $policy.Id; DisplayName = $policy.DisplayName; Description = $policy.Description;
                                                   State = $policy.State; Conditions = $policy.Conditions;
                                                   GrantControls = $policy.GrantControls; SessionControls = $policy.SessionControls }
        }
        $namedLocations = Get-MgIdentityConditionalAccessNamedLocation -ErrorAction Stop
        foreach ($location in $namedLocations) {
            $result.ConditionalAccessNamedLocations += @{ Id = $location.Id; DisplayName = $location.DisplayName;
                                                         IsTrusted = $location.IsTrusted; IpRanges = $location.IpRanges }
        }
        Disconnect-MgGraph | Out-Null
        $Context.Log("Collected $($result.ConditionalAccessPolicies.Count) CA policies", "Info")
    }
    catch { $result.Success = $false; $result.ErrorMessage = $_.Exception.Message; $Context.Log("Azure ABAC collection failed", "Error") }
    return $result
}

# =============================================================================
# Azure RBAC Checks
# =============================================================================

function Invoke-AzureRBACWideScopeCheck {
    param($Assignments, $Context)
    $findings = @()
    $wideScope = $Assignments | Where-Object { $_.Scope -match '/providers/Microsoft.Management' -or 
                                                ($_.Scope -match '/subscriptions/' -and $_.Scope -notmatch '/resourceGroups/') }
    if ($wideScope.Count -gt 0) {
        $f = New-Finding -Id "AZURE-RBAC-001" -Title "RBAC assignments at wide scope" `
            -Description "$($wideScope.Count) RBAC assignments at management group or subscription scope" `
            -Severity $script:FindingSeverity.High -Category "AzureRBAC_WideScope"
        $f.RuleId = "AZURE-RBAC-001"; $f.Source = "AzureRBAC"; $f.CheckName = "WideScopeCheck"
        $f.Remediation = "Reduce scope to resource groups where possible. Use PIM for just-in-time access."
        $f.RemediationSteps = @("Review subscription-level assignments", "Move to resource-group scope", "Enable Azure AD PIM")
        foreach ($a in $wideScope) { Add-FindingObject -Finding $f -Object "$($a.SignInName) -> $($a.RoleDefinitionName)" }
        Add-FindingEvidence -Finding $f -Source "Get-AzRoleAssignment" -Detail "$($wideScope.Count) wide-scope assignments" -Confidence "Medium"
        $findings += $f
    }
    return $findings
}

function Invoke-AzureRBACOverprivilegedCheck {
    param($Assignments, $RoleDefinitions, $Context)
    $findings = @()
    $dangerousRoles = @("Owner", "Contributor", "User Access Administrator", "Security Admin", "Global Administrator", "Privileged Role Administrator")
    foreach ($role in $dangerousRoles) {
        $overpriv = $Assignments | Where-Object { $_.RoleDefinitionName -eq $role -and $_.CanDelegate -ne $false }
        if ($overpriv.Count -gt 5) {
            $f = New-Finding -Id "AZURE-RBAC-002" -Title "Excessive $role role assignments" `
                -Description "$($overpriv.Count) users have permanent $role role" `
                -Severity $script:FindingSeverity.High -Category "AzureRBAC_OverprivilegedRole"
            $f.RuleId = "AZURE-RBAC-002"; $f.Source = "AzureRBAC"; $f.CheckName = "OverprivilegedCheck"
            $f.Remediation = "Reduce $role assignments. Use least-privilege principle and PIM."
            $f.RemediationSteps = @("Review $role assignments", "Convert permanent to eligible via PIM", "Document justifications")
            foreach ($a in $overpriv) { Add-FindingObject -Finding $f -Object $a.SignInName }
            Add-FindingEvidence -Finding $f -Source "Get-AzRoleAssignment" -Detail "$($overpriv.Count) assignments" -Confidence "High"
            $findings += $f
        }
    }
    return $findings
}

function Invoke-AzureRBACClassicAdminCheck {
    param($Context)
    $findings = @()
    try {
        $classic = Get-AzRoleAssignment -Scope "/subscriptions" -RoleDefinitionName "Co-Administrator" -ErrorAction SilentlyContinue
        $classic += Get-AzRoleAssignment -Scope "/subscriptions" -RoleDefinitionName "ServiceAdministrator" -ErrorAction SilentlyContinue
        if ($classic.Count -gt 0) {
            $f = New-Finding -Id "AZURE-RBAC-003" -Title "Classic administrator roles in use" `
                -Description "$($classic.Count) classic admin (Co-Administrator/ServiceAdministrator) assignments" `
                -Severity $script:FindingSeverity.Medium -Category "AzureRBAC_ClassicAdmin"
            $f.RuleId = "AZURE-RBAC-003"; $f.Source = "AzureRBAC"; $f.CheckName = "ClassicAdminCheck"
            $f.Remediation = "Migrate to Azure RBAC roles."
            $f.RemediationSteps = @("Identify classic admin assignments", "Create equivalent RBAC roles", "Test and remove classic admins")
            foreach ($a in $classic) { Add-FindingObject -Finding $f -Object $a.SignInName }
            Add-FindingEvidence -Finding $f -Source "Get-AzRoleAssignment" -Detail "Classic admins found" -Confidence "High"
            $findings += $f
        }
    }
    catch { $Context.Log("Could not check classic admins", "Debug") }
    return $findings
}

# =============================================================================
# Azure PBAC Checks
# =============================================================================

function Invoke-AzurePBACPolicyExemptionCheck {
    param($Exemptions, $Context)
    $findings = @()
    if ($Exemptions.Count -gt 10) {
        $f = New-Finding -Id "AZURE-PBAC-001" -Title "High number of policy exemptions" `
            -Description "$($Exemptions.Count) policy exemptions reduce compliance posture" `
            -Severity $script:FindingSeverity.Medium -Category "AzurePBAC_Exemption"
        $f.RuleId = "AZURE-PBAC-001"; $f.Source = "AzurePBAC"; $f.CheckName = "PolicyExemptionCheck"
        $f.Remediation = "Review and reduce exemptions. Document business justification."
        $f.RemediationSteps = @("Export exemptions", "Review justifications", "Set expiration dates", "Quarterly review")
        foreach ($e in $Exemptions) { Add-FindingObject -Finding $f -Object $e.DisplayName }
        Add-FindingEvidence -Finding $f -Source "Get-AzPolicyExemption" -Detail "$($Exemptions.Count) exemptions" -Confidence "Medium"
        $findings += $f
    }
    return $findings
}

function Invoke-AzurePBACPolicyEffectCheck {
    param($PolicyDefinitions, $Context)
    $findings = @()
    $lenient = $PolicyDefinitions | Where-Object { $_.PolicyRule -match '"effect".*"AuditIfNotExists"' -or 
                                                      $_.PolicyRule -match '"effect".*"Disabled"' }
    if ($lenient.Count -gt 0) {
        $f = New-Finding -Id "AZURE-PBAC-002" -Title "Policies with lenient enforcement effects" `
            -Description "$($lenient.Count) policies use AuditIfNotExists or Disabled effect" `
            -Severity $script:FindingSeverity.Low -Category "AzurePBAC_PolicyEffect"
        $f.RuleId = "AZURE-PBAC-002"; $f.Source = "AzurePBAC"; $f.CheckName = "PolicyEffectCheck"
        $f.Remediation = "Review and upgrade to deny/enforce effects where appropriate."
        $f.RemediationSteps = @("Review lenient policies", "Upgrade to Deny where safe", "Test in non-production")
        foreach ($p in $lenient) { Add-FindingObject -Finding $f -Object $p.DisplayName }
        Add-FindingEvidence -Finding $f -Source "Get-AzPolicyDefinition" -Detail "$($lenient.Count) lenient policies" -Confidence "Medium"
        $findings += $f
    }
    return $findings
}

# =============================================================================
# Azure ABAC Checks
# =============================================================================

function Invoke-AzureABACGrantAllCheck {
    param($CAPolicies, $Context)
    $findings = @()
    $permissive = $CAPolicies | Where-Object { $_.State -eq 'Enabled' -and $_.GrantControls -and 
                                                $_.GrantControls.Operator -eq 'OR' -and 
                                                ($_.GrantControls.BuiltInControls -contains 'All') }
    foreach ($policy in $permissive) {
        $f = New-Finding -Id "AZURE-ABAC-001" -Title "CA policy grants all access without controls" `
            -Description "Policy '$($policy.DisplayName)' grants all access without MFA or device compliance" `
            -Severity $script:FindingSeverity.Critical -Category "AzureABAC_ConditionalAccess"
        $f.RuleId = "AZURE-ABAC-001"; $f.Source = "AzureABAC"; $f.CheckName = "GrantAllCheck"
        $f.Remediation = "Add MFA and security controls to the policy."
        $f.RemediationSteps = @("Add MFA requirement", "Add compliant device check", "Add risk-based conditions")
        Add-FindingObject -Finding $f -Object $policy.DisplayName
        Add-FindingEvidence -Finding $f -Source "Get-MgIdentityConditionalAccessPolicy" -Detail "No controls" -Confidence "High"
        $findings += $f
    }
    return $findings
}

function Invoke-AzureABACLegacyAuthCheck {
    param($CAPolicies, $Context)
    $findings = @()
    $blocksLegacy = $CAPolicies | Where-Object { $_.State -eq 'Enabled' -and $_.Conditions -and 
                                                  $_.Conditions.ClientApplications -and 
                                                  ($_.Conditions.ClientApplications -contains 'exchangeActiveSync' -or 
                                                   $_.Conditions.ClientApplications -contains 'otherClients') }
    if ($blocksLegacy.Count -eq 0 -and $CAPolicies.Count -gt 0) {
        $f = New-Finding -Id "AZURE-ABAC-002" -Title "No policy blocking legacy authentication" `
            -Description "Legacy authentication (Exchange ActiveSync, Basic auth) is not blocked. These bypass MFA." `
            -Severity $script:FindingSeverity.High -Category "AzureABAC_ConditionalAccess"
        $f.RuleId = "AZURE-ABAC-002"; $f.Source = "AzureABAC"; $f.CheckName = "LegacyAuthCheck"
        $f.Remediation = "Create CA policy to block legacy authentication."
        $f.RemediationSteps = @("Create CA policy for all users", "Block 'other clients' and 'Exchange ActiveSync'", 
                                 "Exclude break-glass accounts", "Enable report-only first")
        Add-FindingEvidence -Finding $f -Source "Get-MgIdentityConditionalAccessPolicy" -Detail "No legacy blocking" -Confidence "High"
        $findings += $f
    }
    return $findings
}

function Invoke-AzureABACNoMFAForAdminCheck {
    param($CAPolicies, $Context)
    $findings = @()
    $mfaForAdmins = $CAPolicies | Where-Object { $_.State -eq 'Enabled' -and $_.GrantControls -and 
                                                  ($_.GrantControls.BuiltInControls -contains 'mfa' -or $_.GrantControls.CustomControls) }
    if ($mfaForAdmins.Count -eq 0) {
        $f = New-Finding -Id "AZURE-ABAC-003" -Title "No MFA requirement for privileged users" `
            -Description "No CA policy requires MFA specifically for admin role holders." `
            -Severity $script:FindingSeverity.Critical -Category "AzureABAC_ConditionalAccess"
        $f.RuleId = "AZURE-ABAC-003"; $f.Source = "AzureABAC"; $f.CheckName = "NoMFAForAdminCheck"
        $f.Remediation = "Create CA policy requiring MFA for privileged users."
        $f.RemediationSteps = @("Target privileged roles", "Require MFA", "Exclude break-glass accounts", "Report-only first")
        Add-FindingEvidence -Finding $f -Source "Get-MgIdentityConditionalAccessPolicy" -Detail "No admin MFA" -Confidence "High"
        $findings += $f
    }
    return $findings
}

function Invoke-AzureABACAllLocationsTrustedCheck {
    param($CAPolicies, $NamedLocations, $Context)
    $findings = @()
    foreach ($policy in $CAPolicies) {
        if ($policy.State -eq 'Enabled' -and $policy.Conditions) {
            $locs = $policy.Conditions.Locations
            $includesAll = $locs -and ($locs.Include -contains 'All' -or -not $locs.Include)
            $hasTrusted = $locs.ExcludeLocations -and ($locs.ExcludeLocations | Where-Object { $_ -match 'NamedLocation' }).Count -gt 0
            if ($includesAll -and -not $hasTrusted) {
                $f = New-Finding -Id "AZURE-ABAC-004" -Title "CA policy applies to all locations without trusted exclusions" `
                    -Description "Policy '$($policy.DisplayName)' applies to all locations" `
                    -Severity $script:FindingSeverity.Low -Category "AzureABAC_ConditionalAccess"
                $f.RuleId = "AZURE-ABAC-004"; $f.Source = "AzureABAC"; $f.CheckName = "AllLocationsTrustedCheck"
                $f.Remediation = "Create named corporate locations and exclude them from high-risk policies."
                $f.RemediationSteps = @("Identify corporate IPs", "Create named locations", "Mark as trusted", "Exclude from policies")
                Add-FindingObject -Finding $f -Object $policy.DisplayName
                Add-FindingEvidence -Finding $f -Source "Get-MgIdentityConditionalAccessPolicy" -Detail "All locations" -Confidence "Medium"
                $findings += $f
            }
        }
    }
    return $findings
}

# =============================================================================
# Assessment Engine
# =============================================================================

function New-AssessmentContext { return @{ StartTime = [datetime]::UtcNow; Configuration = @{}; CollectorResults = @(); Log = @() } }
function Add-AssessmentLog { param($Context, $Message, $Level = "Info") 
    $Context.Log += @{ Timestamp = [datetime]::UtcNow; Level = $Level; Message = $Message } }

function Invoke-QuickChecksAssessment {
    param($Config, $Context)
    $findings = @()
    
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
# Report Generation
# =============================================================================

function New-AssessmentReport {
    param($Findings, $Config)
    $score = 100
    foreach ($f in $Findings) {
        switch ($f.Severity) { "Critical" { $score -= 25 } "High" { $score -= 10 } "Medium" { $score -= 5 } "Low" { $score -= 2 } }
    }
    $score = [Math]::Max(0, [Math]::Min(100, $score))
    $crit = ($Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $high = ($Findings | Where-Object { $_.Severity -eq 'High' }).Count
    $med = ($Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $low = ($Findings | Where-Object { $_.Severity -eq 'Low' }).Count
    
    $status = $script:HealthStatus.Healthy
    if ($crit -ge $Config.CriticalThreshold) { $status = $script:HealthStatus.Critical }
    elseif ($high -ge $Config.HighThreshold) { $status = $script:HealthStatus.Warning }
    elseif ($score -lt 60) { $status = $script:HealthStatus.Critical }
    elseif ($score -lt $Config.HealthyScoreThreshold) { $status = $script:HealthStatus.Warning }
    
    return @{ ReportId = [guid]::NewGuid().ToString().Substring(0,8); Timestamp = [datetime]::UtcNow; Version = "1.1.0";
             OverallScore = $score; HealthStatus = $status; TotalFindings = $Findings.Count;
             CriticalCount = $crit; HighCount = $high; MediumCount = $med; LowCount = $low; InfoCount = 0;
             Findings = $Findings; Configuration = $Config }
}

# =============================================================================
# Main Entry Point
# =============================================================================

function Invoke-QuickChecksLite {
    [CmdletBinding()] param(
        [string]$OutputDir = ".\QuickChecks-Lite-Output",
        [ValidateSet('Console', 'Json', 'Html', 'All')][string]$Format = 'Console',
        [int]$CriticalThreshold = 1, [int]$HighThreshold = 5,
        [switch]$Force, [switch]$Help
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

EXIT COODES: 0=Healthy, 1=Warning, 2=Critical, 3=Error
"@
        return
    }
    
    Write-Host "`n╔═══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  IdentityFirst QuickChecks Lite v1.1.0                              ║" -ForegroundColor Cyan
    Write-Host "║  Azure RBAC/PBAC/ABAC Security Assessment                          ║" -ForegroundColor Yellow
    Write-Host "╚═══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    $config = @{ EnabledCollectors = @('AzureRBAC', 'AzurePBAC', 'AzureABAC'); CriticalThreshold = $CriticalThreshold;
                 HighThreshold = $HighThreshold; HealthyScoreThreshold = 80; OutputDirectory = $OutputDir;
                 ExportJson = ($Format -eq 'Json' -or $Format -eq 'All'); ExportHtml = ($Format -eq 'Html' -or $Format -eq 'All') }
    
    $context = New-AssessmentContext
    $context.Configuration = $config
    
    Write-Host "`nRunning Azure Security Assessment..." -ForegroundColor White
    $findings = Invoke-QuickChecksAssessment -Config $config -Context $context
    $report = New-AssessmentReport -Findings $findings -Config $config
    
    $scoreColor = if ($report.HealthStatus -eq 'Healthy') { 'Green' } elseif ($report.HealthStatus -eq 'Warning') { 'Yellow' } else { 'Red' }
    
    Write-Host "`n═══════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host " ASSESSMENT RESULTS " -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "`n  Overall Score: " -NoNewline; Write-Host "$($report.OverallScore)/100" -ForegroundColor $scoreColor
    Write-Host "  Status:       " -NoNewline; Write-Host $report.HealthStatus -ForegroundColor $scoreColor
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
            if ($f.Remediation) { Write-Host "      → Remediation: $($f.Remediation)" -ForegroundColor Yellow }
        }
    }
    
    Write-Host "`n═══════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    
    $exitCode = switch ($report.HealthStatus) { 'Healthy' { 0 } 'Warning' { 1 } 'Critical' { 2 } default { 3 } }
    Write-Host "Exit Code: $exitCode" -ForegroundColor Gray
    
    return $report
}

Export-ModuleMember -Function Invoke-QuickChecksLite

if ($MyInvocation.ScriptName -eq "") { Invoke-QuickChecksLite @args }
