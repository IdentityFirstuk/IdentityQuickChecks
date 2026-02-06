
# ============================================================================
# Finding Helper Functions
# ============================================================================

function New-Finding {
    <#.SYNOPSIS
        Creates a standardized finding object for security assessments.
    .DESCRIPTION
        This helper function creates a consistent finding structure.
    .PARAMETER Id
        Unique identifier for the finding.
    .PARAMETER Title
        Brief descriptive title of the finding.
    .PARAMETER Description
        Detailed explanation of what was found.
    .PARAMETER Severity
        Severity level: Critical, High, Medium, Low, or Info.
    .PARAMETER Category
        Category for grouping related findings.
    .OUTPUTS
        Hashtable representing a standardized finding object.
    #>
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
        [Parameter(Mandatory = $true, HelpMessage = "Finding category")]
        [ValidateNotNullOrEmpty()]
        [string]$Category
    )
    return @{
        Id = $Id; Title = $Title; Description = $Description; Severity = $Severity; Category = $Category
        Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @(); RemediationSteps = @()
        IsResolved = $false; Confidence = "Medium"; RuleId = $Id; RuleDescription = ""; Source = ""; CheckName = ""
        AffectedCount = 0; Remediation = ""; RemediationUrl = ""
    }
}

function Add-FindingObject {
    <#.SYNOPSIS
        Adds an affected object to a finding.
    .PARAMETER Finding
        The finding hashtable to modify.
    .PARAMETER Object
        The object identifier to add.
    #>
    param([Parameter(Mandatory)] [hashtable]$Finding, [Parameter(Mandatory)] [AllowEmptyString()] [string]$Object)
    { $Finding.AffectedObjects += $Object; $Finding.AffectedCount = $Finding.AffectedObjects.Count }
}

function Add-FindingEvidence {
    <#.SYNOPSIS
        Adds evidence to a finding.
    .PARAMETER Finding
        The finding hashtable to modify.
    .PARAMETER Source
        The data source or command that generated the evidence.
    .PARAMETER Detail
        Specific evidence details.
    .PARAMETER Confidence
        Confidence level: High, Medium, or Low.
    #>
    param([Parameter(Mandatory)] [hashtable]$Finding, [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string]$Source,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string]$Detail, [Parameter()] [ValidateSet("High", "Medium", "Low")] [string]$Confidence = "Medium")
    { $Finding.Evidence += @{ Source = $Source; Detail = $Detail; Confidence = $Confidence; Timestamp = [datetime]::UtcNow }; $Finding.Confidence = $Confidence }
}

function Add-FindingRemediation {
    <#.SYNOPSIS
        Adds remediation guidance to a finding.
    .PARAMETER Finding
        The finding hashtable to modify.
    .PARAMETER Remediation
        Summary of remediation actions.
    .PARAMETER Steps
        Array of step-by-step remediation instructions.
    #>
    param([Parameter(Mandatory)] [hashtable]$Finding, [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string]$Remediation, [Parameter()] [string[]]$Steps)
    { $Finding.Remediation = $Remediation; if ($Steps) { $Finding.RemediationSteps = $Steps } }
}

function New-AssessmentContext {
    <#.SYNOPSIS
        Creates a new assessment context object.
    .OUTPUTS
        Hashtable representing the assessment context.
    #>
    { @{ StartTime = [datetime]::UtcNow; Configuration = @(); CollectorResults = @(); Log = @() } }
}

function Add-AssessmentLog {
    <#.SYNOPSIS
        Adds a log entry to the assessment context.
    .PARAMETER Context
        The assessment context object.
    .PARAMETER Message
        Log message content.
    .PARAMETER Level
        Severity level: Debug, Info, Warning, Error.
    #>
    param([Parameter(Mandatory)] [hashtable]$Context, [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string]$Message,
        [Parameter()] [ValidateSet("Debug", "Info", "Warning", "Error")] [string]$Level = "Info")
    { $Context.Log += @{ Timestamp = [datetime]::UtcNow; Level = $Level; Message = $Message } }
}

function New-AssessmentReport {
    <#.SYNOPSIS
        Generates an assessment report from findings.
    .DESCRIPTION
        Calculates overall score, health status, and summary statistics.
    .PARAMETER Findings
        Array of finding hashtables.
    .PARAMETER Config
        Assessment configuration hashtable.
    #>
    param([Parameter(Mandatory)] [array]$Findings, [Parameter(Mandatory)] [hashtable]$Config)
    {
        $score = 100
        foreach ($f in $Findings) { switch ($f.Severity) { "Critical" { $score -= 25 } "High" { $score -= 10 } "Medium" { $score -= 5 } "Low" { $score -= 2 } } }
        $score = [Math]::Max(0, [Math]::Min(100, $score))
        $crit = ($Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
        $high = ($Findings | Where-Object { $_.Severity -eq 'High' }).Count
        $status = $script:HealthStatus.Healthy
        if ($crit -ge $Config.CriticalThreshold) { $status = $script:HealthStatus.Critical }
        elseif ($high -ge $Config.HighThreshold) { $status = $script:HealthStatus.Warning }
        return @{
            ReportId = [guid]::NewGuid().ToString().Substring(0,8); Timestamp = [datetime]::UtcNow; Version = "1.1.0"
            OverallScore = $score; HealthStatus = $status; TotalFindings = $Findings.Count
            CriticalCount = $crit; HighCount = $high; MediumCount = ($Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
            LowCount = ($Findings | Where-Object { $_.Severity -eq 'Low' }).Count; Findings = $Findings; Configuration = $Config
        }
    }
}
# ============================================================================
# Configurable Thresholds
# ============================================================================
# These thresholds can be adjusted based on organizational requirements.
# Module Type: Compliance

$script:DefaultThresholds = @{
    ControlFailThreshold = 0
    PolicyGapThreshold = 10
}

# Severity and Status Definitions
$script:FindingSeverity = @{ Critical = "Critical"; High = "High"; Medium = "Medium"; Low = "Low"; Info = "Info" }
$script:HealthStatus = @{ Healthy = "Healthy"; Warning = "Warning"; Critical = "Critical" }
# ============================================================================
# IdentityFirst QuickChecks - Compliance & Advanced Security Module
# ============================================================================
# PowerShell 5.1 Compatible
# Contains compliance, federation, and advanced security checks
# ============================================================================

#requires -Version 5.1

#region Entra ID Compliance Checks
function Invoke-EntraIdCAGrantAllCheck {
    <#
    .SYNOPSIS
        Checks Conditional Access policies with "Grant All" access
    .DESCRIPTION
        Identifies overly permissive CA grant conditions
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$TenantId,
        
        [Parameter(Mandatory=$false)]
        [pscredential]$Credential
    )
    
    $checkId = 'IDF-ENT-CA-GA-001'
    $checkName = 'Conditional Access Grant All Policies'
    $category = 'Entra ID - Conditional Access'
    $severity = 'Critical'
    
    try {
        $graphParams = @{}
        if ($TenantId) { $graphParams['TenantId'] = $TenantId }
        if ($Credential) { $graphParams['Credential'] = $Credential }
        
        $null = Connect-MgGraph @graphParams -Scopes 'Policy.Read.All' -NoWelcome
        
        $caUri = '/beta/identity/conditionalAccess/policies'
        $policies = Invoke-MgGraphRequest -Method GET -Uri $caUri -ErrorAction Stop
        
        $remediation = @()
        $affectedCount = 0
        
        foreach ($policy in $policies.Value) {
            if ($policy.state -eq 'Enabled') {
                if ($policy.grantControls -and $policy.grantControls.builtInControls -contains 'mfa') {
                    if ($policy.grantControls.operator -eq 'OR' -and 
                        ($policy.grantControls.builtInControls.Count -eq 0 -or 
                         $policy.grantControls.builtInControls -contains 'All')) {
                        $policyName = $policy.displayName
                        $remediation += "Policy '$policyName' requires review - Grant All configuration"
                        $affectedCount++
                    }
                }
                
                $conditions = $policy.conditions
                if ($conditions.userIdentityChanges -and 
                    $conditions.applications -and 
                    $conditions.applications.excludeApplications -and 
                    $conditions.applications.excludeApplications.Count -gt 10) {
                    $policyName = $policy.displayName
                    $excludeCount = $conditions.applications.excludeApplications.Count
                    $remediation += "Policy '$policyName' excludes $excludeCount apps"
                    $affectedCount++
                }
            }
        }
        
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = $severity
            Status = if ($affectedCount -eq 0) { 'Pass' } else { 'Warning' }
            Findings = if ($affectedCount -gt 0) { @(
                @{
                    Title = 'Conditional Access Grant All Policies'
                    Description = "$affectedCount CA policies with potentially overly permissive grant settings"
                    Remediation = $remediation -join '; '
                    AffectedCount = $affectedCount
                    Confidence = 'High'
                }
            ) } else { @() }
            Timestamp = (Get-Date -Format 'o')
        }
    }
    catch {
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = 'High'
            Status = 'Error'
            Findings = @(
                @{
                    Title = 'Unable to retrieve CA policies'
                    Description = $_.Exception.Message
                    Remediation = 'Verify Microsoft Graph API access'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}

function Invoke-EntraIdExternalCollaborationCheck {
    <#
    .SYNOPSIS
        Checks external collaboration settings and B2B policies
    .DESCRIPTION
        Verifies B2B invite settings, cross-tenant access, and guest restrictions
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$TenantId,
        
        [Parameter(Mandatory=$false)]
        [pscredential]$Credential
    )
    
    $checkId = 'IDF-ENT-B2B-001'
    $checkName = 'External Collaboration Configuration'
    $category = 'Entra ID - B2B'
    $severity = 'High'
    
    try {
        $graphParams = @{}
        if ($TenantId) { $graphParams['TenantId'] = $TenantId }
        if ($Credential) { $graphParams['Credential'] = $Credential }
        
        $null = Connect-MgGraph @graphParams -Scopes 'Policy.Read.All,Directory.Read.All' -NoWelcome
        
        $remediation = @()
        $affectedCount = 0
        
        $b2bUri = '/beta/policies/identitySecurityDefaultEnforcementPolicy'
        $b2bPolicy = Invoke-MgGraphRequest -Method GET -Uri $b2bUri -ErrorAction Stop
        
        $crossTenantUri = '/beta/policies/crossTenantAccessPolicy'
        $crossTenant = Invoke-MgGraphRequest -Method GET -Uri $crossTenantUri -ErrorAction Stop
        
        if ($crossTenant.tenantRestrictions -and 
            $crossTenant.tenantRestrictions.mode -ne 'BlockIncoming') {
            $remediation += 'Consider implementing cross-tenant access restrictions'
            $affectedCount++
        }
        
        $orgUri = '/beta/organization'
        $org = Invoke-MgGraphRequest -Method GET -Uri $orgUri -ErrorAction Stop
        
        if ($org.Value[0].settings) {
            $settings = $org.Value[0].settings
            
            if ($settings.allowGuests -eq $true -and $settings.allowGuestsToInviteFriends -eq $true) {
                $remediation += 'Guest users can invite other guests - consider restricting to admins only'
                $affectedCount++
            }
            
            if ($settings.allowInvitesFrom -eq 'everyone') {
                $remediation += 'Any member can invite guests - consider restricting to admins/特定 roles'
                $affectedCount++
            }
        }
        
        $usersUri = '/beta/users?$filter=userType eq ''Guest'''
        $guests = Invoke-MgGraphRequest -Method GET -Uri $usersUri -ErrorAction Stop
        
        $guestCount = $guests.Value.Count
        if ($guestCount -gt 100) {
            $remediation += "Review active guest accounts - $guestCount guest users in tenant"
            $affectedCount++
        }
        
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = $severity
            Status = if ($affectedCount -eq 0) { 'Pass' } else { 'Warning' }
            Findings = if ($affectedCount -gt 0) { @(
                @{
                    Title = 'External Collaboration Settings Review'
                    Description = "$affectedCount collaboration settings need review"
                    Remediation = $remediation -join '; '
                    AffectedCount = $affectedCount
                    Confidence = 'High'
                }
            ) } else { @() }
            Timestamp = (Get-Date -Format 'o')
        }
    }
    catch {
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = 'High'
            Status = 'Error'
            Findings = @(
                @{
                    Title = 'Unable to retrieve external collaboration settings'
                    Description = $_.Exception.Message
                    Remediation = 'Verify Microsoft Graph API access'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}

function Invoke-EntraIdCertificateExpiryCheck {
    <#
    .SYNOPSIS
        Checks for expiring service principal certificates and secrets
    .DESCRIPTION
        Identifies certificates and secrets expiring within 30/60/90 days
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$TenantId,
        
        [Parameter(Mandatory=$false)]
        [pscredential]$Credential
    )
    
    $checkId = 'IDF-ENT-CERT-001'
    $checkName = 'Certificate and Secret Expiry'
    $category = 'Entra ID - Applications'
    $severity = 'High'
    
    try {
        $graphParams = @{}
        if ($TenantId) { $graphParams['TenantId'] = $TenantId }
        if ($Credential) { $graphParams['Credential'] = $Credential }
        
        $null = Connect-MgGraph @graphParams -Scopes 'Application.Read.All' -NoWelcome
        
        $remediation = @()
        $affectedCount = 0
        $expiring30 = 0
        $expiring60 = 0
        $expiring90 = 0
        
        $spUri = '/beta/servicePrincipals'
        $sps = Invoke-MgGraphRequest -Method GET -Uri $spUri -ErrorAction Stop
        
        foreach ($sp in $sps.Value) {
            if ($sp.keyCredentials) {
                foreach ($key in $sp.keyCredentials) {
                    $endDate = [DateTime]$key.endDateTime
                    $daysUntilExpiry = ($endDate - (Get-Date)).Days
                    
                    if ($daysUntilExpiry -le 30) {
                        $spName = $sp.displayName
                        $remediation += "SP $spName`: cert expiring in $daysUntilExpiry days"
                        $expiring30++
                        $affectedCount++
                    }
                    elseif ($daysUntilExpiry -le 60) {
                        $expiring60++
                    }
                    elseif ($daysUntilExpiry -le 90) {
                        $expiring90++
                    }
                }
            }
            
            if ($sp.passwordCredentials) {
                foreach ($pwd in $sp.passwordCredentials) {
                    $endDate = [DateTime]$pwd.endDateTime
                    $daysUntilExpiry = ($endDate - (Get-Date)).Days
                    
                    if ($daysUntilExpiry -le 30) {
                        $spName = $sp.displayName
                        $remediation += "SP $spName`: secret expiring in $daysUntilExpiry days"
                        $expiring30++
                        $affectedCount++
                    }
                    elseif ($daysUntilExpiry -le 60) {
                        $expiring60++
                    }
                    elseif ($daysUntilExpiry -le 90) {
                        $expiring90++
                    }
                }
            }
        }
        
        $description = "Expiring within 30 days: $expiring30, 60 days: $expiring60, 90 days: $expiring90"
        
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = if ($expiring30 -gt 0) { 'Critical' } elseif ($expiring60 -gt 0) { 'High' } else { 'Medium' }
            Status = if ($affectedCount -eq 0) { 'Pass' } else { 'Warning' }
            Findings = if ($affectedCount -gt 0) { @(
                @{
                    Title = 'Certificate and Secret Expiry Alert'
                    Description = $description
                    Remediation = $remediation -join '; '
                    AffectedCount = $affectedCount
                    Confidence = 'High'
                }
            ) } else { @() }
            Timestamp = (Get-Date -Format 'o')
        }
    }
    catch {
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = 'High'
            Status = 'Error'
            Findings = @(
                @{
                    Title = 'Unable to retrieve certificate/secret information'
                    Description = $_.Exception.Message
                    Remediation = 'Verify Microsoft Graph API access'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}
#endregion

#region Azure AD Connect Checks
function Invoke-AADConnectHealthCheck {
    <#
    .SYNOPSIS
        Checks Azure AD Connect health and configuration
    .DESCRIPTION
        Verifies sync health, version, and configuration drift
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ServerName
    )
    
    $checkId = 'IDF-AAD-CONN-001'
    $checkName = 'Azure AD Connect Configuration'
    $category = 'Hybrid Identity - Sync'
    $severity = 'Medium'
    
    try {
        $remediation = @()
        $affectedCount = 0
        
        $aadConnectPath = 'C:\Program Files\Microsoft Azure AD Connect\Sync\Microsoft.Azure AD Connect sync.exe'
        if (Test-Path $aadConnectPath) {
            $versionInfo = (Get-Item $aadConnectPath).VersionInfo
            $version = $versionInfo.ProductVersion
            
            $versionDate = $versionInfo.FileModifiedDate
            if ($versionDate) {
                $monthsOld = ((Get-Date) - $versionDate).Days / 30
                if ($monthsOld -gt 18) {
                    $remediation += "Azure AD Connect is $monthsOld months old - consider upgrading"
                    $affectedCount++
                }
            }
        }
        else {
            $remediation += 'Azure AD Connect not found on this server - run from AAD Connect server'
            $affectedCount++
        }
        
        try {
            $syncService = Get-Service 'ADSync' -ErrorAction Stop
            if ($syncService.Status -ne 'Running') {
                $remediation += 'ADSync service is not running'
                $affectedCount++
            }
        }
        catch {
            $remediation += 'ADSync service not found - verify Azure AD Connect installation'
            $affectedCount++
        }
        
        $regPath = 'HKLM:\SOFTWARE\Microsoft\Azure AD Connect'
        if (Test-Path $regPath) {
            $autoUpgrade = Get-ItemProperty -Path $regPath -Name 'AutoUpgrade' -ErrorAction SilentlyContinue
            if ($autoUpgrade -and $autoUpgrade.AutoUpgrade -ne 'Enabled') {
                $remediation += 'Azure AD Connect auto-upgrade is disabled'
                $affectedCount++
            }
        }
        
        $schedulerPath = 'HKLM:\SOFTWARE\Microsoft\MSOL'
        if (Test-Path $schedulerPath) {
            $scheduler = Get-ItemProperty -Path $schedulerPath -Name 'Scheduler' -ErrorAction SilentlyContinue
            if ($scheduler) {
                $syncInterval = $scheduler.SyncCycleInMinutes
                if ($syncInterval -gt 240) {
                    $remediation += "Sync interval is $syncInterval minutes - consider reducing to 30 minutes"
                    $affectedCount++
                }
            }
        }
        
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = $severity
            Status = if ($affectedCount -eq 0) { 'Pass' } else { 'Warning' }
            Findings = if ($affectedCount -gt 0) { @(
                @{
                    Title = 'Azure AD Connect Configuration Review'
                    Description = "$affectedCount configuration concerns"
                    Remediation = $remediation -join '; '
                    AffectedCount = $affectedCount
                    Confidence = 'High'
                }
            ) } else { @() }
            Timestamp = (Get-Date -Format 'o')
        }
    }
    catch {
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = 'High'
            Status = 'Error'
            Findings = @(
                @{
                    Title = 'Unable to check Azure AD Connect configuration'
                    Description = $_.Exception.Message
                    Remediation = 'Run from Azure AD Connect server with admin privileges'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}

function Invoke-AADConnectAttributeFlowCheck {
    <#
    .SYNOPSIS
        Checks Azure AD Connect attribute flow configurations
    .DESCRIPTION
        Reviews attribute sync rules and possible data leakage
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ServerName
    )
    
    $checkId = 'IDF-AAD-AF-001'
    $checkName = 'Attribute Flow Configuration'
    $category = 'Hybrid Identity - Sync'
    $severity = 'Medium'
    
    try {
        $remediation = @()
        $affectedCount = 0
        
        try {
            $null = Import-Module 'ADSync' -ErrorAction Stop
            $rules = Get-ADSyncRule -ErrorAction Stop
            
            $phsRules = $rules | Where-Object { $_.Name -match 'Password' -and $_.Direction -eq 'Inbound' }
            if (-not $phsRules) {
                $remediation += 'Password Hash Sync is not configured - users cannot sign in if AD is unavailable'
                $affectedCount++
            }
            
            $writebackRules = $rules | Where-Object { $_.Name -match 'Writeback' }
            if (-not $writebackRules) {
                $remediation += 'No attribute writeback rules found - cloud-only attributes not synced to AD'
                $affectedCount++
            }
            
            $sensitiveAttrs = @('unicodePwd', 'ntPwdHistory', 'lmPwdHistory', 'supplementalCredentials')
            foreach ($rule in $rules) {
                if ($rule.Transformations) {
                    foreach ($t in $rule.Transformations) {
                        if ($t.TargetAttribute -in $sensitiveAttrs) {
                            $ruleName = $rule.Name
                            $attrName = $t.TargetAttribute
                            $remediation += "Rule '$ruleName' flows sensitive attribute $attrName"
                            $affectedCount++
                        }
                    }
                }
            }
        }
        catch {
            $regPath = 'HKLM:\SOFTWARE\Microsoft\Azure AD Connect\Sync\Rules'
            if (Test-Path $regPath) {
                $regRules = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue
                if (-not $regRules) {
                    $remediation += 'Unable to read sync rules - verify ADSync installation'
                    $affectedCount++
                }
            }
        }
        
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = $severity
            Status = if ($affectedCount -eq 0) { 'Pass' } else { 'Warning' }
            Findings = if ($affectedCount -gt 0) { @(
                @{
                    Title = 'Attribute Flow Configuration Review'
                    Description = "$affectedCount attribute flow concerns"
                    Remediation = $remediation -join '; '
                    AffectedCount = $affectedCount
                    Confidence = 'High'
                }
            ) } else { @() }
            Timestamp = (Get-Date -Format 'o')
        }
    }
    catch {
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = 'High'
            Status = 'Error'
            Findings = @(
                @{
                    Title = 'Unable to check attribute flow configuration'
                    Description = $_.Exception.Message
                    Remediation = 'Run from Azure AD Connect server'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}
#endregion

#region Azure Key Vault Checks
function Invoke-AzKeyVaultSecretExpiryCheck {
    <#
    .SYNOPSIS
        Checks Azure Key Vault secrets and certificates expiry
    .DESCRIPTION
        Identifies expiring secrets and certificates across key vaults
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$SubscriptionId
    )
    
    $checkId = 'IDF-AZ-KV-001'
    $checkName = 'Key Vault Secret and Certificate Expiry'
    $category = 'Azure - Secrets Management'
    $severity = 'High'
    
    try {
        $null = Connect-AzAccount -ErrorAction Stop
        
        $remediation = @()
        $affectedCount = 0
        $expiringSecrets = 0
        $expiringCerts = 0
        
        if (-not $SubscriptionId) {
            $SubscriptionId = (Get-AzSubscription)[0].Id
        }
        
        $null = Set-AzContext -SubscriptionId $SubscriptionId
        
        $kvUri = "/subscriptions/$SubscriptionId/providers/Microsoft.KeyVault/vaults?api-version=2021-06-01-preview"
        $kvs = Invoke-AzRestMethod -Method GET -Uri $kvUri -ErrorAction Stop
        
        foreach ($kv in $kvs.Value) {
            $kvName = $kv.name
            $kvRg = $kv.id -replace '/subscriptions/[^/]+/resourceGroups/', '' -replace '/providers/Microsoft.KeyVault.*', ''
            
            $secretsUri = "/subscriptions/$SubscriptionId/resourceGroups/$kvRg/providers/Microsoft.KeyVault/vaults/$kvName/secrets?api-version=2021-06-01-preview"
            $secrets = Invoke-AzRestMethod -Method GET -Uri $secretsUri -ErrorAction Stop
            
            foreach ($secret in $secrets.Value) {
                $attrsUri = "/subscriptions/$SubscriptionId/resourceGroups/$kvRg/providers/Microsoft.KeyVault/vaults/$kvName/secrets/$($secret.name)/attributes?api-version=2021-06-01-preview"
                $attrs = Invoke-AzRestMethod -Method GET -Uri $attrsUri -ErrorAction Stop
                
                if ($attrs.attributes.exp) {
                    $expiryDate = [DateTime]::UnixTimeSecondsToDateTime($attrs.attributes.exp)
                    $daysUntilExpiry = ($expiryDate - (Get-Date)).Days
                    
                    if ($daysUntilExpiry -le 30) {
                        $secretName = $secret.name
                        $remediation += "Key Vault $kvName`: secret $secretName expires in $daysUntilExpiry days"
                        $expiringSecrets++
                        $affectedCount++
                    }
                }
                else {
                    $secretName = $secret.name
                    $remediation += "Key Vault $kvName`: secret $secretName has no expiry date set"
                    $affectedCount++
                }
            }
            
            $certsUri = "/subscriptions/$SubscriptionId/resourceGroups/$kvRg/providers/Microsoft.KeyVault/vaults/$kvName/certificates?api-version=2021-06-01-preview"
            $certs = Invoke-AzRestMethod -Method GET -Uri $certsUri -ErrorAction Stop
            
            foreach ($cert in $certs.Value) {
                $certAttrsUri = "/subscriptions/$SubscriptionId/resourceGroups/$kvRg/providers/Microsoft.KeyVault/vaults/$kvName/certificates/$($cert.name)/attributes?api-version=2021-06-01-preview"
                $certAttrs = Invoke-AzRestMethod -Method GET -Uri $certAttrsUri -ErrorAction Stop
                
                if ($certAttrs.attributes.exp) {
                    $expiryDate = [DateTime]::UnixTimeSecondsToDateTime($certAttrs.attributes.exp)
                    $daysUntilExpiry = ($expiryDate - (Get-Date)).Days
                    
                    if ($daysUntilExpiry -le 60) {
                        $certName = $cert.name
                        $remediation += "Key Vault $kvName`: certificate $certName expires in $daysUntilExpiry days"
                        $expiringCerts++
                        $affectedCount++
                    }
                }
            }
        }
        
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = if ($expiringCerts -gt 0) { 'Critical' } elseif ($expiringSecrets -gt 0) { 'High' } else { 'Medium' }
            Status = if ($affectedCount -eq 0) { 'Pass' } else { 'Warning' }
            Findings = if ($affectedCount -gt 0) { @(
                @{
                    Title = 'Key Vault Secret and Certificate Expiry'
                    Description = "Expiring secrets: $expiringSecrets, certificates: $expiringCerts"
                    Remediation = $remediation -join '; '
                    AffectedCount = $affectedCount
                    Confidence = 'High'
                }
            ) } else { @() }
            Timestamp = (Get-Date -Format 'o')
        }
    }
    catch {
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = 'High'
            Status = 'Error'
            Findings = @(
                @{
                    Title = 'Unable to retrieve Key Vault information'
                    Description = $_.Exception.Message
                    Remediation = 'Verify Azure connectivity and Key Vault permissions'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}

function Invoke-AzKeyVaultAccessPolicyCheck {
    <#
    .SYNOPSIS
        Checks Key Vault access policies
    .DESCRIPTION
        Verifies RBAC and access policy configurations
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$SubscriptionId
    )
    
    $checkId = 'IDF-AZ-KV-AP-001'
    $checkName = 'Key Vault Access Policy Configuration'
    $category = 'Azure - Secrets Management'
    $severity = 'High'
    
    try {
        $null = Connect-AzAccount -ErrorAction Stop
        
        $remediation = @()
        $affectedCount = 0
        
        if (-not $SubscriptionId) {
            $SubscriptionId = (Get-AzSubscription)[0].Id
        }
        
        $null = Set-AzContext -SubscriptionId $SubscriptionId
        
        $kvUri = "/subscriptions/$SubscriptionId/providers/Microsoft.KeyVault/vaults?api-version=2021-06-01-preview"
        $kvs = Invoke-AzRestMethod -Method GET -Uri $kvUri -ErrorAction Stop
        
        foreach ($kv in $kvs.Value) {
            $kvName = $kv.name
            $kvRg = $kv.id -replace '/subscriptions/[^/]+/resourceGroups/', '' -replace '/providers/Microsoft.KeyVault.*', ''
            
            $accessPoliciesUri = "/subscriptions/$SubscriptionId/resourceGroups/$kvRg/providers/Microsoft.KeyVault/vaults/$kvName/accessPolicies?api-version=2021-06-01-preview"
            $accessPolicies = Invoke-AzRestMethod -Method GET -Uri $accessPoliciesUri -ErrorAction Stop
            
            if ($accessPolicies.Value) {
                foreach ($policy in $accessPolicies.Value) {
                    $permissions = $policy.properties.permissions
                    
                    $secretPerms = $permissions.secrets
                    if ($secretPerms -contains 'get' -and $secretPerms -contains 'list' -and $secretPerms -contains 'delete') {
                        $objId = $policy.properties.accessPolicies[0].objectId
                        $remediation += "Key Vault $kvName`: broad secret permissions for $objId"
                        $affectedCount++
                    }
                    
                    $keyPerms = $permissions.keys
                    if ($keyPerms -contains 'get' -and $keyPerms -contains 'list' -and $keyPerms -contains 'delete' -and $keyPerms -contains 'wrapKey') {
                        $remediation += "Key Vault $kvName`: broad key permissions including key wrap"
                        $affectedCount++
                    }
                }
            }
            
            if ($kv.properties.networkAcls -and $kv.properties.networkAcls.defaultAction -eq 'Allow') {
                $remediation += "Key Vault $kvName allows public network access"
                $affectedCount++
            }
        }
        
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = $severity
            Status = if ($affectedCount -eq 0) { 'Pass' } else { 'Warning' }
            Findings = if ($affectedCount -gt 0) { @(
                @{
                    Title = 'Key Vault Access Policy Review'
                    Description = "$affectedCount access policy concerns"
                    Remediation = $remediation -join '; '
                    AffectedCount = $affectedCount
                    Confidence = 'High'
                }
            ) } else { @() }
            Timestamp = (Get-Date -Format 'o')
        }
    }
    catch {
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = 'High'
            Status = 'Error'
            Findings = @(
                @{
                    Title = 'Unable to check Key Vault access policies'
                    Description = $_.Exception.Message
                    Remediation = 'Verify Azure connectivity'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}
#endregion

#region AWS IAM Extended Checks
function Invoke-AwsIamPasswordPolicyCheck {
    <#
    .SYNOPSIS
        Checks AWS IAM password policy configuration
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Region = 'us-east-1'
    )
    
    $checkId = 'IDF-AWS-IAM-PW-001'
    $checkName = 'IAM Password Policy Configuration'
    $category = 'AWS - IAM'
    $severity = 'Medium'
    
    try {
        $null = Initialize-AWSDefaultConfiguration -Region $Region -ErrorAction Stop
        
        $remediation = @()
        $affectedCount = 0
        
        $policy = Get-IAMAccountPasswordPolicy -ErrorAction Stop
        
        if (-not $policy) {
            $remediation += 'No IAM password policy configured - implement password requirements'
            $affectedCount = 1
        }
        else {
            if ($policy.MinimumPasswordLength -lt 14) {
                $currentLen = $policy.MinimumPasswordLength
                $remediation += "Increase minimum password length (current: $currentLen, recommended: 14)"
                $affectedCount++
            }
            
            if (-not $policy.RequireUppercaseCharacters) {
                $remediation += 'Enable uppercase character requirement'
                $affectedCount++
            }
            
            if (-not $policy.RequireLowercaseCharacters) {
                $remediation += 'Enable lowercase character requirement'
                $affectedCount++
            }
            
            if (-not $policy.RequireNumbers) {
                $remediation += 'Enable number requirement'
                $affectedCount++
            }
            
            if (-not $policy.RequireSymbols) {
                $remediation += 'Enable symbol requirement'
                $affectedCount++
            }
            
            if ($policy.MaxPasswordAge -lt 90) {
                $currentAge = $policy.MaxPasswordAge
                $remediation += "Increase password expiration (current: $currentAge days, recommended: 90)"
                $affectedCount++
            }
            
            if ($policy.PasswordReusePrevention -lt 24) {
                $currentReuse = $policy.PasswordReusePrevention
                $remediation += "Increase password reuse prevention (current: $currentReuse, recommended: 24)"
                $affectedCount++
            }
            
            if (-not $policy.HardExpiry) {
                $remediation += 'Enable hard expiry to prevent expired password use'
                $affectedCount++
            }
        }
        
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = $severity
            Status = if ($affectedCount -eq 0) { 'Pass' } else { 'Warning' }
            Findings = if ($affectedCount -gt 0) { @(
                @{
                    Title = 'IAM Password Policy Review'
                    Description = "$affectedCount password policy improvements needed"
                    Remediation = $remediation -join '; '
                    AffectedCount = $affectedCount
                    Confidence = 'High'
                }
            ) } else { @() }
            Timestamp = (Get-Date -Format 'o')
        }
    }
    catch {
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = 'High'
            Status = 'Error'
            Findings = @(
                @{
                    Title = 'Unable to retrieve IAM password policy'
                    Description = $_.Exception.Message
                    Remediation = 'Verify AWS IAM permissions'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}

function Invoke-AwsIamUnusedCredentialsCheck {
    <#
    .SYNOPSIS
        Checks for unused IAM credentials
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Region = 'us-east-1'
    )
    
    $checkId = 'IDF-AWS-IAM-UC-001'
    $checkName = 'Unused IAM Credentials'
    $category = 'AWS - IAM'
    $severity = 'High'
    
    try {
        $null = Initialize-AWSDefaultConfiguration -Region $Region -ErrorAction Stop
        
        $remediation = @()
        $affectedCount = 0
        
        $users = Get-IAMUsers -ErrorAction Stop
        
        foreach ($user in $users.Users) {
            $accessKeys = Get-IAMAccessKeyLastUsed -UserName $user.UserName -ErrorAction Stop
            
            foreach ($key in $accessKeys.AccessKeyMetadata) {
                if (-not $key.LastUsedDate -or 
                    ((Get-Date) - $key.LastUsedDate).Days -gt 90) {
                    $userName = $user.UserName
                    $keyId = $key.AccessKeyId
                    $remediation += "User $userName`: access key $keyId unused for > 90 days"
                    $affectedCount++
                }
            }
            
            try {
                $loginProfile = Get-IAMLoginProfile -UserName $user.UserName -ErrorAction Stop
                if ($loginProfile.CreateDate) {
                    $daysSinceCreation = ((Get-Date) - $loginProfile.CreateDate).Days
                    if ($daysSinceCreation -gt 90) {
                        $userName = $user.UserName
                        $remediation += "User $userName`: console password unused for $daysSinceCreation days"
                        $affectedCount++
                    }
                }
            }
            catch {
            }
        }
        
        foreach ($user in $users.Users) {
            if ($user.PasswordLastUsed) {
                $daysSinceLogin = ((Get-Date) - $user.PasswordLastUsed).Days
                if ($daysSinceLogin -gt 90) {
                    $userName = $user.UserName
                    $remediation += "User $userName`: no login for $daysSinceLogin days - consider disabling"
                    $affectedCount++
                }
            }
        }
        
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = $severity
            Status = if ($affectedCount -eq 0) { 'Pass' } else { 'Warning' }
            Findings = if ($affectedCount -gt 0) { @(
                @{
                    Title = 'Unused IAM Credentials Detection'
                    Description = "$affectedCount unused credentials found"
                    Remediation = $remediation -join '; '
                    AffectedCount = $affectedCount
                    Confidence = 'High'
                }
            ) } else { @() }
            Timestamp = (Get-Date -Format 'o')
        }
    }
    catch {
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = 'High'
            Status = 'Error'
            Findings = @(
                @{
                    Title = 'Unable to check unused credentials'
                    Description = $_.Exception.Message
                    Remediation = 'Verify AWS IAM permissions'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}

function Invoke-AwsIamUserMfaCheck {
    <#
    .SYNOPSIS
        Checks for IAM users without MFA enabled
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Region = 'us-east-1'
    )
    
    $checkId = 'IDF-AWS-IAM-MFA-001'
    $checkName = 'IAM User MFA Enforcement'
    $category = 'AWS - IAM'
    $severity = 'Critical'
    
    try {
        $null = Initialize-AWSDefaultConfiguration -Region $Region -ErrorAction Stop
        
        $remediation = @()
        $affectedCount = 0
        
        $users = Get-IAMUsers -ErrorAction Stop
        
        foreach ($user in $users.Users) {
            $mfaDevices = Get-IAMUserMFADevice -UserName $user.UserName -ErrorAction Stop
            
            try {
                $loginProfile = Get-IAMLoginProfile -UserName $user.UserName -ErrorAction Stop
                $hasConsoleAccess = $true
            }
            catch {
                $hasConsoleAccess = $false
            }
            
            if ($hasConsoleAccess -and -not $mfaDevices) {
                $userName = $user.UserName
                $remediation += "User $userName has console access without MFA"
                $affectedCount++
            }
        }
        
        $iamSummary = Get-IAMAccountSummary -ErrorAction Stop
        $summaryMap = $iamSummary.SummaryMap
        if ($summaryMap['AccountMFAEnabled'] -ne 1) {
            $remediation += 'Enable require MFA for root account in IAM settings'
            $affectedCount++
        }
        
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = $severity
            Status = if ($affectedCount -eq 0) { 'Pass' } else { 'Warning' }
            Findings = if ($affectedCount -gt 0) { @(
                @{
                    Title = 'IAM Users Without MFA'
                    Description = "$affectedCount users with console access lack MFA"
                    Remediation = $remediation -join '; '
                    AffectedCount = $affectedCount
                    Confidence = 'High'
                }
            ) } else { @() }
            Timestamp = (Get-Date -Format 'o')
        }
    }
    catch {
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = 'High'
            Status = 'Error'
            Findings = @(
                @{
                    Title = 'Unable to check MFA status'
                    Description = $_.Exception.Message
                    Remediation = 'Verify AWS IAM permissions'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}
#endregion

#region GCP Organization Checks
function Invoke-GcpOrganizationMonitoringCheck {
    <#
    .SYNOPSIS
        Checks GCP organization-level monitoring and logging
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$OrganizationId
    )
    
    $checkId = 'IDF-GCP-MON-001'
    $checkName = 'Organization Monitoring Configuration'
    $category = 'GCP - Operations'
    $severity = 'High'
    
    try {
        $remediation = @()
        $affectedCount = 0
        
        $gcloudPath = (Get-Command gcloud -ErrorAction SilentlyContinue).Path
        if (-not $gcloudPath) {
            throw 'Google Cloud SDK not installed'
        }
        
        if (-not $OrganizationId) {
            $orgResult = gcloud organizations list --format=value --limit=1 2>$null
            if ($LASTEXITCODE -ne 0 -or -not $orgResult) {
                throw 'No organization found'
            }
            $OrganizationId = $orgResult
        }
        
        $sinksResult = gcloud logging sinks list --organization=$OrganizationId --format=json 2>$null
        if ($LASTEXITCODE -eq 0 -and $sinksResult) {
            $sinks = $sinksResult | ConvertFrom-Json
            $logSinks = ($sinks | Where-Object { $_.sinkType -eq 'storage' -or $_.sinkType -eq 'bigquery' }).Count
            
            if ($logSinks -eq 0) {
                $remediation += 'Create logging sinks for audit log retention'
                $affectedCount++
            }
        }
        else {
            $remediation += 'Enable Cloud Logging for the organization'
            $affectedCount++
        }
        
        $auditConfigResult = gcloud organizations get-iam-policy $OrganizationId --filter='bindings.role:roles/logging.configWriter' --format=json 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $auditConfigResult) {
            $remediation += 'Configure organization-level audit logging'
            $affectedCount++
        }
        
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = $severity
            Status = if ($affectedCount -eq 0) { 'Pass' } else { 'Warning' }
            Findings = if ($affectedCount -gt 0) { @(
                @{
                    Title = 'Organization Monitoring Review'
                    Description = "$affectedCount monitoring concerns"
                    Remediation = $remediation -join '; '
                    AffectedCount = $affectedCount
                    Confidence = 'High'
                }
            ) } else { @() }
            Timestamp = (Get-Date -Format 'o')
        }
    }
    catch {
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = 'High'
            Status = 'Error'
            Findings = @(
                @{
                    Title = 'Unable to check organization monitoring'
                    Description = $_.Exception.Message
                    Remediation = 'Verify Google Cloud SDK and permissions'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}

function Invoke-GcpAssetInventoryCheck {
    <#
    .SYNOPSIS
        Checks GCP Cloud Asset Inventory configuration
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$OrganizationId
    )
    
    $checkId = 'IDF-GCP-ASSET-001'
    $checkName = 'Cloud Asset Inventory Configuration'
    $category = 'GCP - Asset Management'
    $severity = 'Medium'
    
    try {
        $remediation = @()
        $affectedCount = 0
        
        $gcloudPath = (Get-Command gcloud -ErrorAction SilentlyContinue).Path
        if (-not $gcloudPath) {
            throw 'Google Cloud SDK not installed'
        }
        
        if (-not $OrganizationId) {
            $orgResult = gcloud organizations list --format=value --limit=1 2>$null
            if ($LASTEXITCODE -ne 0 -or -not $orgResult) {
                throw 'No organization found'
            }
            $OrganizationId = $orgResult
        }
        
        $apiResult = gcloud services list --enabled --filter='name:cloudasset.googleapis.com' --format=value 2>$null
        if (-not $apiResult) {
            $remediation += 'Enable Cloud Asset API for inventory tracking'
            $affectedCount++
        }
        
        $feedsResult = gcloud asset feeds list --organization=$OrganizationId --format=json 2>$null
        if ($LASTEXITCODE -eq 0 -and $feedsResult) {
            $feeds = $feedsResult | ConvertFrom-Json
            if ($feeds.Count -eq 0) {
                $remediation += 'Create asset feeds for real-time change notifications'
                $affectedCount++
            }
        }
        else {
            $remediation += 'Enable Cloud Asset feeds for monitoring'
            $affectedCount++
        }
        
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = $severity
            Status = if ($affectedCount -eq 0) { 'Pass' } else { 'Warning' }
            Findings = if ($affectedCount -gt 0) { @(
                @{
                    Title = 'Cloud Asset Inventory Review'
                    Description = "$affectedCount asset inventory concerns"
                    Remediation = $remediation -join '; '
                    AffectedCount = $affectedCount
                    Confidence = 'High'
                }
            ) } else { @() }
            Timestamp = (Get-Date -Format 'o')
        }
    }
    catch {
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = 'High'
            Status = 'Error'
            Findings = @(
                @{
                    Title = 'Unable to check asset inventory'
                    Description = $_.Exception.Message
                    Remediation = 'Verify Google Cloud SDK and permissions'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}
#endregion

# Export module functions
Export-ModuleMember -Function @(
    'Invoke-EntraIdCAGrantAllCheck',
    'Invoke-EntraIdExternalCollaborationCheck',
    'Invoke-EntraIdCertificateExpiryCheck',
    'Invoke-AADConnectHealthCheck',
    'Invoke-AADConnectAttributeFlowCheck',
    'Invoke-AzKeyVaultSecretExpiryCheck',
    'Invoke-AzKeyVaultAccessPolicyCheck',
    'Invoke-AwsIamPasswordPolicyCheck',
    'Invoke-AwsIamUnusedCredentialsCheck',
    'Invoke-AwsIamUserMfaCheck',
    'Invoke-GcpOrganizationMonitoringCheck',
    'Invoke-GcpAssetInventoryCheck'
)

# SIG # Begin signature block
# MIIf3QYJKoZIhvcNAQcCoIIfzjCCH8oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC3Oybdv1cQgBxv
# LxHXJr/g/FrB6ska1Dqw6DN5tsO/SqCCGNwwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# AgEVMC8GCSqGSIb3DQEJBDEiBCBYnLmjJMAtMQ67Gw66rwVkMr73p7qOkrWrgOoe
# UaHQ4DANBgkqhkiG9w0BAQEFAASCAgCRnWQUK6/wGhnnOWxCBN6LmF4nS+Ed3UXD
# hcXZ7HKfo3/zkkXwnkrMQHAmFCCrsbmWhRB8oM4dH3uvv5mRtXLvWBC+UK1YIg1L
# lEjA1ews5xM+4E1fFnHBzzhx+WfbjBJnEw3TbXQl9f2ug19mA+OQDYGwsz1ojSxa
# 7LFe0kFJjdAQYNcYuwoIIlBlbiH2iz7sIGA69I65qT5Bx7NGBL/lEZe4DFogFxzK
# IYSG/sL9jIT4a7aqY10bautH1TzAP3YoJXjsk+dW2WD3GOI21y2YKGCHMu3TdD5+
# V+28KI3Hf1dl6qcFtOd2BebQHrE5avQW5MQseezsFU8ir4vda3A7HSrXrxnh23iB
# +YtiTE4A8fUgFgpy+Y+FTiBqnm9xN4Y91uZbkpP77OV4NAHlbGdf9jS4FrJqbiwS
# qpABazt7A6pkGC4GaaaMH40nMH5Sa00+pM3IrN4LQOOTmPsPLbs/1t/QCgZj62rQ
# 9n3/Gif/wrSYCfqyOALNmN46v05GbmMpngrLL6QicTBXMij6inAzJgqsF15crKDQ
# cgwoOHMTEmzzzERdl+Id5ExZj7iqgk0iTkPKN2RGpm0umqjhkViDRafIl1GSHDt4
# GTTidsFd6idBowI3jh3qFT8EYg1H6T/4hTFCwHwaYs8S7svl9m5OA0hpTZN4D6eP
# kJex13kPvaGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAyMDUxNzEyNDVaMC8G
# CSqGSIb3DQEJBDEiBCBmW7hDS5dtfsOxbkO1MSdr/Zf4mYsSWUBnsFmBNpvgPDAN
# BgkqhkiG9w0BAQEFAASCAgBeHxpRvNeE2Oka3y9YwSK90vcH6+vXPDZxnNm2sDXS
# nM4GFxJyxM6Qk6yX0tVQ23pqsXBU6WGfodnm+heqMImuu6qHAyZiCEzYgyX56g/4
# CfgvyuUmqp838MDmJSEGywnNxE+sf2fFaosGpGkhL+37RVeAA4tZJYPJVWm+8TRA
# YN4Lkahfkv1Q+3q3mYW8tx3fD0gGCidsZTR2uBhZqKnqf8z2p3z3CtqTsOY/hEiD
# BG6DwZ3F2oYpY3uEVatL7vNj0uNrpNWgQ6R/FHAibMP/9kPVCrDfOc+b2qczG7Kn
# vxk4NqC/1tl95zApd/ixyLs5JR77J4u4H+JgcJfVqXJIz/u8RQuyv+hox4CfslCQ
# n120C1ybe7ooLrh7Ho7ouNPkbCZ4PQKy/30nAZSee8BP3AVu9ldybakxIM8iGlhQ
# 37oU2XX51lJLhAf6vj14EcLqc54x2b+/QYknJqMfQeo/dUf2LgnqDep7X79xfR90
# WlUMU2gauRcIDPB13zqEJkWEG2gePfwdXNemCwx4Zm5afO4jdeuxoe6XSMXTOJ2F
# 6HRFeZR0lPAWOUE1as7+QeuchgriBLV5qQ/F2u7Wjk5q+CUmMz7dMGbVC4fSVX+w
# +rKm1avIBPqZ/0nUADwxwJzVoYYivxVt74B0e0kzLDM2xpr3trKXVVpf9skK/kyO
# HQ==
# SIG # End signature block
