
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
# Module Type: Additional

$script:DefaultThresholds = @{
    SensitivityThreshold = 5
    RiskScoreThreshold = 70
}

# Severity and Status Definitions
$script:FindingSeverity = @{ Critical = "Critical"; High = "High"; Medium = "Medium"; Low = "Low"; Info = "Info" }
$script:HealthStatus = @{ Healthy = "Healthy"; Warning = "Warning"; Critical = "Critical" }
# ============================================================================
# IdentityFirst QuickChecks - Additional Security Checks Module
# ============================================================================
# PowerShell 5.1 Compatible Module with Cross-Platform Support
# Contains additional security checks beyond the core modules
# ============================================================================

#requires -Version 5.1

#region Prerequisites Validation
function Test-Prerequisites {
    <#
    .SYNOPSIS
        Validates all prerequisites for running QuickChecks
    .DESCRIPTION
        Checks for required modules, permissions, and connectivity
    .OUTPUTS
        PSCustomObject with prerequisites status
    #>
    
    [CmdletBinding()]
    param()
    
    $result = @{
        PrerequisitesMet = $true
        Checks = @()
        MissingComponents = @()
        ModuleVersion = $MyInvocation.MyCommand.ScriptBlock.File
    }
    
    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    $result.Checks += @{
        Name = 'PowerShell Version'
        Status = $psVersion.Major -ge 5
        Detail = "Version: $($psVersion.ToString())"
        Required = '5.1+'
    }
    if ($psVersion.Major -lt 5) {
        $result.PrerequisitesMet = $false
    }
    
    # Check for required modules
    $requiredModules = @('AzureAD', 'Az.Accounts', 'AWS.Tools.Common', 'Google.Cloud.SecurityCenter.V1')
    foreach ($mod in $requiredModules) {
        $moduleAvailable = $null -ne (Get-Module -ListAvailable -Name $mod -ErrorAction SilentlyContinue)
        $result.Checks += @{
            Name = "Module: $mod"
            Status = $moduleAvailable
            Detail = if ($moduleAvailable) { 'Available' } else { 'Not installed' }
            Required = 'Optional'
        }
    }
    
    # Check for ActiveDirectory module (Windows only)
    if ($IsWindows -or (-not $PSBoundParameters.ContainsKey('IsWindows'))) {
        try {
            $adModule = Get-Module -ListAvailable -Name 'ActiveDirectory' -ErrorAction SilentlyContinue
            $result.Checks += @{
                Name = 'ActiveDirectory Module'
                Status = $null -ne $adModule
                Detail = if ($null -ne $adModule) { 'Available' } else { 'Not installed' }
                Required = 'Windows Server'
            }
        }
        catch {
            $result.Checks += @{
                Name = 'ActiveDirectory Module'
                Status = $false
                Detail = 'Error checking: $($_.Exception.Message)'
                Required = 'Windows Server'
            }
        }
    }
    
    # Check connectivity
    $connectivityChecks = @(
        @{ Host = 'login.microsoftonline.com'; Port = 443; Protocol = 'HTTPS' }
        @{ Host = 'graph.microsoft.com'; Port = 443; Protocol = 'HTTPS' }
    )
    
    foreach ($check in $connectivityChecks) {
        try {
            $tcpClient = New-Object Net.Sockets.TcpClient
            $tcpClient.Connect($check.Host, $check.Port)
            $tcpClient.Close()
            $status = $true
        }
        catch {
            $status = $false
            $result.PrerequisitesMet = $false
        }
        $result.Checks += @{
            Name = "Connectivity: $($check.Host):$($check.Port)"
            Status = $status
            Detail = "$($check.Protocol) $($check.Host):$($check.Port)"
            Required = 'Network access'
        }
    }
    
    # Check execution policy
    $execPolicy = Get-ExecutionPolicy -Scope CurrentUser
    $allowedPolicies = @('RemoteSigned', 'Unrestricted', 'Bypass')
    $policyOk = $allowedPolicies -contains $execPolicy
    $result.Checks += @{
        Name = 'Execution Policy'
        Status = $policyOk
        Detail = "Current: $execPolicy"
        Required = 'RemoteSigned or Bypass'
    }
    
    # Check PowerShell Gallery access (for module installation)
    try {
        $null = Invoke-RestMethod -Uri 'https://www.powershellgallery.com/api/v2' -TimeoutSec 5
        $psGalleryOk = $true
    }
    catch {
        $psGalleryOk = $false
    }
    $result.Checks += @{
        Name = 'PowerShell Gallery Access'
        Status = $psGalleryOk
        Detail = if ($psGalleryOk) { 'Accessible' } else { 'Not accessible' }
        Required = 'Optional (for module installation)'
    }
    
    return $result
}
#endregion

#region Entra ID Additional Checks
function Invoke-EntraIdAccessReviewCheck {
    <#
    .SYNOPSIS
        Checks for Access Review configurations in Entra ID
    .DESCRIPTION
        Verifies that access reviews are configured for privileged roles and guest access
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$TenantId,
        
        [Parameter(Mandatory=$false)]
        [pscredential]$Credential
    )
    
    $checkId = 'IDF-ENT-AR-001'
    $checkName = 'Access Review Configuration'
    $category = 'Entra ID - Governance'
    $severity = 'Medium'
    
    try {
        # Connect to Graph API
        $graphParams = @{
            ErrorAction = 'Stop'
        }
        if ($TenantId) { $graphParams['TenantId'] = $TenantId }
        if ($Credential) { $graphParams['Credential'] = $Credential }
        
        $null = Connect-MgGraph @graphParams -Scopes 'Policy.Read.All,Directory.Read.All' -NoWelcome
        
        # Check for access review policies
        $accessReviewUri = '/beta/policies/identityGovernancePolicies'
        $accessReviews = Invoke-MgGraphRequest -Method GET -Uri $accessReviewUri -ErrorAction Stop
        
        $remediation = @()
        $affectedCount = 0
        
        # Check if access reviews are enabled for privileged access
        $privilegedAccessReviews = $accessReviews.Value | Where-Object {
            $_.Contains('accessReview') -or $_.Contains('privilegedAccess')
        }
        
        if (-not $privilegedAccessReviews) {
            $remediation += 'Configure Access Reviews for Azure AD privileged roles'
            $affectedCount = 1
        }
        
        # Check for guest access reviews
        $guestAccessReviews = $accessReviews.Value | Where-Object {
            $_.Contains('guest') -or $_.Contains('b2b')
        }
        
        if (-not $guestAccessReviews) {
            $remediation += 'Configure periodic access reviews for guest accounts'
            $affectedCount++
        }
        
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = $severity
            Status = if ($affectedCount -eq 0) { 'Pass' } else { 'Fail' }
            Findings = if ($affectedCount -gt 0) { @(
                @{
                    Title = 'Missing Access Review Configuration'
                    Description = 'Access reviews are not configured for privileged roles or guest access'
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
                    Title = 'Unable to retrieve Access Review configuration'
                    Description = "Error: $($_.Exception.Message)"
                    Remediation = 'Verify Microsoft Graph API connectivity and permissions'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}

function Invoke-EntraIdEntitlementManagementCheck {
    <#
    .SYNOPSIS
        Checks Entitlement Management configuration in Entra ID
    .DESCRIPTION
        Verifies access package policies and assignment requirements
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$TenantId,
        
        [Parameter(Mandatory=$false)]
        [pscredential]$Credential
    )
    
    $checkId = 'IDF-ENT-EM-001'
    $checkName = 'Entitlement Management Configuration'
    $category = 'Entra ID - Governance'
    $severity = 'Medium'
    
    try {
        $graphParams = @{
            ErrorAction = 'Stop'
        }
        if ($TenantId) { $graphParams['TenantId'] = $TenantId }
        if ($Credential) { $graphParams['Credential'] = $Credential }
        
        $null = Connect-MgGraph @graphParams -Scopes 'EntitlementManagement.Read.All' -NoWelcome
        
        # Check for access packages
        $accessPackagesUri = '/beta/accessPackages'
        $accessPackages = Invoke-MgGraphRequest -Method GET -Uri $accessPackagesUri -ErrorAction Stop
        
        $remediation = @()
        $affectedCount = 0
        
        if ($accessPackages.Value.Count -eq 0) {
            $remediation += 'Create access packages for managing access to resources'
            $affectedCount = 1
        }
        else {
            # Check for policy requirements
            foreach ($pkg in $accessPackages.Value) {
                $policiesUri = "/beta/accessPackages/$($pkg.id)/policies"
                $policies = Invoke-MgGraphRequest -Method GET -Uri $policiesUri -ErrorAction Stop
                
                if ($policies.Value.Count -eq 0) {
                    $remediation += "Add assignment policy to access package: $($pkg.displayName)"
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
                    Title = 'Incomplete Entitlement Management Configuration'
                    Description = "$affectedCount access package policy issues detected"
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
                    Title = 'Unable to retrieve Entitlement Management configuration'
                    Description = "Error: $($_.Exception.Message)"
                    Remediation = 'Verify Microsoft Graph API connectivity and EntitlementManagement.Read.All permission'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}

function Invoke-EntraIdConditionalAccessNamedLocationsCheck {
    <#
    .SYNOPSIS
        Checks Conditional Access Named Locations configuration
    .DESCRIPTION
        Verifies that named locations are properly configured and trusted locations are limited
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$TenantId,
        
        [Parameter(Mandatory=$false)]
        [pscredential]$Credential
    )
    
    $checkId = 'IDF-ENT-CA-003'
    $checkName = 'Conditional Access Named Locations'
    $category = 'Entra ID - Conditional Access'
    $severity = 'High'
    
    try {
        $graphParams = @{
            ErrorAction = 'Stop'
        }
        if ($TenantId) { $graphParams['TenantId'] = $TenantId }
        if ($Credential) { $graphParams['Credential'] = $Credential }
        
        $null = Connect-MgGraph @graphParams -Scopes 'Policy.Read.All' -NoWelcome
        
        # Get named locations
        $namedLocationsUri = '/beta/identity/conditionalAccess/namedLocations'
        $namedLocations = Invoke-MgGraphRequest -Method GET -Uri $namedLocationsUri -ErrorAction Stop
        
        $remediation = @()
        $affectedCount = 0
        $trustedLocationCount = 0
        $countryLocations = 0
        
        foreach ($loc in $namedLocations.Value) {
            if ($loc.isTrusted -eq $true) {
                $trustedLocationCount++
                # Check if trusted location includes too many IPs
                if ($loc.ipRanges -and $loc.ipRanges.Count -gt 10) {
                    $remediation += "Trusted location '$($loc.displayName)' has $($loc.ipRanges.Count) IP ranges - review necessity"
                    $affectedCount++
                }
            }
            
            # Check for country-based named locations
            if ($loc.countriesAndRegions) {
                $countryLocations++
            }
        }
        
        # Warn if all locations are trusted
        if ($trustedLocationCount -eq $namedLocations.Value.Count -and $namedLocations.Value.Count -gt 0) {
            $remediation += 'All named locations are marked as trusted - this weakens Conditional Access'
            $affectedCount++
        }
        
        # Check for missing trusted HQ location
        $hasHqLocation = $namedLocations.Value | Where-Object { 
            $_.displayName -match 'HQ|Headquarters|Office|Trusted' -and $_.isTrusted -eq $true 
        }
        
        if (-not $hasHqLocation -and $namedLocations.Value.Count -gt 0) {
            $remediation += 'No trusted HQ/Office location detected - create named location for corporate network'
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
                    Title = 'Named Location Configuration Issues'
                    Description = "$affectedCount issues detected with named locations configuration"
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
                    Title = 'Unable to retrieve Named Locations configuration'
                    Description = "Error: $($_.Exception.Message)"
                    Remediation = 'Verify Microsoft Graph API connectivity and Policy.Read.All permission'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}
#endregion

#region Azure Security Additional Checks
function Invoke-AzureSecurityCenterCheck {
    <#
    .SYNOPSIS
        Checks Azure Security Center (Microsoft Defender for Cloud) configuration
    .DESCRIPTION
        Verifies Security Center pricing tiers, secure score, and alert configurations
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$SubscriptionId
    )
    
    $checkId = 'IDF-AZ-SC-001'
    $checkName = 'Azure Security Center Configuration'
    $category = 'Azure - Security'
    $severity = 'Medium'
    
    try {
        $null = Connect-AzAccount -ErrorAction Stop
        
        $remediation = @()
        $affectedCount = 0
        
        if (-not $SubscriptionId) {
            # Get all subscriptions
            $subscriptions = Get-AzSubscription -ErrorAction Stop
            $SubscriptionId = $subscriptions[0].Id
        }
        
        $null = Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop
        
        # Check Security Center pricing
        $pricingUri = "/subscriptions/$SubscriptionId/providers/Microsoft.Security/pricings?api-version=2021-06-01"
        $pricing = Invoke-AzRestMethod -Method GET -Uri $pricingUri -ErrorAction Stop
        
        $defenderEnabled = $true
        foreach ($tier in $pricing.Value) {
            if ($tier.name -in @('VirtualMachines', 'StorageAccounts', 'SqlServers', 'KeyVaults')) {
                if ($tier.properties.pricingTier -ne 'Standard') {
                    $remediation += "Enable Microsoft Defender for Cloud Standard tier for $($tier.name)"
                    $affectedCount++
                }
            }
        }
        
        # Check secure score
        $secureScoreUri = "/subscriptions/$SubscriptionId/providers/Microsoft.Security/secureScores?api-version=2021-06-01"
        $secureScore = Invoke-AzRestMethod -Method GET -Uri $secureScoreUri -ErrorAction Stop
        
        $currentScore = $secureScore.Value[0].properties.score.current
        $maxScore = $secureScore.Value[0].properties.score.max
        
        if ($currentScore -and $maxScore) {
            $scorePercent = ($currentScore / $maxScore) * 100
            if ($scorePercent -lt 50) {
                $remediation += "Improve secure score: Current $currentScore/$maxScore ($([math]::Round($scorePercent))%)"
                $affectedCount++
            }
        }
        
        # Check security alerts
        $alertsUri = "/subscriptions/$SubscriptionId/providers/Microsoft.Security/alerts?api-version=2021-06-01"
        $alerts = Invoke-AzRestMethod -Method GET -Uri $alertsUri -ErrorAction Stop
        
        $criticalAlerts = ($alerts.Value | Where-Object { $_.properties.severity -eq 'High' }).Count
        
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = $severity
            Status = if ($affectedCount -eq 0) { 'Pass' } else { 'Warning' }
            Findings = if ($affectedCount -gt 0 -or $criticalAlerts -gt 0) { @(
                @{
                    Title = 'Security Center Configuration Review'
                    Description = "$affectedCount configuration issues, $criticalAlerts high-severity active alerts"
                    Remediation = $remediation -join '; '
                    AffectedCount = $affectedCount + $criticalAlerts
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
                    Title = 'Unable to retrieve Security Center configuration'
                    Description = "Error: $($_.Exception.Message)"
                    Remediation = 'Verify AzureRM PowerShell connectivity and permissions'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}

function Invoke-AzureDefenderPlansCheck {
    <#
    .SYNOPSIS
        Checks Microsoft Defender for Cloud (formerly Defender Plans) coverage
    .DESCRIPTION
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$SubscriptionId
    )
    
    $checkId = 'IDF-AZ-DF-001'
    $checkName = 'Microsoft Defender Plan Coverage'
    $category = 'Azure - Security'
    $severity = 'Medium'
    
    try {
        $null = Connect-AzAccount -ErrorAction Stop
        
        $remediation = @()
        $affectedCount = 0
        
        if (-not $SubscriptionId) {
            $subscriptions = Get-AzSubscription -ErrorAction Stop
            $SubscriptionId = $subscriptions[0].Id
        }
        
        $null = Set-AzContext -SubscriptionId $SubscriptionId
        
        $defenderPlans = @{
            'VirtualMachines' = 'Servers'
            'StorageAccounts' = 'Storage'
            'SqlServers' = 'SQL Servers'
            'KeyVaults' = 'Key Vaults'
            'Arm' = 'Resource Manager'
            'Dns' = 'DNS'
            'OpenSourceRelationalDatabases' = 'Open-source RDBMS'
            'CosmosDbs' = 'Cosmos DB'
        }
        
        $pricingUri = "/subscriptions/$SubscriptionId/providers/Microsoft.Security/pricings?api-version=2021-06-01"
        $pricing = Invoke-AzRestMethod -Method GET -Uri $pricingUri -ErrorAction Stop
        
        $disabledPlans = @()
        foreach ($plan in $defenderPlans.GetEnumerator()) {
            $tier = $pricing.Value | Where-Object { $_.name -eq $plan.Key }
            if (-not $tier -or $tier.properties.pricingTier -ne 'Standard') {
                $disabledPlans += $plan.Value
                $affectedCount++
            }
        }
        
        if ($disabledPlans.Count -gt 0) {
            $remediation += "Enable Microsoft Defender for Cloud plans: $($disabledPlans -join ', ')"
        }
        
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = $severity
            Status = if ($affectedCount -eq 0) { 'Pass' } else { 'Warning' }
            Findings = if ($affectedCount -gt 0) { @(
                @{
                    Title = 'Microsoft Defender Plans Not Enabled'
                    Description = "$affectedCount Defender plans are at Free tier instead of Standard"
                    Remediation = $remediation
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
                    Title = 'Unable to retrieve Defender plan configuration'
                    Description = "Error: $($_.Exception.Message)"
                    Remediation = 'Verify Azure connectivity and permissions'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}
#endregion

#region Active Directory Additional Checks
function Invoke-ADAccountLockoutCheck {
    <#
    .SYNOPSIS
        Checks Active Directory account lockout policies
    .DESCRIPTION
        Verifies lockout threshold, duration, and reset settings
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain
    )
    
    $checkId = 'IDF-AD-LK-001'
    $checkName = 'Account Lockout Policy'
    $category = 'Active Directory - Security'
    $severity = 'Medium'
    
    try {
        if (-not $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }
        
        $domainController = (Get-ADDomainController -DomainName $Domain).HostName[0]
        
        # Get lockout policy
        $policy = Get-ADDefaultDomainPasswordPolicy -Server $Domain
        
        $remediation = @()
        $affectedCount = 0
        
        # Check lockout threshold
        if ($policy.LockoutThreshold -eq 0) {
            $remediation += 'Enable account lockout (current: Never lock out)'
            $affectedCount++
        }
        elseif ($policy.LockoutThreshold -gt 10) {
            $remediation += "Reduce lockout threshold (current: $($policy.LockoutThreshold), recommended: 5)"
            $affectedCount++
        }
        
        # Check lockout duration
        if ($policy.LockoutDuration -lt 15) {
            $remediation += "Increase lockout duration (current: $($policy.LockoutDuration) minutes, recommended: 15-30)"
            $affectedCount++
        }
        
        # Check observation window
        if ($policy.LockoutObservationWindow -gt $policy.LockoutDuration) {
            $remediation += 'Lockout observation window should be less than or equal to lockout duration'
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
                    Title = 'Account Lockout Policy Issues'
                    Description = "$affectedCount lockout policy settings need review"
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
                    Title = 'Unable to retrieve account lockout policy'
                    Description = "Error: $($_.Exception.Message)"
                    Remediation = 'Verify Active Directory module and domain connectivity'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}

function Invoke-ADKerberosTicketLifetimeCheck {
    <#
    .SYNOPSIS
        Checks Kerberos ticket lifetime policies
    .DESCRIPTION
        Verifies user and service ticket lifetime settings
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain
    )
    
    $checkId = 'IDF-AD-KR-001'
    $checkName = 'Kerberos Ticket Lifetime'
    $category = 'Active Directory - Security'
    $severity = 'Medium'
    
    try {
        if (-not $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }
        
        # Get domain policy
        $domainPolicy = Get-ADObject -Identity "DC=$($Domain.Replace('.', ',DC='))" -Properties * -Server $Domain
        
        $remediation = @()
        $affectedCount = 0
        
        # Max ticket lifetime for user
        $userTicketLifetime = $domainPolicy.'msDS-MaximumTicketAge'
        if ($userTicketLifetime -and $userTicketLifetime -gt 10) {
            $remediation += "Reduce user ticket lifetime (current: $userTicketLifetime hours, recommended: 8-10)"
            $affectedCount++
        }
        
        # Max ticket lifetime for service
        $serviceTicketLifetime = $domainPolicy.'msDS-MaximumServiceTicketAge'
        if ($serviceTicketLifetime -and $serviceTicketLifetime -gt 10) {
            $remediation += "Reduce service ticket lifetime (current: $serviceTicketLifetime hours, recommended: 8-10)"
            $affectedCount++
        }
        
        # Clock skew tolerance
        $clockSkew = $domainPolicy.'msDS-ClockSkew'
        if ($clockSkew -and $clockSkew -gt 5) {
            $remediation += "Reduce clock skew tolerance (current: $clockSkew minutes, recommended: 5)"
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
                    Title = 'Kerberos Ticket Lifetime Configuration Issues'
                    Description = "$affectedCount ticket lifetime settings may be too permissive"
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
                    Title = 'Unable to retrieve Kerberos policy'
                    Description = "Error: $($_.Exception.Message)"
                    Remediation = 'Verify Active Directory module and domain connectivity'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}
#endregion

#region AWS Additional Checks
function Invoke-AwsCloudTrailCheck {
    <#
    .SYNOPSIS
        Checks AWS CloudTrail configuration
    .DESCRIPTION
        Verifies CloudTrail logging, encryption, and integration with CloudWatch
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Region = 'us-east-1'
    )
    
    $checkId = 'IDF-AWS-CT-001'
    $checkName = 'AWS CloudTrail Configuration'
    $category = 'AWS - Logging'
    $severity = 'High'
    
    try {
        $null = Initialize-AWSDefaultConfiguration -Region $Region -ErrorAction Stop
        
        $remediation = @()
        $affectedCount = 0
        
        # Get all trails
        $trails = Get-CTTrail -ErrorAction Stop
        
        if ($trails.Count -eq 0) {
            $remediation += 'Enable CloudTrail for logging all API calls'
            $affectedCount = 1
        }
        else {
            foreach ($trail in $trails) {
                # Check if logging is enabled
                $status = Get-CTTrailStatus -Name $trail.Name
                if (-not $status.IsLogging) {
                    $remediation += "Enable logging for CloudTrail: $($trail.Name)"
                    $affectedCount++
                }
                
                # Check for multi-region
                if (-not $trail.IsMultiRegionTrail) {
                    $remediation += "Enable multi-region for CloudTrail: $($trail.Name)"
                    $affectedCount++
                }
                
                # Check for log file validation
                if (-not $trail.EnableLogFileValidation) {
                    $remediation += "Enable log file validation for CloudTrail: $($trail.Name)"
                    $affectedCount++
                }
                
                # Check for CloudWatch Logs integration
                if (-not $trail.CloudWatchLogsLogGroupArn) {
                    $remediation += "Integrate CloudTrail with CloudWatch Logs: $($trail.Name)"
                    $affectedCount++
                }
                
                # Check for encryption
                if (-not $trail.KmsKeyId) {
                    $remediation += "Enable SSE-KMS encryption for CloudTrail: $($trail.Name)"
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
                    Title = 'CloudTrail Configuration Issues'
                    Description = "$affectedCount CloudTrail configuration issues detected"
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
                    Title = 'Unable to retrieve CloudTrail configuration'
                    Description = "Error: $($_.Exception.Message)"
                    Remediation = 'Verify AWS Tools for PowerShell installation and credentials'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}

function Invoke-AwsGuardDutyCheck {
    <#
    .SYNOPSIS
        Checks AWS GuardDuty configuration
    .DESCRIPTION
        Verifies GuardDuty is enabled and configured across regions
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Region = 'us-east-1'
    )
    
    $checkId = 'IDF-AWS-GD-001'
    $checkName = 'AWS GuardDuty Configuration'
    $category = 'AWS - Threat Detection'
    $severity = 'High'
    
    try {
        $null = Initialize-AWSDefaultConfiguration -Region $Region -ErrorAction Stop
        
        $remediation = @()
        $affectedCount = 0
        
        # Get all regions
        $regions = Get-AWSRegion -ErrorAction Stop | Select-Object -ExpandProperty Region
        
        $enabledRegions = @()
        foreach ($r in $regions) {
            try {
                $detector = Get-GuardDutyDetector -Region $r -ErrorAction Stop
                if ($detector) {
                    $enabledRegions += $r
                    
                    # Check if publishing findings is enabled
                    if (-not $detector.PublishingFrequency) {
                        $remediation += "Configure publishing frequency for GuardDuty in region: $r"
                        $affectedCount++
                    }
                }
            }
            catch {
                # GuardDuty not enabled in this region
                $remediation += "Enable GuardDuty in region: $r"
                $affectedCount++
            }
        }
        
        if ($enabledRegions.Count -eq 0) {
            $remediation = @('Enable GuardDuty in at least one region')
            $affectedCount = 1
        }
        
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = $severity
            Status = if ($affectedCount -eq 0) { 'Pass' } else { 'Warning' }
            Findings = if ($affectedCount -gt 0) { @(
                @{
                    Title = 'GuardDuty Configuration Issues'
                    Description = "$affectedCount regions without GuardDuty or misconfigured"
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
                    Title = 'Unable to retrieve GuardDuty configuration'
                    Description = "Error: $($_.Exception.Message)"
                    Remediation = 'Verify AWS Tools for PowerShell installation and credentials'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}
#endregion

#region GCP Additional Checks
function Invoke-GcpSecurityCommandCenterCheck {
    <#
    .SYNOPSIS
        Checks GCP Security Command Center configuration
    .DESCRIPTION
        Verifies Security Command Center is enabled and configured properly
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$OrganizationId
    )
    
    $checkId = 'IDF-GCP-SCC-001'
    $checkName = 'GCP Security Command Center Configuration'
    $category = 'GCP - Security'
    $severity = 'High'
    
    try {
        $remediation = @()
        $affectedCount = 0
        
        # Check for Google Cloud module
        $gcloudPath = (Get-Command gcloud -ErrorAction SilentlyContinue).Path
        if (-not $gcloudPath) {
            $remediation += 'Install Google Cloud SDK for GCP checks'
            $affectedCount = 1
            throw 'Google Cloud SDK not installed'
        }
        
        # Get organization
        if (-not $OrganizationId) {
            $orgResult = gcloud organizations list --format=value --limit=1 2>$null
            if ($LASTEXITCODE -ne 0 -or -not $orgResult) {
                $remediation += 'Unable to identify GCP organization - specify OrganizationId parameter'
                $affectedCount++
                throw 'No organization found'
            }
            $OrganizationId = $orgResult
        }
        
        # Check Security Command Center status
        $sccResult = gcloud alpha scc settings get --organization=$OrganizationId --format=json 2>$null
        
        if (-not $sccResult) {
            $remediation += 'Enable Security Command Center for the organization'
            $affectedCount++
        }
        
        # Check for Security Health Analytics
        $shaResult = gcloud alpha scc settings modules describe securityHealthAnalytics --organization=$OrganizationId --format=json 2>$null
        if ($shaResult) {
            $shaState = $shaResult | ConvertFrom-Json
            if ($shaState.state -ne 'ENABLED') {
                $remediation += 'Enable Security Health Analytics in Security Command Center'
                $affectedCount++
            }
        }
        
        # Check for Event Threat Detection
        $etdResult = gcloud alpha scc settings modules describe eventThreatDetection --organization=$OrganizationId --format=json 2>$null
        if ($etdResult) {
            $etdState = $etdResult | ConvertFrom-Json
            if ($etdState.state -ne 'ENABLED') {
                $remediation += 'Enable Event Threat Detection in Security Command Center'
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
                    Title = 'Security Command Center Configuration Issues'
                    Description = "$affectedCount Security Command Center configuration issues"
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
                    Title = 'Unable to retrieve Security Command Center configuration'
                    Description = "Error: $($_.Exception.Message)"
                    Remediation = 'Verify Google Cloud SDK installation and authentication'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}

function Invoke-GcpServiceAccountKeyCheck {
    <#
    .SYNOPSIS
        Checks GCP service account key management
    .DESCRIPTION
        Verifies service account keys are rotated and old keys are removed
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ProjectId
    )
    
    $checkId = 'IDF-GCP-SAK-001'
    $checkName = 'GCP Service Account Key Management'
    $category = 'GCP - Identity'
    $severity = 'High'
    
    try {
        $remediation = @()
        $affectedCount = 0
        
        # Check for Google Cloud module
        $gcloudPath = (Get-Command gcloud -ErrorAction SilentlyContinue).Path
        if (-not $gcloudPath) {
            $remediation += 'Install Google Cloud SDK for GCP checks'
            $affectedCount = 1
            throw 'Google Cloud SDK not installed'
        }
        
        # Get project
        if (-not $ProjectId) {
            $projResult = gcloud projects list --format=value --limit=1 2>$null
            if ($LASTEXITCODE -ne 0 -or -not $projResult) {
                $remediation += 'Unable to identify GCP project - specify ProjectId parameter'
                $affectedCount++
                throw 'No project found'
            }
            $ProjectId = $projResult
        }
        
        # Get service accounts
        $saList = gcloud iam service-accounts list --project=$ProjectId --format=json 2>$null
        
        if ($saList) {
            $sas = $saList | ConvertFrom-Json
            
            foreach ($sa in $sas) {
                $email = $sa.email
                
                # Get keys for this service account
                $keyList = gcloud iam service-accounts keys list --iam-account=$email --project=$ProjectId --format=json 2>$null
                
                if ($keyList) {
                    $keys = $keyList | ConvertFrom-Json
                    
                    foreach ($key in $keys) {
                        # Check key age
                        $keyCreated = [DateTime]::Parse($key.validAfterTime)
                        $keyAge = (New-TimeSpan -Start $keyCreated -End (Get-Date)).Days
                        
                        if ($keyAge -gt 90) {
                            $remediation += "Rotate service account key for $email (key created $keyAge days ago)"
                            $affectedCount++
                        }
                    }
                    
                    # Check for too many keys
                    if ($keys.Count -gt 2) {
                        $remediation += "Service account $email has $($keys.Count) keys - review necessity"
                        $affectedCount++
                    }
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
                    Title = 'Service Account Key Management Issues'
                    Description = "$affectedCount service account keys need attention"
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
                    Title = 'Unable to retrieve service account key information'
                    Description = "Error: $($_.Exception.Message)"
                    Remediation = 'Verify Google Cloud SDK installation and authentication'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}
#endregion

#region Run-All Additional Checks
function Invoke-AllAdditionalChecks {
    <#
    .SYNOPSIS
        Runs all additional security checks
    .DESCRIPTION
        Executes all checks in this module and returns consolidated results
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$TenantId,
        
        [Parameter(Mandatory=$false)]
        [pscredential]$Credential,
        
        [Parameter(Mandatory=$false)]
        [string]$AzureSubscriptionId,
        
        [Parameter(Mandatory=$false)]
        [string]$ADDomain,
        
        [Parameter(Mandatory=$false)]
        [string]$AWSRegion = 'us-east-1',
        
        [Parameter(Mandatory=$false)]
        [string]$GCPOrganizationId,
        
        [Parameter(Mandatory=$false)]
        [string]$GCPProjectId
    )
    
    Write-Host "Running Additional Security Checks..." -ForegroundColor Cyan
    
    $results = @()
    
    # Prerequisites
    Write-Host "  - Prerequisites Check..."
    $results += Test-Prerequisites
    
    # Entra ID Checks
    Write-Host "  - Entra ID: Access Reviews..."
    $results += Invoke-EntraIdAccessReviewCheck -TenantId $TenantId -Credential $Credential
    
    Write-Host "  - Entra ID: Entitlement Management..."
    $results += Invoke-EntraIdEntitlementManagementCheck -TenantId $TenantId -Credential $Credential
    
    Write-Host "  - Entra ID: Conditional Access Named Locations..."
    $results += Invoke-EntraIdConditionalAccessNamedLocationsCheck -TenantId $TenantId -Credential $Credential
    
    # Azure Checks
    Write-Host "  - Azure: Security Center..."
    $results += Invoke-AzureSecurityCenterCheck -SubscriptionId $AzureSubscriptionId
    
    Write-Host "  - Azure: Defender Plans..."
    $results += Invoke-AzureDefenderPlansCheck -SubscriptionId $AzureSubscriptionId
    
    # Active Directory Checks
    Write-Host "  - AD: Account Lockout Policy..."
    $results += Invoke-ADAccountLockoutCheck -Domain $ADDomain
    
    Write-Host "  - AD: Kerberos Ticket Lifetime..."
    $results += Invoke-ADKerberosTicketLifetimeCheck -Domain $ADDomain
    
    # AWS Checks
    Write-Host "  - AWS: CloudTrail..."
    $results += Invoke-AwsCloudTrailCheck -Region $AWSRegion
    
    Write-Host "  - AWS: GuardDuty..."
    $results += Invoke-AwsGuardDutyCheck -Region $AWSRegion
    
    # GCP Checks
    Write-Host "  - GCP: Security Command Center..."
    $results += Invoke-GcpSecurityCommandCenterCheck -OrganizationId $GCPOrganizationId
    
    Write-Host "  - GCP: Service Account Keys..."
    $results += Invoke-GcpServiceAccountKeyCheck -ProjectId $GCPProjectId
    
    return $results
}
#endregion

# Export module functions
Export-ModuleMember -Function @(
    'Test-Prerequisites',
    'Invoke-EntraIdAccessReviewCheck',
    'Invoke-EntraIdEntitlementManagementCheck',
    'Invoke-EntraIdConditionalAccessNamedLocationsCheck',
    'Invoke-AzureSecurityCenterCheck',
    'Invoke-AzureDefenderPlansCheck',
    'Invoke-ADAccountLockoutCheck',
    'Invoke-ADKerberosTicketLifetimeCheck',
    'Invoke-AwsCloudTrailCheck',
    'Invoke-AwsGuardDutyCheck',
    'Invoke-GcpSecurityCommandCenterCheck',
    'Invoke-GcpServiceAccountKeyCheck',
    'Invoke-AllAdditionalChecks'
)
