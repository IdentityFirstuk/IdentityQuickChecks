
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

# SIG # Begin signature block
# MIIf3QYJKoZIhvcNAQcCoIIfzjCCH8oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC4dGgsQB0QjVb1
# 3gkn5Y+EvbmPkIL6aKOEz4zeVLVU/aCCGNwwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# AgEVMC8GCSqGSIb3DQEJBDEiBCAo+fEawbFRGLfpsAp2wOL7BtnhYlvu4zHEeULZ
# 4499xjANBgkqhkiG9w0BAQEFAASCAgDAT4gZH2ijuM0NDBeG27mwDAKhyOV8B3Wp
# N6fxvHRmQKnbY5ArPEg0H1hjACG03v1t7pgAOd67JambLcRmk2NDsKUsBFeskZj9
# VR+2u5M2AvbS5+Vo4ADuh0R+J95uTgJCeM+cGUxsMTkPKXe/ka2xVBYJBkZSWoc9
# zsQUIMnR4kXTQ54Z9/U8eRS1aljxuKBgNalr9q68RqPWo95izDfzJCgrY7QUbIoM
# aj4hHV5M0cAah39LM3m+3ju/nw0642dX7wqSjcUDbnfKPOHZfFuQjWIJZ6D8scbV
# GsJTpNstYECffevpuI/QYDhVF66boShQ7S0X8wwlBX1MtWEE4gGlV7gMhEleQ5pk
# oh/KHNBI5yRrSlGSl+C4uEMKPs7zlT/+PSOcJQR4/zZbW5bzKHE7l1TOEh/rWCii
# K6fhO8qiMM1RqD4CwGOObHx9LWVtcAWmhCqwsRZw2I7mh8r1JraVO312wTCpmHBz
# bem3D+EtKY45uySfLZ5zf0nqykYTv5tKbUQT/mFHN+vdGe/fBXsnM1I3pcCQRQAG
# 8dlUo8KOa9dWw4UsewguB637nxsJGmZ8AOCpjP2C4HEktBXdx+Ku3q+0Ma5ltCDo
# FcszO9+jgcIPKqYy+rF+J/hIDQLqOFc2e61kFM/sdY8IH641dKsgAumOE+ZUgeYe
# hHy8vzOsXaGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAyMDUxNzEyNDRaMC8G
# CSqGSIb3DQEJBDEiBCAd9xZTmer8bypmRscQW4dN6gv7Xt/Dmnu81RruVnPKuDAN
# BgkqhkiG9w0BAQEFAASCAgA0O7A+SJVF3Tak2WovltkIJYTwfUPfjauv4PxUUpzj
# +fQlHsUuqVPxqP8Vb6jlEJ/VsSh1FRXeA+YzQS48kRQbqpKJSyYRAseltrsq5472
# NwvwudpFk6ff9wKhNYf6PIGM/GTb3geconoPT4ggRDih/VDgbhRKha4fBkgT5rPQ
# pmHkU8DYtTMmlf9UriyYpEPi6vg2G8ZewRMPxEvAOLZ1auVDtmgU2k1qQe57cV1K
# n2INYgBsXqkZ+WnBZ4wGHOaDC2wR7k14wP3Qg5I/FcEwu6D3WyjGPi1zENtoxQIl
# fjnx9ekyEojv2zi53lzMrfAphcaludHWBhM212pzXE1DfB7s5IC95EfuvlD5Ikzy
# d71NNKneZiRn3FPAtBx3RXTZhH/nsRm1UYhNns4lSbqRVqrn/gaERRqYp+cE0DKs
# B+36yuA2TBDE32RB+Zg+TwQnHypPjNDgCVvAIJTB2nflyRSnv0pei6VoqEjtdLRq
# QOtQBZ3E6KpPDPsp25chlZ9W/lzhzDhCxkHA+YJD4tQXugqrurKmwb65Vo51qccf
# 6Hl7ZNz8KbYZEunmQuyVqtlMm2lDoO9ZWjq7rAQWtvrkPDhgM97y1x4izeV/LxPp
# K3QRfiUl9G1F4rr8pL6ybHIWM99VYRc/FDDRiqtIBXi2fNJumr4WfW4tBBXIhpAN
# Fg==
# SIG # End signature block
