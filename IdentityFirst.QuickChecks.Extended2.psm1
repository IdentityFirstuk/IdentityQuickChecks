
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
# Module Type: Extended2

$script:DefaultThresholds = @{
    FederationThreshold = 5
    CertificateExpiryDays = 30
}

# Severity and Status Definitions
$script:FindingSeverity = @{ Critical = "Critical"; High = "High"; Medium = "Medium"; Low = "Low"; Info = "Info" }
$script:HealthStatus = @{ Healthy = "Healthy"; Warning = "Warning"; Critical = "Critical" }
# ============================================================================
# IdentityFirst QuickChecks - Extended Security Checks Module
# ============================================================================
# PowerShell 5.1 Compatible
# Contains comprehensive security checks beyond standard modules
# ============================================================================

#requires -Version 5.1

#region Entra ID Extended Checks
function Invoke-EntraIdAdministrativeUnitCheck {
    <#
    .SYNOPSIS
        Checks Administrative Unit configuration and permissions
    .DESCRIPTION
        Verifies AU scoping, role assignments, and governance
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$TenantId,
        
        [Parameter(Mandatory=$false)]
        [pscredential]$Credential
    )
    
    $checkId = 'IDF-ENT-AU-001'
    $checkName = 'Administrative Unit Configuration'
    $category = 'Entra ID - Administration'
    $severity = 'Medium'
    
    try {
        $graphParams = @{}
        if ($TenantId) { $graphParams['TenantId'] = $TenantId }
        if ($Credential) { $graphParams['Credential'] = $Credential }
        
        $null = Connect-MgGraph @graphParams -Scopes 'Directory.Read.All,RoleManagement.Read.Directory' -NoWelcome
        
        # Get administrative units
        $auUri = '/beta/administrativeUnits'
        $aus = Invoke-MgGraphRequest -Method GET -Uri $auUri -ErrorAction Stop
        
        $remediation = @()
        $affectedCount = 0
        
        # Check for empty AUs
        foreach ($au in $aus.Value) {
            $membersUri = "/beta/administrativeUnits/$($au.id)/members"
            $members = Invoke-MgGraphRequest -Method GET -Uri $membersUri -ErrorAction Stop
            
            if ($members.Value.Count -eq 0) {
                $remediation += "Review empty Administrative Unit: $($au.displayName)"
                $affectedCount++
            }
            
            # Check for broad role assignments
            $roleAssignmentsUri = "/beta/roleManagement/directory/roleAssignments?`$filter=directoryScopeId eq '/AdministrativeUnits/$($au.id)'"
            $roleAssignments = Invoke-MgGraphRequest -Method GET -Uri $roleAssignmentsUri -ErrorAction Stop
            
            foreach ($ra in $roleAssignments.Value) {
                $roleUri = "/beta/directoryRoles/roleTemplateId=$($ra.roleDefinitionId)"
                $role = Invoke-MgGraphRequest -Method GET -Uri $roleUri -ErrorAction Stop
                
                # Flag Global Admin on AU
                if ($role.displayName -match 'Global Administrator|Company Administrator') {
                    $remediation += "Global Admin scoped to AU $($au.displayName) - consider least privilege"
                    $affectedCount++
                }
            }
        }
        
        # Check if AUs are being used
        if ($aus.Value.Count -eq 0) {
            $remediation += 'Consider using Administrative Units for delegated administration'
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
                    Title = 'Administrative Unit Configuration Review'
                    Description = "$affectedCount AU configuration issues detected"
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
                    Title = 'Unable to retrieve Administrative Unit configuration'
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

function Invoke-EntraIdPermissionGrantCheck {
    <#
    .SYNOPSIS
        Checks OAuth2 permission grants across the tenant
    .DESCRIPTION
        Identifies excessive delegated and application permissions
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$TenantId,
        
        [Parameter(Mandatory=$false)]
        [pscredential]$Credential
    )
    
    $checkId = 'IDF-ENT-PG-001'
    $checkName = 'OAuth2 Permission Grants'
    $category = 'Entra ID - Applications'
    $severity = 'High'
    
    try {
        $graphParams = @{}
        if ($TenantId) { $graphParams['TenantId'] = $TenantId }
        if ($Credential) { $graphParams['Credential'] = $Credential }
        
        $null = Connect-MgGraph @graphParams -Scopes 'Policy.Read.All,Directory.Read.All' -NoWelcome
        
        $remediation = @()
        $affectedCount = 0
        
        # Get delegated permission grants
        $delegatedUri = '/beta/oAuth2PermissionGrants'
        $delegatedGrants = Invoke-MgGraphRequest -Method GET -Uri $delegatedUri -ErrorAction Stop
        
        # Check for wide-scope grants
        foreach ($grant in $delegatedGrants.Value) {
            if ($grant.scope -eq '*' -or $grant.scope -match '\.default') {
                $remediation += "Wide-scope delegated grant found - Client: $($grant.clientId)"
                $affectedCount++
            }
        }
        
        # Get app-only access (service principals)
        $spUri = '/beta/servicePrincipals'
        $sps = Invoke-MgGraphRequest -Method GET -Uri $spUri -ErrorAction Stop
        
        $appRoleAssignmentsUri = '/beta/appRoleAssignedResources'
        $appRoleAssignments = Invoke-MgGraphRequest -Method GET -Uri $appRoleAssignmentsUri -ErrorAction Stop
        
        # Check for privileged app roles
        foreach ($sp in $sps) {
            $privilegedRoles = @('Directory.ReadWrite.All', 'Group.ReadWrite.All', 'User.ReadWrite.All')
            foreach ($role in $privilegedRoles) {
                $hasRole = $sp.appRoles | Where-Object { $_.Value -eq $role -and $_.AllowedMemberTypes -contains 'Application' }
                if ($hasRole) {
                    $remediation += "Service Principal $($sp.displayName) has $role application role"
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
                    Title = 'OAuth2 Permission Grant Review'
                    Description = "$affectedCount permission grants need review"
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
                    Title = 'Unable to retrieve permission grants'
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

function Invoke-EntraIdTokenLifetimeCheck {
    <#
    .SYNOPSIS
        Checks token lifetime policies configuration
    .DESCRIPTION
        Verifies access, refresh, and ID token lifetime settings
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$TenantId,
        
        [Parameter(Mandatory=$false)]
        [pscredential]$Credential
    )
    
    $checkId = 'IDF-ENT-TL-001'
    $checkName = 'Token Lifetime Configuration'
    $category = 'Entra ID - Security'
    $severity = 'Medium'
    
    try {
        $graphParams = @{}
        if ($TenantId) { $graphParams['TenantId'] = $TenantId }
        if ($Credential) { $graphParams['Credential'] = $Credential }
        
        $null = Connect-MgGraph @graphParams -Scopes 'Policy.Read.All' -NoWelcome
        
        $remediation = @()
        $affectedCount = 0
        
        # Get token lifetime policies
        $policyUri = '/beta/policies/authorizationPolicy'
        $policy = Invoke-MgGraphRequest -Method GET -Uri $policyUri -ErrorAction Stop
        
        # Check default token lifetime
        $accessLifetime = $policy.defaultUserRolePermissions.tokenLifetimePolicy
        if (-not $accessLifetime -or $accessLifetime.accessTokenLifetime -gt 3600) {
            $remediation += 'Review access token lifetime (consider 1 hour maximum for sensitive apps)'
            $affectedCount++
        }
        
        # Check single-page application lifetime
        if ($policy.spaApplicationConfiguration -and $policy.spaApplicationConfiguration.sessionTokenLifetime -gt 86400) {
            $remediation += 'Reduce SPA session token lifetime (consider 24 hours maximum)'
            $affectedCount++
        }
        
        # Check for custom policies
        $customPoliciesUri = '/beta/policies/tokenLifetimePolicy'
        $customPolicies = Invoke-MgGraphRequest -Method GET -Uri $customPoliciesUri -ErrorAction Stop
        
        foreach ($cp in $customPolicies.Value) {
            if ($cp.definition -match 'AccessTokenLifetime.*?(\d+)' -and $matches[1] -gt 3600) {
                $remediation += "Custom token policy '$($cp.displayName)' has extended token lifetime"
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
                    Title = 'Token Lifetime Configuration Review'
                    Description = "$affectedCount token lifetime concerns detected"
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
                    Title = 'Unable to retrieve token lifetime policies'
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

#region Azure Extended Checks
function Invoke-AzurePrivateEndpointCheck {
    <#
    .SYNOPSIS
        Checks Azure Private Endpoint configurations
    .DESCRIPTION
        Verifies private endpoints for storage, SQL, Key Vault, and other services
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$SubscriptionId
    )
    
    $checkId = 'IDF-AZ-PE-001'
    $checkName = 'Private Endpoint Configuration'
    $category = 'Azure - Network Security'
    $severity = 'Medium'
    
    try {
        $null = Connect-AzAccount -ErrorAction Stop
        
        $remediation = @()
        $affectedCount = 0
        
        if (-not $SubscriptionId) {
            $SubscriptionId = (Get-AzSubscription)[0].Id
        }
        
        $null = Set-AzContext -SubscriptionId $SubscriptionId
        
        # Get private endpoints
        $peUri = "/subscriptions/$SubscriptionId/providers/Microsoft.Network/privateEndpoints?api-version=2021-05-01"
        $peResult = Invoke-AzRestMethod -Method GET -Uri $peUri -ErrorAction Stop
        
        if ($peResult.Value.Count -eq 0) {
            $remediation += 'Enable Private Endpoints for secure service access'
            $affectedCount = 1
        }
        else {
            # Check for NSG associations
            foreach ($pe in $peResult.Value) {
                if (-not $pe.properties.networkInterfaces) {
                    $remediation += "Private Endpoint $($pe.name) missing network interface configuration"
                    $affectedCount++
                }
            }
            
            # Check private DNS zone integration
            $dnsUri = "/subscriptions/$SubscriptionId/providers/Microsoft.Network/privateDnsZones?api-version=2020-06-01"
            $dnsResult = Invoke-AzRestMethod -Method GET -Uri $dnsUri -ErrorAction Stop
            
            if ($dnsResult.Value.Count -eq 0) {
                $remediation += 'Configure Private DNS Zones for Private Endpoint name resolution'
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
                    Title = 'Private Endpoint Configuration Review'
                    Description = "$affectedCount private endpoint concerns"
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
                    Title = 'Unable to retrieve Private Endpoint configuration'
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

function Invoke-AzureVnetPeeringCheck {
    <#
    .SYNOPSIS
        Checks Virtual Network peering configurations
    .DESCRIPTION
        Verifies VNet peering security and configuration
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$SubscriptionId
    )
    
    $checkId = 'IDF-AZ-VPN-001'
    $checkName = 'Virtual Network Peering Configuration'
    $category = 'Azure - Network Security'
    $severity = 'Medium'
    
    try {
        $null = Connect-AzAccount -ErrorAction Stop
        
        $remediation = @()
        $affectedCount = 0
        
        if (-not $SubscriptionId) {
            $SubscriptionId = (Get-AzSubscription)[0].Id
        }
        
        $null = Set-AzContext -SubscriptionId $SubscriptionId
        
        # Get all VNets
        $vnetUri = "/subscriptions/$SubscriptionId/providers/Microsoft.Network/virtualNetworks?api-version=2021-05-01"
        $vnets = Invoke-AzRestMethod -Method GET -Uri $vnetUri -ErrorAction Stop
        
        foreach ($vnet in $vnets.Value) {
            $vnetName = $vnet.name
            $vnetRg = $vnet.id -replace '/subscriptions/[^/]+/resourceGroups/', '' -replace '/providers/Microsoft.Network.*', ''
            
            # Get peerings
            $peeringUri = "/subscriptions/$SubscriptionId/resourceGroups/$vnetRg/providers/Microsoft.Network/virtualNetworks/$vnetName/virtualNetworkPeerings?api-version=2021-05-01"
            $peerings = Invoke-AzRestMethod -Method GET -Uri $peeringUri -ErrorAction Stop
            
            foreach ($peering in $peerings.Value) {
                # Check for untrusted peering
                if ($peering.properties.allowForwardedTraffic -and $peering.properties.allowGatewayTransit) {
                    $remediation += "VNet $vnetName peering $($peering.name) allows forwarded traffic and gateway transit"
                    $affectedCount++
                }
                
                # Check for disabled virtual network access
                if (-not $peering.properties.allowVirtualNetworkAccess) {
                    $remediation += "VNet peering $($peering.name) has Virtual Network Access disabled"
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
                    Title = 'VNet Peering Configuration Review'
                    Description = "$affectedCount peering configurations need review"
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
                    Title = 'Unable to retrieve VNet peering configuration'
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

function Invoke-AzureFirewallPolicyCheck {
    <#
    .SYNOPSIS
        Checks Azure Firewall Policy configurations
    .DESCRIPTION
        Verifies firewall rules, threat intelligence, and network rules
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$SubscriptionId
    )
    
    $checkId = 'IDF-AZ-FW-001'
    $checkName = 'Azure Firewall Policy Configuration'
    $category = 'Azure - Network Security'
    $severity = 'Medium'
    
    try {
        $null = Connect-AzAccount -ErrorAction Stop
        
        $remediation = @()
        $affectedCount = 0
        
        if (-not $SubscriptionId) {
            $SubscriptionId = (Get-AzSubscription)[0].Id
        }
        
        $null = Set-AzContext -SubscriptionId $SubscriptionId
        
        # Get firewall policies
        $fwUri = "/subscriptions/$SubscriptionId/providers/Microsoft.Network/firewallPolicies?api-version=2021-05-01"
        $fwPolicies = Invoke-AzRestMethod -Method GET -Uri $fwUri -ErrorAction Stop
        
        if ($fwPolicies.Value.Count -eq 0) {
            $remediation += 'Consider implementing Azure Firewall for network security'
            $affectedCount = 1
        }
        else {
            foreach ($fw in $fwPolicies.Value) {
                $fwRg = $fw.id -replace '/subscriptions/[^/]+/resourceGroups/', '' -replace '/providers/Microsoft.Network.*', ''
                $fwName = $fw.name
                
                # Get rule groups
                $ruleGroupsUri = "/subscriptions/$SubscriptionId/resourceGroups/$fwRg/providers/Microsoft.Network/firewallPolicies/$fwName/ruleGroups?api-version=2021-05-01"
                $ruleGroups = Invoke-AzRestMethod -Method GET -Uri $ruleGroupsUri -ErrorAction Stop
                
                # Check threat intelligence mode
                if ($fw.properties.threatIntelMode -ne 'Alert') {
                    $remediation += "Enable Threat Intelligence mode for Firewall Policy $fwName"
                    $affectedCount++
                }
                
                # Check for DNS settings
                if ($fw.properties.dnsSettings -and -not $fw.properties.dnsSettings.enableProxy) {
                    $remediation += "Enable DNS proxy for Firewall Policy $fwName"
                    $affectedCount++
                }
                
                # Check for empty rule groups
                foreach ($rg in $ruleGroups.Value) {
                    $rulesUri = "/subscriptions/$SubscriptionId/resourceGroups/$fwRg/providers/Microsoft.Network/firewallPolicies/$fwName/ruleGroups/$($rg.name)/azureFirewallPolicies?api-version=2021-05-01"
                    # Rule count check logic
                    $ruleCount = 0
                    if ($rg.properties.rules) { $ruleCount = $rg.properties.rules.Count }
                    if ($ruleCount -eq 0) {
                        $remediation += "Empty rule group $($rg.name) in Firewall Policy $fwName"
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
                    Title = 'Azure Firewall Policy Review'
                    Description = "$affectedCount firewall policy concerns"
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
                    Title = 'Unable to retrieve Firewall Policy configuration'
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

#region AD Extended Checks
function Invoke-ADDuplicateSpnCheck {
    <#
    .SYNOPSIS
        Checks for duplicate Service Principal Names in AD
    .DESCRIPTION
        Identifies SPN conflicts that can cause authentication issues
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain
    )
    
    $checkId = 'IDF-AD-DSPN-001'
    $checkName = 'Duplicate Service Principal Names'
    $category = 'Active Directory - Security'
    $severity = 'High'
    
    try {
        if (-not $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }
        
        $remediation = @()
        $affectedCount = 0
        
        # Get all user accounts with SPN
        $usersWithSpn = Get-ADUser -Filter { ServicePrincipalName -like '*' } -Properties ServicePrincipalName, DistinguishedName -Server $Domain
        
        $spnMap = @{}
        foreach ($user in $usersWithSpn) {
            foreach ($spn in $user.ServicePrincipalName) {
                if ($spnMap.ContainsKey($spn)) {
                    $spnMap[$spn] += $user.DistinguishedName
                    $affectedCount++
                }
                else {
                    $spnMap[$spn] = @($user.DistinguishedName)
                }
            }
        }
        
        foreach ($spn in $spnMap.GetEnumerator()) {
            if ($spn.Value.Count -gt 1) {
                $remediation += "Duplicate SPN '$($spn.Key)': $($spn.Value -join ', ')"
            }
        }
        
        if ($affectedCount -eq 0) {
            return @{
                CheckId = $checkId
                CheckName = $checkName
                Category = $category
                Severity = $severity
                Status = 'Pass'
                Findings = @()
                Timestamp = (Get-Date -Format 'o')
            }
        }
        
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = $severity
            Status = 'Fail'
            Findings = @(
                @{
                    Title = 'Duplicate Service Principal Names Detected'
                    Description = "$affectedCount duplicate SPN entries found"
                    Remediation = $remediation -join '; '
                    AffectedCount = $affectedCount
                    Confidence = 'High'
                }
            )
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
                    Title = 'Unable to check for duplicate SPNs'
                    Description = $_.Exception.Message
                    Remediation = 'Verify Active Directory module access'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}

function Invoke-ADAdminCountCheck {
    <#
    .SYNOPSIS
        Checks for accounts with adminCount attribute set
    .DESCRIPTION
        Identifies privileged accounts that may have protected status
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain
    )
    
    $checkId = 'IDF-AD-AC-001'
    $checkName = 'Admin Count Configuration'
    $category = 'Active Directory - Administration'
    $severity = 'Low'
    
    try {
        if (-not $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }
        
        $remediation = @()
        $affectedCount = 0
        
        # Get users with adminCount > 0
        $privilegedUsers = Get-ADUser -Filter { adminCount -ge 1 } -Properties adminCount, DistinguishedName, SamAccountName -Server $Domain
        
        if ($privilegedUsers.Count -gt 20) {
            $remediation += "Review adminCount usage - $($privilegedUsers.Count) accounts have elevated adminCount"
            $affectedCount = 1
        }
        
        # Check for users with adminCount = 1 but not in protected groups
        foreach ($user in $privilegedUsers) {
            $isProtected = $false
            $protectedGroups = @('Administrators', 'Domain Admins', 'Enterprise Admins', 'Schema Admins')
            
            foreach ($group in $protectedGroups) {
                try {
                    $members = Get-ADGroupMember -Identity $group -Server $Domain
                    if ($members.SamAccountName -contains $user.SamAccountName) {
                        $isProtected = $true
                        break
                    }
                }
                catch { }
            }
            
            if (-not $isProtected) {
                $remediation += "User $($user.SamAccountName) has adminCount=1 but not in protected groups"
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
                    Title = 'Admin Count Configuration Review'
                    Description = "$affectedCount accounts need adminCount review"
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
                    Title = 'Unable to check adminCount attributes'
                    Description = $_.Exception.Message
                    Remediation = 'Verify Active Directory module access'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}

function Invoke-ADRODCCheck {
    <#
    .SYNOPSIS
        Checks Read-Only Domain Controller configuration
    .DESCRIPTION
        Verifies RODC placement and replication filtering
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain
    )
    
    $checkId = 'IDF-AD-RODC-001'
    $checkName = 'RODC Configuration'
    $category = 'Active Directory - Infrastructure'
    $severity = 'Medium'
    
    try {
        if (-not $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }
        
        $remediation = @()
        $affectedCount = 0
        
        # Get all domain controllers
        $dcs = Get-ADDomainController -Filter * -Server $Domain
        
        $rodcCount = ($dcs | Where-Object { $_.IsReadOnly }).Count
        $rwdcCount = ($dcs | Where-Object { -not $_.IsReadOnly }).Count
        
        if ($rodcCount -gt 0) {
            # Check for RODC-only sites
            $sites = Get-ADObject -Filter { objectClass -eq 'site' } -Properties * -Server $Domain
            
            foreach ($site in $sites) {
                $siteName = $site.Name
                $siteServers = $site.siteServerBL
                
                if ($siteServers) {
                    $hasWritable = $false
                    foreach ($server in $siteServers) {
                        $dcInfo = Get-ADDomainController -Identity $server -Server $Domain
                        if (-not $dcInfo.IsReadOnly) {
                            $hasWritable = $true
                            break
                        }
                    }
                    
                    if (-not $hasWritable) {
                        $remediation += "Site $siteName has only RODC - ensure writable DC is accessible"
                        $affectedCount++
                    }
                }
            }
            
            # Check for credential caching on RODCs
            $rodcParams = Get-ADDomainControllerPasswordReplicationPolicy -Identity $dcs[0].HostName[0] -Server $Domain -ErrorAction SilentlyContinue
            if ($rodcParams -and $rodcParams.Allowed -and $rodcParams.Allowed.Count -gt 10) {
                $remediation += "RODC allows password replication for $($rodcParams.Allowed.Count) accounts - review necessity"
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
                    Title = 'RODC Configuration Review'
                    Description = "$affectedCount RODC configuration concerns"
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
                    Title = 'Unable to check RODC configuration'
                    Description = $_.Exception.Message
                    Remediation = 'Verify Active Directory module access'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}
#endregion

#region AWS Extended Checks
function Invoke-AwsIamAccessAnalyzerCheck {
    <#
    .SYNOPSIS
        Checks AWS IAM Access Analyzer findings
    .DESCRIPTION
        Reviews external and unused access findings
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Region = 'us-east-1'
    )
    
    $checkId = 'IDF-AWS-IAA-001'
    $checkName = 'IAM Access Analyzer Findings'
    $category = 'AWS - IAM'
    $severity = 'High'
    
    try {
        $null = Initialize-AWSDefaultConfiguration -Region $Region -ErrorAction Stop
        
        $remediation = @()
        $affectedCount = 0
        
        # Get access analyzers
        $analyzers = Get-IAMAccessAnalyzer -ErrorAction Stop
        
        if ($analyzers.Analyzers.Count -eq 0) {
            $remediation += 'Enable IAM Access Analyzer for the organization'
            $affectedCount = 1
        }
        else {
            foreach ($analyzer in $analyzers.Analyzers) {
                # Get findings for each analyzer
                $findings = Get-IAMAccessAnalyzerFinding -analyzer-arn $analyzer.Arn -ErrorAction Stop
                
                $externalCount = ($findings.Findings | Where-Object { $_.Status -eq 'ACTIVE' -and $_.ResourceType -match 'AWS::S3::Bucket|AWS::IAM::Role|AWS::KMS::Key' }).Count
                
                if ($externalCount -gt 0) {
                    $remediation += "Analyzer $($analyzer.Name) has $externalCount external access findings"
                    $affectedCount++
                }
                
                # Check for unused access
                $unusedCount = ($findings.Findings | Where-Object { $_.ResourceType -eq 'AWS::IAM::User' }).Count
                if ($unusedCount -gt 5) {
                    $remediation += "Analyzer $($analyzer.Name) has $unusedCount unused access findings"
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
                    Title = 'IAM Access Analyzer Review'
                    Description = "$affectedCount access analyzer concerns"
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
                    Title = 'Unable to retrieve Access Analyzer findings'
                    Description = $_.Exception.Message
                    Remediation = 'Verify AWS Tools for PowerShell installation and iam:AccessAnalyzer permissions'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}

function Invoke-AwsVpcFlowLogsCheck {
    <#
    .SYNOPSIS
        Checks VPC Flow Logs configuration
    .DESCRIPTION
        Verifies flow logs are enabled on VPCs
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Region = 'us-east-1'
    )
    
    $checkId = 'IDF-AWS-VPC-001'
    $checkName = 'VPC Flow Logs Configuration'
    $category = 'AWS - Network Security'
    $severity = 'Medium'
    
    try {
        $null = Initialize-AWSDefaultConfiguration -Region $Region -ErrorAction Stop
        
        $remediation = @()
        $affectedCount = 0
        
        # Get all VPCs
        $vpcs = Get-EC2Vpc -ErrorAction Stop
        
        foreach ($vpc in $vpcs) {
            $flowLogs = Get-EC2FlowLogs -Filter @{ Name = 'resource-id'; Values = $vpc.VpcId } -ErrorAction Stop
            
            if ($flowLogs.FlowLogs.Count -eq 0) {
                $remediation += "Enable Flow Logs for VPC $($vpc.VpcId)"
                $affectedCount++
            }
            else {
                foreach ($fl in $flowLogs.FlowLogs) {
                    # Check log destination
                    if ($fl.LogDestinationType -eq 'cloud-watch-logs' -and -not $fl.LogGroupName) {
                        $remediation += "VPC $($vpc.VpcId) flow log missing log group"
                        $affectedCount++
                    }
                    
                    # Check traffic type
                    if ($fl.FlowLogStatus -ne 'ACTIVE') {
                        $remediation += "Enable active Flow Logs for VPC $($vpc.VpcId)"
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
                    Title = 'VPC Flow Logs Configuration Review'
                    Description = "$affectedCount VPC flow log concerns"
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
                    Title = 'Unable to retrieve VPC Flow Log configuration'
                    Description = $_.Exception.Message
                    Remediation = 'Verify AWS Tools for PowerShell installation'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}

function Invoke-AwsConfigRemediationCheck {
    <#
    .SYNOPSIS
        Checks AWS Config conformance packs and remediation
    .DESCRIPTION
        Verifies AWS Config rules and remediation configurations
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Region = 'us-east-1'
    )
    
    $checkId = 'IDF-AWS-CONFIG-001'
    $checkName = 'AWS Config Configuration'
    $category = 'AWS - Compliance'
    $severity = 'Medium'
    
    try {
        $null = Initialize-AWSDefaultConfiguration -Region $Region -ErrorAction Stop
        
        $remediation = @()
        $affectedCount = 0
        
        # Check if AWS Config is enabled
        $configRecorder = Get-AWSConfigServiceRole -ErrorAction Stop
        
        if (-not $configRecorder) {
            $remediation += 'Enable AWS Config for compliance monitoring'
            $affectedCount = 1
        }
        else {
            # Check config rules
            $rules = Get-AWSConfigRule -ErrorAction Stop
            
            if ($rules.Count -lt 10) {
                $remediation += "Add more AWS Config rules (current: $($rules.Count), recommended: 20+)"
                $affectedCount++
            }
            
            # Check for non-compliant resources
            foreach ($rule in $rules | Select-Object -First 5) {
                $evaluations = Get-AWSConfigRuleEvaluationStatus -ConfigRuleName $rule.Name -ErrorAction SilentlyContinue
                if ($evaluations -and $evaluations.CompliantResourceCount -eq 0 -and $evaluations.NonCompliantResourceCount -gt 10) {
                    $remediation += "Rule $($rule.Name) has $($evaluations.NonCompliantResourceCount) non-compliant resources"
                    $affectedCount++
                }
            }
            
            # Check for conformance packs
            $packs = Get-AWSConfigConformancePack -ErrorAction SilentlyContinue
            if (-not $packs -or $packs.Count -eq 0) {
                $remediation += 'Consider implementing Conformance Packs for baseline compliance'
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
                    Title = 'AWS Config Configuration Review'
                    Description = "$affectedCount AWS Config concerns"
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
                    Title = 'Unable to retrieve AWS Config configuration'
                    Description = $_.Exception.Message
                    Remediation = 'Verify AWS Tools for PowerShell installation'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}
#endregion

#region GCP Extended Checks
function Invoke-GcpOrganizationPolicyCheck {
    <#
    .SYNOPSIS
        Checks GCP Organization Policy constraints
    .DESCRIPTION
        Verifies key organization policies are configured
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$OrganizationId
    )
    
    $checkId = 'IDF-GCP-ORG-001'
    $checkName = 'Organization Policy Configuration'
    $category = 'GCP - Organization'
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
        
        # Key policies to check
        $importantPolicies = @(
            'constraints/iam.allowedPolicyMemberDomains',
            'constraints/compute.disableSerialPortAccess',
            'constraints/iam.requireProjectOwner',
            'constraints/storage.publicAccessPrevention',
            'constraints/constraints/iam.automaticIamGrantsForDefaultServiceAccounts'
        )
        
        foreach ($policy in $importantPolicies) {
            $policyResult = gcloud alpha resource-manager org-policies describe $policy --organization=$OrganizationId --format=json 2>$null
            
            if ($LASTEXITCODE -ne 0 -or -not $policyResult) {
                $remediation += "Organization policy $policy is not configured"
                $affectedCount++
            }
            else {
                $policyObj = $policyResult | ConvertFrom-Json
                if (-not $policyObj.spec) {
                    $remediation += "Organization policy $policy has no enforcement rules"
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
                    Title = 'Organization Policy Review'
                    Description = "$affectedCount organization policies need configuration"
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
                    Title = 'Unable to retrieve Organization Policy configuration'
                    Description = $_.Exception.Message
                    Remediation = 'Verify Google Cloud SDK installation and authentication'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}

function Invoke-GcpVpcServiceControlCheck {
    <#
    .SYNOPSIS
        Checks VPC Service Controls perimeter configuration
    .DESCRIPTION
        Verifies service control perimeters for sensitive data
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$OrganizationId
    )
    
    $checkId = 'IDF-GCP-VPCSC-001'
    $checkName = 'VPC Service Controls Configuration'
    $category = 'GCP - Network Security'
    $severity = 'High'
    
    try {
        $remediation = @()
        $affectedCount = 0
        
        $gcloudPath = (Get-Command gcloud -ErrorAction SilentlyContinue).Path
        if (-not $gcloudPath) {
            throw 'Google Cloud SDK not installed'
        }
        
        # Check for VPC-SC API enablement
        $apiResult = gcloud services list --enabled --filter='name:vpcaccess.googleapis.com' --format=value 2>$null
        if (-not $apiResult) {
            $remediation += 'Enable VPC Access API for Service Controls'
            $affectedCount++
        }
        
        # Check for access levels
        $accessLevelsUri = 'https://accesscontextmanager.googleapis.com/v1/accessLevels'
        try {
            $accessLevels = Invoke-RestMethod -Uri $accessLevelsUri -Headers @{ Authorization = "Bearer $(gcloud auth print-access-token)" } -ErrorAction Stop
            if (-not $accessLevels.accessLevels -or $accessLevels.accessLevels.Count -eq 0) {
                $remediation += 'Create Access Levels for VPC Service Controls'
                $affectedCount++
            }
        }
        catch {
            # Access Context Manager not available
            $remediation += 'Enable Access Context Manager for VPC Service Controls'
            $affectedCount++
        }
        
        # Check for service perimeters
        $perimetersUri = 'https://accesscontextmanager.googleapis.com/v1/servicePerimeters'
        try {
            $perimeters = Invoke-RestMethod -Uri $perimetersUri -Headers @{ Authorization = "Bearer $(gcloud auth print-access-token)" } -ErrorAction Stop
            if (-not $perimeters.servicePerimeters -or $perimeters.servicePerimeters.Count -eq 0) {
                $remediation += 'Create Service Perimeters to protect sensitive resources'
                $affectedCount++
            }
            else {
                foreach ($sp in $perimeters.servicePerimeters) {
                    if ($sp.status -and $sp.status.ingressPolicies) {
                        $ingressCount = ($sp.status.ingressPolicies | Measure-Object).Count
                        if ($ingressCount -gt 10) {
                            $remediation += "Service Perimeter $($sp.name) has $ingressCount ingress policies - review necessity"
                            $affectedCount++
                        }
                    }
                }
            }
        }
        catch {
            $remediation += 'Configure Service Perimeters in Access Context Manager'
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
                    Title = 'VPC Service Controls Review'
                    Description = "$affectedCount VPC-SC configuration concerns"
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
                    Title = 'Unable to retrieve VPC Service Controls configuration'
                    Description = $_.Exception.Message
                    Remediation = 'Verify Google Cloud SDK installation and authentication'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}

function Invoke-GcpCloudArmorCheck {
    <#
    .SYNOPSIS
        Checks Google Cloud Armor security policies
    .DESCRIPTION
        Verifies Cloud Armor is deployed and configured on backend services
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ProjectId
    )
    
    $checkId = 'IDF-GCP-ARMOR-001'
    $checkName = 'Cloud Armor Security Policy'
    $category = 'GCP - Network Security'
    $severity = 'Medium'
    
    try {
        $remediation = @()
        $affectedCount = 0
        
        $gcloudPath = (Get-Command gcloud -ErrorAction SilentlyContinue).Path
        if (-not $gcloudPath) {
            throw 'Google Cloud SDK not installed'
        }
        
        if (-not $ProjectId) {
            $projResult = gcloud projects list --format=value --limit=1 2>$null
            if ($LASTEXITCODE -ne 0 -or -not $projResult) {
                throw 'No project found'
            }
            $ProjectId = $projResult
        }
        
        # Check for Cloud Armor policies
        $armorPolicies = gcloud compute security-policies list --project=$ProjectId --format=json 2>$null
        
        if ($LASTEXITCODE -ne 0 -or -not $armorPolicies) {
            $remediation += 'Consider implementing Cloud Armor security policies'
            $affectedCount = 1
        }
        else {
            $policies = $armorPolicies | ConvertFrom-Json
            
            # Check backend services without Armor
            $backends = gcloud compute backend-services list --project=$ProjectId --format=json 2>$null
            if ($backends) {
                $backendList = $backends | ConvertFrom-Json
                $protectedBackends = 0
                
                foreach ($backend in $backendList) {
                    if ($backend.securityPolicy) {
                        $protectedBackends++
                    }
                }
                
                $unprotectedCount = $backendList.Count - $protectedBackends
                if ($unprotectedCount -gt 0) {
                    $remediation += "Attach Cloud Armor policies to $unprotectedCount backend services"
                    $affectedCount++
                }
            }
            
            # Check for WAF rules in policies
            foreach ($policy in $policies) {
                $rulesUri = "gcloud compute security-policies describe $($policy.name) --project=$ProjectId --format=json"
                $rulesResult = Invoke-Expression $rulesUri 2>$null
                if ($rulesResult) {
                    $rulesObj = $rulesResult | ConvertFrom-Json
                    $wafRules = ($rulesObj.rules | Where-Object { $_.match -and $_.match.config -and $_.match.config.expression }).Count
                    if ($wafRules -eq 0) {
                        $remediation += "Security policy $($policy.name) has no WAF rules configured"
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
                    Title = 'Cloud Armor Configuration Review'
                    Description = "$affectedCount Cloud Armor concerns"
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
                    Title = 'Unable to retrieve Cloud Armor configuration'
                    Description = $_.Exception.Message
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

# Export module functions
Export-ModuleMember -Function @(
    'Invoke-EntraIdAdministrativeUnitCheck',
    'Invoke-EntraIdPermissionGrantCheck',
    'Invoke-EntraIdTokenLifetimeCheck',
    'Invoke-AzurePrivateEndpointCheck',
    'Invoke-AzureVnetPeeringCheck',
    'Invoke-AzureFirewallPolicyCheck',
    'Invoke-ADDuplicateSpnCheck',
    'Invoke-ADAdminCountCheck',
    'Invoke-ADRODCCheck',
    'Invoke-AwsIamAccessAnalyzerCheck',
    'Invoke-AwsVpcFlowLogsCheck',
    'Invoke-AwsConfigRemediationCheck',
    'Invoke-GcpOrganizationPolicyCheck',
    'Invoke-GcpVpcServiceControlCheck',
    'Invoke-GcpCloudArmorCheck'
)

# SIG # Begin signature block
# MIIf3QYJKoZIhvcNAQcCoIIfzjCCH8oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAtlLGMo63Neqzi
# LxGo/HYUuLlkrfOQIM3LFtxieQTL06CCGNwwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# AgEVMC8GCSqGSIb3DQEJBDEiBCDd0HuoU4yrbkSKYIekRFdrJlkpgyDlQ5UNeqL9
# u0caijANBgkqhkiG9w0BAQEFAASCAgDHwW6OZ5ueWa2SIrkNxi6qm26eX3a3urj8
# l2TEnuG+xGjJAky9NdbPeJFliNZr5hhggZLKpam5b3VEJURi+GcdMsqRvjxauW8T
# n10lfUtZF+KtvWtzarQ5C1a01FMkH3PCMIgXtCh8JlSuy86lNbhNzqj4s6/Fr9a4
# ZCos/HwietIPh8RGn62RaDnNXSMu3mBFbMfnOIgAXfdhxkAV+pdf/y3DHaSC9Yol
# Q6Ro5U+Wc6hWIhbf84z7f7mkw9n1Zi9xgB7Is8wzEgZK/7Jl6yCei7LoJ4DsQC6b
# sIhBR/UnE2dCO4TxPrLeDRmO/Dc8MjbXD7YSGMIk+IR/NhugEE9MoY4hmYsexKC+
# 5W6ld21PGfINy65vPb51BtwBdLJc2FVzxE3t5p7YueKNF8LVukq5VrsMsKBfPPHP
# wkuSVd7Rc0a0qF9RzM7GTDMjLvce67lTC+qDs2jqFEpoVRL/C3se4GJJO9Jc2Ajo
# DlsELbJNahFP+1N9aArmZMrMHrUaBr8Sp50r7r92WaNxHJe12O+zxqrg9wgzixlG
# PGysJ8Lx/sdVf6+uE+g0g9ZJ6Uwq19xbj03safAeMLC1xW1BuFOFZfd76pItO/pp
# SWT3ReTc9EzuTMBL61jE1KuLI9Bl3WsFaOPgLiCRURs8D9FThs1rEQhqV2Qd07GD
# kmLbUG3+PaGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAyMDUxNzEyNDZaMC8G
# CSqGSIb3DQEJBDEiBCDVwxkrmxEFpAqMybwWIUpz2cnt0USMghc3t94ymzFxRDAN
# BgkqhkiG9w0BAQEFAASCAgCPrQn5SlvkU2H13Mjo1gzX+eBklHtU8sTF4GfCZviP
# gAE7fKB2DFVmCZNnRViqVbplJeRMG1GJcD5shUXgipgWEQA4HWR5e7qDC1HMgCJ+
# 9sNUZSg428CBcawFM2VUuQbGNEDVAtPR5JGQAbTGLqttA3Qhq9YYC8AUUHcKy35A
# MgERHQE37zKg2f7wi4EcOIN94TOngt6EszVkCpMnv9NbSxuASWJxVcN2cwwMJGf9
# SYfv2EfqWJ4W1Qe4Enbx1J68vyUF+dfs0l7AsyT4FG7uSfWirwtNVKAStq/aspk7
# lttVyp2vp496op4oQjz2gjsbVL5Z+4fnQw+kxPt0h+UJRBUrW2Um1oiYBpEa8OkQ
# hMphRzxh8iVMFabxq5tbRrbmy8BYPbrn6zEm6m0G5gTusiaj6/sJO+13nVSpgCaL
# RhUliWvk4773JhFycwZC3Nm0BVmgzLsde1oNzw40ivXcskLkY6eO7zn7nldJVKzt
# 0tAmwjFwWD6DhzhM6EQ25WCZbGSEuZR8tA0/wfhBRVeIjglJ/1UiMpkjMVr5Vdof
# YE3SvDtGO2yuWlaSKIQFXPJPHjEkV0k6b0Uy5usQSsT0NKDWfsogUXWAHJC3MxmA
# SrRBqFa56ngVYLGrnir/9NbGobYxYFoSSubRvc6YWS4ka3wLKZjwWy7rTHsfbl3W
# xA==
# SIG # End signature block
