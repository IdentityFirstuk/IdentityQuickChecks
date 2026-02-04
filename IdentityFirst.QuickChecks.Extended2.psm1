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
