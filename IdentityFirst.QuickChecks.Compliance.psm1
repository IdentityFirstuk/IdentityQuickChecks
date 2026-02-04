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
