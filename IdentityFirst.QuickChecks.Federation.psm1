# ============================================================================
# IdentityFirst QuickChecks - Federation, Backup & APIM Module
# ============================================================================
# PowerShell 5.1 Compatible
# Contains Okta, Federation, Backup, and API Management security checks
# ============================================================================

#requires -Version 5.1

#region Okta Identity Checks
function Invoke-OktaOrganizationSecurityCheck {
    <#
    .SYNOPSIS
        Checks Okta organization security configuration
    .DESCRIPTION
        Verifies Okta admin access, policies, and security settings
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ApiToken,
        
        [Parameter(Mandatory=$false)]
        [string]$OktaDomain = 'https://dev-{yourOktaDomain}.okta.com'
    )
    
    $checkId = 'IDF-OKTA-ORG-001'
    $checkName = 'Okta Organization Security'
    $category = 'Okta - Organization'
    $severity = 'High'
    
    try {
        $remediation = @()
        $affectedCount = 0
        
        # Check for API token
        if (-not $ApiToken) {
            $remediation += 'Provide Okta API token for organization checks'
            $affectedCount = 1
            throw 'API token required'
        }
        
        $headers = @{
            'Authorization' = "SSWS $ApiToken"
            'Accept' = 'application/json'
            'Content-Type' = 'application/json'
        }
        
        # Get organization configuration
        $orgUri = "$OktaDomain/api/v1/org"
        $orgInfo = Invoke-RestMethod -Uri $orgUri -Headers $headers -Method Get -ErrorAction Stop
        
        # Check for administrator reviews
        $adminsUri = "$OktaDomain/api/v1/roles/users"
        $admins = Invoke-RestMethod -Uri $adminsUri -Headers $headers -Method Get -ErrorAction Stop
        
        $adminCount = ($admins | Measure-Object).Count
        if ($adminCount -gt 10) {
            $remediation += "Review Okta administrator count: $adminCount users"
            $affectedCount++
        }
        
        # Check for MFA requirements
        $orgFactorsUri = "$OktaDomain/api/v1/org/factors"
        $factors = Invoke-RestMethod -Uri $orgFactorsUri -Headers $headers -Method Get -ErrorAction Stop
        
        $mfaEnabled = $factors | Where-Object { $_.status -eq 'ACTIVE' }
        if ($mfaEnabled.Count -lt 2) {
            $remediation += 'Enable multiple MFA factors for Okta organization'
            $affectedCount++
        }
        
        # Check API token creation settings
        $hooksUri = "$OktaDomain/api/v1/org/tasks"
        try {
            $tasks = Invoke-RestMethod -Uri $hooksUri -Headers $headers -Method Get -ErrorAction Stop
        }
        catch {
            $remediation += 'Review Okta task configuration'
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
                    Title = 'Okta Organization Security Review'
                    Description = "$affectedCount organization security concerns"
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
                    Title = 'Unable to check Okta organization security'
                    Description = $_.Exception.Message
                    Remediation = 'Verify Okta API token and domain'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}

function Invoke-OktaPolicyCheck {
    <#
    .SYNOPSIS
        Checks Okta policy configurations
    .DESCRIPTION
        Reviews password, MFA, and sign-on policies
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ApiToken,
        
        [Parameter(Mandatory=$false)]
        [string]$OktaDomain = 'https://dev-{yourOktaDomain}.okta.com'
    )
    
    $checkId = 'IDF-OKTA-POL-001'
    $checkName = 'Okta Policy Configuration'
    $category = 'Okta - Policies'
    $severity = 'Medium'
    
    try {
        $remediation = @()
        $affectedCount = 0
        
        if (-not $ApiToken) {
            throw 'API token required'
        }
        
        $headers = @{
            'Authorization' = "SSWS $ApiToken"
            'Accept' = 'application/json'
        }
        
        # Check password policies
        $pwdPolicyUri = "$OktaDomain/api/v1/policies?type=PASSWORD"
        $pwdPolicies = Invoke-RestMethod -Uri $pwdPolicyUri -Headers $headers -Method Get -ErrorAction Stop
        
        foreach ($policy in $pwdPolicies) {
            $policyName = $policy.name
            $settings = $policy.settings
            
            if ($settings.complexity.minLength -lt 14) {
                $currentLen = $settings.complexity.minLength
                $remediation += "Increase password complexity for $policyName (current: $currentLen, recommended: 14)"
                $affectedCount++
            }
            
            if ($settings.complexity.requireUppercase -ne $true) {
                $remediation += "Enable uppercase requirement for $policyName"
                $affectedCount++
            }
            
            if ($settings.complexity.requireLowercase -ne $true) {
                $remediation += "Enable lowercase requirement for $policyName"
                $affectedCount++
            }
            
            if ($settings.complexity.requireNumber -ne $true) {
                $remediation += "Enable number requirement for $policyName"
                $affectedCount++
            }
            
            if ($settings.complexity.requireSymbol -ne $true) {
                $remediation += "Enable symbol requirement for $policyName"
                $affectedCount++
            }
            
            # Check password expiration
            if ($settings.age.maxAgeDays -gt 60) {
                $maxAge = $settings.age.maxAgeDays
                $remediation += "Reduce password max age for $policyName (current: $maxAge days, recommended: 60)"
                $affectedCount++
            }
        }
        
        # Check sign-on policies
        $signOnUri = "$OktaDomain/api/v1/policies?type=OKTA_SIGN_ON"
        $signOnPolicies = Invoke-RestMethod -Uri $signOnUri -Headers $headers -Method Get -ErrorAction Stop
        
        foreach ($policy in $signOnPolicies) {
            $policyName = $policy.name
            $conditions = $policy.conditions
            
            # Check for MFA required
            if ($conditions.authenticator -and $conditions.authenticator.enroll -ne 'REQUIRED') {
                $remediation += "Require MFA enrollment in sign-on policy: $policyName"
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
                    Title = 'Okta Policy Configuration Review'
                    Description = "$affectedCount policy configuration concerns"
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
                    Title = 'Unable to check Okta policies'
                    Description = $_.Exception.Message
                    Remediation = 'Verify Okta API access'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}

function Invoke-OktaApplicationSecurityCheck {
    <#
    .SYNOPSIS
        Checks Okta application integrations security
    .DESCRIPTION
        Reviews app assignments, visibility, and sign-on modes
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$ApiToken,
        
        [Parameter(Mandatory=$false)]
        [string]$OktaDomain = 'https://dev-{yourOktaDomain}.okta.com'
    )
    
    $checkId = 'IDF-OKTA-APP-001'
    $checkName = 'Okta Application Security'
    $category = 'Okta - Applications'
    $severity = 'Medium'
    
    try {
        $remediation = @()
        $affectedCount = 0
        
        if (-not $ApiToken) {
            throw 'API token required'
        }
        
        $headers = @{
            'Authorization' = "SSWS $ApiToken"
            'Accept' = 'application/json'
        }
        
        # Get all applications
        $appsUri = "$OktaDomain/api/v1/apps"
        $apps = Invoke-RestMethod -Uri $appsUri -Headers $headers -Method Get -ErrorAction Stop
        
        $appWithoutMFA = 0
        $appWithImplicit = 0
        
        foreach ($app in $apps) {
            $appName = $app.name
            $appStatus = $app.status
            
            if ($appStatus -ne 'ACTIVE') {
                continue
            }
            
            # Check for apps without MFA
            $signOn = $app.signOnMode
            
            if ($signOn -match 'SAML|AUTO_WORKFLOW|OIDC') {
                $appSettingsUri = "$OktaDomain/api/v1/apps/$($app.id)/settings/signon"
                try {
                    $settings = Invoke-RestMethod -Uri $appSettingsUri -Headers $headers -Method Get -ErrorAction Stop
                    if ($settings -and -not $settings.revealPassword -and $signOn -ne 'AUTO_WORKFLOW') {
                        # Check if MFA is required
                        $appUsersUri = "$OktaDomain/api/v1/apps/$($app.id)/users"
                        $appUsers = Invoke-RestMethod -Uri $appUsersUri -Headers $headers -Method Get -ErrorAction Stop
                        
                        $assignedUsers = ($appUsers | Where-Object { $_.scope -eq 'USER' }).Count
                        if ($assignedUsers -gt 0 -and $signOn -ne 'AUTO_WORKFLOW') {
                            $appWithoutMFA++
                        }
                    }
                }
                catch {
                    # Unable to get settings
                }
            }
            
            # Check for implicit grant
            if ($signOn -eq 'SAML_2.0') {
                $appSamlUri = "$OktaDomain/api/v1/apps/$($app.id)/sso"
                $samlSettings = Invoke-RestMethod -Uri $appSamlUri -Headers $headers -Method Get -ErrorAction Stop
                if ($samlSettings -and $samlSettings.authnContextClassRef -match 'AuthnContextClassRef') {
                    $appWithImplicit++
                }
            }
        }
        
        if ($appWithoutMFA -gt 0) {
            $remediation += "Review $appWithoutMFA applications for MFA requirements"
            $affectedCount++
        }
        
        if ($appWithImplicit -gt 0) {
            $remediation += "Review $appWithImplicit SAML apps for implicit grant settings"
            $affectedCount++
        }
        
        # Check app visibility
        $hiddenApps = ($apps | Where-Object { $_.visibility.hide -and ($_.visibility.hide.ios -or $_.visibility.hide.web) }).Count
        if ($hiddenApps -gt 5) {
            $remediation += "Review app visibility settings: $hiddenApps hidden apps"
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
                    Title = 'Okta Application Security Review'
                    Description = "$affectedCount application security concerns"
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
                    Title = 'Unable to check Okta applications'
                    Description = $_.Exception.Message
                    Remediation = 'Verify Okta API access'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}
#endregion

#region Federation Services Checks
function Invoke-ADFSConfigurationCheck {
    <#
    .SYNOPSIS
        Checks Active Directory Federation Services configuration
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$AdfsServer
    )
    
    $checkId = 'IDF-ADFS-001'
    $checkName = 'ADFS Configuration Security'
    $category = 'Federation - ADFS'
    $severity = 'High'
    
    try {
        $remediation = @()
        $affectedCount = 0
        
        # Check if ADFS module is available
        try {
            $null = Import-Module ADFS -ErrorAction Stop
        }
        catch {
            # Try WMI approach
            $adfsPresent = Get-WmiObject -Namespace 'root/ADFS' -Class SecurityTokenService -ErrorAction SilentlyContinue
            if (-not $adfsPresent) {
                $remediation += 'ADFS not detected on this system'
                $affectedCount = 1
            }
        }
        
        if ($AdfsServer -or $adfsPresent) {
            $server = $AdfsServer -or 'localhost'
            
            # Check for certificate monitoring
            $certPath = 'HKLM:\SOFTWARE\Microsoft\ADFS'
            if (Test-Path $certPath) {
                $certProperties = Get-ItemProperty -Path $certPath -ErrorAction SilentlyContinue
                
                if (-not $certProperties.AutoCertificateRollover) {
                    $remediation += 'Enable automatic certificate rollover in ADFS'
                    $affectedCount++
                }
                
                if ($certProperties.SslCertificateName) {
                    $cert = Get-ChildItem -Path 'Cert:\LocalMachine\My' | Where-Object { $_.Subject -match $certProperties.SslCertificateName }
                    if ($cert) {
                        $daysRemaining = ($cert.NotAfter - (Get-Date)).Days
                        if ($daysRemaining -lt 30) {
                            $remediation += "ADFS SSL certificate expires in $daysRemaining days"
                            $affectedCount++
                        }
                    }
                }
            }
            
            # Check ADFS proxy settings
            $proxyPath = 'HKLM:\SOFTWARE\Microsoft\ADFS\Proxy'
            if (Test-Path $proxyPath) {
                $proxyProps = Get-ItemProperty -Path $proxyPath -ErrorAction SilentlyContinue
                if ($proxyProps -and $proxyProps.ProxyTrustVerificationEnabled -ne $true) {
                    $remediation += 'Enable proxy trust verification'
                    $affectedCount++
                }
            }
            
            # Check for primary federation service
            $fsUri = 'https://' + $server + '/FederationMetadata/2007-06/FederationMetadata.xml'
            try {
                $metadata = Invoke-RestMethod -Uri $fsUri -ErrorAction Stop
                if ($metadata) {
                    $entityId = $metadata.EntityDescriptor.entityID
                    if ($entityId -match 'adfs/services/trust') {
                        $remediation += 'Consider migrating from ADFS to cloud-only authentication'
                        $affectedCount++
                    }
                }
            }
            catch {
                # Unable to access metadata
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
                    Title = 'ADFS Configuration Review'
                    Description = "$affectedCount ADFS configuration concerns"
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
                    Title = 'Unable to check ADFS configuration'
                    Description = $_.Exception.Message
                    Remediation = 'Run on ADFS server with admin privileges'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}

function Invoke-FederationTrustCheck {
    <#
    .SYNOPSIS
        Checks federation trust relationships
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain
    )
    
    $checkId = 'IDF-FED-TRUST-001'
    $checkName = 'Federation Trust Configuration'
    $category = 'Federation - Trusts'
    $severity = 'Medium'
    
    try {
        if (-not $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }
        
        $remediation = @()
        $affectedCount = 0
        
        # Get domain trust relationships
        $trusts = Get-ADObject -Filter { objectClass -eq 'trustedDomain' } -Properties * -Server $Domain
        
        foreach ($trust in $trusts) {
            $trustName = $trust.Name
            $trustType = $trust.TrustType
            $trustDirection = $trust.TrustDirection
            
            # Check for incoming trusts
            if ($trustDirection -eq 'Inbound' -or $trustDirection -eq 'Bidirectional') {
                $remediation += "Review federation trust: $trustName (Direction: $trustDirection)"
                $affectedCount++
            }
            
            # Check for selective authentication
            if ($trust.SideTrustValues -and $trust.SideTrustValues.AuthenticationLevel -ne 1) {
                $remediation += "Enable selective authentication for trust: $trustName"
                $affectedCount++
            }
        }
        
        # Check for claims provider trust with external IdP
        $claimsProviders = Get-ADObject -Filter { objectClass -eq 'claimsProviderTrust' } -Server $Domain
        foreach ($cp in $claimsProviders) {
            $cpName = $cp.Name
            $remediation += "Review claims provider: $cpName"
            $affectedCount++
        }
        
        # Get relying party trusts
        $relyingParties = Get-ADObject -Filter { objectClass -eq 'relyingPartyTrust' } -Server $Domain
        foreach ($rp in $relyingParties) {
            $rpName = $rp.Name
            
            # Check for SAML token replay
            $tokenReplay = $rp.TokenReplayLifetime
            if ($tokenReplay -gt 300) {
                $remediation += "Reduce token replay lifetime for $rpName (current: $tokenReplay)"
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
                    Title = 'Federation Trust Configuration Review'
                    Description = "$affectedCount federation trust concerns"
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
                    Title = 'Unable to check federation trusts'
                    Description = $_.Exception.Message
                    Remediation = 'Verify AD RSAT and domain connectivity'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}
#endregion

#region Backup & Recovery Checks
function Invoke-AzureBackupSecurityCheck {
    <#
    .SYNOPSIS
        Checks Azure Backup security configuration
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$SubscriptionId
    )
    
    $checkId = 'IDF-AZ-BACKUP-001'
    $checkName = 'Azure Backup Security Configuration'
    $category = 'Backup - Azure'
    $severity = 'High'
    
    try {
        $null = Connect-AzAccount -ErrorAction Stop
        
        $remediation = @()
        $affectedCount = 0
        
        if (-not $SubscriptionId) {
            $SubscriptionId = (Get-AzSubscription)[0].Id
        }
        
        $null = Set-AzContext -SubscriptionId $SubscriptionId
        
        # Get Recovery Services vaults
        $vaultUri = "/subscriptions/$SubscriptionId/providers/Microsoft.RecoveryServices/vaults?api-version=2021-06-01"
        $vaults = Invoke-AzRestMethod -Method GET -Uri $vaultUri -ErrorAction Stop
        
        if ($vaults.Value.Count -eq 0) {
            $remediation += 'Consider implementing Azure Backup for critical workloads'
            $affectedCount = 1
        }
        else {
            foreach ($vault in $vaults.Value) {
                $vaultName = $vault.name
                $vaultRg = $vault.id -replace '/subscriptions/[^/]+/resourceGroups/', '' -replace '/providers/Microsoft.RecoveryServices.*', ''
                
                # Check for soft delete
                $sdUri = "/subscriptions/$SubscriptionId/resourceGroups/$vaultRg/providers/Microsoft.RecoveryServices/vaults/$vaultName/backupconfig?api-version=2021-06-01"
                $sdConfig = Invoke-AzRestMethod -Method GET -Uri $sdUri -ErrorAction Stop
                
                if ($sdConfig.properties.softDeleteFeatureState -ne 'Enabled') {
                    $remediation += "Enable soft delete for vault: $vaultName"
                    $affectedCount++
                }
                
                # Check for encryption
                $encUri = "/subscriptions/$SubscriptionId/resourceGroups/$vaultRg/providers/Microsoft.RecoveryServices/vaults/$vaultName/encryption?api-version=2021-06-01"
                $encConfig = Invoke-AzRestMethod -Method GET -Uri $encUri -ErrorAction Stop
                
                if (-not $encConfig.properties.encryptionKeyId) {
                    $remediation += "Configure customer-managed key encryption for vault: $vaultName"
                    $affectedCount++
                }
                
                # Check backup policies
                $policyUri = "/subscriptions/$SubscriptionId/resourceGroups/$vaultRg/providers/Microsoft.RecoveryServices/vaults/$vaultName/backupPolicies?api-version=2021-06-01"
                $policies = Invoke-AzRestMethod -Method GET -Uri $policyUri -ErrorAction Stop
                
                foreach ($policy in $policies.Value) {
                    $policyName = $policy.name
                    $retention = $policy.properties.retentionPolicy
                    
                    if ($retention.dailySchedule -and $retention.dailySchedule.retentionCount -lt 7) {
                        $remediation += "Increase daily backup retention for $policyName (current: $($retention.dailySchedule.retentionCount))"
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
                    Title = 'Azure Backup Security Review'
                    Description = "$affectedCount backup security concerns"
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
                    Title = 'Unable to check Azure Backup security'
                    Description = $_.Exception.Message
                    Remediation = 'Verify Azure permissions'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}

function Invoke-AwsBackupCheck {
    <#
    .SYNOPSIS
        Checks AWS Backup configuration
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Region = 'us-east-1'
    )
    
    $checkId = 'IDF-AWS-BACKUP-001'
    $checkName = 'AWS Backup Configuration'
    $category = 'Backup - AWS'
    $severity = 'Medium'
    
    try {
        $null = Initialize-AWSDefaultConfiguration -Region $Region -ErrorAction Stop
        
        $remediation = @()
        $affectedCount = 0
        
        # Check if Backup is enabled
        try {
            $backupPlans = Get-BAKBackupPlan -ErrorAction Stop
            $backupVaults = Get-BAKBackupVault -ErrorAction Stop
        }
        catch {
            $remediation += 'Enable AWS Backup for critical workloads'
            $affectedCount = 1
            throw 'AWS Backup not available'
        }
        
        # Check backup vaults
        if ($backupVaults.BackupVaultList.Count -eq 0) {
            $remediation += 'Create backup vaults in AWS Backup'
            $affectedCount++
        }
        else {
            foreach ($vault in $backupVaults.BackupVaultList) {
                # Check for encryption
                if (-not $vault.EncryptionKeyArn) {
                    $remediation += "Enable encryption for backup vault: $($vault.BackupVaultName)"
                    $affectedCount++
                }
                
                # Check for access policy
                $vaultAccess = Get-BAKBackupVaultAccessPolicy -BackupVaultName $vault.BackupVaultName -ErrorAction SilentlyContinue
                if ($vaultAccess -and $vaultAccess.Policy -match '"Action": "backup:StartBackup"') {
                    if ($vaultAccess.Policy -match '"Principal": "*"') {
                        $remediation += "Restrict backup vault access policy: $($vault.BackupVaultName)"
                        $affectedCount++
                    }
                }
            }
        }
        
        # Check backup plans
        if ($backupPlans.BackupPlans.Count -eq 0) {
            $remediation += 'Create backup plans for critical resources'
            $affectedCount++
        }
        else {
            foreach ($plan in $backupPlans.BackupPlans) {
                $planName = $plan.BackupPlanName
                
                # Check for completion window
                if ($plan.BackupPlanRule -and $plan.BackupPlanRule.CompletionWindowMinutes -gt 1440) {
                    $remediation += "Reduce completion window for backup plan: $planName"
                    $affectedCount++
                }
                
                # Check for retention
                $retention = $plan.BackupPlanRule.LifecycleDeleteAfterDays
                if ($retention -lt 30) {
                    $remediation += "Increase backup retention for $planName (current: $retention days)"
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
                    Title = 'AWS Backup Configuration Review'
                    Description = "$affectedCount backup configuration concerns"
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
                    Title = 'Unable to check AWS Backup configuration'
                    Description = $_.Exception.Message
                    Remediation = 'Verify AWS Backup permissions'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}

function Invoke-ADBackupCheck {
    <#
    .SYNOPSIS
        Checks Active Directory backup configuration
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain
    )
    
    $checkId = 'IDF-AD-BACKUP-001'
    $checkName = 'Active Directory Backup Configuration'
    $category = 'Backup - Active Directory'
    $severity = 'High'
    
    try {
        if (-not $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }
        
        $remediation = @()
        $affectedCount = 0
        
        # Get domain controllers
        $dcs = Get-ADDomainController -Filter * -Server $Domain
        
        # Check for AD Recycle Bin
        try {
            $recycleBin = Get-ADObject -Identity "CN=Recycle Bin Feature,CN=Optional Features,CN=Configuration,DC=$($Domain.Replace('.', ',DC='))" -Properties * -Server $Domain -ErrorAction Stop
            if (-not $recycleBin) {
                $remediation += 'Enable AD Recycle Bin for deleted object recovery'
                $affectedCount++
            }
        }
        catch {
            $remediation += 'Enable AD Recycle Bin for deleted object recovery'
            $affectedCount++
        }
        
        # Check for system state backup
        $backupJob = Get-WBJob -ErrorAction SilentlyContinue
        if (-not $backupJob) {
            $remediation += 'Configure Windows Server Backup for AD system state'
            $affectedCount++
        }
        
        # Check for critical object protected groups
        $protectedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins')
        foreach ($group in $protectedGroups) {
            try {
                $members = Get-ADGroupMember -Identity $group -Server $Domain
                if ($members.Count -gt 5) {
                    $remediation += "Review membership of protected group: $group"
                    $affectedCount++
                }
            }
            catch { }
        }
        
        # Check for fine-grained password policy
        $fgpp = Get-ADFineGrainedPasswordPolicy -Filter * -Server $Domain -ErrorAction SilentlyContinue
        if (-not $fgpp) {
            $remediation += 'Consider implementing Fine-Grained Password Policies'
            $affectedCount++
        }
        
        # Check last backup time
        $dcs = Get-ADDomainController -Filter * -Server $Domain
        foreach ($dc in $dcs) {
            $dcName = $dc.HostName
            try {
                $partitionInfo = Get-ADObject -Identity "DC=$($Domain.Replace('.', ',DC='))" -Partition 'CN=Schema,CN=Configuration,DC=' -Properties * -Server $dcName
                $schemaTime = $partitionInfo.SchemaNamingContext
                if ($schemaTime) {
                    $lastSync = $dc.LastReplicationSynced
                    if ($lastSync) {
                        $hoursSince = ((Get-Date) - $lastSync).TotalHours
                        if ($hoursSince -gt 48) {
                            $remediation += "DC $dcName has not replicated in $hoursSince hours"
                            $affectedCount++
                        }
                    }
                }
            }
            catch { }
        }
        
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = $severity
            Status = if ($affectedCount -eq 0) { 'Pass' } else { 'Warning' }
            Findings = if ($affectedCount -gt 0) { @(
                @{
                    Title = 'AD Backup Configuration Review'
                    Description = "$affectedCount backup configuration concerns"
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
                    Title = 'Unable to check AD backup configuration'
                    Description = $_.Exception.Message
                    Remediation = 'Verify AD RSAT and domain connectivity'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}
#endregion

#region Azure API Management Security Checks
function Invoke-AzApimSecurityCheck {
    <#
    .SYNOPSIS
        Checks Azure API Management security configuration
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$SubscriptionId
    )
    
    $checkId = 'IDF-AZ-APIM-001'
    $checkName = 'API Management Security'
    $category = 'Application Security - APIM'
    $severity = 'High'
    
    try {
        $null = Connect-AzAccount -ErrorAction Stop
        
        $remediation = @()
        $affectedCount = 0
        
        if (-not $SubscriptionId) {
            $SubscriptionId = (Get-AzSubscription)[0].Id
        }
        
        $null = Set-AzContext -SubscriptionId $SubscriptionId
        
        # Get APIM instances
        $apimUri = "/subscriptions/$SubscriptionId/providers/Microsoft.ApiManagement/service?api-version=2021-08-01"
        $apimInstances = Invoke-AzRestMethod -Method GET -Uri $apimUri -ErrorAction Stop
        
        if ($apimInstances.Value.Count -eq 0) {
            $remediation += 'No APIM instances found'
            $affectedCount = 1
        }
        else {
            foreach ($apim in $apimInstances.Value) {
                $apimName = $apim.name
                $apimRg = $apim.id -replace '/subscriptions/[^/]+/resourceGroups/', '' -replace '/providers/Microsoft.ApiManagement.*', ''
                
                # Check for public access
                $apimConfig = Invoke-AzRestMethod -Method GET -Uri "$apimUri/$apimName?api-version=2021-08-01" -ErrorAction Stop
                if ($apimConfig.properties.publicIPAddresses -or $apimConfig.properties.enableClientCertificate) {
                    $remediation += "Consider restricting public access to APIM: $apimName"
                    $affectedCount++
                }
                
                # Check for virtual network
                if (-not $apimConfig.properties.virtualNetworkConfiguration) {
                    $remediation += "Deploy APIM in virtual network: $apimName"
                    $affectedCount++
                }
                
                # Check for managed identity
                if ($apimConfig.identity.type -ne 'SystemAssigned') {
                    $remediation += "Enable managed identity for APIM: $apimName"
                    $affectedCount++
                }
                
                # Check for authorization server
                $authUri = "$apimUri/$apimName/authorizationServers?api-version=2021-08-01"
                $authServers = Invoke-AzRestMethod -Method GET -Uri $authUri -ErrorAction Stop
                
                if ($authServers.Value.Count -gt 0) {
                    foreach ($auth in $authServers.Value) {
                        if ($auth.displayName -notmatch 'oauth2|oauth|azure') {
                            $remediation += "Review authorization server: $($auth.displayName)"
                            $affectedCount++
                        }
                    }
                }
                
                # Check for subscription validation
                $productsUri = "$apimUri/$apimName/products?api-version=2021-08-01"
                $products = Invoke-AzRestMethod -Method GET -Uri $productsUri -ErrorAction Stop
                
                foreach ($product in $products.Value) {
                    $productName = $product.name
                    $approvalRequired = $product.properties.approvalRequired
                    $subscriptionsLimit = $product.properties.subscriptionRequired
                    
                    if (-not $subscriptionsLimit) {
                        $remediation += "Require subscription for product: $productName"
                        $affectedCount++
                    }
                }
                
                # Check for rate limit policies
                $apisUri = "$apimUri/$apimName/apis?api-version=2021-08-01"
                $apis = Invoke-AzRestMethod -Method GET -Uri $apisUri -ErrorAction Stop
                
                foreach ($api in $apis.Value) {
                    $policyUri = "$apimUri/$apimName/apis/$($api.name)/policy?api-version=2021-08-01"
                    $policy = Invoke-AzRestMethod -Method GET -Uri $policyUri -ErrorAction Stop
                    
                    if ($policy -and $policy.ToString() -notmatch 'rate-limit|quota') {
                        $remediation += "Consider rate limiting for API: $($api.name)"
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
                    Title = 'API Management Security Review'
                    Description = "$affectedCount APIM security concerns"
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
                    Title = 'Unable to check APIM security'
                    Description = $_.Exception.Message
                    Remediation = 'Verify Azure permissions'
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
    'Invoke-OktaOrganizationSecurityCheck',
    'Invoke-OktaPolicyCheck',
    'Invoke-OktaApplicationSecurityCheck',
    'Invoke-ADFSConfigurationCheck',
    'Invoke-FederationTrustCheck',
    'Invoke-AzureBackupSecurityCheck',
    'Invoke-AwsBackupCheck',
    'Invoke-ADBackupCheck',
    'Invoke-AzApimSecurityCheck'
)
