# ============================================================================
# IdentityFirst QuickChecks - Enterprise Security Module
# ============================================================================
# PowerShell 5.1 Compatible
# Contains enterprise-level security checks: PAW, AD CS, SIEM, Containers, etc.
# ============================================================================

#requires -Version 5.1

#region Active Directory Certificate Services Checks
function Invoke-ADCSConfigurationCheck {
    <#
    .SYNOPSIS
        Checks Active Directory Certificate Services configuration
    .DESCRIPTION
        Verifies CA security settings, template permissions, and auditing
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$CAHostName
    )
    
    $checkId = 'IDF-AD-CS-001'
    $checkName = 'AD Certificate Services Configuration'
    $category = 'Active Directory - Certificate Services'
    $severity = 'High'
    
    try {
        $remediation = @()
        $affectedCount = 0
        
        # Check if ADCS module is available
        try {
            $null = Import-Module ActiveDirectory -ErrorAction Stop
        }
        catch {
            throw 'Active Directory module not available'
        }
        
        # Get CA server
        if (-not $CAHostName) {
            $caServers = Get-ADObject -Filter { objectClass -eq 'pKIEnrollmentService' } -Properties DNSHostName
            if ($caServers.Count -eq 0) {
                $remediation += 'No Certificate Authority found in domain'
                $affectedCount++
            }
            else {
                $CAHostName = $caServers[0].DNSHostName
            }
        }
        
        if ($CAHostName) {
            # Check CA security settings via registry
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$CAHostName"
            if (Test-Path $regPath) {
                $security = Get-ItemProperty -Path $regPath -Name Security -ErrorAction SilentlyContinue
                
                # Check for certificate manager restrictions
                $certmgrPerms = $security.Security | Select-String 'Certificate Manager' -SimpleMatch
                if (-not $certmgrPerms) {
                    $remediation += 'Configure Certificate Manager restrictions on CA'
                    $affectedCount++
                }
                
                # Check audit settings
                $auditFlags = Get-ItemProperty -Path $regPath -Name AuditFilter -ErrorAction SilentlyContinue
                if ($auditFlags) {
                    $auditValue = $auditFlags.AuditFilter
                    $requiredAudits = @('Issue', 'Revoke', 'Fail')
                    foreach ($audit in $requiredAudits) {
                        if ($auditValue -notmatch $audit) {
                            $remediation += "Enable $audit auditing on CA"
                            $affectedCount++
                        }
                    }
                }
                else {
                    $remediation += 'Enable auditing on Certificate Authority'
                    $affectedCount++
                }
            }
            
            # Get certificate templates
            $templates = Get-ADObject -Filter { objectClass -eq 'pKICertificateTemplate' } -Properties *
            
            # Check for dangerous templates
            $dangerousTemplates = @('Administrator', 'User', 'Computer', 'EnrollmentAgent', 'KeyRecoveryAgent')
            foreach ($template in $templates) {
                $templateName = $template.DisplayName
                foreach ($dangerous in $dangerousTemplates) {
                    if ($templateName -match $dangerous -and $templateName -notmatch 'Subordinate') {
                        $remediation += "Review certificate template permissions: $templateName"
                        $affectedCount++
                    }
                }
                
                # Check for templates allowing private key export
                if ($template.KeyUsage -and ($template.KeyUsage -match 'KeyEncipherment' -or $template.KeyUsage -match 'DigitalSignature')) {
                    if ($template.Properties -match 'EXPORT') {
                        $remediation += "Template $templateName allows private key export - review necessity"
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
                    Title = 'AD Certificate Services Configuration Review'
                    Description = "$affectedCount CA configuration concerns"
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
                    Title = 'Unable to check AD CS configuration'
                    Description = $_.Exception.Message
                    Remediation = 'Run from domain controller or admin workstation with AD RSAT'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}

function Invoke-ADCSCertificateTemplateCheck {
    <#
    .SYNOPSIS
        Checks certificate template security configurations
    .DESCRIPTION
        Reviews template versions, enrollment rights, and key usage
    #>
    
    [CmdletBinding()]
    param()
    
    $checkId = 'IDF-AD-CS-TPL-001'
    $checkName = 'Certificate Template Security'
    $category = 'Active Directory - Certificate Services'
    $severity = 'High'
    
    try {
        $remediation = @()
        $affectedCount = 0
        
        # Get certificate templates
        $templates = Get-ADObject -Filter { objectClass -eq 'pKICertificateTemplate' } -Properties DisplayName, pKICriticalExtensions, pKIKeyUsage, msPKI-Certificate-Name-Flag, msPKI-Enrollment-Flag, nTSecurityDescriptor
        
        foreach ($template in $templates) {
            $templateName = $template.DisplayName
            
            # Check for template version (v1 templates are less secure)
            $schemaVersion = Get-ADObject -Identity $template.DistinguishedName -Properties msPKI-Template-Schema-Version -ErrorAction SilentlyContinue
            if ($schemaVersion.'msPKI-Template-Schema-Version' -lt 2) {
                $remediation += "Template $templateName is v1 schema - upgrade to v2"
                $affectedCount++
            }
            
            # Check for automatic enrollment
            $enrollmentFlag = $template.'msPKI-Enrollment-Flag'
            if ($enrollmentFlag -band 0x00000002) { # CT_FLAG_AUTO_ENROLLMENT
                $remediation += "Template $templateName allows auto-enrollment - review necessity"
                $affectedCount++
            }
            
            # Check for CT_FLAG_DIGITAL_SIGNATURE in key usage
            $keyUsage = $template.'pKIKeyUsage'
            if ($keyUsage -band 0x80) { # CERT_DIGITAL_SIGNATURE_KEY_USAGE
                # Check if requiring approved CA
                $nameFlag = $template.'msPKI-Certificate-Name-Flag'
                if ($nameFlag -eq 0) {
                    $remediation += "Template $templateName doesn't require approved CA"
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
                    Title = 'Certificate Template Security Review'
                    Description = "$affectedCount template security concerns"
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
                    Title = 'Unable to check certificate templates'
                    Description = $_.Exception.Message
                    Remediation = 'Verify AD RSAT and AD CS installation'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}
#endregion

#region Privileged Access Workstation Checks
function Invoke-PAWConfigurationCheck {
    <#
    .SYNOPSIS
        Checks Privileged Access Workstation configuration
    .DESCRIPTION
        Verifies PAW security settings, AppLocker policies, and LAPS
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$Domain
    )
    
    $checkId = 'IDF-PAW-001'
    $checkName = 'Privileged Access Workstation Configuration'
    $category = 'Workstation Security - PAW'
    $severity = 'High'
    
    try {
        if (-not $Domain) {
            $Domain = (Get-ADDomain).DNSRoot
        }
        
        $remediation = @()
        $affectedCount = 0
        
        # Check for PAW OU structure
        $pawOUs = Get-ADOrganizationalUnit -Filter { Name -like '*PAW*' -or Name -like '*Privileged*' } -Server $Domain -ErrorAction SilentlyContinue
        if (-not $pawOUs) {
            $remediation += 'Create dedicated OU structure for Privileged Access Workstations'
            $affectedCount++
        }
        
        # Check for LAPS implementation
        try {
            $lapsConfig = Get-ADObject -Identity "CN=MS-LAPS,CN=Program,CN=System,DC=$($Domain.Replace('.', ',DC='))" -Properties * -ErrorAction Stop
            $lapsEnabled = $true
        }
        catch {
            $lapsEnabled = $false
        }
        
        if (-not $lapsEnabled) {
            $remediation += 'Enable LAPS (Local Administrator Password Solution) for PAW management'
            $affectedCount++
        }
        
        # Check for PAW-specific GPOs
        $pawGpos = Get-ADObject -Filter { Name -like '*PAW*' -and objectClass -eq 'groupPolicyContainer' } -Server $Domain
        if (-not $pawGpos) {
            $remediation += 'Implement PAW-specific Group Policy objects'
            $affectedCount++
        }
        
        # Check for Tiering model
        $tierOUs = Get-ADOrganizationalUnit -Filter { Name -like '*Tier*' } -Server $Domain
        if (-not $tierOUs -or $tierOUs.Count -lt 2) {
            $remediation += 'Implement Tiering model (Tier 0, Tier 1, Tier 2)'
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
                    Title = 'PAW Configuration Review'
                    Description = "$affectedCount PAW configuration concerns"
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
                    Title = 'Unable to check PAW configuration'
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

#region Email Security Checks
function Invoke-ExchangeOnlineProtectionCheck {
    <#
    .SYNOPSIS
        Checks Exchange Online Protection and anti-spam policies
    .DESCRIPTION
        Verifies SPF, DKIM, DMARC, and anti-phishing configurations
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$TenantId
    )
    
    $checkId = 'IDF-EOP-001'
    $checkName = 'Exchange Online Protection Configuration'
    $category = 'Email Security - Exchange Online'
    $severity = 'High'
    
    try {
        $remediation = @()
        $affectedCount = 0
        
        # Connect to Exchange Online
        try {
            $null = Connect-ExchangeOnline -ErrorAction Stop -ShowBanner:$false
        }
        catch {
            throw 'Unable to connect to Exchange Online'
        }
        
        # Get anti-phishing policies
        $antiPhishing = Get-AntiPhishingPolicy -ErrorAction SilentlyContinue
        foreach ($policy in $antiPhishing) {
            if ($policy.EnableATPForSPOTeams -ne $true) {
                $policyName = $policy.Name
                $remediation += "Enable ATP for SharePoint and Teams in policy: $policyName"
                $affectedCount++
            }
            
            if ($policy.EnableSafeLinks -ne $true) {
                $remediation += "Enable Safe Links in policy: $($policy.Name)"
                $affectedCount++
            }
        }
        
        # Check for DKIM configuration
        $dkimConfig = Get-DkimSigningConfig -ErrorAction SilentlyContinue
        foreach ($dkim in $dkimConfig) {
            if ($dkim.Status -ne 'Enabled') {
                $remediation += "Enable DKIM for $($dkim.Selector)"
                $affectedCount++
            }
        }
        
        # Get transport rules
        $transportRules = Get-TransportRule -ErrorAction SilentlyContinue
        $highRiskRules = $transportRules | Where-Object {
            $_.Conditions.AnyOfToHeader -match 'external' -or
            $_.Conditions.SubjectContainsWords -contains 'urgent' -or
            $_.Actions.SetHeaderName -eq 'X-External-Organization'
        }
        
        if ($highRiskRules.Count -gt 5) {
            $remediation += "Review $highRiskRules.Count transport rules for potential data leakage"
            $affectedCount++
        }
        
        # Check outbound connector configuration
        $outboundConnectors = Get-OutboundConnector -ErrorAction SilentlyContinue
        foreach ($connector in $outboundConnectors) {
            if (-not $connector.RouteOutboundMailVia) {
                $remediation += "Outbound connector $($connector.Name) has no smart host routing"
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
                    Title = 'Exchange Online Protection Review'
                    Description = "$affectedCount EOP configuration concerns"
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
                    Title = 'Unable to check EOP configuration'
                    Description = $_.Exception.Message
                    Remediation = 'Verify Exchange Online admin access'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
    finally {
        try { Disconnect-ExchangeOnline -ErrorAction SilentlyContinue } catch { }
    }
}

function Invoke-DomainAuthenticationCheck {
    <#
    .SYNOPSIS
        Checks email domain authentication (SPF, DKIM, DMARC)
    .DESCRIPTION
        Validates DNS records for email sender authentication
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string[]]$Domains
    )
    
    $checkId = 'IDF-EOP-DMARC-001'
    $checkName = 'Email Domain Authentication'
    $category = 'Email Security - DNS'
    $severity = 'High'
    
    try {
        $remediation = @()
        $affectedCount = 0
        
        if (-not $Domains) {
            # Try to get domains from Exchange Online
            try {
                $null = Connect-ExchangeOnline -ErrorAction Stop -ShowBanner:$false
                $domains = Get-AcceptedDomain | Select-Object -ExpandProperty DomainName
                Disconnect-ExchangeOnline -ErrorAction SilentlyContinue | Out-Null
            }
            catch {
                throw 'No domains specified and unable to retrieve from Exchange Online'
            }
        }
        
        foreach ($domain in $Domains) {
            # Check SPF record
            try {
                $spfRecords = Resolve-DnsName -Name $domain -Type TXT -ErrorAction Stop | Where-Object { $_.Strings -like 'v=spf*' }
                if (-not $spfRecords) {
                    $remediation += "Add SPF record for domain: $domain"
                    $affectedCount++
                }
                else {
                    $spf = $spfRecords.Strings
                    if ($spf -like '*~all*' -or $spf -like '*+all*') {
                        $remediation += "SPF record for $domain uses permissive ~all or +all"
                        $affectedCount++
                    }
                }
            }
            catch {
                $remediation += "Unable to resolve SPF record for: $domain"
                $affectedCount++
            }
            
            # Check DMARC record
            try {
                $dmarcRecords = Resolve-DnsName -Name "_dmarc.$domain" -Type TXT -ErrorAction Stop | Where-Object { $_.Strings -like 'v=DMARC1*' }
                if (-not $dmarcRecords) {
                    $remediation += "Add DMARC record for domain: $domain"
                    $affectedCount++
                }
                else {
                    $dmarc = $dmarcRecords.Strings
                    if ($dmarc -notlike '*p=reject*' -and $dmarc -notlike '*p=quarantine*') {
                        $remediation += "DMARC policy for $domain should be reject or quarantine"
                        $affectedCount++
                    }
                }
            }
            catch {
                $remediation += "Unable to resolve DMARC record for: $domain"
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
                    Title = 'Email Domain Authentication Review'
                    Description = "$affectedCount domains missing or have weak authentication"
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
                    Title = 'Unable to check domain authentication'
                    Description = $_.Exception.Message
                    Remediation = 'Verify DNS resolution and Exchange Online access'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}
#endregion

#region SIEM Integration Checks
function Invoke-AzureSentinelCheck {
    <#
    .SYNOPSIS
        Checks Azure Sentinel (Microsoft Sentinel) configuration
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$SubscriptionId
    )
    
    $checkId = 'IDF-SENT-001'
    $checkName = 'Azure Sentinel Configuration'
    $category = 'SIEM - Azure Sentinel'
    $severity = 'Medium'
    
    try {
        $null = Connect-AzAccount -ErrorAction Stop
        
        $remediation = @()
        $affectedCount = 0
        
        if (-not $SubscriptionId) {
            $SubscriptionId = (Get-AzSubscription)[0].Id
        }
        
        $null = Set-AzContext -SubscriptionId $SubscriptionId
        
        # Check if Sentinel is deployed
        $sentinelUri = "/subscriptions/$SubscriptionId/providers/Microsoft.OperationalInsights/workspaces?api-version=2021-06-01"
        $workspaces = Invoke-AzRestMethod -Method GET -Uri $sentinelUri -ErrorAction Stop
        
        $sentinelWorkspaces = @()
        foreach ($ws in $workspaces.Value) {
            $sentinelUri = "/subscriptions/$SubscriptionId/resourceGroups/$($ws.ResourceGroupName)/providers/Microsoft.OperationsManagement/solutions/MicrosoftSentinel-$($ws.Name)?api-version=2015-11-01-preview"
            try {
                $null = Invoke-AzRestMethod -Method GET -Uri $sentinelUri -ErrorAction Stop
                $sentinelWorkspaces += $ws
            }
            catch {
                # Workspace doesn't have Sentinel
            }
        }
        
        if ($sentinelWorkspaces.Count -eq 0) {
            $remediation += 'Deploy Azure Sentinel for security monitoring'
            $affectedCount++
        }
        else {
            # Check data connectors
            foreach ($ws in $sentinelWorkspaces) {
                $connectorsUri = "/subscriptions/$SubscriptionId/resourceGroups/$($ws.ResourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($ws.Name)/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2021-04-01"
                $connectors = Invoke-AzRestMethod -Method GET -Uri $connectorsUri -ErrorAction Stop
                
                if ($connectors.Value.Count -lt 5) {
                    $wsName = $ws.Name
                    $remediation += "Add more data connectors to Sentinel workspace: $wsName"
                    $affectedCount++
                }
                
                # Check for active analytics rules
                $rulesUri = "/subscriptions/$SubscriptionId/resourceGroups/$($ws.ResourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($ws.Name)/providers/Microsoft.SecurityInsights/alertRules?api-version=2021-04-01"
                $rules = Invoke-AzRestMethod -Method GET -Uri $rulesUri -ErrorAction Stop
                
                if ($rules.Value.Count -lt 10) {
                    $wsName = $ws.Name
                    $remediation += "Create more analytics rules in Sentinel: $wsName"
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
                    Title = 'Azure Sentinel Configuration Review'
                    Description = "$affectedCount Sentinel configuration concerns"
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
                    Title = 'Unable to check Sentinel configuration'
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

#region Kubernetes Security Checks
function Invoke-AksSecurityCheck {
    <#
    .SYNOPSIS
        Checks Azure Kubernetes Service security configuration
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$SubscriptionId
    )
    
    $checkId = 'IDF-AKS-001'
    $checkName = 'Azure Kubernetes Service Security'
    $category = 'Container Security - AKS'
    $severity = 'High'
    
    try {
        $null = Connect-AzAccount -ErrorAction Stop
        
        $remediation = @()
        $affectedCount = 0
        
        if (-not $SubscriptionId) {
            $SubscriptionId = (Get-AzSubscription)[0].Id
        }
        
        $null = Set-AzContext -SubscriptionId $SubscriptionId
        
        # Get AKS clusters
        $aksUri = "/subscriptions/$SubscriptionId/providers/Microsoft.ContainerService/managedClusters?api-version=2022-02-01"
        $clusters = Invoke-AzRestMethod -Method GET -Uri $aksUri -ErrorAction Stop
        
        if ($clusters.Value.Count -eq 0) {
            $remediation += 'No AKS clusters found - container security monitoring may be needed elsewhere'
            $affectedCount = 1
        }
        else {
            foreach ($cluster in $clusters.Value) {
                $clusterName = $cluster.Name
                $clusterRg = $cluster.id -replace '/subscriptions/[^/]+/resourceGroups/', '' -replace '/providers/Microsoft.ContainerService.*', ''
                
                # Check for RBAC enabled
                if ($cluster.properties.enableRBAC -ne $true) {
                    $remediation += "Enable RBAC for AKS cluster: $clusterName"
                    $affectedCount++
                }
                
                # Check API server authorized IP ranges
                $apiServer = $cluster.properties.apiServerAccessProfile
                if (-not $apiServer -or -not $apiServer.authorizedIPRanges) {
                    $remediation += "Configure API server authorized IP ranges for: $clusterName"
                    $affectedCount++
                }
                
                # Check for managed identity
                if ($cluster.identity.type -ne 'SystemAssigned') {
                    $remediation += "Use managed identity for AKS cluster: $clusterName"
                    $affectedCount++
                }
                
                # Check pod security policy (deprecated) or pod security standards
                $addonProfiles = $cluster.properties.addonProfiles
                if ($addonProfiles -and $addonProfiles.AADPodIdentity -and $addonProfiles.AADPodIdentity.enabled -ne 'true') {
                    $remediation += "Enable AAD Pod Identity for: $clusterName"
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
                    Title = 'AKS Security Configuration Review'
                    Description = "$affectedCount AKS security concerns"
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
                    Title = 'Unable to check AKS security'
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

function Invoke-KubernetesPodSecurityCheck {
    <#
    .SYNOPSIS
        Checks Kubernetes pod security standards
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$KubeConfigPath
    )
    
    $checkId = 'IDF-K8S-POD-001'
    $checkName = 'Kubernetes Pod Security Standards'
    $category = 'Container Security - Pods'
    $severity = 'High'
    
    try {
        $remediation = @()
        $affectedCount = 0
        
        # Check if kubectl is available
        $kubectlPath = (Get-Command kubectl -ErrorAction SilentlyContinue).Path
        if (-not $kubectlPath) {
            $remediation += 'kubectl not found - install Kubernetes tools'
            $affectedCount++
            throw 'kubectl not available'
        }
        
        # Get namespaces
        $namespaces = kubectl get namespaces -o json 2>$null | ConvertFrom-Json
        foreach ($ns in $namespaces.items) {
            $nsName = $ns.metadata.name
            
            # Skip system namespaces
            if ($nsName -match 'kube-system|kube-public|kube-node-lease') { continue }
            
            # Get pods in namespace
            $pods = kubectl get pods -n $nsName -o json 2>$null | ConvertFrom-Json
            
            foreach ($pod in $pods.items) {
                $podName = $pod.metadata.name
                $spec = $pod.spec
                
                # Check for privileged containers
                foreach ($container in $spec.containers) {
                    if ($container.securityContext -and $container.securityContext.privileged -eq $true) {
                        $remediation += "Privileged container in $nsName/$podName"
                        $affectedCount++
                    }
                    
                    # Check for root user
                    if ($container.securityContext -and $container.securityContext.runAsUser -eq 0) {
                        $remediation += "Container running as root in $nsName/$podName"
                        $affectedCount++
                    }
                    
                    # Check for hostPath mounts
                    if ($spec.volumes) {
                        foreach ($vol in $spec.volumes) {
                            if ($vol.hostPath) {
                                $remediation += "HostPath volume in $nsName/$podName"
                                $affectedCount++
                            }
                        }
                    }
                }
            }
        }
        
        # Check Pod Security Standards
        $pssEnabled = $true
        foreach ($ns in $namespaces.items) {
            $labels = $ns.metadata.labels
            if (-not $labels['pod-security.kubernetes.io/enforce']) {
                $remediation += "Namespace $($ns.metadata.name) has no Pod Security Standard enforcement"
                $affectedCount++
                $pssEnabled = $false
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
                    Title = 'Kubernetes Pod Security Review'
                    Description = "$affectedCount pod security concerns"
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
                    Title = 'Unable to check pod security'
                    Description = $_.Exception.Message
                    Remediation = 'Verify kubectl configuration and cluster access'
                    AffectedCount = 1
                    Confidence = 'Medium'
                }
            )
            Timestamp = (Get-Date -Format 'o')
        }
    }
}
#endregion

#region Database Security Checks
function Invoke-SqlDatabaseSecurityCheck {
    <#
    .SYNOPSIS
        Checks Azure SQL Database security configurations
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$SubscriptionId
    )
    
    $checkId = 'IDF-SQL-001'
    $checkName = 'Azure SQL Database Security'
    $category = 'Database Security - Azure SQL'
    $severity = 'High'
    
    try {
        $null = Connect-AzAccount -ErrorAction Stop
        
        $remediation = @()
        $affectedCount = 0
        
        if (-not $SubscriptionId) {
            $SubscriptionId = (Get-AzSubscription)[0].Id
        }
        
        $null = Set-AzContext -SubscriptionId $SubscriptionId
        
        # Get SQL servers
        $sqlUri = "/subscriptions/$SubscriptionId/providers/Microsoft.Sql/servers?api-version=2021-11-01"
        $servers = Invoke-AzRestMethod -Method GET -Uri $sqlUri -ErrorAction Stop
        
        foreach ($server in $servers.Value) {
            $serverName = $server.name
            $serverRg = $server.id -replace '/subscriptions/[^/]+/resourceGroups/', '' -replace '/providers/Microsoft.Sql.*', ''
            
            # Check for private endpoint
            $peUri = "/subscriptions/$SubscriptionId/resourceGroups/$serverRg/providers/Microsoft.Sql/servers/$serverName/privateEndpointConnections?api-version=2021-11-01"
            $pe = Invoke-AzRestMethod -Method GET -Uri $peUri -ErrorAction Stop
            
            if ($pe.Value.Count -eq 0) {
                $remediation += "Enable private endpoint for SQL server: $serverName"
                $affectedCount++
            }
            
            # Check firewall rules
            $fwUri = "/subscriptions/$SubscriptionId/resourceGroups/$serverRg/providers/Microsoft.Sql/servers/$serverName/firewallRules?api-version=2021-11-01"
            $fwRules = Invoke-AzRestMethod -Method GET -Uri $fwUri -ErrorAction Stop
            
            foreach ($rule in $fwRules.Value) {
                if ($rule.properties.startIpAddress -eq '0.0.0.0' -and $rule.properties.endIpAddress -eq '255.255.255.255') {
                    $remediation += "SQL server $serverName allows all IP addresses"
                    $affectedCount++
                }
            }
            
            # Check threat detection
            $tdUri = "/subscriptions/$SubscriptionId/resourceGroups/$serverRg/providers/Microsoft.Sql/servers/$serverName/securityAlertPolicies/default?api-version=2021-11-01"
            $tdPolicy = Invoke-AzRestMethod -Method GET -Uri $tdUri -ErrorAction Stop
            
            if ($tdPolicy.properties.state -ne 'Enabled') {
                $remediation += "Enable Threat Detection for SQL server: $serverName"
                $affectedCount++
            }
            
            # Check auditing
            $audUri = "/subscriptions/$SubscriptionId/resourceGroups/$serverRg/providers/Microsoft.Sql/servers/$serverName/auditingSettings/default?api-version=2021-11-01"
            $auditing = Invoke-AzRestMethod -Method GET -Uri $audUri -ErrorAction Stop
            
            if ($auditing.properties.state -ne 'Enabled') {
                $remediation += "Enable auditing for SQL server: $serverName"
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
                    Title = 'Azure SQL Security Review'
                    Description = "$affectedCount SQL security concerns"
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
                    Title = 'Unable to check SQL security'
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

function Invoke-CosmosDBSecurityCheck {
    <#
    .SYNOPSIS
        Checks Azure Cosmos DB security configurations
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$SubscriptionId
    )
    
    $checkId = 'IDF-COSMOS-001'
    $checkName = 'Azure Cosmos DB Security'
    $category = 'Database Security - Cosmos DB'
    $severity = 'High'
    
    try {
        $null = Connect-AzAccount -ErrorAction Stop
        
        $remediation = @()
        $affectedCount = 0
        
        if (-not $SubscriptionId) {
            $SubscriptionId = (Get-AzSubscription)[0].Id
        }
        
        $null = Set-AzContext -SubscriptionId $SubscriptionId
        
        # Get Cosmos DB accounts
        $cosmosUri = "/subscriptions/$SubscriptionId/providers/Microsoft.DocumentDB/databaseAccounts?api-version=2021-10-15"
        $accounts = Invoke-AzRestMethod -Method GET -Uri $cosmosUri -ErrorAction Stop
        
        foreach ($account in $accounts.Value) {
            $accountName = $account.name
            $accountRg = $account.id -replace '/subscriptions/[^/]+/resourceGroups/', '' -replace '/providers/Microsoft.DocumentDB.*', ''
            
            # Check for private endpoint
            $peUri = "/subscriptions/$SubscriptionId/resourceGroups/$accountRg/providers/Microsoft.DocumentDB/databaseAccounts/$accountName/privateEndpointConnections?api-version=2021-10-15"
            $pe = Invoke-AzRestMethod -Method GET -Uri $peUri -ErrorAction Stop
            
            if ($pe.Value.Count -eq 0) {
                $remediation += "Enable private endpoint for Cosmos DB: $accountName"
                $affectedCount++
            }
            
            # Check public network access
            if ($account.properties.publicNetworkAccess -ne 'Disabled') {
                $remediation += "Disable public network access for Cosmos DB: $accountName"
                $affectedCount++
            }
            
            # Check IP firewall
            $ipRules = $account.properties.ipRules
            if (-not $ipRules -or $ipRules.Count -eq 0) {
                $remediation += "Configure IP firewall for Cosmos DB: $accountName"
                $affectedCount++
            }
            
            # Check disable key based metadata write access
            $capabilities = $account.properties.capabilities
            if ($capabilities -and $capabilities.Name -contains 'EnableMongo') {
                # Check for mongod write access
                $remediation += "Review MongoDB wire protocol settings for: $accountName"
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
                    Title = 'Cosmos DB Security Review'
                    Description = "$affectedCount Cosmos DB security concerns"
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
                    Title = 'Unable to check Cosmos DB security'
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

#region Zero Trust Architecture Checks
function Invoke-ZeroTrustReadinessCheck {
    <#
    .SYNOPSIS
        Checks Zero Trust architecture readiness
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [string]$TenantId
    )
    
    $checkId = 'IDF-ZT-001'
    $checkName = 'Zero Trust Architecture Readiness'
    $category = 'Zero Trust - Architecture'
    $severity = 'Medium'
    
    try {
        $graphParams = @{}
        if ($TenantId) { $graphParams['TenantId'] = $TenantId }
        
        $null = Connect-MgGraph @graphParams -Scopes 'Policy.Read.All,Directory.Read.All' -NoWelcome
        
        $remediation = @()
        $affectedCount = 0
        
        # Check for Conditional Access policies
        $caUri = '/beta/identity/conditionalAccess/policies'
        $caPolicies = Invoke-MgGraphRequest -Method GET -Uri $caUri -ErrorAction Stop
        $enabledCA = ($caPolicies.Value | Where-Object { $_.state -eq 'Enabled' }).Count
        
        if ($enabledCA -lt 3) {
            $remediation += "Implement Conditional Access policies (current: $enabledCA, recommended: 5+)"
            $affectedCount++
        }
        
        # Check for Identity Protection
        $riskUri = '/beta/identityProtection/root'
        try {
            $riskConfig = Invoke-MgGraphRequest -Method GET -Uri $riskUri -ErrorAction Stop
            if (-not $riskConfig) {
                $remediation += 'Enable Identity Protection for risk-based policies'
                $affectedCount++
            }
        }
        catch {
            $remediation += 'Enable Identity Protection for risk detection'
            $affectedCount++
        }
        
        # Check for Privileged Identity Management
        $pimUri = '/beta/privilegedAccess/azureResources/resources'
        try {
            $pimConfig = Invoke-MgGraphRequest -Method GET -Uri $pimUri -ErrorAction Stop
            if (-not $pimConfig.Value) {
                $remediation += 'Implement Privileged Identity Management'
                $affectedCount++
            }
        }
        catch {
            $remediation += 'Enable Privileged Identity Management'
            $affectedCount++
        }
        
        # Check for password protection
        $ppUri = '/beta/policies/passwordProtectionPolicy'
        try {
            $ppPolicy = Invoke-MgGraphRequest -Method GET -Uri $ppUri -ErrorAction Stop
            if (-not $ppPolicy) {
                $remediation += 'Enable password protection and smart lockout'
                $affectedCount++
            }
        }
        catch {
            $remediation += 'Configure password protection policy'
            $affectedCount++
        }
        
        # Check for tenant restrictions
        $trUri = '/beta/policies/tenantRestrictionsPolicy'
        try {
            $trPolicy = Invoke-MgGraphRequest -Method GET -Uri $trUri -ErrorAction Stop
            if (-not $trPolicy) {
                $remediation += 'Consider implementing tenant restrictions'
                $affectedCount++
            }
        }
        catch {
            # Policy doesn't exist yet
        }
        
        return @{
            CheckId = $checkId
            CheckName = $checkName
            Category = $category
            Severity = $severity
            Status = if ($affectedCount -eq 0) { 'Pass' } else { 'Warning' }
            Findings = if ($affectedCount -gt 0) { @(
                @{
                    Title = 'Zero Trust Readiness Assessment'
                    Description = "$affectedCount Zero Trust implementation gaps"
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
                    Title = 'Unable to assess Zero Trust readiness'
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

# Export module functions
Export-ModuleMember -Function @(
    'Invoke-ADCSConfigurationCheck',
    'Invoke-ADCSCertificateTemplateCheck',
    'Invoke-PAWConfigurationCheck',
    'Invoke-ExchangeOnlineProtectionCheck',
    'Invoke-DomainAuthenticationCheck',
    'Invoke-AzureSentinelCheck',
    'Invoke-AksSecurityCheck',
    'Invoke-KubernetesPodSecurityCheck',
    'Invoke-SqlDatabaseSecurityCheck',
    'Invoke-CosmosDBSecurityCheck',
    'Invoke-ZeroTrustReadinessCheck'
)
