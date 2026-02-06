
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
# Module Type: Enterprise

$script:DefaultThresholds = @{
    CrossTenantThreshold = 0
    TenantThreshold = 1
}

# Severity and Status Definitions
$script:FindingSeverity = @{ Critical = "Critical"; High = "High"; Medium = "Medium"; Low = "Low"; Info = "Info" }
$script:HealthStatus = @{ Healthy = "Healthy"; Warning = "Warning"; Critical = "Critical" }
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

# SIG # Begin signature block
# MIIf3QYJKoZIhvcNAQcCoIIfzjCCH8oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDm+J1Dg7Thpz1s
# q5qH0oh4zZrpo6IScoqerYJSvy+69KCCGNwwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# AgEVMC8GCSqGSIb3DQEJBDEiBCCGF4eSwQxfFxI6gVNPtOS3I/AtYo40ylpNZIiX
# A9FtQDANBgkqhkiG9w0BAQEFAASCAgCmoopJRC3uqTgInhXGzM9I587UleqEBjIX
# jStSnCNiwHIpkdCmnW55yjpfhP1c+p0qYEv90Mumgv+2z3H1iK8eR4ApwMWpIMi6
# 2RwYaM4qiyhU4omMaQ3OyDJDu5V1tyluEgc00RYvrCoNwo9AUSY4eLen7Vt+p2Zk
# oTH/aEQlaWRefxhvBP52nB47o8DgB4wU4EA4lAeJS8ySLL+/BTDlgR1e6P7fgH7q
# kTyrAfJQTRYfUkXwzam6x/i8WZsKKWE7CBQu/sa53UFkzTwl/jLSkoiB0tlwC5JA
# TOhX15KOiJMO6R4E/Qa+gOEBivYXgDndSYmRV6vLYhQGZYtigQ2PO3Q6s35xxXSd
# XB3saeJYn5T+guUDLX7E2DHh8u07Pdf6Pwa+K4XdzV6CWZsyJaFYaaey8rnYfVL/
# A044pObLMT0/MHz0oRiUldLiqy8NiXCdMfSUrt6Qsd9x2hmRiaggddeBZ2WH6huA
# KuMeO/Y/d31Lysro4GWkTP8iBfwh8c2xau8NplNVFVJnOk64DRAuoM7nKuF8IcbN
# T6UeNuzXpubBkWdKizhfb74BC154JPfmky33Lmx2lTpDdkFh69CTgC5y49fNv7Fz
# bD2h+e91zuxNTGDTT2d/oySp3jbi1rHnmIpPNXXvcYIPnDoRQVjA1WebPbVrc1zB
# BD6jh3aNwKGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAyMDUxNzEyNDVaMC8G
# CSqGSIb3DQEJBDEiBCDNdhJyJeO3ugUsozGppiB5zE4xauSCj/Jir2FV9VkoqDAN
# BgkqhkiG9w0BAQEFAASCAgB/oNJlJM5itb4zM9fATKVoL6pntO4xXNUz5TXbJXbi
# Z+WxKKDA6piCc+Uh1Z1DbCVfFXKYEjOtBOO3NnHrYg9xv48PVP5GuKbSpxUuYZd7
# rig4AtOFEv4MkOe9s4AmYx6eGxCgi3ej2ME5p1LL0baIl0y5WoLmN+1m6nK6q7uG
# TXxtMmjsSVUWhCEVjk3sl/5fiOw+LhTHhP5o9IQfVGvMqGyoi/o4ozB8Zoo81B/Q
# vl0iGqx2RJ1xd39iApPmtuZViNJc9nP/CQ7fjzmcoL/XwTwDYXzY5Z62YPnVGIC1
# DbQNekfh0psokl6bJoHSXNjZtzgy81OWZ1S4NBT2o4S9QOmiBFOc2VbujqC9g/KN
# LP7StRXTHJoTNN7oAIdCid9lOrXwA4AQtbI0jpMQgEFKkDq+I6wqgwHxuNPH/7bB
# 05S2ed0Mo45PXY/vo+AxzN1bzmxEmRNtBIOkYWKpZrlsyjlgfTCV851M4YOWhD8A
# lRpWGbYvAalzsKalV+yimGR612h4U3fGL1Pj+zDxxlObNs2P/AoygNCsTxbCeqCc
# 0MB8iRRyWopJzd3gRvJ3UCqLqtzmDUb3G+f8D8IR8jIiDtZ0EjjlfttYiDJ0SzyD
# b024Zdz74BPtSpB9DXfsoXlcWrXwkuCj1rrZ6TT4+s7lLTwQ3B3gCDZhA0lStinS
# 5Q==
# SIG # End signature block
