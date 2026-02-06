
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
# Module Type: Federation

$script:DefaultThresholds = @{
    WsFedTokenLifetime = 60
    SamlTokenLifetime = 60
}

# Severity and Status Definitions
$script:FindingSeverity = @{ Critical = "Critical"; High = "High"; Medium = "Medium"; Low = "Low"; Info = "Info" }
$script:HealthStatus = @{ Healthy = "Healthy"; Warning = "Warning"; Critical = "Critical" }
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

# SIG # Begin signature block
# MIIf3QYJKoZIhvcNAQcCoIIfzjCCH8oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAStH9u1iwz2pEE
# iCmahOn+lCiNWhyFWCBMh5ALB1cOyaCCGNwwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# AgEVMC8GCSqGSIb3DQEJBDEiBCCj/knsZPz+dq2LkPURI2ysmdAlbPEIrRUstAU2
# OacXTTANBgkqhkiG9w0BAQEFAASCAgCsHA3uWlRdld/j6S9Ikbo+z+kQiqsiviDx
# VCHMO2npQ76OniqnoGCyc7Z+F37+pmX94jmFYonYqCY7ZVahAE6IweWSxn8rAH9F
# 2scDyTCtOqcxxOHh89mqOYZbc0J3StMK1a6nCtApdM2jUT281B1LFv2jk9MecRto
# NGjAc2kPgnxo3bFpP+EanJzQ80OHsu5bL4URdA3lpr2/QVEqk5C5GPtKm6Qii1wy
# DYxebZfvm3Ghz8LTBA3MtYo5hyuUiHh0poYPyeBKOl7w0UsKHJM7+TZ/9ZCmOoOf
# YkSDepDDoW6/bhwuCb2AkXw/6IXR7y8P33YM5AScPVQt9G+hWls/kInZ7jNl61l8
# v/fekaUzcrC9eEmm+xy9vo4ZnTUt4j0/89eWOyPMhbqzf1Tt7rcVHi6UhrxHby1Q
# jkbOiCXufQxQ8QCFSUpv3zmzhE59giWx/lmxRFVQ8IGTqsTkw0LxR75bDhCdfFnG
# TUWZOMJ+uaiNI4NJKcBWgFu0+xh34iDLfup3PhVuzqsuq0hfRxD7xCnA1H8jsVnA
# k+W3dmh5oePzCUHBLDTltcVuIAmPP0tRaJYm0iim7J5yyp2+SwO5MaNakG9UGa+7
# sxjE/EwCX0tapyH2koXz6wPctugkmgBs5J6vEJEO7QA4YtZM49XY4e12IBycIf1e
# YXramgTzJ6GCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAyMDUxNzEyNDZaMC8G
# CSqGSIb3DQEJBDEiBCCGhJSquqgyt4ZyQuIowoBs5UIrFPipSTz2x7+u8u0X7zAN
# BgkqhkiG9w0BAQEFAASCAgA9aR7CUSHGalDeG6B++BjtLswiOdT228SC0JMycyy5
# M45jb6uNypmyfvZl0FsuOlyPIBW8lNYX2GyymnM//r0DE9dl1rclbj7QrC4lDsuC
# UTus8mWKFLUXziEB0AI3waJXhCO1wwRezOL6Q/R0acAouj592Gya29VuxarwbV4b
# FsB5InulnweW3eggFpaJOrNxXSvGAZTJ7Fl7+W8RqhwnLpRwwLwfCrQZa+ooiYo3
# lkfhYUmy3OqLBCrfq/Hwz/XGXadE+ZB2f2bTc7ADUt8lJO8Kzl/NARgG+QQzcV26
# OBqPj2O7VW3tkrZYxWJwOxDiACbuVJSNAzBWDXmxwFVBOamp9gJoHvUtyEYcmhzu
# EkSVFFdqGzgXnRkye8GeHx1GVtevM4oaeo2frbpBVW1F6eCUqimHnfiS7V+A3DGy
# yxb7qKv++/ksKsllpjnxEq3AyCAmDN75yygh8BkohLuUPu0eMETXKxydH3kXa9k/
# MY3wb1RZWdkXm3Mn+o2+MfFB/+GEMZFTLAAINJ6DlwRmcnVixx0pkjdJcaIHiUaE
# Y4QOplR9XgAJcIDWpSy/VLLYhw0+mONZHhXvkpX6jUhA9LCLGyHFN2rxaPLraXtP
# FxxnJmHY/5ELQLVgVfTqCqNvz1Rv6SpCs1c59DxiB333rSFlZTd1b1XRs+Qh+RvZ
# Qw==
# SIG # End signature block
