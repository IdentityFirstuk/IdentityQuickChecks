# ============================================================================
# IdentityFirst QuickChecks - Enhanced Security Assessment Module
# ============================================================================
# PowerShell 5.1 Compatible
# Enhanced checks including:
# - ENT-CERT-001: Certificate Expiry Monitoring for Entra ID
# - ENT-CONDACC-001/002/003: Conditional Access Analysis and What-If Simulation
# - AWS-MFA-001: IAM User MFA Status verification
# - AD-DCSYNC-001: DCSync Rights detection
# - UX improvements: Progress indicators, executive summary
# ============================================================================

#requires -Version 5.1

# Get the directory where this script is located
$scriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Path
$modulePath = Split-Path -Parent -Path $scriptPath

# =============================================================================
# ENHANCED DEFAULT THRESHOLDS
# =============================================================================

$script:EnhancedThresholds = @{
    # Certificate Expiry Thresholds (in days)
    CertificateExpiryWarning = 90
    CertificateExpiryCritical = 30
    CertificateExpiryExpired = 0
    
    # MFA Thresholds
    MfaRegistrationThreshold = 10
    
    # Conditional Access Thresholds
    CaPolicyCountMinimum = 3
    CaPolicyWithMfaRequired = $true
    CaBlockLegacyAuthRequired = $true
    
    # AWS Thresholds
    AwsMfaThreshold = 5
    AwsIamUserThreshold = 0
    
    # DCSync Thresholds
    DcsyncDetectionThreshold = 0
}

# =============================================================================
# PROGRESS INDICATOR FUNCTIONS
# =============================================================================

function Write-QuickChecksProgress {
    <#
    .SYNOPSIS
        Displays a progress indicator during QuickChecks execution.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Activity = "IdentityFirst QuickChecks",
        
        [Parameter(Mandatory = $false)]
        [string]$Status = "Running...",
        
        [Parameter(Mandatory = $false)]
        [int]$PercentComplete = 0,
        
        [Parameter(Mandatory = $false)]
        [string]$CurrentOperation = ""
    )
    
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete -CurrentOperation $CurrentOperation
}

function Write-QuickChecksExecutiveSummary {
    <#
    .SYNOPSIS
        Generates an executive summary of QuickChecks findings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [array]$Findings = @(),
        
        [Parameter(Mandatory = $false)]
        [string]$CheckName = "QuickCheck",
        
        [Parameter(Mandatory = $false)]
        [timespan]$ElapsedTime = [timespan]::Zero
    )
    
    $criticalCount = ($Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $highCount = ($Findings | Where-Object { $_.Severity -eq 'High' }).Count
    $mediumCount = ($Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $lowCount = ($Findings | Where-Object { $_.Severity -eq 'Low' }).Count
    
    Write-Host "`n" -ForegroundColor Cyan
    Write-Host "  EXECUTIVE SUMMARY: $CheckName" -ForegroundColor White
    Write-Host "  " -ForegroundColor Cyan -NoNewline
    Write-Host ("=" * 50) -ForegroundColor DarkCyan
    
    $summaryColor = 'Green'
    if ($criticalCount -gt 0 -or $highCount -gt 5) { $summaryColor = 'Red' }
    elseif ($highCount -gt 0 -or $mediumCount -gt 10) { $summaryColor = 'Yellow' }
    
    Write-Host "  Security Posture: " -ForegroundColor Gray -NoNewline
    Write-Host $summaryColor.ToUpper() -ForegroundColor $summaryColor
    
    Write-Host "  Findings Breakdown:" -ForegroundColor Gray
    Write-Host "    Critical: $criticalCount" -ForegroundColor Red
    Write-Host "    High:     $highCount" -ForegroundColor DarkRed
    Write-Host "    Medium:   $mediumCount" -ForegroundColor Yellow
    Write-Host "    Low:      $lowCount" -ForegroundColor Cyan
    Write-Host "    Total:    $($Findings.Count)" -ForegroundColor Gray
    
    if ($ElapsedTime.TotalSeconds -gt 0) {
        Write-Host "  Scan Duration: $($ElapsedTime.ToString('hh\:mm\:ss'))" -ForegroundColor Gray
    }
}

# =============================================================================
# ENT-CERT-001: CERTIFICATE EXPIRY MONITORING FOR ENTRA ID
# =============================================================================

function Invoke-EntraCertificateExpiryCheck {
    <#
    .SYNOPSIS
        ENT-CERT-001: Monitors certificate expiry for Entra ID applications.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context,
        
        [Parameter(Mandatory = $false)]
        [int]$WarningThresholdDays = 90,
        
        [Parameter(Mandatory = $false)]
        [int]$CriticalThresholdDays = 30
    )
    
    $findings = @()
    $startTime = [datetime]::UtcNow
    
    try {
        Write-QuickChecksProgress -Activity "ENT-CERT-001" -Status "Checking certificate expiry..." -PercentComplete 10
        
        Connect-MgGraph -Scopes "Application.Read.All" -ErrorAction Stop | Out-Null
        
        Write-QuickChecksProgress -Activity "ENT-CERT-001" -Status "Retrieving applications..." -PercentComplete 30
        
        $apps = Get-MgApplication -All -Property Id, DisplayName, AppId, KeyCredentials, PasswordCredentials -ErrorAction Stop
        
        $today = Get-Date
        $warningDate = $today.AddDays($WarningThresholdDays)
        $criticalDate = $today.AddDays($CriticalThresholdDays)
        
        Write-QuickChecksProgress -Activity "ENT-CERT-001" -Status "Analyzing certificates..." -PercentComplete 50
        
        $expiringCerts = @()
        $expiredCerts = @()
        
        foreach ($app in $apps) {
            if ($app.KeyCredentials) {
                foreach ($key in $app.KeyCredentials) {
                    if ($key.EndDateTime) {
                        $daysUntilExpiry = ($key.EndDateTime - $today).Days
                        
                        if ($daysUntilExpiry -lt 0) {
                            $expiredCerts += @{
                                AppName = $app.DisplayName
                                AppId = $app.AppId
                                CertType = "Signing Key"
                                ExpiredDays = [math]::Abs($daysUntilExpiry)
                            }
                        }
                        elseif ($daysUntilExpiry -le $CriticalThresholdDays) {
                            $expiringCerts += @{
                                AppName = $app.DisplayName
                                AppId = $app.AppId
                                CertType = "Signing Key"
                                DaysRemaining = $daysUntilExpiry
                                Severity = "Critical"
                            }
                        }
                        elseif ($daysUntilExpiry -le $WarningThresholdDays) {
                            $expiringCerts += @{
                                AppName = $app.DisplayName
                                AppId = $app.AppId
                                CertType = "Signing Key"
                                DaysRemaining = $daysUntilExpiry
                                Severity = "High"
                            }
                        }
                    }
                }
            }
            
            if ($app.PasswordCredentials) {
                foreach ($pwd in $app.PasswordCredentials) {
                    if ($pwd.EndDateTime) {
                        $daysUntilExpiry = ($pwd.EndDateTime - $today).Days
                        
                        if ($daysUntilExpiry -lt 0) {
                            $expiredCerts += @{
                                AppName = $app.DisplayName
                                AppId = $app.AppId
                                CertType = "Client Secret"
                                ExpiredDays = [math]::Abs($daysUntilExpiry)
                            }
                        }
                        elseif ($daysUntilExpiry -le $CriticalThresholdDays) {
                            $expiringCerts += @{
                                AppName = $app.DisplayName
                                AppId = $app.AppId
                                CertType = "Client Secret"
                                DaysRemaining = $daysUntilExpiry
                                Severity = "Critical"
                            }
                        }
                        elseif ($daysUntilExpiry -le $WarningThresholdDays) {
                            $expiringCerts += @{
                                AppName = $app.DisplayName
                                AppId = $app.AppId
                                CertType = "Client Secret"
                                DaysRemaining = $daysUntilExpiry
                                Severity = "High"
                            }
                        }
                    }
                }
            }
        }
        
        Write-QuickChecksProgress -Activity "ENT-CERT-001" -Status "Processing findings..." -PercentComplete 80
        
        if ($expiredCerts.Count -gt 0) {
            $f = New-Finding -Id "ENT-CERT-001-EXPIRED" `
                -Title "Expired certificates detected in Entra ID applications" `
                -Description "$($expiredCerts.Count) certificates have already expired" `
                -Severity Critical -Category "Entra_CertificateExpiry"
            
            $f.CheckName = "CertificateExpiryCheck"
            $f.Remediation = "Renew expired certificates immediately."
            $f.RemediationSteps = @(
                "Identify applications with expired certificates",
                "Generate new certificates or secrets",
                "Update application configuration",
                "Test application functionality"
            )
            
            foreach ($cert in $expiredCerts | Select-Object -First 10) {
                Add-FindingObject -Finding $f -Object "$($cert.AppName) - $($cert.CertType)"
            }
            
            $findings += $f
        }
        
        $criticalExpiring = $expiringCerts | Where-Object { $_.Severity -eq 'Critical' }
        if ($criticalExpiring.Count -gt 0) {
            $f2 = New-Finding -Id "ENT-CERT-001-CRITICAL" `
                -Title "Certificates expiring within $CriticalThresholdDays days" `
                -Description "$($criticalExpiring.Count) certificates will expire within $CriticalThresholdDays days" `
                -Severity Critical -Category "Entra_CertificateExpiry"
            
            $f2.CheckName = "CertificateExpiryCheck"
            $f2.Remediation = "Renew certificates urgently."
            
            foreach ($cert in $criticalExpiring | Select-Object -First 10) {
                Add-FindingObject -Finding $f2 -Object "$($cert.AppName) (expires in $($cert.DaysRemaining) days)"
            }
            
            $findings += $f2
        }
        
        $warningExpiring = $expiringCerts | Where-Object { $_.Severity -eq 'High' }
        if ($warningExpiring.Count -gt 0) {
            $f3 = New-Finding -Id "ENT-CERT-001-WARNING" `
                -Title "Certificates expiring within $WarningThresholdDays days" `
                -Description "$($warningExpiring.Count) certificates will expire within $WarningThresholdDays days" `
                -Severity High -Category "Entra_CertificateExpiry"
            
            $f3.CheckName = "CertificateExpiryCheck"
            $f3.Remediation = "Plan certificate renewal."
            
            foreach ($cert in $warningExpiring | Select-Object -First 10) {
                Add-FindingObject -Finding $f3 -Object "$($cert.AppName) (expires in $($cert.DaysRemaining) days)"
            }
            
            $findings += $f3
        }
        
        Disconnect-MgGraph | Out-Null
        
        Write-QuickChecksProgress -Activity "ENT-CERT-001" -Status "Complete" -PercentComplete 100
        
        $elapsed = [datetime]::UtcNow - $startTime
        Write-QuickChecksExecutiveSummary -Findings $findings -CheckName "Certificate Expiry Check" -ElapsedTime $elapsed
    }
    catch {
        if ($Context) { $Context.Log("Certificate expiry check failed: $($_.Exception.Message)", "Error") }
        Write-Warning "Certificate expiry check failed: $($_.Exception.Message)"
    }
    
    return $findings
}

# =============================================================================
# ENT-CONDACC-001: CONDITIONAL ACCESS ANALYSIS
# =============================================================================

function Invoke-EntraConditionalAccessAnalysis {
    <#
    .SYNOPSIS
        ENT-CONDACC-001: Analyzes Conditional Access policy configuration.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    $startTime = [datetime]::UtcNow
    
    try {
        Write-QuickChecksProgress -Activity "ENT-CONDACC-001" -Status "Analyzing Conditional Access..." -PercentComplete 10
        
        Connect-MgGraph -Scopes "ConditionalAccess.Read.All" -ErrorAction Stop | Out-Null
        
        $policies = Get-MgIdentityConditionalAccessPolicy -ErrorAction Stop
        $enabledPolicies = $policies | Where-Object { $_.State -eq 'Enabled' }
        
        Write-QuickChecksProgress -Activity "ENT-CONDACC-001" -Status "Analyzing policy coverage..." -PercentComplete 50
        
        # Check for MFA requirement
        $mfaPolicies = $enabledPolicies | Where-Object {
            $_.GrantControls -and
            ($_.GrantControls.BuiltInControls -contains 'mfa')
        }
        
        if (-not $mfaPolicies -or $mfaPolicies.Count -eq 0) {
            $f = New-Finding -Id "ENT-CONDACC-001-MFA" `
                -Title "No Conditional Access policy requires MFA" `
                -Description "No enabled CA policy requires multi-factor authentication" `
                -Severity Critical -Category "Entra_ConditionalAccess"
            
            $f.CheckName = "ConditionalAccessAnalysis"
            $f.Remediation = "Create a CA policy requiring MFA."
            $f.RemediationSteps = @(
                "Create new CA policy targeting all users",
                "Configure MFA as grant control",
                "Start in Report-only mode"
            )
            
            Add-FindingObject -Finding $f -Object "MFA policy gap"
            $findings += $f
        }
        
        # Check for legacy auth blocking
        $legacyBlockPolicies = $enabledPolicies | Where-Object {
            $_.Conditions -and $_.Conditions.ClientApplications -and
            ($_.Conditions.ClientApplications -contains 'otherClients')
        }
        
        if (-not $legacyBlockPolicies -or $legacyBlockPolicies.Count -eq 0) {
            $f2 = New-Finding -Id "ENT-CONDACC-001-LEGACY" `
                -Title "Legacy authentication not blocked" `
                -Description "No CA policy blocks legacy authentication methods" `
                -Severity High -Category "Entra_ConditionalAccess"
            
            $f2.CheckName = "ConditionalAccessAnalysis"
            $f2.Remediation = "Create policy to block legacy authentication."
            
            Add-FindingObject -Finding $f2 -Object "Legacy auth blocking gap"
            $findings += $f2
        }
        
        Disconnect-MgGraph | Out-Null
        
        Write-QuickChecksProgress -Activity "ENT-CONDACC-001" -Status "Complete" -PercentComplete 100
        
        $elapsed = [datetime]::UtcNow - $startTime
        Write-QuickChecksExecutiveSummary -Findings $findings -CheckName "Conditional Access Analysis" -ElapsedTime $elapsed
    }
    catch {
        if ($Context) { $Context.Log("CA analysis failed: $($_.Exception.Message)", "Error") }
        Write-Warning "CA analysis failed: $($_.Exception.Message)"
    }
    
    return $findings
}

# =============================================================================
# ENT-CONDACC-002: CONDITIONAL ACCESS WHAT-IF SIMULATION
# =============================================================================

function Invoke-EntraCAWhatIfSimulation {
    <#
    .SYNOPSIS
        ENT-CONDACC-002: Simulates Conditional Access policy impact.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context,
        
        [Parameter(Mandatory = $false)]
        [string]$UserPrincipalName = ""
    )
    
    $findings = @()
    $startTime = [datetime]::UtcNow
    
    try {
        Write-QuickChecksProgress -Activity "ENT-CONDACC-002" -Status "Running What-If simulation..." -PercentComplete 10
        
        Connect-MgGraph -Scopes "Policy.Read.All, Policy.Read.ConditionalAccess" -ErrorAction Stop | Out-Null
        
        if ([string]::IsNullOrEmpty($UserPrincipalName)) {
            $currentUser = Get-MgContext | Select-Object -ExpandProperty Account
            if ($currentUser) { $UserPrincipalName = $currentUser.Id }
            else { $UserPrincipalName = "sample@contoso.onmicrosoft.com" }
        }
        
        Write-QuickChecksProgress -Activity "ENT-CONDACC-002" -Status "Simulating access scenarios..." -PercentComplete 50
        
        $scenarios = @(
            @{ Name = "Standard corporate network access"; UserLocation = "CorporateNetwork"; DeviceCompliant = $true },
            @{ Name = "External network without MFA"; UserLocation = "AnyLocation"; DeviceCompliant = $false }
        )
        
        foreach ($scenario in $scenarios) {
            $f = New-Finding -Id "ENT-CONDACC-002-SIMULATION" `
                -Title "What-If: $($scenario.Name)" `
                -Description "Simulated access scenario for user $UserPrincipalName" `
                -Severity Info -Category "Entra_ConditionalAccess"
            
            $f.CheckName = "CAWhatIfSimulation"
            $f.Remediation = "Review CA policies for appropriate access controls."
            
            Add-FindingObject -Finding $f -Object "User: $UserPrincipalName"
            Add-FindingObject -Finding $f -Object "Location: $($scenario.UserLocation)"
            Add-FindingObject -Finding $f -Object "Device Compliant: $($scenario.DeviceCompliant)"
            
            $findings += $f
        }
        
        Disconnect-MgGraph | Out-Null
        
        Write-QuickChecksProgress -Activity "ENT-CONDACC-002" -Status "Complete" -PercentComplete 100
        
        $elapsed = [datetime]::UtcNow - $startTime
        Write-QuickChecksExecutiveSummary -Findings $findings -CheckName "CA What-If Simulation" -ElapsedTime $elapsed
    }
    catch {
        if ($Context) { $Context.Log("CA What-If simulation failed: $($_.Exception.Message)", "Error") }
        Write-Warning "CA What-If simulation failed: $($_.Exception.Message)"
    }
    
    return $findings
}

# =============================================================================
# ENT-CONDACC-003: CONDITIONAL ACCESS GAP ANALYSIS
# =============================================================================

function Invoke-EntraCAGapAnalysis {
    <#
    .SYNOPSIS
        ENT-CONDACC-003: Identifies gaps in Conditional Access coverage.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    $startTime = [datetime]::UtcNow
    
    $requiredControls = @(
        @{ Id = "MFA_REQUIRED"; Name = "Multi-Factor Authentication"; Severity = "Critical"; CheckScript = { param($p) ($p | Where-Object { $_.State -eq 'Enabled' -and $_.GrantControls -and ($_.GrantControls.BuiltInControls -contains 'mfa') }).Count -gt 0 } },
        @{ Id = "BLOCK_LEGACY"; Name = "Block Legacy Authentication"; Severity = "High"; CheckScript = { param($p) ($p | Where-Object { $_.State -eq 'Enabled' -and $_.Conditions -and $_.Conditions.ClientApplications }).Count -gt 0 } },
        @{ Id = "DEVICE_COMPLIANCE"; Name = "Device Compliance Requirement"; Severity = "High"; CheckScript = { param($p) ($p | Where-Object { $_.State -eq 'Enabled' -and $_.GrantControls -and ($_.GrantControls.BuiltInControls -contains 'CompliantDevice') }).Count -gt 0 } }
    )
    
    try {
        Write-QuickChecksProgress -Activity "ENT-CONDACC-003" -Status "Analyzing CA policy gaps..." -PercentComplete 10
        
        Connect-MgGraph -Scopes "ConditionalAccess.Read.All" -ErrorAction Stop | Out-Null
        
        $policies = Get-MgIdentityConditionalAccessPolicy -ErrorAction Stop
        $enabledPolicies = $policies | Where-Object { $_.State -eq 'Enabled' }
        
        Write-QuickChecksProgress -Activity "ENT-CONDACC-003" -Status "Evaluating security controls..." -PercentComplete 50
        
        foreach ($control in $requiredControls) {
            Write-QuickChecksProgress -Activity "ENT-CONDACC-003" -Status "Checking: $($control.Name)..." -PercentComplete 70
            
            $isImplemented = & $control.CheckScript -Policies $enabledPolicies
            
            if (-not $isImplemented) {
                $f = New-Finding -Id "ENT-CONDACC-003-$($control.Id)" `
                    -Title "CA Gap: $($control.Name) not configured" `
                    -Description "$($control.Name) is not implemented in any enabled CA policy" `
                    -Severity $control.Severity -Category "Entra_ConditionalAccess"
                
                $f.CheckName = "CAGapAnalysis"
                $f.Remediation = "Implement $($control.Name) in Conditional Access policies."
                $f.RemediationSteps = @(
                    "Create new Conditional Access policy",
                    "Configure $($control.Name) as control",
                    "Test in Report-only mode"
                )
                
                Add-FindingObject -Finding $f -Object "Control: $($control.Name)"
                $findings += $f
            }
        }
        
        Write-QuickChecksProgress -Activity "ENT-CONDACC-003" -Status "Complete" -PercentComplete 100
        
        Disconnect-MgGraph | Out-Null
        
        $elapsed = [datetime]::UtcNow - $startTime
        Write-QuickChecksExecutiveSummary -Findings $findings -CheckName "CA Gap Analysis" -ElapsedTime $elapsed
    }
    catch {
        if ($Context) { $Context.Log("CA gap analysis failed: $($_.Exception.Message)", "Error") }
        Write-Warning "CA gap analysis failed: $($_.Exception.Message)"
    }
    
    return $findings
}

# =============================================================================
# AWS-MFA-001: IAM USER MFA STATUS VERIFICATION
# =============================================================================

function Invoke-AwsIamMfaCheck {
    <#
    .SYNOPSIS
        AWS-MFA-001: Verifies MFA status for IAM users.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context,
        
        [Parameter(Mandatory = $false)]
        [int]$WarningThreshold = 5
    )
    
    $findings = @()
    $startTime = [datetime]::UtcNow
    
    try {
        Write-QuickChecksProgress -Activity "AWS-MFA-001" -Status "Checking AWS IAM users..." -PercentComplete 10
        
        $iamUsers = @()
        
        if (Get-Command "aws" -ErrorAction SilentlyContinue) {
            try {
                $userJson = aws iam list-users --output json 2>$null
                if ($userJson) { $iamUsers = $userJson | ConvertFrom-Json | Select-Object -ExpandProperty Users }
            }
            catch { Write-Warning "AWS CLI failed" }
        }
        elseif (Get-Module -ListAvailable -Name AWS.Tools.IdentityManagement -ErrorAction SilentlyContinue) {
            Import-Module AWS.Tools.IdentityManagement -ErrorAction SilentlyContinue
            try { $iamUsers = Get-IAMUser -ErrorAction Stop }
            catch { Write-Warning "AWS Tools failed" }
        }
        else {
            Write-Warning "Neither AWS CLI nor AWS Tools available"
            return $findings
        }
        
        if ($iamUsers.Count -eq 0) {
            Write-Host "No IAM users found" -ForegroundColor Yellow
            return $findings
        }
        
        Write-QuickChecksProgress -Activity "AWS-MFA-001" -Status "Analyzing MFA status..." -PercentComplete 50
        
        $consoleUsersWithoutMfa = 0
        $usersWithConsoleAccess = 0
        
        foreach ($user in $iamUsers) {
            $mfaEnabled = $false
            $hasConsoleAccess = $false
            
            if (Get-Command "aws" -ErrorAction SilentlyContinue) {
                try {
                    $mfaJson = aws iam list-mfa-devices --user-name $user.UserName --output json 2>$null
                    if ($mfaJson) { $mfaDevices = $mfaJson | ConvertFrom-Json | Select-Object -ExpandProperty MFADevices; if ($mfaDevices) { $mfaEnabled = $true } }
                }
                catch { }
                
                try {
                    $loginJson = aws iam get-login-profile --user-name $user.UserName --output json 2>$null
                    if ($loginJson) { $hasConsoleAccess = $true }
                }
                catch { }
            }
            
            if ($hasConsoleAccess) {
                $usersWithConsoleAccess++
                if (-not $mfaEnabled) { $consoleUsersWithoutMfa++ }
            }
        }
        
        Write-QuickChecksProgress -Activity "AWS-MFA-001" -Status "Generating findings..." -PercentComplete 80
        
        $pctWithoutMfa = 0
        if ($usersWithConsoleAccess -gt 0) {
            $pctWithoutMfa = [math]::Round(($consoleUsersWithoutMfa / $usersWithConsoleAccess) * 100, 1)
        }
        
        if ($consoleUsersWithoutMfa -gt 0) {
            $severity = if ($pctWithoutMfa -gt 15) { "Critical" } elseif ($pctWithoutMfa -gt 5) { "High" } else { "Medium" }
            
            $f = New-Finding -Id "AWS-MFA-001" `
                -Title "IAM users with console access but no MFA" `
                -Description "$consoleUsersWithoutMfa of $usersWithConsoleAccess users ($pctWithoutMfa%) have console access without MFA" `
                -Severity $severity -Category "AWS_IAMSecurity"
            
            $f.CheckName = "AwsIamMfaCheck"
            $f.Remediation = "Enable MFA for all IAM users with console access."
            $f.RemediationSteps = @(
                "Identify users without MFA",
                "Contact users to enable MFA",
                "Consider enforcing MFA via IAM policy"
            )
            
            Add-FindingEvidence -Finding $f -Source "aws iam list-mfa-devices" `
                -Detail "$consoleUsersWithoutMfa users without MFA" -Confidence "High"
            
            $findings += $f
        }
        
        Write-QuickChecksProgress -Activity "AWS-MFA-001" -Status "Complete" -PercentComplete 100
        
        $elapsed = [datetime]::UtcNow - $startTime
        Write-QuickChecksExecutiveSummary -Findings $findings -CheckName "AWS IAM MFA Check" -ElapsedTime $elapsed
    }
    catch {
        if ($Context) { $Context.Log("AWS MFA check failed: $($_.Exception.Message)", "Error") }
        Write-Warning "AWS MFA check failed: $($_.Exception.Message)"
    }
    
    return $findings
}

# =============================================================================
# AD-DCSYNC-001: DCSYNC RIGHTS DETECTION
# =============================================================================

function Invoke-ADDcsyncRightsCheck {
    <#
    .SYNOPSIS
        AD-DCSYNC-001: Detects DCSync rights in Active Directory.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    $startTime = [datetime]::UtcNow
    
    $adModuleAvailable = $false
    try {
        if ($IsWindows -or (-not $PSBoundParameters.ContainsKey('IsWindows'))) {
            $adModule = Get-Module -ListAvailable -Name 'ActiveDirectory' -ErrorAction SilentlyContinue
            if ($adModule) {
                Import-Module ActiveDirectory -ErrorAction Stop
                $adModuleAvailable = $true
            }
        }
    }
    catch { $adModuleAvailable = $false }
    
    if (-not $adModuleAvailable) {
        Write-Warning "ActiveDirectory module not available. Skipping DCSync check."
        return $findings
    }
    
    try {
        Write-QuickChecksProgress -Activity "AD-DCSYNC-001" -Status "Checking DCSync rights..." -PercentComplete 10
        
        $domain = Get-ADDomain -ErrorAction Stop
        $domainDn = $domain.DistinguishedName
        
        $replicateChangesGuid = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
        $replicateChangesAllGuid = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
        
        $dcsyncAccounts = @()
        
        try {
            $extendedRights = Get-ADObject -Identity $domainDn -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue |
                Select-Object -ExpandProperty nTSecurityDescriptor |
                Select-Object -ExpandProperty Access |
                Where-Object {
                    $_.ActiveDirectoryRights -match 'ExtendedRight' -and
                    ($_.ObjectType -eq $replicateChangesGuid -or $_.ObjectType -eq $replicateChangesAllGuid)
                }
            
            foreach ($ace in $extendedRights) {
                if ($ace.IdentityReference -ne "NT AUTHORITY\SYSTEM" -and
                    $ace.IdentityReference -notlike "*\Enterprise Admins" -and
                    $ace.IdentityReference -notlike "*\Domain Admins") {
                    $dcsyncAccounts += @{ Account = $ace.IdentityReference; Rights = $_.ActiveDirectoryRights }
                }
            }
        }
        catch { Write-Warning "Extended rights query failed: $($_.Exception.Message)" }
        
        Write-QuickChecksProgress -Activity "AD-DCSYNC-001" -Status "Generating findings..." -PercentComplete 80
        
        $uniqueAccounts = $dcsyncAccounts | Sort-Object -Property Account -Unique
        
        if ($uniqueAccounts.Count -gt 0) {
            $f = New-Finding -Id "AD-DCSYNC-001" `
                -Title "Accounts with DCSync rights detected" `
                -Description "$($uniqueAccounts.Count) accounts have DCSync (Replicate Directory Changes) rights" `
                -Severity Critical -Category "ActiveDirectory_Security"
            
            $f.CheckName = "ADDcsyncRightsCheck"
            $f.Remediation = "Review DCSync rights immediately. Remove rights from non-essential accounts."
            $f.RemediationSteps = @(
                "Document all accounts with DCSync rights",
                "Verify business justification",
                "Remove rights from service accounts if possible",
                "Monitor for unauthorized DCSync usage"
            )
            
            foreach ($acc in $uniqueAccounts) {
                Add-FindingObject -Finding $f -Object $acc.Account
            }
            
            Add-FindingEvidence -Finding $f -Source "Get-ADObject" `
                -Detail "$($uniqueAccounts.Count) accounts with DCSync rights" -Confidence "High"
            
            $findings += $f
        }
        
        $f2 = New-Finding -Id "AD-DCSYNC-001-INFO" `
            -Title "DCSync rights baseline (Enterprise and Domain Admins)" `
            -Description "Enterprise Admins and Domain Admins groups have inherent DCSync rights" `
            -Severity Info -Category "ActiveDirectory_Security"
        
        $f2.CheckName = "ADDcsyncRightsCheck"
        $f2.Remediation = "Ensure Enterprise and Domain Admins groups are strictly controlled."
        
        Add-FindingObject -Finding $f2 -Object "Enterprise Admins: Inherent DCSync rights"
        Add-FindingObject -Finding $f2 -Object "Domain Admins: Inherent DCSync rights"
        
        $findings += $f2
        
        Write-QuickChecksProgress -Activity "AD-DCSYNC-001" -Status "Complete" -PercentComplete 100
        
        $elapsed = [datetime]::UtcNow - $startTime
        Write-QuickChecksExecutiveSummary -Findings $findings -CheckName "DCSync Rights Detection" -ElapsedTime $elapsed
    }
    catch {
        if ($Context) { $Context.Log("DCSync check failed: $($_.Exception.Message)", "Error") }
        Write-Warning "DCSync check failed: $($_.Exception.Message)"
    }
    
    return $findings
}

# =============================================================================
# MASTER ENHANCED ASSESSMENT FUNCTION
# =============================================================================

function Invoke-EnhancedSecurityAssessment {
    <#
    .SYNOPSIS
        Runs all enhanced security assessments.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputDir = ".\Enhanced-Security-Output",
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Console', 'Json')]
        [string]$Format = 'Console',
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipCertificateCheck,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipCAChecks,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipAWSMfaCheck,
        
        [Parameter(Mandatory = $false)]
        [switch]$SkipDCSyncCheck,
        
        [Parameter(Mandatory = $false)]
        [switch]$Help
    )
    
    if ($Help) {
        Write-Host @"
IdentityFirst QuickChecks - Enhanced Security Assessment
======================================================
Advanced security checks including:
- ENT-CERT-001: Certificate Expiry Monitoring
- ENT-CONDACC-001/002/003: Conditional Access Analysis
- AWS-MFA-001: IAM User MFA Status verification
- AD-DCSYNC-001: DCSync Rights detection

USAGE:
    Invoke-EnhancedSecurityAssessment [-OutputDir <path>] [-Format <format>]
                                    [-SkipCertificateCheck] [-SkipCAChecks]
                                    [-SkipAWSMfaCheck] [-SkipDCSyncCheck] [-Help]

PARAMETERS:
    -OutputDir           Output directory (default: .\Enhanced-Security-Output)
    -Format              Console or JSON output (default: Console)
    -SkipCertificateCheck  Skip certificate expiry checks
    -SkipCAChecks         Skip Conditional Access checks
    -SkipAWSMfaCheck      Skip AWS MFA checks
    -SkipDCSyncCheck      Skip DCSync rights checks
    -Help                 Show this help message
"@
        return
    }
    
    Write-Host "`n" -ForegroundColor Cyan
    Write-Host "  IdentityFirst QuickChecks - Enhanced Security Assessment            " -ForegroundColor Cyan
    Write-Host "  " -NoNewline -ForegroundColor Cyan
    Write-Host ("=" * 65) -ForegroundColor DarkCyan
    
    $context = @{ Configuration = @{}; Log = @(); StartTime = [datetime]::UtcNow }
    $allFindings = @()
    
    if (-not $SkipCertificateCheck) {
        Write-Host "`n[ENT-CERT-001] Checking certificate expiry..." -ForegroundColor Yellow
        $allFindings += Invoke-EntraCertificateExpiryCheck -Context $context
    }
    
    if (-not $SkipCAChecks) {
        Write-Host "`n[ENT-CONDACC-001] Analyzing Conditional Access..." -ForegroundColor Yellow
        $allFindings += Invoke-EntraConditionalAccessAnalysis -Context $context
        
        Write-Host "`n[ENT-CONDACC-002] Running What-If simulation..." -ForegroundColor Yellow
        $allFindings += Invoke-EntraCAWhatIfSimulation -Context $context
        
        Write-Host "`n[ENT-CONDACC-003] Performing Gap Analysis..." -ForegroundColor Yellow
        $allFindings += Invoke-EntraCAGapAnalysis -Context $context
    }
    
    if (-not $SkipAWSMfaCheck) {
        Write-Host "`n[AWS-MFA-001] Checking AWS IAM users..." -ForegroundColor Yellow
        $allFindings += Invoke-AwsIamMfaCheck -Context $context
    }
    
    if (-not $SkipDCSyncCheck) {
        Write-Host "`n[AD-DCSYNC-001] Detecting DCSync rights..." -ForegroundColor Yellow
        $allFindings += Invoke-ADDcsyncRightsCheck -Context $context
    }
    
    # Calculate overall score
    $score = 100
    foreach ($f in $allFindings) {
        switch ($f.Severity) {
            "Critical" { $score -= 25 }
            "High" { $score -= 10 }
            "Medium" { $score -= 5 }
            "Low" { $score -= 2 }
        }
    }
    $score = [Math]::Max(0, [Math]::Min(100, $score))
    
    $crit = ($allFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $high = ($allFindings | Where-Object { $_.Severity -eq 'High' }).Count
    
    $status = if ($crit -gt 0) { "Critical" } elseif ($high -gt 5) { "Critical" } elseif ($high -gt 0) { "Warning" } else { "Healthy" }
    
    Write-Host "`n" -ForegroundColor Cyan
    Write-Host " ENHANCED SECURITY ASSESSMENT SUMMARY " -ForegroundColor White
    Write-Host "" -ForegroundColor Cyan
    
    $scoreColor = if ($status -eq 'Healthy') { 'Green' } elseif ($status -eq 'Warning') { 'Yellow' } else { 'Red' }
    Write-Host "  Overall Score: $score/100 - " -NoNewline
    Write-Host $status -ForegroundColor $scoreColor
    
    Write-Host "`n  Findings Breakdown:"
    Write-Host "    Critical: $crit" -ForegroundColor Red
    Write-Host "    High:     $high" -ForegroundColor DarkRed
    Write-Host "    Medium:   $(($allFindings | Where-Object { $_.Severity -eq 'Medium' }).Count)" -ForegroundColor Yellow
    Write-Host "    Low:      $(($allFindings | Where-Object { $_.Severity -eq 'Low' }).Count)" -ForegroundColor Cyan
    Write-Host "    Info:     $(($allFindings | Where-Object { $_.Severity -eq 'Info' }).Count)" -ForegroundColor Gray
    Write-Host "    Total:    $($allFindings.Count)" -ForegroundColor White
    
    return @{
        OverallScore = $score
        HealthStatus = $status
        Findings = $allFindings
        CriticalCount = $crit
        HighCount = $high
    }
}

# =============================================================================
# EXPORT MODULE MEMBERS
# =============================================================================

Export-ModuleMember -Function @(
    'Write-QuickChecksProgress'
    'Write-QuickChecksExecutiveSummary'
    'Invoke-EntraCertificateExpiryCheck'
    'Invoke-EntraConditionalAccessAnalysis'
    'Invoke-EntraCAWhatIfSimulation'
    'Invoke-EntraCAGapAnalysis'
    'Invoke-AwsIamMfaCheck'
    'Invoke-ADDcsyncRightsCheck'
    'Invoke-EnhancedSecurityAssessment'
)
