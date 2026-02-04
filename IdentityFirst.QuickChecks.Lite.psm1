<#
.SYNOPSIS
    IdentityFirst QuickChecks - Lite Framework Module

.DESCRIPTION
    This module provides the core framework for IdentityFirst QuickChecks.
    It includes wrapper functions for all legacy scripts and standardized
    finding objects, thresholds, and reporting.

.NOTES
    Author: mark.ahearne@identityfirst.net
    Requirements: PowerShell 5.1+

    This module replaces the standalone .ps1 scripts with proper
    PowerShell functions that can be imported and used programmatically.

    All functions follow the Invoke-QuickChecks* naming convention
    for consistency and discoverability.
#>

# =============================================================================
# Configuration and Defaults
# =============================================================================

# Default thresholds for finding severity
$script:DefaultThresholds = @{
    Critical = 0      # Zero tolerance
    High = 5          # Immediate action
    Medium = 10       # Review within 30 days
    Low = 20          # Informational
}

# Finding categories for classification
$script:FindingCategories = @{
    CredentialHandling = "Security_CredentialHandling"
    LeastPrivilege = "Security_LeastPrivilege"
    ExecutionPolicy = "Security_ExecutionPolicy"
    CodeSigning = "Trust_CodeSigning"
    FileIntegrity = "Trust_FileIntegrity"
    PowerShellVersion = "Validation_PowerShellVersion"
    Modules = "Validation_Modules"
    DotNet = "Validation_DotNet"
    Connectivity = "Validation_Connectivity"
    Configuration = "Validation_Configuration"
}

# Severity levels
$script:SeverityLevels = @('Critical', 'High', 'Medium', 'Low')

# =============================================================================
# Finding Helper Functions
# =============================================================================

function New-Finding {
    <#
    .SYNOPSIS
        Creates a standardized finding object.

    .DESCRIPTION
        Returns a hashtable with all required properties for a finding,
        ready to be populated with evidence and remediation steps.

    .PARAMETER Id
        Unique identifier for the finding (e.g., 'SEC-CRED-001')

    .PARAMETER Title
        Brief, descriptive title for the finding.

    .PARAMETER Description
        Detailed description of what was found.

    .PARAMETER Severity
        Severity level: Critical, High, Medium, or Low.

    .PARAMETER Category
        Category for grouping findings.

    .OUTPUTS
        Hashtable with all finding properties.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,

        [Parameter(Mandatory = $true)]
        [string]$Title,

        [Parameter(Mandatory = $true)]
        [string]$Description,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low')]
        [string]$Severity,

        [Parameter(Mandatory = $true)]
        [string]$Category,

        [Parameter(Mandatory = $false)]
        [string]$RuleId = $Id
    )

    return @{
        Id = $Id
        Title = $Title
        Description = $Description
        Severity = $Severity
        Category = $Category
        Timestamp = [datetime]::UtcNow
        AffectedObjects = @()
        Evidence = @()
        RemediationSteps = @()
        IsResolved = $false
        Confidence = "High"
        RuleId = $RuleId
        Source = "IdentityFirst.QuickChecks"
        CheckName = $MyInvocation.MyCommand.Name
        AffectedCount = 0
        Remediation = ""
    }
}

function Add-FindingObject {
    <#
    .SYNOPSIS
        Adds an affected object to a finding.

    .DESCRIPTION
        Appends an object to the finding's AffectedObjects array
        and increments the AffectedCount.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Finding,

        [Parameter(Mandatory = $true)]
        [string]$AffectedObject
    )

    $Finding.AffectedObjects += $AffectedObject
    $Finding.AffectedCount = $Finding.AffectedObjects.Count
}

function Add-FindingEvidence {
    <#
    .SYNOPSIS
        Adds evidence to a finding.

    .DESCRIPTION
        Appends evidence to the finding's Evidence array.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Finding,

        [Parameter(Mandatory = $true)]
        [string]$Evidence
    )

    $Finding.Evidence += $Evidence
}

function Add-FindingRemediation {
    <#
    .SYNOPSIS
        Adds a remediation step to a finding.

    .DESCRIPTION
        Appends a remediation step to the finding's RemediationSteps array
        and generates a summary Remediation string.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Finding,

        [Parameter(Mandatory = $true)]
        [string]$Step
    )

    $Finding.RemediationSteps += $Step
    $Finding.Remediation = $Finding.RemediationSteps -join "; "
}

# =============================================================================
# Assessment Context Functions
# =============================================================================

function New-AssessmentContext {
    <#
    .SYNOPSIS
        Creates an assessment context for tracking state.

    .DESCRIPTION
        Returns a hashtable with StartTime, Log, Settings, and other
        state tracking properties for the duration of an assessment.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = ".\QuickChecks-Output",

        [Parameter(Mandatory = $false)]
        [int]$MaxFindings = 100
    )

    return @{
        StartTime = [datetime]::UtcNow
        Log = @()
        Settings = @{
            OutputPath = $OutputPath
            MaxFindings = $MaxFindings
            IncludeEvidence = $true
            IncludeRemediation = $true
        }
        Findings = @()
        Statistics = @{
            CheckCount = 0
            ErrorCount = 0
        }
    }
}

function Add-AssessmentLog {
    <#
    .SYNOPSIS
        Adds a log entry to the assessment context.

    .DESCRIPTION
        Appends a timestamped log entry to the context's Log array.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Context,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Debug')]
        [string]$Level = 'Info'
    )

    $entry = @{
        Timestamp = [datetime]::UtcNow
        Level = $Level
        Message = $Message
    }

    $Context.Log += $entry

    if ($Level -eq 'Error') {
        $Context.Statistics.ErrorCount++
    }
}

function New-AssessmentReport {
    <#
    .SYNOPSIS
        Generates a final assessment report.

    .DESCRIPTION
        Creates a comprehensive report from the assessment context,
        including summary statistics and categorized findings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Context
    )

    $endTime = [datetime]::UtcNow
    $duration = ($endTime - $Context.StartTime).TotalSeconds

    $bySeverity = $Context.Findings | Group-Object Severity
    $byCategory = $Context.Findings | Group-Object Category

    return @{
        Timestamp = $endTime
        Duration = [math]::Round($duration, 2)
        TotalFindings = $Context.Findings.Count
        BySeverity = $bySeverity
        ByCategory = $byCategory
        CriticalCount = ($Context.Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
        HighCount = ($Context.Findings | Where-Object { $_.Severity -eq 'High' }).Count
        MediumCount = ($Context.Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
        LowCount = ($Context.Findings | Where-Object { $_.Severity -eq 'Low' }).Count
        Statistics = $Context.Statistics
        Findings = $Context.Findings
    }
}

# =============================================================================
# Main Wrapper Functions
# =============================================================================

function Invoke-BreakGlassReality {
    <#
    .SYNOPSIS
        Identifies break-glass accounts and checks their posture.

    .DESCRIPTION
        Searches for accounts named or described as break-glass
        and reports on their security posture.

    .PARAMETER OutputPath
        Path to save JSON report.

    .EXAMPLE
        Invoke-BreakGlassReality -OutputPath ".\Reports"
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath = ".\QuickChecks-Output"
    )

    $context = New-AssessmentContext -OutputPath $OutputPath
    $findings = @()

    try {
        Add-AssessmentLog -Context $context -Message "Starting break-glass account detection" -Level Info

        # Check if ActiveDirectory module is available
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
            Add-AssessmentLog -Context $context -Message "ActiveDirectory module not available - skipping AD checks" -Level Warning
            return @()
        }

        # Get all admin account patterns
        $patterns = @(
            'break',
            'glass',
            'emergency',
            'bak',
            'backup',
            'fg',
            'fireg',
            'critical'
        )

        # Search AD for matching accounts (simplified for demo)
        $adUsers = Get-ADUser -Filter * -Properties SamAccountName, DisplayName, Description -ErrorAction SilentlyContinue -ErrorVariable err

        if ($err) {
            Add-AssessmentLog -Context $context -Message "AD query failed: $($err[0].Message)" -Level Error
        }

        if ($adUsers) {
            foreach ($user in $adUsers) {
                $matched = $false
                foreach ($pattern in $patterns) {
                    if ($user.SamAccountName -match $pattern -or $user.Description -match $pattern -or $user.DisplayName -match $pattern) {
                        $matched = $true
                        break
                    }
                }

                if ($matched) {
                    $f = New-Finding -Id "LITE-BG-001" `
                        -Title "Potential break-glass account: $($user.SamAccountName)" `
                        -Description "Account matches break-glass naming patterns" `
                        -Severity "Medium" `
                        -Category "Identity_BreakGlass"

                    Add-FindingObject -Finding $f -AffectedObject $user.SamAccountName
                    Add-FindingEvidence -Finding $f -Evidence "SAM: $($user.SamAccountName)"
                    Add-FindingEvidence -Finding $f -Evidence "DN: $($user.DistinguishedName)"
                    Add-FindingRemediation -Finding $f -Step "Verify break-glass account necessity"
                    Add-FindingRemediation -Finding $f -Step "Document approval and testing requirements"

                    $findings += $f
                    Add-AssessmentLog -Context $context -Message "Found break-glass candidate: $($user.SamAccountName)" -Level Info
                }
            }
        }

        Add-AssessmentLog -Context $context -Message "Break-glass check complete: $($findings.Count) findings" -Level Info
    }
    catch {
        Add-AssessmentLog -Context $context -Message "Error: $($_.Exception.Message)" -Level Error
        throw
    }

    $context.Findings = $findings
    $report = New-AssessmentReport -Context $context

    # Save report
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $report | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $OutputPath "BreakGlass-Report-$timestamp.json") -Encoding UTF8

    return $findings
}

function Invoke-IdentityNamingHygiene {
    <#
    .SYNOPSIS
        Checks identity naming conventions.

    .DESCRIPTION
        Identifies accounts that violate naming conventions
        and reports on naming hygiene issues.
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath = ".\QuickChecks-Output"
    )

    $context = New-AssessmentContext -OutputPath $OutputPath
    $findings = @()

    try {
        Add-AssessmentLog -Context $context -Message "Starting naming hygiene check" -Level Info

        # Check if ActiveDirectory module is available
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
            Add-AssessmentLog -Context $context -Message "ActiveDirectory module not available" -Level Warning
            return @()
        }

        # Get users without proper naming
        $adUsers = Get-ADUser -Filter * -Properties SamAccountName, DisplayName, Mail -ErrorAction SilentlyContinue

        if ($adUsers) {
            foreach ($user in $adUsers) {
                $issues = @()

                # Check for missing display name
                if (-not $user.DisplayName) {
                    $issues += "Missing DisplayName"
                }

                # Check for spaces in SamAccountName
                if ($user.SamAccountName -match '\s') {
                    $issues += "SamAccountName contains spaces"
                }

                # Check for special characters
                if ($user.SamAccountName -match '[^a-zA-Z0-9._-]') {
                    $issues += "SamAccountName contains special characters"
                }

                # Check for admin in name but not in admin groups
                if ($user.SamAccountName -match 'admin' -or $user.DisplayName -match 'admin') {
                    # Could flag for review
                }

                if ($issues.Count -gt 0) {
                    $f = New-Finding -Id "LITE-NAME-001" `
                        -Title "Naming convention violation: $($user.SamAccountName)" `
                        -Description "Account has naming issues: $($issues -join ', ')" `
                        -Severity "Low" `
                        -Category "Identity_Naming"

                    Add-FindingObject -Finding $f -AffectedObject $user.SamAccountName
                    Add-FindingEvidence -Finding $f -Evidence "Issues: $($issues -join '; ')"
                    Add-FindingRemediation -Finding $f -Step "Review and update naming convention compliance"

                    $findings += $f
                }
            }
        }

        Add-AssessmentLog -Context $context -Message "Naming check complete: $($findings.Count) findings" -Level Info
    }
    catch {
        Add-AssessmentLog -Context $context -Message "Error: $($_.Exception.Message)" -Level Error
        throw
    }

    $context.Findings = $findings
    $report = New-AssessmentReport -Context $context

    # Save report
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $report | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $OutputPath "NamingHygiene-Report-$timestamp.json") -Encoding UTF8

    return $findings
}

function Invoke-PasswordPolicyDrift {
    <#
    .SYNOPSIS
        Identifies accounts bypassing password policies.

    .DESCRIPTION
        Finds accounts with PasswordNeverExpires or other
        settings that may bypass organizational password policies.
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath = ".\QuickChecks-Output"
    )

    $context = New-AssessmentContext -OutputPath $OutputPath
    $findings = @()

    try {
        Add-AssessmentLog -Context $context -Message "Starting password policy drift check" -Level Info

        if (-not (Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
            Add-AssessmentLog -Context $context -Message "ActiveDirectory module not available" -Level Warning
            return @()
        }

        # Get users with PasswordNeverExpires
        $pneUsers = Get-ADUser -Filter { PasswordNeverExpires -eq $true } `
            -Properties SamAccountName, DisplayName, PasswordLastSet, LastLogonDate `
            -ErrorAction SilentlyContinue

        foreach ($user in $pneUsers) {
            $f = New-Finding -Id "LITE-PWD-001" `
                -Title "Password never expires: $($user.SamAccountName)" `
                -Description "Account has PasswordNeverExpires set" `
                -Severity "Medium" `
                -Category "Identity_PasswordPolicy"

            Add-FindingObject -Finding $f -AffectedObject $user.SamAccountName
            Add-FindingEvidence -Finding $f -Evidence "Last password set: $($user.PasswordLastSet)"
            Add-FindingEvidence -Finding $f -Evidence "Last logon: $($user.LastLogonDate)"
            Add-FindingRemediation -Finding $f -Step "Review necessity for PasswordNeverExpires"
            Add-FindingRemediation -Finding $f -Step "Consider enforcing password expiration"

            $findings += $f
        }

        Add-AssessmentLog -Context $context -Message "Password policy check complete: $($findings.Count) findings" -Level Info
    }
    catch {
        Add-AssessmentLog -Context $context -Message "Error: $($_.Exception.Message)" -Level Error
        throw
    }

    $context.Findings = $findings
    $report = New-AssessmentReport -Context $context

    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $report | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $OutputPath "PasswordPolicy-Report-$timestamp.json") -Encoding UTF8

    return $findings
}

function Invoke-PrivilegedNestingAbuse {
    <#
    .SYNOPSIS
        Finds indirect privilege through nested groups.

    .DESCRIPTION
        Identifies users who have privileged access through
        nested group membership rather than direct assignment.
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath = ".\QuickChecks-Output"
    )

    $context = New-AssessmentContext -OutputPath $OutputPath
    $findings = @()

    try {
        Add-AssessmentLog -Context $context -Message "Starting privileged nesting check" -Level Info

        if (-not (Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
            Add-AssessmentLog -Context $context -Message "ActiveDirectory module not available" -Level Warning
            return @()
        }

        # Get domain admins and their nested members
        $privilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins')

        foreach ($groupName in $privilegedGroups) {
            $group = Get-ADGroup -Filter { Name -eq $groupName } -Properties Members -ErrorAction SilentlyContinue

            if ($group) {
                $directMembers = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue

                foreach ($member in $directMembers) {
                    if ($member.objectClass -eq 'user') {
                        $f = New-Finding -Id "LITE-NEST-001" `
                            -Title "Direct privileged access: $($member.Name)" `
                            -Description "User is direct member of $groupName" `
                            -Severity "High" `
                            -Category "Identity_Privilege"

                        Add-FindingObject -Finding $f -AffectedObject $member.SamAccountName
                        Add-FindingEvidence -Finding $f -Evidence "Group: $groupName"
                        Add-FindingRemediation -Finding $f -Step "Review direct membership necessity"
                        Add-FindingRemediation -Finding $f -Step "Consider using groups for access management"

                        $findings += $f
                    }
                }
            }
        }

        Add-AssessmentLog -Context $context -Message "Nesting check complete: $($findings.Count) findings" -Level Info
    }
    catch {
        Add-AssessmentLog -Context $context -Message "Error: $($_.Exception.Message)" -Level Error
        throw
    }

    $context.Findings = $findings
    $report = New-AssessmentReport -Context $context

    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $report | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $OutputPath "PrivilegedNesting-Report-$timestamp.json") -Encoding UTF8

    return $findings
}

function Invoke-QuickChecksLite {
    <#
    .SYNOPSIS
        Runs all lite identity checks.

    .DESCRIPTION
        Executes all available lite identity posture checks and
        generates a comprehensive report.

    .PARAMETER OutputPath
        Directory for output reports.

    .PARAMETER SkipCategories
        Categories to skip (Security, Identity, Trust).

    .EXAMPLE
        Invoke-QuickChecksLite -OutputPath ".\Reports"
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath = ".\QuickChecks-Output",
        [string[]]$SkipCategories = @()
    )

    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  IdentityFirst QuickChecks Lite v1.1.0" -ForegroundColor Cyan
    Write-Host "  Azure RBAC/PBAC/ABAC Security Assessment" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""

    $allFindings = @()
    $allChecks = @(
        @{ Name = "BreakGlassReality"; Category = "Identity" }
        @{ Name = "IdentityNamingHygiene"; Category = "Identity" }
        @{ Name = "PasswordPolicyDrift"; Category = "Security" }
        @{ Name = "PrivilegedNestingAbuse"; Category = "Security" }
    )

    foreach ($check in $allChecks) {
        if ($SkipCategories -contains $check.Category) {
            Write-Host "[SKIP] $($check.Name) - Category skipped" -ForegroundColor Gray
            continue
        }

        Write-Host "[RUN]  $($check.Name)..." -ForegroundColor Yellow

        try {
            $result = & "Invoke-$($check.Name)" -OutputPath $OutputPath -ErrorAction Stop
            $allFindings += $result
            Write-Host "[OK]   $($check.Name) - $($result.Count) findings" -ForegroundColor Green
        }
        catch {
            Write-Host "[ERR]  $($check.Name) - $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # Generate summary
    $critCount = ($allFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $highCount = ($allFindings | Where-Object { $_.Severity -eq 'High' }).Count

    Write-Host ""
    Write-Host " ASSESSMENT RESULTS " -ForegroundColor White
    Write-Host ""

    $score = if ($critCount -gt 0) { 0 } elseif ($highCount -gt 0) { 50 } else { 100 }
    Write-Host "  Overall Score: $score/100" -ForegroundColor $(if ($score -eq 100) { 'Green' } elseif ($score -eq 50) { 'Yellow' } else { 'Red' })
    Write-Host "  Status:       $(if ($score -eq 100) { 'Healthy' } elseif ($score -eq 50) { 'Warning' } else { 'Critical' })" -ForegroundColor $(if ($score -eq 100) { 'Green' } elseif ($score -eq 50) { 'Yellow' } else { 'Red' })
    Write-Host ""
    Write-Host "  Findings:"
    Write-Host "    Critical: $critCount" -ForegroundColor $(if ($critCount -gt 0) { 'Red' } else { 'Green' })
    Write-Host "    High:     $highCount" -ForegroundColor $(if ($highCount -gt 0) { 'DarkRed' } else { 'Green' })
    Write-Host "    Medium:   $(($allFindings | Where-Object { $_.Severity -eq 'Medium' }).Count)" -ForegroundColor Yellow
    Write-Host "    Low:      $(($allFindings | Where-Object { $_.Severity -eq 'Low' }).Count)" -ForegroundColor Cyan
    Write-Host ""

    return @{
        Findings = $allFindings
        Score = $score
        Timestamp = [datetime]::UtcNow
    }
}

# Export module members
Export-ModuleMember -Function @(
    'New-Finding',
    'Add-FindingObject',
    'Add-FindingEvidence',
    'Add-FindingRemediation',
    'New-AssessmentContext',
    'Add-AssessmentLog',
    'New-AssessmentReport',
    'Invoke-BreakGlassReality',
    'Invoke-IdentityNamingHygiene',
    'Invoke-PasswordPolicyDrift',
    'Invoke-PrivilegedNestingAbuse',
    'Invoke-QuickChecksLite'
)
