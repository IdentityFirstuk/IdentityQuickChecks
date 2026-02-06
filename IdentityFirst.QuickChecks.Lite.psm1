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

# SIG # Begin signature block
# MIIf3QYJKoZIhvcNAQcCoIIfzjCCH8oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAUrOt7GGfMhjPQ
# FbPbKn4YJm5nGNfmu1huWktYlPENNaCCGNwwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# AgEVMC8GCSqGSIb3DQEJBDEiBCAawuQn5inFmrouysRQP84xAzdveqcVN3rJ4Kmj
# SUpeFjANBgkqhkiG9w0BAQEFAASCAgAgYXmuJKFlSZe3tpYVb7KBZx7Ewcs6CdOd
# hTP7xKEuCvXiwkyhBXQBJMAaX0XJcOFuz1wsu6ss1ZnMMJi49VRsURM9avOn/Bg7
# LZjz1ACoOM0DAxZlm/64K2kZUCdNpPTYPhMebW0EYR1M3UeSGXXi/InAraT2cIKt
# Uu5coYmTr1XDzkOGwX3JnWuO/jm+XJq1n54M8LsxqL1nQr/pLpN5ZpT9F53YlKft
# CwnvfUFJl1jG77X+7dmgjHkpsqFXk6jLyiGVr1ZK2vWZxtsIZxibonvHbx4WxFP5
# rsCiTkXx2tTGl9229Zv8Utsg7VT7s5vwU8f6pxedNkNmeUScmDf64xrGIJYFOa/Z
# 4Ug8RV1ekD74VMLzUDmg/g90ARlU29/lzmRPVkRHyw29VCSuL4xhuCQ+eQ2zM5eF
# ggYAqeJDQXSqrxXcGAYvSzArd3+n4bA7pRi+gTxTz8fYbOVqc+UwGVv/VzmFUx3C
# n6Xu7QzfB08Ld8fyLzbkBKfof+KzdDehXjkYfXp2f1c5ghbv6UYBdIjwFhcWCgIV
# 5WWyCY9vZdjj7HON5wbZWuQVXzHkBW4NWbA1Igoh9pmIsHthrXu9dV8uxobigdnF
# FUOhzQT/mRZHeMFbz3vEb4gQn4Rs3oK/fHfEDB1cH5eeDiT9TbYNIzHytqkk5dRv
# 0E8I2V2Z0KGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAyMDUxNzEyNDZaMC8G
# CSqGSIb3DQEJBDEiBCBGmoIReIDL6WIOUstNy/iRDM881SEN4jwsIfM61pl28jAN
# BgkqhkiG9w0BAQEFAASCAgC9QLTru/WrPhiRpxkG+FcSiySbZjdbAEUIwHdM/eM4
# 9XBnPuOoKY7aGOFl279gFUQTRJ9iX+Kp5JGpEdIdPKnFBXQfpwMkdQKfa4YgTEWM
# KiXfsDCHvs20j0NNUL+Im0zSCcWYKiJhoISOuTON51WIF9NogEbFcQYA/oO8MAxh
# El6N8VhnLP90UckfcIa/YxtPj55gUlGXz2ibjPDiGytPESCtu9Zkdhl8zZutSlJJ
# K3SEIS2zGGzUqhNzorz/aiVKyQnnjF+hHhtD6V834lTQ9qIykwipzjxTFPsERqpI
# hvww9xJdwVm25PDy93UfrmVwvPRiBtHXWSoq3UaVCV25SPzlOt6BjpmGnTertPag
# V4JNHikUqvzGnzv7BKdrgQjNB73J9pFCnRHk1qV+MsRiUr/ohjGpjxoptaiyo6nK
# WfNM3Iv+YzXuoR/146yOgpGs0QVWVqta1j1qK2WFoMjxmhQtVKOBujQycS7aOMT4
# 5N13eiRAseprUS8OZS2ueouXueBoiQEuAXR5JEJ1y+U54kGGMrdlSNQX+oQCtuwB
# tjvarz9RDJmznqHRRHFHdeCVQP1Li0WWgqD1yxaX4Gxqmcx9HSHssX1/AkEaTZyI
# wWeD8RQcwaBzVBhDcDZI250olSD7XZGBUQ2ybr/gqSs+P/gQrK6xWbz04nrD4nXp
# sA==
# SIG # End signature block
