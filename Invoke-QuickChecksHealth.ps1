<#
.SYNOPSIS
    IdentityFirst QuickChecks - Health Assessment Runner
    
.DESCRIPTION
    Lite version of IdentityHealthCheck. Runs all QuickChecks and produces:
    - Overall health score (0-100)
    - Severity classification (Critical/High/Medium/Low)
    - Actionable remediation recommendations
    - Exit codes for automation
    - JSON and HTML report generation

.NOTES
    Author: mark.ahearne@identityfirst.net | Owner: IdentityFirst Ltd
    Requirements: PowerShell 5.1+
#>

[CmdletBinding()]
param(
    # Output directory for reports
    [Parameter()]
    [string]$OutputDir = ".\QuickChecks_Health_Output",
    
    # Critical findings threshold
    [Parameter()]
    [int]$CriticalThreshold = 1,
    
    # High findings threshold
    [Parameter()]
    [int]$HighThreshold = 5,
    
    # Output format: Console, JSON, HTML, All
    [Parameter()]
    [ValidateSet('Console', 'JSON', 'HTML', 'All')]
    [string]$OutputFormat = 'All',
    
    # Minimum score for "Healthy" status
    [Parameter()]
    [int]$HealthyThreshold = 80,
    
    # Skip confirmation prompts
    [Parameter()]
    [switch]$Force,
    
    # Show help
    [Parameter()]
    [switch]$Help
)

if ($Help) {
    Write-Output @"
IdentityFirst QuickChecks - Health Assessment
==============================================

Lite version of IdentityHealthCheck for quick identity posture assessment.

USAGE:
    .\Invoke-QuickChecksHealth.ps1 [-OutputDir <path>] [-OutputFormat <format>]

PARAMETERS:
    -OutputDir         Directory for output files (default: .\QuickChecks_Health_Output)
    -OutputFormat      Output format: Console, JSON, HTML, All (default: All)
    -CriticalThreshold Critical findings to trigger Critical status (default: 1)
    -HighThreshold     High findings to trigger Warning status (default: 5)
    -HealthyThreshold  Score threshold for Healthy status (default: 80)
    -Force             Skip confirmation prompts
    -Help              Show this help

EXIT CODES:
    0   - Healthy (no critical findings)
    1   - Warning (high findings detected)
    2   - Critical (critical findings detected)
    3   - Error (execution failed)

OUTPUT:
    Creates JSON and HTML reports with:
    - Overall health score (0-100)
    - Finding severity breakdown
    - Actionable remediation steps
    - Executive summary

EXAMPLES:
    .\Invoke-QuickChecksHealth.ps1
    .\Invoke-QuickChecksHealth.ps1 -OutputFormat JSON -Force
    .\Invoke-QuickChecksHealth.ps1 -CriticalThreshold 3 -HighThreshold 10

REQUIREMENTS:
    - PowerShell 5.1+
    - QuickChecks scripts in subdirectories
    - Appropriate module permissions (AD, Graph, etc.)

"@
    exit 0
}

# ============================================================================
# Configuration
# ============================================================================

$script:Version = "1.0.0"
$script:Timestamp = (Get-Date).ToString('o')
$script:ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:HealthStatus = 'Healthy'
$script:OverallScore = 100

# ============================================================================
# Helper Functions
# ============================================================================

function Write-HealthLog {
    <#
    .SYNOPSIS
        Logs messages with timestamps for audit trail.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Debug')]
        [string]$Level = 'Info'
    )
    
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $entry = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        'Error'   { Write-Host $entry -ForegroundColor Red }
        'Warning' { Write-Host $entry -ForegroundColor Yellow }
        'Success' { Write-Host $entry -ForegroundColor Green }
        'Debug'   { Write-Host $entry -ForegroundColor Gray }
        default   { Write-Host $entry }
    }
}

function Get-SeverityColor {
    <#
    .SYNOPSIS
        Returns color for severity level.
    #>
    param([string]$Severity)
    switch ($Severity.ToLower()) {
        'critical' { return 'Red' }
        'high'     { return 'DarkRed' }
        'medium'   { return 'Yellow' }
        'low'      { return 'Cyan' }
        default    { return 'White' }
    }
}

function Import-ModuleSafe {
    <#
    .SYNOPSIS
        Safely imports a PowerShell module with error handling.
    #>
    param([Parameter(Mandatory=$true)][string]$Name)
    
    try {
        if (Get-Module -Name $Name -ErrorAction SilentlyContinue) {
            return $true
        }
        Import-Module $Name -ErrorAction Stop
        Write-HealthLog -Message "Module loaded: $Name" -Level Success
        return $true
    }
    catch {
        Write-HealthLog -Message "Module not available: $Name" -Level Warning
        return $false
    }
}

# ============================================================================
# Health Calculation Engine
# ============================================================================

function New-Finding {
    <#
    .SYNOPSIS
        Creates a standardized finding object.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$Title,
        
        [Parameter(Mandatory=$true)]
        [string]$Description,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity,
        
        [Parameter(Mandatory=$true)]
        [string]$Category,
        
        [Parameter(Mandatory=$false)]
        [string]$Remediation,
        
        [Parameter(Mandatory=$false)]
        [string]$AffectedObjects,
        
        [Parameter(Mandatory=$false)]
        [string]$CheckSource
    )
    
    return [PSCustomObject]@{
        Title = $Title
        Description = $Description
        Severity = $Severity
        Category = $Category
        Remediation = $Remediation
        AffectedObjects = $AffectedObjects
        CheckSource = $CheckSource
        Timestamp = (Get-Date).ToString('o')
    }
}

function Add-Finding {
    <#
    .SYNOPSIS
        Adds a finding to the global findings collection.
    #>
    param([Parameter(Mandatory=$true)]$Finding)
    
    $script:Findings += $Finding
    $script:FindingsBySeverity[$Finding.Severity]++
}

function Calculate-HealthScore {
    <#
    .SYNOPSIS
        Calculates overall health score based on findings.
        
    .DESCRIPTION
        Starts at 100 and deducts points based on severity:
        - Critical: -25 points each
        - High: -10 points each
        - Medium: -5 points each
        - Low: -2 points each
        - Info: -0 points (no impact)
        
        Score is clamped between 0-100.
    #>
    Write-HealthLog -Message "Calculating health score..." -Level Info
    
    $score = 100
    
    foreach ($finding in $script:Findings) {
        switch ($finding.Severity) {
            'Critical' { $score -= 25 }
            'High'     { $score -= 10 }
            'Medium'   { $score -= 5 }
            'Low'      { $score -= 2 }
            'Info'     { $score -= 0 }
        }
    }
    
    # Clamp between 0-100
    $script:OverallScore = [Math]::Max(0, [Math]::Min(100, $score))
    
    Write-HealthLog -Message "Health Score: $script:OverallScore" -Level Info
}

function Determine-HealthStatus {
    <#
    .SYNOPSIS
        Determines overall health status based on score and thresholds.
    #>
    param()
    
    $criticalCount = $script:FindingsBySeverity['Critical']
    $highCount = $script:FindingsBySeverity['High']
    
    # Check thresholds first
    if ($criticalCount -ge $CriticalThreshold) {
        $script:HealthStatus = 'Critical'
    }
    elseif ($highCount -ge $HighThreshold) {
        $script:HealthStatus = 'Warning'
    }
    # Check score thresholds
    elseif ($script:OverallScore -lt 60) {
        $script:HealthStatus = 'Critical'
    }
    elseif ($script:OverallScore -lt $HealthyThreshold) {
        $script:HealthStatus = 'Warning'
    }
    else {
        $script:HealthStatus = 'Healthy'
    }
    
    Write-HealthLog -Message "Health Status: $script:HealthStatus" -Level Info
}

# ============================================================================
# QuickCheck Runner
# ============================================================================

function Get-AvailableChecks {
    <#
    .SYNOPSIS
        Discovers all available QuickChecks scripts.
    #>
    $checks = @()
    
    # Define check directories
    $checkDirs = @(
        @{ Name = 'IdentityQuickChecks'; Path = Join-Path $script:ScriptRoot 'IdentityQuickChecks' },
        @{ Name = 'IdentityTrustQuickChecks'; Path = Join-Path $script:ScriptRoot 'IdentityTrustQuickChecks' },
        @{ Name = 'IdentityBoundaryQuickChecks'; Path = Join-Path $script:ScriptRoot 'IdentityBoundaryQuickChecks' },
        @{ Name = 'IdentityAssumptionQuickChecks'; Path = Join-Path $script:ScriptRoot 'IdentityAssumptionQuickChecks' }
    )
    
    foreach ($dir in $checkDirs) {
        if (Test-Path $dir.Path) {
            $psFiles = Get-ChildItem -Path $dir.Path -Filter '*.ps1' -ErrorAction SilentlyContinue
            foreach ($file in $psFiles) {
                $checks += [PSCustomObject]@{
                    Name = $file.BaseName
                    FullPath = $file.FullName
                    Category = $dir.Name
                }
            }
        }
    }
    
    return $checks
}

function Invoke-CheckWithFindings {
    <#
    .SYNOPSIS
        Runs a check script and parses findings from output.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Check
    )
    
    Write-HealthLog -Message "Running: $($Check.Name)" -Level Info
    
    try {
        $output = & $Check.FullPath -ErrorAction Stop 2>&1 | Out-String
        
        # Parse findings from output
        # Expected format: IFQC JSON output or structured text
        $parsed = $output | ConvertFrom-Json -ErrorAction SilentlyContinue
        
        if ($parsed -and $parsed.findings) {
            foreach ($finding in $parsed.findings) {
                # Add check source if not present
                if (-not $finding.CheckSource) {
                    $finding | Add-Member -NotePropertyName 'CheckSource' -NotePropertyValue $Check.Name -Force
                }
                Add-Finding -Finding $finding
            }
            Write-HealthLog -Message "  Found $($parsed.findings.Count) findings" -Level Info
        }
        else {
            # Check for inline findings (PowerShell objects)
            $objects = $output | ConvertFrom-Json -ErrorAction SilentlyContinue
            if ($objects) {
                foreach ($obj in $objects) {
                    if ($obj.Severity -and $obj.Title) {
                        if (-not $obj.CheckSource) {
                            $obj | Add-Member -NotePropertyName 'CheckSource' -NotePropertyValue $Check.Name -Force
                        }
                        Add-Finding -Finding $obj
                    }
                }
            }
        }
    }
    catch {
        Write-HealthLog -Message "  Check failed: $($_.Exception.Message)" -Level Warning
        
        # Add an error finding
        Add-Finding -Finding (
            New-Finding `
                -Title "Check Execution Error: $($Check.Name)" `
                -Description "The check script failed to execute: $($_.Exception.Message)" `
                -Severity 'Medium' `
                -Category $Check.Category `
                -Remediation "Verify the check script is valid and dependencies are installed." `
                -CheckSource $Check.Name
        )
    }
}

function Invoke-AllChecks {
    <#
    .SYNOPSIS
        Runs all available QuickChecks.
    #>
    Write-HealthLog -Message "Discovering available checks..." -Level Info
    
    $checks = Get-AvailableChecks
    Write-HealthLog -Message "Found $($checks.Count) checks" -Level Info
    
    if ($checks.Count -eq 0) {
        Write-HealthLog -Message "No checks found. Ensure QuickChecks scripts are in subdirectories." -Level Warning
        return
    }
    
    foreach ($check in $checks) {
        Invoke-CheckWithFindings -Check $check
    }
}

# ============================================================================
# Report Generation
# ============================================================================

function New-HealthReport {
    <#
    .SYNOPSIS
        Generates the health assessment report object.
    #>
    return [PSCustomObject]@{
        Timestamp = $script:Timestamp
        Version = $script:Version
        HealthStatus = $script:HealthStatus
        OverallScore = $script:OverallScore
        Summary = [PSCustomObject]@{
            TotalFindings = $script:Findings.Count
            CriticalCount = $script:FindingsBySeverity['Critical']
            HighCount = $script:FindingsBySeverity['High']
            MediumCount = $script:FindingsBySeverity['Medium']
            LowCount = $script:FindingsBySeverity['Low']
            InfoCount = $script:FindingsBySeverity['Info']
        }
        Findings = $script:Findings
        Recommendations = Get-Recommendations
        Configuration = [PSCustomObject]@{
            CriticalThreshold = $CriticalThreshold
            HighThreshold = $HighThreshold
            HealthyThreshold = $HealthyThreshold
        }
    }
}

function Get-Recommendations {
    <#
    .SYNOPSIS
        Generates actionable recommendations based on findings.
    #>
    $recommendations = @()
    
    # Group findings by category
    $byCategory = $script:Findings | Group-Object Category
    
    foreach ($group in $byCategory) {
        $criticalInCategory = ($group.Group | Where-Object { $_.Severity -eq 'Critical' }).Count
        $highInCategory = ($group.Group | Where-Object { $_.Severity -eq 'High' }).Count
        
        if ($criticalInCategory -gt 0) {
            $recommendations += [PSCustomObject]@{
                Priority = 'P0'
                Category = $group.Name
                Action = 'IMMEDIATE ACTION REQUIRED'
                Details = "$criticalInCategory critical findings in $($group.Name). Review and remediate immediately."
            }
        }
        
        if ($highInCategory -gt 0) {
            $recommendations += [PSCustomObject]@{
                Priority = 'P1'
                Category = $group.Name
                Action = 'Review within 7 days'
                Details = "$highInCategory high-severity findings in $($group.Name). Plan remediation."
            }
        }
    }
    
    return $recommendations
}

function Export-JSONReport {
    <#
    .SYNOPSIS
        Exports report to JSON format.
    #>
    param([Parameter(Mandatory=$true)][string]$Path)
    
    $report = New-HealthReport
    $report | ConvertTo-Json -Depth 10 | Set-Content -Path $Path -Encoding UTF8
    Write-HealthLog -Message "JSON report: $Path" -Level Success
}

function Export-HTMLReport {
    <#
    .SYNOPSIS
        Exports report to HTML format with styling.
    #>
    param([Parameter(Mandatory=$true)][string]$Path)
    
    $report = New-HealthReport
    
    # Generate HTML
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>IdentityFirst QuickChecks - Health Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #444; margin-top: 30px; }
        .score-box { display: flex; gap: 20px; margin: 20px 0; }
        .score { padding: 20px 40px; border-radius: 8px; font-size: 24px; font-weight: bold; text-align: center; }
        .score.healthy { background: #d4edda; color: #155724; }
        .score.warning { background: #fff3cd; color: #856404; }
        .score.critical { background: #f8d7da; color: #721c24; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #0078d4; color: white; }
        tr:hover { background: #f5f5f5; }
        .severity-critical { background: #f8d7da; color: #721c24; padding: 2px 8px; border-radius: 4px; }
        .severity-high { background: #f5c6cb; color: #721c24; padding: 2px 8px; border-radius: 4px; }
        .severity-medium { background: #fff3cd; color: #856404; padding: 2px 8px; border-radius: 4px; }
        .severity-low { background: #d1ecf1; color: #0c5460; padding: 2px 8px; border-radius: 4px; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }
        .recommendation { background: #e7f3ff; padding: 15px; margin: 10px 0; border-left: 4px solid #0078d4; }
    </style>
</head>
<body>
    <div class="container">
        <h1>IdentityFirst QuickChecks - Health Assessment Report</h1>
        
        <div class="score-box">
            <div class="score $($script:HealthStatus.ToLower())">
                Score: $($report.OverallScore)/100<br>
                Status: $($report.HealthStatus)
            </div>
        </div>
        
        <h2>Summary</h2>
        <table>
            <tr><th>Severity</th><th>Count</th></tr>
            <tr><td><span class="severity-critical">Critical</span></td><td>$($report.Summary.CriticalCount)</td></tr>
            <tr><td><span class="severity-high">High</span></td><td>$($report.Summary.HighCount)</td></tr>
            <tr><td><span class="severity-medium">Medium</span></td><td>$($report.Summary.MediumCount)</td></tr>
            <tr><td><span class="severity-low">Low</span></td><td>$($report.Summary.LowCount)</td></tr>
            <tr><td><span class="severity-info">Info</span></td><td>$($report.Summary.InfoCount)</td></tr>
        </table>
        
        <h2>Findings</h2>
        <table>
            <tr><th>Severity</th><th>Title</th><th>Category</th><th>Remediation</th></tr>
"@
    
    foreach ($finding in $report.Findings) {
        $html += @"
            <tr>
                <td><span class="severity-$($finding.Severity.ToLower())">$($finding.Severity)</span></td>
                <td>$($finding.Title)</td>
                <td>$($finding.Category)</td>
                <td>$($finding.Remediation)</td>
            </tr>
"@
    }
    
    $html += @"
        </table>
        
        <h2>Recommendations</h2>
"@
    
    foreach ($rec in $report.Recommendations) {
        $html += @"
        <div class="recommendation">
            <strong>[$($rec.Priority)] $($rec.Category)</strong><br>
            $($rec.Action): $($rec.Details)
        </div>
"@
    }
    
    $html += @"
        <div class="footer">
            <p>Generated: $($report.Timestamp)</p>
            <p>Version: $($report.Version)</p>
            <p>This is a lite health assessment. For comprehensive analysis, consider IdentityHealthCheck.</p>
        </div>
    </div>
</body>
</html>
"@
    
    $html | Set-Content -Path $Path -Encoding UTF8
    Write-HealthLog -Message "HTML report: $Path" -Level Success
}

# ============================================================================
# Main Execution
# ============================================================================

function Main {
    Write-Output ""
    Write-Output "╔════════════════════════════════════════════════════════════════════════╗"
    Write-Output "║  IdentityFirst QuickChecks - Health Assessment (Lite)                 ║"
    Write-Output "║  Version $script:Version                                                           ║"
    Write-Output "╚════════════════════════════════════════════════════════════════════════╝"
    Write-Output ""
    
    # Initialize collections
    $script:Findings = @()
    $script:FindingsBySeverity = @{
        Critical = 0
        High = 0
        Medium = 0
        Low = 0
        Info = 0
    }
    
    # Create output directory
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
    Write-HealthLog -Message "Output directory: $OutputDir" -Level Info
    
    # Run all checks
    Write-Output ""
    Write-Output "════════════════════════════════════════════════════════════════════════"
    Write-Output " Running QuickChecks "
    Write-Output "════════════════════════════════════════════════════════════════════════"
    Write-Output ""
    
    Invoke-AllChecks
    
    # Calculate health
    Write-Output ""
    Write-Output "════════════════════════════════════════════════════════════════════════"
    Write-Output " Calculating Health Score "
    Write-Output "════════════════════════════════════════════════════════════════════════"
    Write-Output ""
    
    Calculate-HealthScore
    Determine-HealthStatus
    
    # Generate reports
    Write-Output ""
    Write-Output "════════════════════════════════════════════════════════════════════════"
    Write-Output " Generating Reports "
    Write-Output "════════════════════════════════════════════════════════════════════════"
    Write-Output ""
    
    $timestamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    
    if ($OutputFormat -eq 'JSON' -or $OutputFormat -eq 'All') {
        Export-JSONReport -Path (Join-Path $OutputDir "QuickChecks-Health-$timestamp.json")
    }
    
    if ($OutputFormat -eq 'HTML' -or $OutputFormat -eq 'All') {
        Export-HTMLReport -Path (Join-Path $OutputDir "QuickChecks-Health-$timestamp.html")
    }
    
    # Console summary
    Write-Output ""
    Write-Output "════════════════════════════════════════════════════════════════════════"
    Write-Output " Health Assessment Summary "
    Write-Output "════════════════════════════════════════════════════════════════════════"
    Write-Output ""
    
    $statusColor = switch ($script:HealthStatus) {
        'Critical' { 'Red' }
        'Warning'  { 'Yellow' }
        'Healthy'  { 'Green' }
        default    { 'White' }
    }
    
    Write-Host "  Overall Score: " -NoNewline
    Write-Host "$script:OverallScore/100" -ForegroundColor $statusColor
    Write-Host "  Status: " -NoNewline
    Write-Host $script:HealthStatus -ForegroundColor $statusColor
    Write-Host ""
    Write-Host "  Findings:"
    Write-Host "    Critical: " -NoNewline; Write-Host $script:FindingsBySeverity['Critical'] -ForegroundColor Red
    Write-Host "    High:     " -NoNewline; Write-Host $script:FindingsBySeverity['High'] -ForegroundColor DarkRed
    Write-Host "    Medium:   " -NoNewline; Write-Host $script:FindingsBySeverity['Medium'] -ForegroundColor Yellow
    Write-Host "    Low:      " -NoNewline; Write-Host $script:FindingsBySeverity['Low'] -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Reports saved to: $OutputDir" -ForegroundColor Gray
    Write-Output ""
    
    # Actionable recommendations
    $recommendations = Get-Recommendations
    if ($recommendations.Count -gt 0) {
        Write-Output "════════════════════════════════════════════════════════════════════════"
        Write-Output " Recommended Actions "
        Write-Output "════════════════════════════════════════════════════════════════════════"
        Write-Output ""
        
        foreach ($rec in $recommendations) {
            $recColor = switch ($rec.Priority) {
                'P0' { 'Red' }
                'P1' { 'Yellow' }
                default { 'White' }
            }
            Write-Host "  [$($rec.Priority)] " -ForegroundColor $recColor -NoNewline
            Write-Host $rec.Category -NoNewline
            Write-Host ": $($rec.Action)"
            Write-Host "    → $($rec.Details)"
            Write-Output ""
        }
    }
    else {
        Write-Host "  ✓ No immediate action required" -ForegroundColor Green
        Write-Output ""
    }
    
    # Exit with appropriate code
    Write-Output "════════════════════════════════════════════════════════════════════════"
    
    $exitCode = switch ($script:HealthStatus) {
        'Healthy' { 0 }
        'Warning' { 1 }
        'Critical' { 2 }
        default { 3 }
    }
    
    Write-Output " Exit Code: $exitCode"
    Write-Output "════════════════════════════════════════════════════════════════════════"
    
    exit $exitCode
}

# Run
Main

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD32TSrjDSrNWNi
# lc8DE6WEnDafwWKlHN5i6kIvGJkxx6CCFlIwggMUMIIB/KADAgECAhBDR0HvMFNE
# lkJ70azsYRwnMA0GCSqGSIb3DQEBCwUAMCIxIDAeBgNVBAMMF0lkZW50aXR5Rmly
# c3QgQ29kZSBTaWduMB4XDTI2MDIwNDE2NDE0OFoXDTI3MDIwNDE3MDE0OFowIjEg
# MB4GA1UEAwwXSWRlbnRpdHlGaXJzdCBDb2RlIFNpZ24wggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQDWJrlUCUN9yoS4qyJUFIIrjVVnfoFqTXwze3ijNE5q
# wUAAiypU86tc6ct9/wQ9Q9qOn6gjKU3vDhq8XojyQhi/q0ffxG1pP8bHfCQtrMFc
# kTOKLZRgQO73caKFxunCuRdAGxdDxy94NNjwITySkaaLFb3gULH1wbfmu5l2v9ga
# CgpRJGoofRbYbjBS5B7TTNVXlyxl5I3toq9cYRwauWq0Fqj2h6gZ/8izDVU6nMGX
# k+ZfsQwTsVSxfiiWHozhjU7Rt8ckxfVt1YLyPamewESLxw4ijFgHYZUrxNtbm2DP
# QUUG4ekzdDQlBLBzjdIJh8hIz+gcqvyXIQpoFjF2xyoFAgMBAAGjRjBEMA4GA1Ud
# DwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQU0LvUry7V
# 3WlfTmidD6yCOpbcmSQwDQYJKoZIhvcNAQELBQADggEBAAWDzEqYgCCQHZwHCMlU
# ob2Jkqcbk6GYylmfTwW9EQ7iJjyKHFJlbUGuDJxClDwDteBCVpxhfbi0fJjkib8r
# b4Fbk9Rex5rJxEMidBYbnASWnLuJD7dsHbwf6N4SM/LsYhiEtllGb0UsKET6PyuO
# f1sYdDY+UcTssCzDAElCrlVIl4Z4/JBlXOhInMD7AnP6Xx2r4hCAVEWhHtJ+ahY/
# bFAJ7v+EsTET2Pa34kiymxJ7yYRNSxwxyb1umUx/Q6pui0lYjyNXt8AAg4A0ybyj
# ABLNYct6zilczJ6JqPCBJLL0ZbCDpg8SkmAn3G3Y+bSztlOIUo4eXpjXV1DE7oB/
# kuAwggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUA
# MGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsT
# EHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQg
# Um9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqcl
# LskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YF
# PFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceIt
# DBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZX
# V59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1
# ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2Tox
# RJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdp
# ekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF
# 30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9
# t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQ
# UOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXk
# aS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud
# DgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEt
# UYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsG
# AQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0
# dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RD
# QS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAw
# DQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72arKGHLOyF
# XqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFIDyE7QKt76
# LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8L
# punyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2
# CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si
# /xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQwgga0MIIEnKADAgEC
# AhANx6xXBf8hmS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcw
# MDAwMDBaFw0zODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1l
# U3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZ
# loMsVO1DahGPNRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM
# 2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj
# 7GH8BLuxBG5AvftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQ
# Sku2Ws3IfDReb6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZ
# lDwFt+cVFBURJg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+
# 8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRx
# ykvq6gbylsXQskBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yG
# OP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqI
# MRvUBDx6z1ev+7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm
# 1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBj
# UwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729T
# SunkBnx6yuKQVvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4c
# D08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUF
# BwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEG
# CCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAX
# MAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaA
# HP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQ
# M2qEJPe36zwbSI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt
# 6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7
# bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmS
# Nq1UH410ANVko43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69
# M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnF
# RsjsYg39OlV8cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmM
# Thi0vw9vODRzW6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oa
# Qf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx
# 9yHbxtl5TPau1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3
# /BAPvIXKUjPSxyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN
# 8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQg
# VGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAw
# MDAwMFoXDTM2MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBU
# aW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx
# +wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvN
# Zh6wW2R6kSu9RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlL
# nh00Cll8pjrUcCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmn
# cOOMA3CoB/iUSROUINDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5KqCvpSduSwhw
# UmotuQhcg9tw2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL
# 4Q1OpbybpMe46YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdoRORVbPR1VVnD
# uSeHVZlc4seAO+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCy
# FG1roSrgHjSHlq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7rlRyTlaCCfw7a
# SUROwnu7zER6EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K096V1hE0yZIXe+gi
# AwW00aHzrDchIc2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGj
# ggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39/dfzkXFjGVBD
# z2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8E
# BAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGF
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUH
# MAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRH
# NFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBW
# MFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVk
# RzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkw
# FzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3x
# HCcEua5gQezRCESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh
# 8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim8/9yJmZS
# e2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUqW4daIqToXFE/
# JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMnxYOX8VBRKe1u
# NnzQVTeLni2nHkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq
# 8/gVutDojBIFeRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AWcIQfVjnzrvwi
# CZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJgddJ35XTxfUlQ
# +8Hggt8l2Yv7roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1
# R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVccAvlKV9jEnstr
# niLvUxxVZE/rptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8atufk+EMF/cWu
# iC7POGT75qaL6vdCvHlshtjdNXOCIUjsarfNZzGCBRIwggUOAgEBMDYwIjEgMB4G
# A1UEAwwXSWRlbnRpdHlGaXJzdCBDb2RlIFNpZ24CEENHQe8wU0SWQnvRrOxhHCcw
# DQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkq
# hkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGC
# NwIBFTAvBgkqhkiG9w0BCQQxIgQg1ukHDrHB8Os38BoaJivo3YO49hLVqQinV2Pd
# 2DDstMUwDQYJKoZIhvcNAQEBBQAEggEAUce7beMlrTOzefRMiQivNs3c9K4lBDK4
# rmRnTSshvPk0VNQZ3rslfZjJEDw2ykfyKL6l3jfWGNKhLxzqvHwL9RJs4jFSxxhz
# gxLCdHRSVlR6a96phnGTaQ6ExfpJI14Q+WxtJBD+QIXuinmGP9ED9T8HPbbNkMSD
# ppHM3Iok9JqyMWm94pFGBt6irfp20+WpSJU0/AFE0laz4175r+21SRsX3lBnZAz2
# UBNujKvoDF/eZhBemgCRnvAg80NMcj5g9cWa7Ms1TxjZTNk55MFR4BjYf735kpuJ
# 8X0J0WBf9CjUO/ET07gfU8uiEfdSKb5lRMaDLGh382tWGSLno7JYlKGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjAyMDQxNjUyMDhaMC8GCSqGSIb3DQEJBDEiBCBV
# TAywJa1kpuFZqIYG9Ec2fvQjcEvRVnBGQX/SP3XybTANBgkqhkiG9w0BAQEFAASC
# AgADVDYJE81mqCzh+K4sztlL6Hm4+glmMlABoY47AYYc0HT7qDjjWN56zrx9vcCA
# GTon7dQA/EuWBC57N5qW75kIlyImY/SnulQiudoJYL9n8gUVpqIwG5ooQjYV10yE
# Fyh7B9omtiExo77QbS3R40nFuCUKGFgVhdLo3qEhKaJ3uuGe854ThQrSvN9IbfOf
# 0/A+QbgDfVyrqX/TytRCGXdvgJcutU+6pMDGndiSF2N2AOw+4sr+P43Z56i1/IQF
# /rhmXdV6RvY9JP3glESDDjgGTeVeQuZAo3PczzM1u7vVPD+9BkbYzo3d0clVnbf5
# p5yjlxBwEgBvWeLloW3RbagbdJQmtJmRptVicyWbBfcYwNibGFCdP1d4ejFKb605
# y9tbtTvwRoZoNPvUWO4M/jR2XpdF/5hEgV1r3leypysc5q+P5dlv5Z/dNr5iyjUu
# 7076BdG+kuV8sD642lWpFkkPZuEdL23wHTGU+8jTafnftpLc0lI6QEYqPmO2QTrW
# 8sycsRJRzpv5Zuib646t1m8854PHGgIRnS7vyYZWyBdLUAUnGvRpQXhw5pGCnahU
# ANGo4rthMeQNJl8HoFeGStx8foA2DCqL+BPSJqxbvpaFM/JIpykJoi2flJ7EgJhw
# 8qGlAY989nc+Ba+WnnJ8JPI4Xu82Gx318Lor3llVzLELiA==
# SIG # End signature block
