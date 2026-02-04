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
