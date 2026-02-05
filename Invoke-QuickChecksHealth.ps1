# ============================================================================
# ATTRIBUTION
# ============================================================================
# Author: Mark Ahearne
# Email: mark.ahearne@identityfirst.net
# Company: IdentityFirst Ltd
#
# This script is provided by IdentityFirst Ltd for identity security assessment.
# All rights reserved.
#
# License: See EULA.txt for license terms.
# ============================================================================
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

