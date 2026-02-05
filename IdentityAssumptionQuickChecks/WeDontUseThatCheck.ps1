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
param([string]$OutputPath = ".")

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================================================"
Write-Host "  'We Don't Use That' Reality Check"
Write-Host "========================================================================"

<#
.SYNOPSIS
    Verify that features marked as 'not in use' are actually disabled.

.DESCRIPTION
    Many organizations assume certain features aren't used (e.g., 
    "We don't use basic auth", "We don't have external sharing").
    This check verifies these assumptions against actual configuration.

.NOTES
    - Read-only: YES
    - Requires: ActiveDirectory module (RSAT), Microsoft.Graph
    - Permissions: Domain Admin recommended

.EXAMPLE
    .\WeDontUseThatCheck.ps1
#>

# Initialize tracking variables
$assumptionsVerified = @()
$assumptionsBroken = @()
$errors = @()
$processedCount = 0

Write-Host ""
Write-Host "  Verifying commonly held assumptions..." -ForegroundColor Gray

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "  ActiveDirectory module loaded" -ForegroundColor Green
}
catch {
    Write-Host "  ERROR: ActiveDirectory module not available" -ForegroundColor Red
    Write-Host "  This check requires RSAT for AD queries" -ForegroundColor Yellow
    exit 1
}

# Check for Microsoft.Graph (optional)
$graphAvailable = $false
try {
    Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop | Out-Null
    $graphAvailable = $true
    Write-Host "  Microsoft.Graph module loaded" -ForegroundColor Green
}
catch {
    Write-Host "  Microsoft.Graph not available (cloud checks skipped)" -ForegroundColor Yellow
}

