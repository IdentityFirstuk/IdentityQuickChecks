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
Write-Host "  Identity Review Debt Check"
Write-Host "========================================================================"

<#
.SYNOPSIS
    Find privileged access that hasn't been reviewed in years.

.DESCRIPTION
    Identifies accounts and group memberships that have remained unchanged
    for extended periods, potentially representing "review debt" where
    access hasn't been validated against current needs.

.NOTES
    - Read-only: YES
    - Requires: ActiveDirectory module (RSAT)
    - Permissions: Domain Admin recommended

.EXAMPLE
    .\IdentityReviewDebt.ps1
#>

# Initialize tracking variables
$reviewDebt = @()
$recentReviews = @()
$errors = @()
$processedCount = 0

Write-Host ""
Write-Host "  Analyzing identity review debt..." -ForegroundColor Gray

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "  ActiveDirectory module loaded" -ForegroundColor Green
}
catch {
    Write-Host "  ERROR: ActiveDirectory module not available" -ForegroundColor Red
    exit 1
}

# Define thresholds
$Thresholds = @{
    NoLogonWarning = 180    # Days without logon
    NoLogonCritical = 365   # Days without logon (highly suspicious)
    PasswordNeverChanged = 365  # Days with same password
    GroupMembershipOld = 730     # Days in same privileged group
}

