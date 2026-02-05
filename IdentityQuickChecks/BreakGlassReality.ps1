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
param(
    [string]$OutputPath = "."
)

$ErrorActionPreference = "Stop"

<#
.SYNOPSIS
    Find break-glass accounts and check their posture.

.DESCRIPTION
    Searches for accounts named or described as break-glass,
    emergency, or firecall accounts. Reports on their posture
    including password never expires, last logon, and risk factors.

.NOTES
    - Read-only: YES
    - Requires: ActiveDirectory module (RSAT)
    - Permissions: Domain Admin recommended

.EXAMPLE
    .\BreakGlassReality.ps1

.EXAMPLE
    # As module command
    Invoke-BreakGlassReality -OutputPath ".\Reports"
#>

