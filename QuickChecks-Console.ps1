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
    IdentityFirst QuickChecks - Guided Console Experience

.DESCRIPTION
    Interactive console experience for running QuickChecks with:
    - Beautiful welcome screen
    - Connection testing with live feedback
    - Auto-detect domain
    - Guided 4-step process
    - Automatic first assessment

.NOTES
    Author: mark.ahearne@identityfirst.net | Owner: IdentityFirst Ltd
    Requirements: PowerShell 5.1+
#>

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$AutoRun,

    [Parameter()]
    [switch]$Help
)

if ($Help) {
    Write-Output @"
IdentityFirst QuickChecks - Guided Console
===========================================

Interactive console for running identity posture checks.

USAGE:
  .\\QuickChecks-Console.ps1           # Interactive guided experience
  .\\QuickChecks-Console.ps1 -AutoRun  # Run without prompts

FEATURES:
  ✓ Welcome screen with branding
  ✓ Connection testing with live feedback
  ✓ Auto-detect domain
  ✓ Guided 4-step process
  ✓ Automatic first assessment

"@
    exit 0
}

