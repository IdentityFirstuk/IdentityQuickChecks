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
    Checks for Kerberos misconfigurations and security issues.

.DESCRIPTION
    Identifies common Kerberos misconfigurations including:
    - Duplicate SPNs
    - Kerberoastable accounts
    - Constrained delegation issues
    - Unconstrained delegation
    - Resource-based constrained delegation

.OUTPUTS
    - JSON report
    - HTML report
    - Log file

.NOTES
    Author: IdentityFirst Ltd
    Safety: Read-only. No changes are made.
    Requirements: ActiveDirectory module
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path $PWD "IFQC-Output"),

    [Parameter()]
    [ValidateSet("Normal","Detailed")]
    [string]$DetailLevel = "Normal"
)

$modulePath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $modulePath "Module\IdentityFirst.QuickChecks.psm1") -Force

$ctx = New-IFQCContext -ToolName "KerberosReality" -OutputDirectory $OutputDirectory -DetailLevel $DetailLevel
Add-IFQCNote -Context $ctx -Note "Kerberos assessment requires ActiveDirectory module."
Add-IFQCNote -Context $ctx -Note "Full attack path analysis available in IdentityHealthCheck."

Invoke-IFQCSafe -Context $ctx -Name "Kerberos Security Assessment" -Block {
    # Check if AD module is available
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
        throw "ActiveDirectory module not available"
    }

    Import-Module ActiveDirectory -ErrorAction Stop

    $domain = Get-ADDomain -ErrorAction SilentlyContinue
    if (-not $domain) {
        throw "Could not retrieve domain information"
    }
    $ctx.Data.domain = $domain.DnsRoot

    $evidenceLimit = if ($DetailLevel -eq "Detailed") { 100 } else { 30 }
    $findings = @()

    # =========================================================================
    # Check 1: Duplicate SPNs (Kerberoast target)
    # =========================================================================
    Write-Host "[INFO] Checking for duplicate SPNs..." -ForegroundColor Gray
    try {
        # Get all user accounts with SPN set
        $spnUsers = Get-ADUser -Filter { ServicePrincipalName -like '*' } `
            -Properties ServicePrincipalName, Name, SamAccountName, DistinguishedName `
            -ErrorAction SilentlyContinue

        $spnCounts = @{}
        foreach ($user in $spnUsers) {
            foreach ($spn in $user.ServicePrincipalName) {
                $spnCounts[$spn] = @($spnCounts[$spn] ?? @()) + $user.DistinguishedName
            }
        }

        $duplicateSpns = $spnCounts.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 }

        if ($duplicateSpns) {
            $dupEvidence = foreach ($dup in $duplicateSpns | Select-Object -First $evidenceLimit) {
                [PSCustomObject]@{
                    SPN = $dup.Key
                    Count = $dup.Value.Count
                }
            }

            $findings += @{
                Id = "KERB-DUPLICATE-SPN"
                Title = "Duplicate Service Principal Names"
                Severity = "High"
                Description = "$($duplicateSpns.Count) SPN(s) are assigned to multiple accounts. This can cause authentication failures."
                Count = $duplicateSpns.Count
                Evidence = $dupEvidence
                Recommendation = "Identify and fix duplicate SPNs. Kerberos authentication may fail for affected services."
            }
        }
    }
    catch {
        Add-IFQCNote -Context $ctx -Note "Could not check duplicate SPNs: $($_.Exception.Message)"
    }

    # =========================================================================
    # Check 2: Kerberoastable accounts
    # =========================================================================
    Write-Host "[INFO] Checking for Kerberoastable accounts..." -ForegroundColor Gray
    try {
        # Accounts with SPN but not requiring pre-auth
        $kerberoastable = Get-ADUser -Filter { (ServicePrincipalName -like '*') -and (DoesNotRequirePreAuth -eq $false) } `
            -Properties ServicePrincipalName, Name, SamAccountName, DistinguishedName, DoesNotRequirePreAuth `
            -ErrorAction SilentlyContinue

        if ($kerberoastable) {
            $krEvidence = foreach ($account in $kerberoastable | Select-Object -First $evidenceLimit) {
                [PSCustomObject]@{
                    Account = $account.SamAccountName
                    SPNs = ($account.ServicePrincipalName -join ', ').Substring(0, 50)
                }
            }

            $findings += @{
                Id = "KERB-KERBEROASTABLE"
                Title = "Accounts Susceptible to Kerberoasting"
                Severity = "High"
                Description = "$($kerberoastable.Count) account(s) have SPNs set but are not configured to require pre-authentication."
                Count = $kerberoastable.Count
                Evidence = $krEvidence
                Recommendation = "Enable 'Do not require Kerberos pre-authentication' should be avoided. Enable UF_DONT_REQUIRE_PREAUTH where possible."
            }
        }
    }
    catch {
        Add-IFQCNote -Context $ctx -Note "Could not check Kerberoastable accounts: $($_.Exception.Message)"
    }

    # =========================================================================
    # Check 3: Unconstrained delegation
    # =========================================================================
    Write-Host "[INFO] Checking for unconstrained delegation..." -ForegroundColor Gray
    try {
        # Accounts with TRUSTED_FOR_DELEGATION
        $unconstrained = Get-ADUser -Filter { TrustedForDelegation -eq $true } `
            -Properties TrustedForDelegation, Name, SamAccountName, DistinguishedName `
            -ErrorAction SilentlyContinue

        # Computers with unconstrained delegation
        $unconstrainedComputers = Get-ADComputer -Filter { TrustedForDelegation -eq $true } `
            -Properties TrustedForDelegation, Name, SamAccountName, DistinguishedName `
            -ErrorAction SilentlyContinue

        $allUnconstrained = @()
        $allUnconstrained += $unconstrained
        $allUnconstrained += $unconstrainedComputers

        if ($allUnconstrained) {
            $unconEvidence = foreach ($obj in $allUnconstrained | Select-Object -First $evidenceLimit) {
                [PSCustomObject]@{
                    Type = if ($obj.ObjectClass -eq 'user') { "User" } else { "Computer" }
                    Name = $obj.SamAccountName
                }
            }

            $findings += @{
                Id = "KERB-UNCONSTRAINED"
                Title = "Unconstrained Delegation Enabled"
                Severity = "High"
                Description = "$($allUnconstrained.Count) account(s)/computer(s) have unconstrained delegation enabled."
                Count = $allUnconstrained.Count
                Evidence = $unconEvidence
                Recommendation = "Avoid unconstrained delegation. Use Constrained Delegation or RBCD instead."
            }
        }
    }
    catch {
        Add-IFQCNote -Context $ctx -Note "Could not check unconstrained delegation: $($_.Exception.Message)"
    }

    # =========================================================================
    # Check 4: Constrained delegation configured
    # =========================================================================
    Write-Host "[INFO] Checking for constrained delegation..." -ForegroundColor Gray
    try {
        # Accounts with msDS-AllowedToDelegateTo - use quotes for hyphenated property
        $constrainedUsers = Get-ADUser -Filter { "msDS-AllowedToDelegateTo" -like '*' } `
            -Properties "msDS-AllowedToDelegateTo", Name, SamAccountName, DistinguishedName `
            -ErrorAction SilentlyContinue

        $constrainedComputers = Get-ADComputer -Filter { "msDS-AllowedToDelegateTo" -like '*' } `
            -Properties "msDS-AllowedToDelegateTo", Name, SamAccountName, DistinguishedName `
            -ErrorAction SilentlyContinue

        $allConstrained = @()
        $allConstrained += $constrainedUsers
        $allConstrained += $constrainedComputers

        if ($allConstrained) {
            $conEvidence = foreach ($obj in $allConstrained | Select-Object -First $evidenceLimit) {
                $delegationValue = if ($null -ne $obj."msDS-AllowedToDelegateTo") {
                    ($obj."msDS-AllowedToDelegateTo" -join ', ').Substring(0, 50)
                } else { "None" }
                [PSCustomObject]@{
                    Type = $obj.ObjectClass
                    Name = $obj.SamAccountName
                    DelegatesTo = $delegationValue
                }
            }

            $findings += @{
                Id = "KERB-CONSTRAINED"
                Title = "Constrained Delegation Configured"
                Severity = "Medium"
                Description = "$($allConstrained.Count) account(s) have constrained delegation configured."
                Count = $allConstrained.Count
                Evidence = $conEvidence
                Recommendation = "Review delegation targets. Ensure only necessary services are allowed."
            }
        }
    }
    catch {
        Add-IFQCNote -Context $ctx -Note "Could not check constrained delegation: $($_.Exception.Message)"
    }

    # =========================================================================
    # Check 5: Resource-based constrained delegation (RBCD)
    # =========================================================================
    Write-Host "[INFO] Checking for RBCD..." -ForegroundColor Gray
    try {
        # msDS-AllowedToActOnBehalfOfOtherIdentity
        $rbcdUsers = Get-ADUser -Filter { "msDS-AllowedToActOnBehalfOfOtherIdentity" -like '*' } `
            -Properties "msDS-AllowedToActOnBehalfOfOtherIdentity", Name, SamAccountName `
            -ErrorAction SilentlyContinue

        $rbcdComputers = Get-ADComputer -Filter { "msDS-AllowedToActOnBehalfOfOtherIdentity" -like '*' } `
            -Properties "msDS-AllowedToActOnBehalfOfOtherIdentity", Name, SamAccountName `
            -ErrorAction SilentlyContinue

        $allRbcd = @()
        $allRbcd += $rbcdUsers
        $allRbcd += $rbcdComputers

        if ($allRbcd) {
            $rbcdEvidence = foreach ($obj in $allRbcd | Select-Object -First $evidenceLimit) {
                [PSCustomObject]@{
                    Type = $obj.ObjectClass
                    Name = $obj.SamAccountName
                    RBCD = "Configured"
                }
            }

            $findings += @{
                Id = "KERB-RBCD"
                Title = "Resource-Based Constrained Delegation Configured"
                Severity = "Medium"
                Description = "$($allRbcd.Count) account(s)/computer(s) have RBCD configured."
                Count = $allRbcd.Count
                Evidence = $rbcdEvidence
                Recommendation = "Review RBCD assignments. Attackers can abuse this for privilege escalation."
            }
        }
    }
    catch {
        Add-IFQCNote -Context $ctx -Note "Could not check RBCD: $($_.Exception.Message)"
    }

    # =========================================================================
    # Check 6: Pre-auth not required (AS-REP roasting)
    # =========================================================================
    Write-Host "[INFO] Checking for AS-REP roastable accounts..." -ForegroundColor Gray
    try {
        $asrepRoastable = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } `
            -Properties DoesNotRequirePreAuth, Name, SamAccountName, DistinguishedName `
            -ErrorAction SilentlyContinue

        if ($asrepRoastable) {
            $asrepEvidence = foreach ($account in $asrepRoastable | Select-Object -First $evidenceLimit) {
                [PSCustomObject]@{
                    Account = $account.SamAccountName
                    Enabled = $account.Enabled
                }
            }

            $findings += @{
                Id = "KERB-ASREP-ROAST"
                Title = "Accounts Vulnerable to AS-REP Roasting"
                Severity = "High"
                Description = "$($asrepRoastable.Count) account(s) have 'Do not require Kerberos pre-authentication' enabled."
                Count = $asrepRoastable.Count
                Evidence = $asrepEvidence
                Recommendation = "AS-REP roasting extracts account hashes. Only enable this setting when absolutely required."
            }
        }
    }
    catch {
        Add-IFQCNote -Context $ctx -Note "Could not check AS-REP roasting: $($_.Exception.Message)"
    }

    # =========================================================================
    # Output findings
    # =========================================================================
    foreach ($finding in $findings) {
        Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
            -Id $finding.Id `
            -Title $finding.Title `
            -Severity $finding.Severity `
            -Description $finding.Description `
            -Count $finding.Count `
            -Evidence $finding.Evidence `
            -Recommendation $finding.Recommendation
        )
    }
}

$output = Save-IFQCReport -Context $ctx

# Emit structured report saved event
$reportEvent = [PSCustomObject]@{
    Timestamp = (Get-Date).ToString('o')
    Level = 'Info'
    Action = 'ReportSaved'
    Tool = $ctx.ToolName
    Json = $output.Json
    Html = $output.Html
}
Write-IFQC -InputObject $reportEvent
