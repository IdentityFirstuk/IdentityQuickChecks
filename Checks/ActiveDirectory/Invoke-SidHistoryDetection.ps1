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
    Checks for SID History security issues.

.DESCRIPTION
    Identifies SID History attributes which can indicate:
    - Privilege migration paths
    - Cross-forest trust abuse potential
    - Legacy account access persistence

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

$ctx = New-IFQCContext -ToolName "SidHistoryDetection" -OutputDirectory $OutputDirectory -DetailLevel $DetailLevel
Add-IFQCNote -Context $ctx -Note "SID History assessment requires ActiveDirectory module."
Add-IFQCNote -Context $ctx -Note "Full SID History analysis available in IdentityHealthCheck."

Invoke-IFQCSafe -Context $ctx -Name "SID History Security Assessment" -Block {
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
    # Check 1: Users with SID History
    # =========================================================================
    Write-Host "[INFO] Checking for SID History on users..." -ForegroundColor Gray
    try {
        # SID History stored inSIDHistory attribute
        $usersWithSidHistory = Get-ADUser -Filter { SIDHistory -like '*' } `
            -Properties SIDHistory, Name, SamAccountName, DistinguishedName `
            -ErrorAction SilentlyContinue

        if ($usersWithSidHistory) {
            $userEvidence = foreach ($user in $usersWithSidHistory | Select-Object -First $evidenceLimit) {
                $sidCount = if ($user.SIDHistory) { $user.SIDHistory.Count } else { 0 }
                [PSCustomObject]@{
                    Account = $user.SamAccountName
                    SIDHistoryCount = $sidCount
                    SIDs = ($user.SIDHistory | Select-Object -First 3) -join ', '
                }
            }

            $findings += @{
                Id = "SIDHIST-USERS"
                Title = "Users with SID History"
                Severity = "High"
                Description = "$($usersWithSidHistory.Count) user account(s) have SID History populated."
                Count = $usersWithSidHistory.Count
                Evidence = $userEvidence
                Recommendation = "Review SID History. Remove if not needed for migrations. Can indicate persistence mechanisms."
            }
        }
        else {
            $findings += @{
                Id = "SIDHIST-NONE-USERS"
                Title = "No Users with SID History Found"
                Severity = "Low"
                Description = "No user accounts with SID History were found."
                Count = 0
                Evidence = @(@{ Note = "Clean environment" })
                Recommendation = "No action needed."
            }
        }
    }
    catch {
        Add-IFQCNote -Context $ctx -Note "Could not check user SID History: $($_.Exception.Message)"
    }

    # =========================================================================
    # Check 2: Computers with SID History
    # =========================================================================
    Write-Host "[INFO] Checking for SID History on computers..." -ForegroundColor Gray
    try {
        $computersWithSidHistory = Get-ADComputer -Filter { SIDHistory -like '*' } `
            -Properties SIDHistory, Name, SamAccountName, DistinguishedName `
            -ErrorAction SilentlyContinue

        if ($computersWithSidHistory) {
            $computerEvidence = foreach ($comp in $computersWithSidHistory | Select-Object -First $evidenceLimit) {
                $sidCount = if ($comp.SIDHistory) { $comp.SIDHistory.Count } else { 0 }
                [PSCustomObject]@{
                    Computer = $comp.SamAccountName
                    SIDHistoryCount = $sidCount
                }
            }

            $findings += @{
                Id = "SIDHIST-COMPUTERS"
                Title = "Computers with SID History"
                Severity = "High"
                Description = "$($computersWithSidHistory.Count) computer account(s) have SID History populated."
                Count = $computersWithSidHistory.Count
                Evidence = $computerEvidence
                Recommendation = "Computer SID History is rare. Investigate - may indicate trust compromise."
            }
        }
    }
    catch {
        Add-IFQCNote -Context $ctx -Note "Could not check computer SID History: $($_.Exception.Message)"
    }

    # =========================================================================
    # Check 3: SID History with Enterprise Admins or Domain Admins SIDs
    # =========================================================================
    Write-Host "[INFO] Checking for privileged SID History..." -ForegroundColor Gray
    try {
        # Get well-known privileged SIDs for this domain
        $domainSid = $domain.DomainSID
        $eaSid = "$domainSid-519"  # Enterprise Admins
        $daSid = "$domainSid-512"  # Domain Admins
        $adminSid = "$domainSid-544"  # Administrators

        $privilegedSidHistory = Get-ADUser -Filter { SIDHistory -like '*' } `
            -Properties SIDHistory, Name, SamAccountName `
            -ErrorAction SilentlyContinue

        $dangerousAssignments = @()
        foreach ($user in $privilegedSidHistory) {
            foreach ($sid in $user.SIDHistory) {
                if ($sid -eq $eaSid -or $sid -eq $daSid) {
                    $dangerousAssignments += [PSCustomObject]@{
                        Account = $user.SamAccountName
                        DangerousSID = $sid
                        SIDType = if ($sid -eq $eaSid) { "Enterprise Admins" } else { "Domain Admins" }
                    }
                }
            }
        }

        if ($dangerousAssignments) {
            $findings += @{
                Id = "SIDHIST-PRIVILEGED"
                Title = "SID History Assigning Domain/Enterprise Admin"
                Severity = "Critical"
                Description = "$($dangerousAssignments.Count) account(s) have SID History pointing to privileged groups."
                Count = $dangerousAssignments.Count
                Evidence = $dangerousAssignments | Select-Object -First $evidenceLimit
                Recommendation = "CRITICAL: Remove SID History immediately. Indicates potential privilege persistence."
            }
        }
    }
    catch {
        Add-IFQCNote -Context $ctx -Note "Could not check privileged SID History: $($_.Exception.Message)"
    }

    # =========================================================================
    # Check 4: Cross-forest SID History (foreign SIDs)
    # =========================================================================
    Write-Host "[INFO] Checking for cross-forest SID History..." -ForegroundColor Gray
    try {
        $allSidHistory = Get-ADUser -Filter { SIDHistory -like '*' } `
            -Properties SIDHistory, Name, SamAccountName `
            -ErrorAction SilentlyContinue

        $crossForestSids = @()
        foreach ($user in $allSidHistory) {
            foreach ($sid in $user.SIDHistory) {
                # Check if SID is from a different domain (not matching current domain SID)
                if ($sid -notlike "$($domain.DomainSid)*" -and $sid.Length -gt 15) {
                    $crossForestSids += [PSCustomObject]@{
                        Account = $user.SamAccountName
                        ForeignSID = $sid
                    }
                }
            }
        }

        if ($crossForestSids) {
            $findings += @{
                Id = "SIDHIST-CROSS-FOREST"
                Title = "Cross-Forest SID History Detected"
                Severity = "High"
                Description = "$($crossForestSids.Count) account(s) have SID History from other domains/forests."
                Count = $crossForestSids.Count
                Evidence = $crossForestSids | Select-Object -First $evidenceLimit
                Recommendation = "Review cross-forest SID History. Ensure trust relationships are appropriate."
            }
        }
    }
    catch {
        Add-IFQCNote -Context $ctx -Note "Could not check cross-forest SID History: $($_.Exception.Message)"
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
