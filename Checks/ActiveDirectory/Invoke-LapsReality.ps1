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
    Checks for LAPS deployment status and security.

.DESCRIPTION
    Identifies LAPS deployment status including:
    - Computers with LAPS installed
    - Computers missing LAPS (local admin exposure)
    - LAPS password expiration status
    - Local admin account visibility

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

$ctx = New-IFQCContext -ToolName "LapsReality" -OutputDirectory $OutputDirectory -DetailLevel $DetailLevel
Add-IFQCNote -Context $ctx -Note "LAPS assessment requires ActiveDirectory module."
Add-IFQCNote -Context $ctx -Note "Full LAPS reporting available in IdentityHealthCheck."

Invoke-IFQCSafe -Context $ctx -Name "LAPS Deployment Assessment" -Block {
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
    # Check 1: Computers with LAPS attributes
    # =========================================================================
    Write-Host "[INFO] Checking LAPS deployment..." -ForegroundColor Gray
    try {
        # LAPS stores expiration time in ms-MCS-AdmPwdExpirationTime
        $lapsComputers = Get-ADComputer -Filter { "ms-MCS-AdmPwdExpirationTime" -like '*' } `
            -Properties "ms-MCS-AdmPwdExpirationTime", Name, SamAccountName, DistinguishedName `
            -ErrorAction SilentlyContinue

        if ($lapsComputers) {
            $lapsEvidence = foreach ($comp in $lapsComputers | Select-Object -First $evidenceLimit) {
                $expTime = if ($comp."ms-MCS-AdmPwdExpirationTime") {
                    [DateTime]::FromFileTime($comp."ms-MCS-AdmPwdExpirationTime").ToString('yyyy-MM-dd HH:mm')
                } else { "Unknown" }
                [PSCustomObject]@{
                    Computer = $comp.SamAccountName
                    PasswordExpires = $expTime
                }
            }

            $findings += @{
                Id = "LAPS-DEPLOYED"
                Title = "LAPS Deployed Computers"
                Severity = "Low"
                Description = "$($lapsComputers.Count) computer(s) have LAPS attributes, indicating LAPS is deployed."
                Count = $lapsComputers.Count
                Evidence = $lapsEvidence
                Recommendation = "LAPS is deployed. Regular password rotation is active."
            }
        }
        else {
            $findings += @{
                Id = "LAPS-NOT-FOUND"
                Title = "No LAPS-Enabled Computers Found"
                Severity = "High"
                Description = "No computers with LAPS attributes were found in the domain."
                Count = 0
                Evidence = @(@{ Note = "LAPS may not be deployed or no computers have registered yet" })
                Recommendation = "Deploy LAPS to all workstations and servers. Consider IdentityHealthCheck for comprehensive inventory."
            }
        }
    }
    catch {
        Add-IFQCNote -Context $ctx -Note "Could not check LAPS deployment: $($_.Exception.Message)"
    }

    # =========================================================================
    # Check 2: Computers without LAPS (potential exposure)
    # =========================================================================
    Write-Host "[INFO] Checking for computers without LAPS..." -ForegroundColor Gray
    try {
        # Get all computers and filter for those without LAPS
        $allComputers = Get-ADComputer -Filter * `
            -Properties Name, SamAccountName, DistinguishedName `
            -ErrorAction SilentlyContinue

        if ($allComputers) {
            $nonLapsComputers = @()
            foreach ($comp in $allComputers) {
                # Check if the computer has the LAPS expiration attribute
                $hasLaps = $false
                try {
                    $lapsAttr = Get-ADObject -Identity $comp.DistinguishedName `
                        -Properties "ms-MCS-AdmPwdExpirationTime" `
                        -ErrorAction SilentlyContinue
                    if ($lapsAttr -and $lapsAttr."ms-MCS-AdmPwdExpirationTime") {
                        $hasLaps = $true
                    }
                }
                catch {
                    # Attribute not present
                }

                if (-not $hasLaps) {
                    $nonLapsComputers += $comp
                    if ($nonLapsComputers.Count -ge $evidenceLimit) { break }
                }
            }

            if ($nonLapsComputers) {
                $nonLapsEvidence = $nonLapsComputers | Select-Object -First $evidenceLimit @{
                    Name = "Computer"; Expression = { $_.SamAccountName }
                }, @{
                    Name = "Status"; Expression = { "No LAPS Attribute" }
                }

                $findings += @{
                    Id = "LAPS-NOT-DEPLOYED"
                    Title = "Computers Without LAPS"
                    Severity = "High"
                    Description = "$($nonLapsComputers.Count) computer(s) do not have LAPS attributes. Local admin passwords may be static."
                    Count = $nonLapsComputers.Count
                    Evidence = $nonLapsEvidence
                    Recommendation = "Deploy LAPS to these computers. Local admin passwords should be rotated regularly."
                }
            }
        }
    }
    catch {
        Add-IFQCNote -Context $ctx -Note "Could not check non-LAPS computers: $($_.Exception.Message)"
    }

    # =========================================================================
    # Check 3: LAPS password expiration status
    # =========================================================================
    Write-Host "[INFO] Checking LAPS password expiration..." -ForegroundColor Gray
    try {
        $lapsComputers = Get-ADComputer -Filter { "ms-MCS-AdmPwdExpirationTime" -like '*' } `
            -Properties "ms-MCS-AdmPwdExpirationTime", Name, SamAccountName `
            -ErrorAction SilentlyContinue

        if ($lapsComputers) {
            $now = [DateTime]::Now
            $expiringCount = 0
            $expiredCount = 0

            foreach ($comp in $lapsComputers) {
                if ($comp."ms-MCS-AdmPwdExpirationTime") {
                    $expTime = [DateTime]::FromFileTime($comp."ms-MCS-AdmPwdExpirationTime")
                    if ($expTime -lt $now) {
                        $expiredCount++
                    }
                    elseif ($expTime -lt $now.AddDays(7)) {
                        $expiringCount++
                    }
                }
            }

            if ($expiredCount -gt 0 -or $expiringCount -gt 0) {
                $findings += @{
                    Id = "LAPS-EXPIRING"
                    Title = "LAPS Password Expiration Status"
                    Severity = "Medium"
                    Description = "Expired: $expiredCount, Expiring in 7 days: $expiringCount"
                    Count = $expiredCount + $expiringCount
                    Evidence = @(@{ Expired = $expiredCount; ExpiringSoon = $expiringCount })
                    Recommendation = "Investigate computers with expired passwords. May indicate LAPS service issues."
                }
            }
        }
    }
    catch {
        Add-IFQCNote -Context $ctx -Note "Could not check password expiration: $($_.Exception.Message)"
    }

    # =========================================================================
    # Check 4: Check for LAPS schema extension
    # =========================================================================
    Write-Host "[INFO] Checking LAPS schema..." -ForegroundColor Gray
    try {
        # Check if LAPS schema is extended
        $schemaPath = "CN=Schema,CN=Configuration,$($domain.ConfigurationNamingContext)"
        $lapsSchema = Get-ADObject -SearchBase $schemaPath `
            -Filter { Name -like "*AdmPwd*" } `
            -ErrorAction SilentlyContinue

        if ($lapsSchema) {
            $findings += @{
                Id = "LAPS-SCHEMA-EXTENDED"
                Title = "LAPS Schema Extension Present"
                Severity = "Low"
                Description = "LAPS schema attributes are present in the domain."
                Count = 1
                Evidence = @(@{ Note = "LAPS schema is properly extended" })
                Recommendation = "No action needed. LAPS schema is in place."
            }
        }
        else {
            $findings += @{
                Id = "LAPS-SCHEMA-MISSING"
                Title = "LAPS Schema Extension Not Found"
                Severity = "High"
                Description = "LAPS schema attributes are not present in the domain."
                Count = 0
                Evidence = @(@{ Note = "Schema needs to be extended for LAPS" })
                Recommendation = "Run LAPS schema extension. Install LAPS management tools on domain controllers."
            }
        }
    }
    catch {
        Add-IFQCNote -Context $ctx -Note "Could not check LAPS schema: $($_.Exception.Message)"
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
