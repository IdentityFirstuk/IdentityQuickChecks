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
    Checks for DCSync rights and dangerous replication privileges.

.DESCRIPTION
    Identifies accounts with DCSync rights which can:
    - Replicate domain credentials
    - Extract password hashes
    - Perform pass-the-hash attacks

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

$ctx = New-IFQCContext -ToolName "DcsyncRights" -OutputDirectory $OutputDirectory -DetailLevel $DetailLevel
Add-IFQCNote -Context $ctx -Note "DCSync assessment requires ActiveDirectory module and read access to SDDLs."
Add-IFQCNote -Context $ctx -Note "Full DCSync analysis available in IdentityHealthCheck."

Invoke-IFQCSafe -Context $ctx -Name "DCSync Rights Assessment" -Block {
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
    # Check 1: Get domain DN for SDDL checks
    # =========================================================================
    $domainDN = $domain.DistinguishedName
    $domainNC = "CN=DomainUpdates,CN=Schema,CN=Configuration,$($domain.ConfigurationNamingContext)"

    # =========================================================================
    # Check 2: Accounts with replication rights (DS-Replication-Get-Changes)
    # =========================================================================
    Write-Host "[INFO] Checking for replication privileges..." -ForegroundColor Gray
    try {
        # Get directory entry for domain
        $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDN")

        # Get security descriptor
        $ds = $de.ObjectSecurity

        # Convert SDDL
        $sddl = $ds.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)

        # Well-known replication rights GUIDs
        $replGuid = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"  # DS-Replication-Get-Changes
        $replAllGuid = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"  # DS-Replication-Get-Changes-All

        # Extract accounts with replication rights from SDDL
        $replAccounts = @()
        $sddlLines = $sddl -split '\)(?=[A-Z];)' | Where-Object { $_ -match "($replGuid|$replAllGuid)" }

        # Parse O:SYD:... format for ownership/primary group
        if ($sddl -match "O:(?<owner>[A-Z]+)") {
            $ownerSid = $Matches.owner
            try {
                $ownerAcct = (New-Object System.Security.Principal.SecurityIdentifier($ownerSid)).Translate([System.Security.Principal.NTAccount])
                $replAccounts += [PSCustomObject]@{
                    Type = "Owner"
                    Account = $ownerAcct.Value
                    SID = $ownerSid
                    Rights = "Full Control via Ownership"
                }
            }
            catch {
                # Could not translate SID
            }
        }

        # Look for specific ACE patterns
        # The pattern for DS-Replication-Get-Changes in SDDL
        $sddl | Select-String -Pattern "[A-Z]+;[A-Z]+;[A-Z]+;$replGuid" -AllMatches | ForEach-Object {
            $match = $_
            # Parse the ACE
            if ($match -match "^(?<trustee>[^;]+);(?<rights>[^;]+);(?<objtype>[^;]+);(?<guid>$replGuid)") {
                try {
                    $trusteeSid = $Matches.trustee
                    $trusteeAcct = (New-Object System.Security.Principal.SecurityIdentifier($trusteeSid)).Translate([System.Security.Principal.NTAccount])
                    $replAccounts += [PSCustomObject]@{
                        Type = "Explicit ACE"
                        Account = $trusteeAcct.Value
                        SID = $trusteeSid
                        Rights = "DS-Replication-Get-Changes"
                    }
                }
                catch {
                    $replAccounts += [PSCustomObject]@{
                        Type = "Explicit ACE"
                        Account = $Matches.trustee
                        SID = $Matches.trustee
                        Rights = "DS-Replication-Get-Changes"
                    }
                }
            }
        }
    }
    catch {
        Add-IFQCNote -Context $ctx -Note "Could not parse domain SDDL: $($_.Exception.Message)"
    }

    # =========================================================================
    # Check 3: Known privileged groups
    # =========================================================================
    Write-Host "[INFO] Checking privileged group memberships..." -ForegroundColor Gray
    try {
        $privilegedGroups = @(
            @{ Name = "Domain Admins"; SidSuffix = "-512" },
            @{ Name = "Enterprise Admins"; SidSuffix = "-519" },
            @{ Name = "Administrators"; SidSuffix = "-544" },
            @{ Name = "Schema Admins"; SidSuffix = "-518" }
        )

        $privilegedMembers = @()
        foreach ($pg in $privilegedGroups) {
            $groupSid = "$($domain.DomainSid)$($pg.SidSuffix)"
            try {
                $group = Get-ADGroup -Identity $groupSid -ErrorAction SilentlyContinue
                if ($group) {
                    $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
                    foreach ($member in $members) {
                        $privilegedMembers += [PSCustomObject]@{
                            Group = $pg.Name
                            Member = $member.SamAccountName
                            Type = $member.objectClass
                        }
                    }
                }
            }
            catch {
                # Group not found or access denied
            }
        }

        if ($privilegedMembers) {
            $findings += @{
                Id = "DCSYNC-PRIVILEGED-GROUPS"
                Title = "Privileged Group Memberships"
                Severity = "Medium"
                Description = "$($privilegedMembers.Count) privileged group memberships detected."
                Count = $privilegedMembers.Count
                Evidence = $privilegedMembers | Select-Object -First $evidenceLimit
                Recommendation = "Review privileged group memberships. Use Just-In-Time admin access where possible."
            }
        }
    }
    catch {
        Add-IFQCNote -Context $ctx -Note "Could not check privileged groups: $($_.Exception.Message)"
    }

    # =========================================================================
    # Check 4: Service accounts with SPNs (potential high-value targets)
    # =========================================================================
    Write-Host "[INFO] Checking service accounts..." -ForegroundColor Gray
    try {
        $serviceAccounts = Get-ADUser -Filter { ServicePrincipalName -like '*' } `
            -Properties ServicePrincipalName, Name, SamAccountName, DistinguishedName `
            -ErrorAction SilentlyContinue

        if ($serviceAccounts) {
            $svcEvidence = foreach ($svc in $serviceAccounts | Select-Object -First $evidenceLimit) {
                [PSCustomObject]@{
                    Account = $svc.SamAccountName
                    SPNCount = $svc.ServicePrincipalName.Count
                }
            }

            $findings += @{
                Id = "DCSYNC-SERVICE-ACCOUNTS"
                Title = "Service Accounts with SPNs"
                Severity = "Medium"
                Description = "$($serviceAccounts.Count) service account(s) with SPNs. These are high-value targets."
                Count = $serviceAccounts.Count
                Evidence = $svcEvidence
                Recommendation = "Service accounts should have strong passwords and be protected from Kerberoasting."
            }
        }
    }
    catch {
        Add-IFQCNote -Context $ctx -Note "Could not check service accounts: $($_.Exception.Message)"
    }

    # =========================================================================
    # Check 5: Accounts with 'Do not require preauth' (Kerberoastable)
    # =========================================================================
    Write-Host "[INFO] Checking for AS-REP roastable accounts..." -ForegroundColor Gray
    try {
        $asrepRoastable = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } `
            -Properties DoesNotRequirePreAuth, Name, SamAccountName, DistinguishedName `
            -ErrorAction SilentlyContinue

        if ($asrepRoastable) {
            $asrepEvidence = $asrepRoastable | Select-Object -First $evidenceLimit @{
                Name = "Account"; Expression = { $_.SamAccountName }
            }

            $findings += @{
                Id = "DCSYNC-ASREP-ROAST"
                Title = "AS-REP Roastable Accounts"
                Severity = "High"
                Description = "$($asrepRoastable.Count) account(s) have 'Do not require Kerberos pre-authentication' enabled."
                Count = $asrepRoastable.Count
                Evidence = $asrepEvidence
                Recommendation = "AS-REP roasting allows offline password cracking. Only enable when absolutely required."
            }
        }
    }
    catch {
        Add-IFQCNote -Context $ctx -Note "Could not check AS-REP roastable accounts: $($_.Exception.Message)"
    }

    # =========================================================================
    # Check 6: Domain Controllers (potential DCSync sources)
    # =========================================================================
    Write-Host "[INFO] Checking domain controllers..." -ForegroundColor Gray
    try {
        $dcs = Get-ADDomainController -Filter * `
            -ErrorAction SilentlyContinue

        if ($dcs) {
            $dcEvidence = $dcs | Select-Object -First $evidenceLimit @{
                Name = "DC"; Expression = { $_.Name }
            }, @{
                Name = "IP"; Expression = { $_.IPAddress }
            }, @{
                Name = "Site"; Expression = { $_.SiteName }
            }

            $findings += @{
                Id = "DCSYNC-DC-LIST"
                Title = "Domain Controllers"
                Severity = "Low"
                Description = "$($dcs.Count) domain controller(s) in the environment."
                Count = $dcs.Count
                Evidence = $dcEvidence
                Recommendation = "Domain Controllers have DCSync rights by default. Monitor for unauthorized access."
            }
        }
    }
    catch {
        Add-IFQCNote -Context $ctx -Note "Could not enumerate domain controllers: $($_.Exception.Message)"
    }

    # =========================================================================
    # Check 7: Protected Users group membership
    # =========================================================================
    Write-Host "[INFO] Checking Protected Users group..." -ForegroundColor Gray
    try {
        $protectedUsers = Get-ADGroupMember -Identity "Protected Users" -ErrorAction SilentlyContinue

        if ($protectedUsers) {
            $puEvidence = $protectedUsers | Select-Object -First $evidenceLimit @{
                Name = "Member"; Expression = { $_.SamAccountName }
            }, @{
                Name = "Type"; Expression = { $_.objectClass }
            }

            $findings += @{
                Id = "DCSYNC-PROTECTED-USERS"
                Title = "Protected Users Group Members"
                Severity = "Low"
                Description = "$($protectedUsers.Count) account(s) in the Protected Users group."
                Count = $protectedUsers.Count
                Evidence = $puEvidence
                Recommendation = "Protected Users have enhanced Kerberos protection. Consider adding all privileged accounts."
            }
        }
    }
    catch {
        # Protected Users group may not exist or be accessible
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
