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
    Analyzes privileged group membership counts across Active Directory.

.DESCRIPTION
    Counts members in high-privilege groups such as Domain Admins, Enterprise Admins,
    Schema Admins, and other administrative groups. High membership counts indicate
    potential over-provisioning and increased attack surface.

.NOTES
    File Name      : Invoke-PrivilegedGroupMembership.ps1
    Prerequisite   : PowerShell 5.1 or 7, ActiveDirectory module
    Author         : IdentityFirst Security Team
    Copyright      : (c) 2025 IdentityFirst Ltd
    License        : MIT License
    Version        : 1.0.0
    Compatible     : PowerShell 5.1, 7.x, Windows Server 2012 R2+
#>

[CmdletBinding()]
param()

# PowerShell 5.1/7 Cross-compatibility
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $script:OutputData = [ordered]@{}
} else {
    $script:OutputData = @{}
}

# Check identification
$CheckId = "AD-PRIVILEGED-001"
$CheckName = "Privileged Group Membership Analysis"
$CheckCategory = "Active Directory"
$CheckSeverity = "High"
$CheckDescription = "Analyzes membership counts in privileged AD groups"

# Privileged groups to monitor with their RID and risk level
$script:PrivilegedGroups = @(
    @{ Name = "Domain Admins"; RID = 512; Risk = "Critical" }
    @{ Name = "Enterprise Admins"; RID = 519; Risk = "Critical" }
    @{ Name = "Schema Admins"; RID = 518; Risk = "Critical" }
    @{ Name = "Group Policy Creator Owners"; RID = 520; Risk = "High" }
    @{ Name = "Administrators (Built-in)"; RID = "S-1-5-32-544"; Risk = "Critical" }
    @{ Name = "Account Operators"; RID = "S-1-5-32-548"; Risk = "High" }
    @{ Name = "Server Operators"; RID = "S-1-5-32-549"; Risk = "High" }
    @{ Name = "Print Operators"; RID = "S-1-5-32-550"; Risk = "Medium" }
    @{ Name = "Backup Operators"; RID = "S-1-5-32-551"; Risk = "High" }
    @{ Name = "Replicators"; RID = "S-1-5-32-552"; Risk = "Medium" }
    @{ Name = "Remote Management Users"; RID = "S-1-5-32-580"; Risk = "Medium" }
)

$script:GroupResults = @()
$script:CheckPassed = $true
$script:TotalPrivilegedMembers = 0

function Get-PrivilegedGroupMemberCount {
    <#
    .SYNOPSIS
        Gets member count for a specific privileged group.
    .DESCRIPTION
        Resolves the group SID and counts unique members. Uses LDAP queries
        with recursive membership search.
    .PARAMETER GroupInfo
        Hashtable containing group Name, RID, and Risk level.
    .PARAMETER DomainSID
        The domain SID to construct group SIDs from.
    #>
    
    param(
        [Parameter(Mandatory)]
        [hashtable]$GroupInfo,
        
        [Parameter(Mandatory)]
        [string]$DomainSID
    )
    
    try {
        # Construct the full SID
        if ($GroupInfo.RID -match '^\d+$') {
            $groupSID = "$DomainSID-$($GroupInfo.RID)"
        } else {
            $groupSID = $GroupInfo.RID  # Already a full SID
        }
        
        # Use Get-ADGroup with member resolution
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            # PowerShell 7 approach
            $group = Get-ADGroup -Identity $groupSID -ErrorAction SilentlyContinue
            
            if ($null -ne $group) {
                $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
                $count = if ($null -ne $members) { $members.Count } else { 0 }
                
                return [PSCustomObject]@{
                    Name = $GroupInfo.Name
                    SID = $groupSID
                    Risk = $GroupInfo.Risk
                    MemberCount = $count
                    Members = $members
                    DistinguishedName = $group.DistinguishedName
                }
            }
            else {
                return [PSCustomObject]@{
                    Name = $GroupInfo.Name
                    SID = $groupSID
                    Risk = $GroupInfo.Risk
                    MemberCount = -1  # Group not found
                    Members = $null
                    DistinguishedName = $null
                }
            }
        }
        else {
            # PowerShell 5.1 approach using DirectorySearcher
            $rootDSE = [ADSI]"LDAP://RootDSE"
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.SearchRoot = "LDAP://$($rootDSE.defaultNamingContext)"
            $searcher.Filter = "(objectSID=$groupSID)"
            $searcher.PropertiesToLoad.Add("name") | Out-Null
            $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
            $result = $searcher.FindOne()
            
            if ($null -ne $result) {
                $dn = $result.Properties['distinguishedName'][0]
                
                # Find members using LDAP OID for recursive search
                $memberSearcher = New-Object System.DirectoryServices.DirectorySearcher
                $memberSearcher.SearchRoot = "LDAP://$dn"
                $memberSearcher.Filter = "(memberOf:1.2.840.113556.1.4.1941:=$dn)"
                $memberSearcher.PropertiesToLoad.Add("name") | Out-Null
                $memberSearcher.PropertiesToLoad.Add("sAMAccountName") | Out-Null
                $memberSearcher.PageSize = 1000
                $members = $memberSearcher.FindAll()
                $count = $members.Count
                
                return [PSCustomObject]@{
                    Name = $GroupInfo.Name
                    SID = $groupSID
                    Risk = $GroupInfo.Risk
                    MemberCount = $count
                    MembersList = $members
                    DistinguishedName = $dn
                }
            }
            else {
                return [PSCustomObject]@{
                    Name = $GroupInfo.Name
                    SID = $groupSID
                    Risk = $GroupInfo.Risk
                    MemberCount = -1
                    MembersList = $null
                    DistinguishedName = $null
                }
            }
        }
    }
    catch {
        Write-Warning "Error querying group $($GroupInfo.Name): $($_.Exception.Message)"
        return [PSCustomObject]@{
            Name = $GroupInfo.Name
            SID = $groupSID
            Risk = $GroupInfo.Risk
            MemberCount = -2  # Error occurred
            MembersList = $null
            DistinguishedName = $null
            Error = $_.Exception.Message
        }
    }
}

# Main execution
try {
    Write-Verbose "Starting Privileged Group Membership check..."
    
    # Get current domain SID
    $domainInfo = Get-ADDomain -ErrorAction Stop
    $domainSID = $domainInfo.DomainSID.Value
    
    # Process each privileged group
    foreach ($groupInfo in $script:PrivilegedGroups) {
        Write-Verbose "Analyzing $($groupInfo.Name)..."
        
        $result = Get-PrivilegedGroupMemberCount -GroupInfo $groupInfo -DomainSID $domainSID
        $script:GroupResults += $result
        
        if ($result.MemberCount -gt 0) {
            $script:TotalPrivilegedMembers += $result.MemberCount
            
            # Check if this group has excessive membership
            $threshold = switch ($result.Risk) {
                "Critical" { 5 }
                "High" { 10 }
                "Medium" { 20 }
                default { 50 }
            }
            
            if ($result.MemberCount -gt $threshold) {
                $script:CheckPassed = $false
            }
        }
    }
    
    # Calculate overall risk
    $highRiskGroups = ($script:GroupResults | Where-Object { $_.Risk -eq "Critical" -and $_.MemberCount -gt 0 }).Count
    $excessiveGroups = ($script:GroupResults | Where-Object { 
        $threshold = switch ($_.Risk) {
            "Critical" { 5 }
            "High" { 10 }
            "Medium" { 20 }
            default { 50 }
        }
        $_.MemberCount -gt $threshold -and $_.MemberCount -gt 0
    }).Count
    
    $riskLevel = if ($highRiskGroups -gt 0 -or $excessiveGroups -gt 2) {
        "Critical"
    } elseif ($excessiveGroups -gt 0 -or $script:TotalPrivilegedMembers -gt 50) {
        "High"
    } elseif ($script:TotalPrivilegedMembers -gt 20) {
        "Medium"
    } else {
        "Low"
    }
    
    $status = if (-not $script:CheckPassed) { "Fail" } else { "Pass" }
    
    # Build result object
    $Result = [PSCustomObject]@{
        CheckId = $CheckId
        CheckName = $CheckName
        Category = $CheckCategory
        Severity = $CheckSeverity
        Status = $status
        RiskLevel = $riskLevel
        Description = $CheckDescription
        Details = @{
            TotalPrivilegedMembers = $script:TotalPrivilegedMembers
            TotalGroupsAnalyzed = $script:PrivilegedGroups.Count
            GroupsWithMembers = ($script:GroupResults | Where-Object { $_.MemberCount -gt 0 }).Count
            HighRiskGroups = $highRiskGroups
            ExcessiveMembershipGroups = $excessiveGroups
            GroupDetails = $script:GroupResults | Select-Object Name, Risk, MemberCount, DistinguishedName | Sort-Object @{Expression = {$_.Risk}; Descending = $true}, MemberCount -Descending
            CriticalGroups = $script:GroupResults | Where-Object { $_.Risk -eq "Critical" -and $_.MemberCount -gt 0 }
            Recommendation = if ($status -eq "Fail") {
                "Review privileged group membership. $($excessiveGroups) groups exceed recommended thresholds. Consider implementing Just-In-Time access and regular access reviews."
            } else {
                "Privileged group membership appears within acceptable limits. Continue regular access reviews."
            }
        }
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
    
    return $Result
}
catch {
    Write-Error "Check failed with exception: $($_.Exception.Message)"
    
    return [PSCustomObject]@{
        CheckId = $CheckId
        CheckName = $CheckName
        Category = $CheckCategory
        Severity = $CheckSeverity
        Status = "Error"
        RiskLevel = "Unknown"
        Description = "$CheckDescription (Error during execution)"
        Details = @{
            ErrorMessage = $_.Exception.Message
            TotalPrivilegedMembers = -1
            GroupsAnalyzed = 0
            GroupDetails = @()
        }
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
}
