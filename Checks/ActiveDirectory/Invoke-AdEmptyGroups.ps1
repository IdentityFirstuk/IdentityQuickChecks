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
    Identifies empty Active Directory groups.

.DESCRIPTION
    Detects security and distribution groups with no members. Empty groups can indicate 
    orphaned groups, missed access reviews, or potential security concerns where membership
    should be actively maintained. This helps identify groups that may need cleanup or review.

.NOTES
    File Name      : Invoke-AdEmptyGroups.ps1
    Prerequisite   : PowerShell 5.1 or 7, ActiveDirectory module
    Author         : IdentityFirst Security Team
    Copyright      : (c) 2025 IdentityFirst Ltd
    License        : MIT License
    Version        : 1.0.0
    Compatible     : PowerShell 5.1, 7.x, Windows Server 2012 R2+
#>

[CmdletBinding()]
param()

# PowerShell 5.1/7 Cross-compatibility: Define proper output structure
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $script:OutputData = [ordered]@{}
} else {
    $script:OutputData = @{}
}

# Check identification
$CheckId = "AD-GROUPS-EMPTY-001"
$CheckName = "Empty Active Directory Groups"
$CheckCategory = "Active Directory"
$CheckSeverity = "Low"
$CheckDescription = "Identifies security and distribution groups with no members"

# Initialize result collection
$script:EmptyGroups = @()
$script:CheckPassed = $true  # Empty groups is typically informational
$script:SecurityGroups = @()
$script:DistributionGroups = @()

function Get-ADEmptyGroups {
    <#
    .SYNOPSIS
        Finds groups in AD that have no members.
    .DESCRIPTION
        Uses LDAP filter to find groups with (!member=*) which means no members.
        Excludes built-in groups commonly used as primary groups.
    .EXAMPLE
        Get-ADEmptyGroups | Format-Table Name, DistinguishedName
    #>
    
    # Groups commonly used as primary groups that should be excluded
    $excludeGroups = @(
        'Domain Users',
        'Domain Computers', 
        'Domain Controllers',
        'Domain Guests',
        'Enterprise Read-only Domain Controllers',
        'Read-only Domain Controllers',
        'Group Policy Creator Owners',
        'Print Operators',
        'Backup Operators',
        'Replicators'
    )
    
    try {
        # LDAP filter for groups with no members
        $ldapFilter = '(&(objectCategory=Group)(!member=*))'
        
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            # PowerShell 7 approach
            $searcher = Get-ADObject -Filter $ldapFilter -Properties Name, DistinguishedName, GroupCategory -ErrorAction Stop
        } else {
            # PowerShell 5.1 DirectorySearcher approach
            $rootDSE = [ADSI]"LDAP://RootDSE"
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.SearchRoot = "LDAP://$($rootDSE.defaultNamingContext)"
            $searcher.Filter = $ldapFilter
            $searcher.PropertiesToLoad.Add("name") | Out-Null
            $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
            $searcher.PropertiesToLoad.Add("groupType") | Out-Null
            $searcher.PageSize = 1000
            $searcher = $searcher.FindAll()
        }
        
        # Filter out excluded groups
        $results = @()
        if ($null -ne $searcher) {
            foreach ($item in $searcher) {
                $name = if ($item.Name) { $item.Name } else { $item['name'][0] }
                if ($excludeGroups -notcontains $name) {
                    $results += $item
                }
            }
        }
        
        return $results
    }
    catch {
        Write-Warning "Error querying for empty groups: $($_.Exception.Message)"
        return $null
    }
}

# Main execution
try {
    Write-Verbose "Starting Empty Groups check..."
    
    # Perform the check
    $emptyGroups = Get-ADEmptyGroups
    
    if ($null -eq $emptyGroups) {
        Write-Verbose "No empty groups found or error occurred"
        $script:EmptyGroups = @()
    }
    else {
        # Process results
        foreach ($group in $emptyGroups) {
            if ($group -is [System.DirectoryServices.SearchResult]) {
                # PowerShell 5.1 results
                $props = $group.Properties
                $name = $props['name'][0]
                $dn = $props['distinguishedName'][0]
                $groupType = $props['groupType'][0]
                
                # Determine category from groupType bitmask
                # -2147483648 = Security Group
                # 2 or 8 = Distribution Group (depending on scope)
                $isSecurity = ($groupType -band 0x80000000) -ne 0
                $category = if ($isSecurity) { "Security" } else { "Distribution" }
                
                $groupObj = [PSCustomObject]@{
                    Name = $name
                    DistinguishedName = $dn
                    Category = $category
                }
            }
            else {
                # PowerShell 7+ Get-ADObject results
                $groupType = $group.GroupCategory
                $category = if ($groupType -eq 'Security') { 'Security' } else { 'Distribution' }
                
                $groupObj = [PSCustomObject]@{
                    Name = $group.Name
                    DistinguishedName = $group.DistinguishedName
                    Category = $category
                }
            }
            
            $script:EmptyGroups += $groupObj
            
            if ($groupObj.Category -eq 'Security') {
                $script:SecurityGroups += $groupObj
            } else {
                $script:DistributionGroups += $groupObj
            }
        }
    }
    
    # Determine risk level based on security groups
    $riskLevel = if ($script:SecurityGroups.Count -gt 10) {
        "Medium"
    } elseif ($script:SecurityGroups.Count -gt 0) {
        "Low"
    } else {
        "None"
    }
    
    # Build result object
    $Result = [PSCustomObject]@{
        CheckId = $CheckId
        CheckName = $CheckName
        Category = $CheckCategory
        Severity = $CheckSeverity
        Status = if ($script:EmptyGroups.Count -gt 0) { "Informational" } else { "Pass" }
        RiskLevel = $riskLevel
        Description = $CheckDescription
        Details = @{
            TotalEmptyGroups = $script:EmptyGroups.Count
            SecurityGroupsEmpty = $script:SecurityGroups.Count
            DistributionGroupsEmpty = $script:DistributionGroups.Count
            EmptySecurityGroups = $script:SecurityGroups
            EmptyDistributionGroups = $script:DistributionGroups
            Recommendation = if ($script:EmptyGroups.Count -gt 0) {
                "Review $($script:EmptyGroups.Count) empty groups. Consider removing unused groups: $($script:SecurityGroups.Count) security and $($script:DistributionGroups.Count) distribution groups have no members. Focus on security groups for immediate review."
            } else {
                "No empty groups found. Active directory group hygiene appears good."
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
            TotalEmptyGroups = -1
            SecurityGroupsEmpty = -1
            DistributionGroupsEmpty = -1
            EmptySecurityGroups = @()
            EmptyDistributionGroups = @()
        }
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
}
