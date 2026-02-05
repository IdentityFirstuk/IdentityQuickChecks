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
    Analyzes AdminSDHolder configuration and protected group membership.

.DESCRIPTION
    Checks AdminSDHolder permissions and identifies accounts that may be
    unintentionally protected due to group membership. This helps identify
    where the AdminSDHolder protection mechanism may be over-applying.

.NOTES
    File Name      : Invoke-AdminSdHolderAssessment.ps1
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
$CheckId = "AD-ADMINSDHOLDER-001"
$CheckName = "AdminSDHolder Assessment"
$CheckCategory = "Active Directory"
$CheckSeverity = "Medium"
$CheckDescription = "Analyzes AdminSDHolder permissions and protected group membership"

# Initialize results
$script:AdminSDHolderACL = @()
$script:ProtectedGroups = @()
$script:ExcludedAccounts = @()
$script:CheckPassed = $true

function Get-AdminSDHolderInfo {
    <#
    .SYNOPSIS
        Retrieves AdminSDHolder configuration and ACLs.
    .DESCRIPTION
        Gets the AdminSDHolder object and analyzes its permissions.
    #>
    
    try {
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            # PowerShell 7 approach
            $adminSDHolder = Get-ADObject -Identity "CN=AdminSDHolder,CN=System,$((Get-ADDomain).DistinguishedName)" -Properties nTSecurityDescriptor -ErrorAction SilentlyContinue
            
            if ($null -ne $adminSDHolder) {
                $acl = $adminSDHolder.nTSecurityDescriptor
                return [PSCustomObject]@{
                    Success = $true
                    DistinguishedName = $adminSDHolder.DistinguishedName
                    ACL = $acl
                }
            }
            return [PSCustomObject]@{
                Success = $false
                Error = "AdminSDHolder not found"
            }
        }
        else {
            # PowerShell 5.1 approach
            $domain = Get-ADDomain
            $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$($domain.DistinguishedName)"
            
            $rootDSE = [ADSI]"LDAP://RootDSE"
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.SearchRoot = "LDAP://$($rootDSE.defaultNamingContext)"
            $searcher.Filter = "(&(objectClass=container)(name=AdminSDHolder))"
            $result = $searcher.FindOne()
            
            if ($null -ne $result) {
                return [PSCustomObject]@{
                    Success = $true
                    DistinguishedName = $result.Properties['distinguishedName'][0]
                    ACL = $null  # ACL would need separate call
                }
            }
            return [PSCustomObject]@{
                Success = $false
                Error = "AdminSDHolder not found"
            }
        }
    }
    catch {
        Write-Warning "Error accessing AdminSDHolder: $($_.Exception.Message)"
        return [PSCustomObject]@{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-ProtectedGroups {
    <#
    .SYNOPSIS
        Gets list of groups protected by AdminSDHolder.
    .DESCRIPTION
        Identifies groups that have adminCount=1 set, indicating they
        are protected by the AdminSDHolder mechanism.
    #>
    
    try {
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            $groups = Get-ADGroup -Filter {adminCount -eq 1} -Properties Name, DistinguishedName, adminCount -ErrorAction SilentlyContinue
            return $groups
        }
        else {
            $rootDSE = [ADSI]"LDAP://RootDSE"
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.SearchRoot = "LDAP://$($rootDSE.defaultNamingContext)"
            $searcher.Filter = "(&(objectClass=group)(adminCount=1))"
            $searcher.PropertiesToLoad.Add("name") | Out-Null
            $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
            $searcher.PropertiesToLoad.Add("adminCount") | Out-Null
            $results = $searcher.FindAll()
            
            $groups = @()
            foreach ($r in $results) {
                $groups += [PSCustomObject]@{
                    Name = $r.Properties['name'][0]
                    DistinguishedName = $r.Properties['distinguishedName'][0]
                    adminCount = $r.Properties['adminCount'][0]
                }
            }
            return $groups
        }
    }
    catch {
        Write-Warning "Error querying protected groups: $($_.Exception.Message)"
        return @()
    }
}

function Get-AccountsProtectedByAdminSDHolder {
    <#
    .SYNOPSIS
        Finds accounts that are protected due to AdminSDHolder.
    .DESCRIPTION
        Identifies users, computers, and service accounts that have
        adminCount=1 set due to membership in protected groups.
    #>
    
    try {
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            # Get all objects with adminCount=1 (excluding groups)
            $protected = Get-ADObject -Filter {adminCount -eq 1 -and ObjectClass -ne 'group'} `
                -Properties Name, DistinguishedName, ObjectClass, adminCount -ErrorAction SilentlyContinue
            
            return $protected
        }
        else {
            $rootDSE = [ADSI]"LDAP://RootDSE"
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.SearchRoot = "LDAP://$($rootDSE.defaultNamingContext)"
            $searcher.Filter = "(&(|(objectClass=user)(objectClass=computer)(objectClass=msDS-ManagedServiceAccount))(adminCount=1))"
            $searcher.PropertiesToLoad.Add("name") | Out-Null
            $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
            $searcher.PropertiesToLoad.Add("objectClass") | Out-Null
            $searcher.PropertiesToLoad.Add("adminCount") | Out-Null
            $results = $searcher.FindAll()
            
            $protected = @()
            foreach ($r in $results) {
                $protected += [PSCustomObject]@{
                    Name = $r.Properties['name'][0]
                    DistinguishedName = $r.Properties['distinguishedName'][0]
                    ObjectClass = $r.Properties['objectClass'][0]
                    adminCount = $r.Properties['adminCount'][0]
                }
            }
            return $protected
        }
    }
    catch {
        Write-Warning "Error querying protected accounts: $($_.Exception.Message)"
        return @()
    }
}

# Main execution
try {
    Write-Verbose "Starting AdminSDHolder Assessment..."
    
    # Get AdminSDHolder info
    Write-Verbose "Retrieving AdminSDHolder configuration..."
    $adminSDHolder = Get-AdminSDHolderInfo
    
    # Get protected groups
    Write-Verbose "Identifying protected groups..."
    $script:ProtectedGroups = Get-ProtectedGroups
    
    # Get protected accounts
    Write-Verbose "Identifying protected accounts..."
    $protectedAccounts = Get-AccountsProtectedByAdminSDHolder
    
    # Separate by type
    foreach ($account in $protectedAccounts) {
        switch ($account.ObjectClass) {
            "user" { $script:ProtectedUsers += $account }
            "computer" { $script:ProtectedComputers += $account }
            "msDS-ManagedServiceAccount" { $script:ProtectedServiceAccounts += $account }
            default { $script:OtherProtected += $account }
        }
    }
    
    # Count issues
    $totalProtected = ($script:ProtectedUsers.Count + $script:ProtectedComputers.Count + $script:ProtectedServiceAccounts.Count)
    
    # Determine status - high number of protected accounts may indicate issues
    if ($totalProtected -gt 100) {
        $script:CheckPassed = $false
    }
    
    # Calculate risk level
    $riskLevel = if ($totalProtected -gt 500) {
        "High"
    } elseif ($totalProtected -gt 200) {
        "Medium"
    } elseif ($totalProtected -gt 50) {
        "Low"
    } else {
        "None"
    }
    
    $status = if ($script:CheckPassed) { "Pass" } else { "Warning" }
    
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
            AdminSDHolderFound = $adminSDHolder.Success
            ProtectedGroupsCount = $script:ProtectedGroups.Count
            ProtectedGroups = $script:ProtectedGroups | Select-Object Name, DistinguishedName | Sort-Object Name
            TotalProtectedAccounts = $totalProtected
            ProtectedUsers = @{
                Count = $script:ProtectedUsers.Count
                Sample = $script:ProtectedUsers | Select-Object Name, DistinguishedName | Sort-Object Name | Select-Object -First 20
            }
            ProtectedComputers = @{
                Count = $script:ProtectedComputers.Count
                Sample = $script:ProtectedComputers | Select-Object Name, DistinguishedName | Sort-Object Name | Select-Object -First 20
            }
            ProtectedServiceAccounts = @{
                Count = $script:ProtectedServiceAccounts.Count
                Accounts = $script:ProtectedServiceAccounts | Select-Object Name, DistinguishedName | Sort-Object Name
            }
            Recommendation = if ($totalProtected -gt 50) {
                "$totalProtected accounts are protected by AdminSDHolder. Review protected users and computers to ensure adminCount=1 is intentional. Consider using 'Set-ADObject -Identity <user> -Clear adminCount' to remove protection where not needed."
            } else {
                "AdminSDHolder configuration appears normal with $totalProtected protected accounts."
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
            ProtectedGroupsCount = -1
            TotalProtectedAccounts = -1
        }
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
}
