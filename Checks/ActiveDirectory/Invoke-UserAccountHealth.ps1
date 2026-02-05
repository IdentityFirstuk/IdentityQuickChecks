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
    Analyzes user account security health in Active Directory.

.DESCRIPTION
    Identifies user accounts with security concerns including:
    - Password Never Expires enabled
    - Password Not Required set
    - Password Change at Next Logon required
    - Passwords due to expire within 30 days
    - Accounts that don't require Kerberos authentication
    - Disabled user accounts
    - Accounts with no expiration date

.NOTES
    File Name      : Invoke-UserAccountHealth.ps1
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
$CheckId = "AD-USER-HEALTH-001"
$CheckName = "User Account Health"
$CheckCategory = "Active Directory"
$CheckSeverity = "High"
$CheckDescription = "Analyzes user account security posture"

# Initialize result collections
$script:PasswordNeverExpires = @()
$script:PasswordNotRequired = @()
$script:PasswordChangeNextLogon = @()
$script:PasswordExpiringSoon = @()
$script:NoKerberosAuth = @()
$script:AccountNeverExpires = @()
$script:DisabledUsers = @()
$script:CheckPassed = $true

function Get-ADUserAccountHealth {
    <#
    .SYNOPSIS
        Gets user accounts with specific security conditions.
    .DESCRIPTION
        Uses LDAP filters to find users with security concerns.
    #>
    
    param(
        [Parameter(Mandatory)]
        [string]$DomainName,
        
        [Parameter(Mandatory)]
        [string]$Mode
    )
    
    try {
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            # PowerShell 7 approach
            switch ($Mode) {
                "PasswordNeverExpires" {
                    $filter = "(sAMAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=65536)"
                    $users = Get-ADUser -Filter $filter -Properties Name, SamAccountName, DistinguishedName -ErrorAction SilentlyContinue
                }
                "PasswordNotRequired" {
                    $filter = "(sAMAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=32)"
                    $users = Get-ADUser -Filter $filter -Properties Name, SamAccountName, DistinguishedName -ErrorAction SilentlyContinue
                }
                "PasswordChangeNextLogon" {
                    $filter = "(sAMAccountType=805306368)(pwdLastSet=0)"
                    $users = Get-ADUser -Filter $filter -Properties Name, SamAccountName, DistinguishedName -ErrorAction SilentlyContinue
                }
                "PasswordExpiration" {
                    $allUsers = Get-ADUser -Filter {sAMAccountType -eq 805306368} -Properties Name, SamAccountName, DistinguishedName, PasswordLastSet -ErrorAction SilentlyContinue
                    $users = $allUsers | Where-Object { $null -ne $_.PasswordLastSet }
                }
                "NoKerberosAuth" {
                    $filter = "(sAMAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
                    $users = Get-ADUser -Filter $filter -Properties Name, SamAccountName, DistinguishedName -ErrorAction SilentlyContinue
                }
                "AccountNeverExpires" {
                    $filter = "(sAMAccountType=805306368)(|(accountExpires=0)(accountExpires=9223372036854775807))"
                    $users = Get-ADUser -Filter $filter -Properties Name, SamAccountName, DistinguishedName -ErrorAction SilentlyContinue
                }
                "Disabled" {
                    $filter = "(sAMAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=2)"
                    $users = Get-ADUser -Filter $filter -Properties Name, SamAccountName, DistinguishedName -ErrorAction SilentlyContinue
                }
            }
            
            return $users
        }
        else {
            # PowerShell 5.1 DirectorySearcher approach
            $rootDSE = [ADSI]"LDAP://RootDSE"
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.SearchRoot = "LDAP://$DomainName"
            $searcher.SearchScope = 'Subtree'
            $searcher.PageSize = 1000
            
            switch ($Mode) {
                "PasswordNeverExpires" {
                    $searcher.Filter = "(&(sAMAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=65536))"
                }
                "PasswordNotRequired" {
                    $searcher.Filter = "(&(sAMAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=32))"
                }
                "PasswordChangeNextLogon" {
                    $searcher.Filter = "(&(sAMAccountType=805306368)(pwdLastSet=0))"
                }
                "PasswordExpiration" {
                    $searcher.Filter = "(sAMAccountType=805306368)(pwdLastSet>=0)"
                }
                "NoKerberosAuth" {
                    $searcher.Filter = "(&(sAMAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
                }
                "AccountNeverExpires" {
                    $searcher.Filter = "(&(sAMAccountType=805306368)(|(accountExpires=0)(accountExpires=9223372036854775807)))"
                }
                "Disabled" {
                    $searcher.Filter = "(&(sAMAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=2))"
                }
            }
            
            $searcher.PropertiesToLoad.Add("name") | Out-Null
            $searcher.PropertiesToLoad.Add("sAMAccountName") | Out-Null
            $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
            $searcher.PropertiesToLoad.Add("pwdLastSet") | Out-Null
            
            $results = $searcher.FindAll()
            
            if ($Mode -eq "PasswordExpiration") {
                # Filter for passwords older than 30 days
                $filtered = @()
                foreach ($item in $results) {
                    $pwdLastSet = $item.Properties['pwdLastSet'][0]
                    if ($null -ne $pwdLastSet) {
                        $fileTime = [DateTime]::FromFileTime($pwdLastSet)
                        if ($fileTime -lt (Get-Date).AddDays(-30)) {
                            $filtered += $item
                        }
                    }
                }
                return $filtered
            }
            
            return $results
        }
    }
    catch {
        Write-Warning "Error querying users ($Mode): $($_.Exception.Message)"
        return $null
    }
}

# Main execution
try {
    Write-Verbose "Starting User Account Health check..."
    
    # Get domain information
    $domain = Get-ADDomain -ErrorAction Stop
    $domainName = $domain.Name
    
    Write-Verbose "Querying domain: $domainName"
    
    # Check Password Never Expires
    Write-Verbose "Checking Password Never Expires..."
    $pwdNeverExpires = Get-ADUserAccountHealth -DomainName $domainName -Mode PasswordNeverExpires
    if ($null -ne $pwdNeverExpires) {
        foreach ($user in $pwdNeverExpires) {
            if ($user -is [System.DirectoryServices.SearchResult]) {
                $script:PasswordNeverExpires += [PSCustomObject]@{
                    Name = $user.Properties['name'][0]
                    SamAccountName = $user.Properties['sAMAccountName'][0]
                    DistinguishedName = $user.Properties['distinguishedName'][0]
                }
            } else {
                $script:PasswordNeverExpires += [PSCustomObject]@{
                    Name = $user.Name
                    SamAccountName = $user.SamAccountName
                    DistinguishedName = $user.DistinguishedName
                }
            }
        }
    }
    
    # Check Password Not Required
    Write-Verbose "Checking Password Not Required..."
    $pwdNotRequired = Get-ADUserAccountHealth -DomainName $domainName -Mode PasswordNotRequired
    if ($null -ne $pwdNotRequired) {
        foreach ($user in $pwdNotRequired) {
            if ($user -is [System.DirectoryServices.SearchResult]) {
                $script:PasswordNotRequired += [PSCustomObject]@{
                    Name = $user.Properties['name'][0]
                    SamAccountName = $user.Properties['sAMAccountName'][0]
                    DistinguishedName = $user.Properties['distinguishedName'][0]
                }
            } else {
                $script:PasswordNotRequired += [PSCustomObject]@{
                    Name = $user.Name
                    SamAccountName = $user.SamAccountName
                    DistinguishedName = $user.DistinguishedName
                }
            }
        }
    }
    
    # Check Password Change Next Logon
    Write-Verbose "Checking Password Change at Next Logon..."
    $pwdChangeNext = Get-ADUserAccountHealth -DomainName $domainName -Mode PasswordChangeNextLogon
    if ($null -ne $pwdChangeNext) {
        foreach ($user in $pwdChangeNext) {
            if ($user -is [System.DirectoryServices.SearchResult]) {
                $script:PasswordChangeNextLogon += [PSCustomObject]@{
                    Name = $user.Properties['name'][0]
                    SamAccountName = $user.Properties['sAMAccountName'][0]
                    DistinguishedName = $user.Properties['distinguishedName'][0]
                }
            } else {
                $script:PasswordChangeNextLogon += [PSCustomObject]@{
                    Name = $user.Name
                    SamAccountName = $user.SamAccountName
                    DistinguishedName = $user.DistinguishedName
                }
            }
        }
    }
    
    # Check Password Expiring Soon (30+ days old)
    Write-Verbose "Checking Passwords expiring soon..."
    $pwdExpiring = Get-ADUserAccountHealth -DomainName $domainName -Mode PasswordExpiration
    if ($null -ne $pwdExpiring) {
        foreach ($user in $pwdExpiring) {
            if ($user -is [System.DirectoryServices.SearchResult]) {
                $pwdLastSet = $user.Properties['pwdLastSet'][0]
                $fileTime = if ($pwdLastSet) { [DateTime]::FromFileTime($pwdLastSet) } else { $null }
                $script:PasswordExpiringSoon += [PSCustomObject]@{
                    Name = $user.Properties['name'][0]
                    SamAccountName = $user.Properties['sAMAccountName'][0]
                    PasswordLastSet = $fileTime
                    PasswordAgeDays = if ($fileTime) { (Get-Date).Subtract($fileTime).Days } else { -1 }
                }
            } else {
                $script:PasswordExpiringSoon += [PSCustomObject]@{
                    Name = $user.Name
                    SamAccountName = $user.SamAccountName
                    PasswordLastSet = $user.PasswordLastSet
                    PasswordAgeDays = if ($user.PasswordLastSet) { (Get-Date).Subtract($user.PasswordLastSet).Days } else { -1 }
                }
            }
        }
    }
    
    # Check No Kerberos Auth Required
    Write-Verbose "Checking No Kerberos Authentication..."
    $noKerb = Get-ADUserAccountHealth -DomainName $domainName -Mode NoKerberosAuth
    if ($null -ne $noKerb) {
        foreach ($user in $noKerb) {
            if ($user -is [System.DirectoryServices.SearchResult]) {
                $script:NoKerberosAuth += [PSCustomObject]@{
                    Name = $user.Properties['name'][0]
                    SamAccountName = $user.Properties['sAMAccountName'][0]
                    DistinguishedName = $user.Properties['distinguishedName'][0]
                }
            } else {
                $script:NoKerberosAuth += [PSCustomObject]@{
                    Name = $user.Name
                    SamAccountName = $user.SamAccountName
                    DistinguishedName = $user.DistinguishedName
                }
            }
        }
    }
    
    # Check Account Never Expires
    Write-Verbose "Checking Accounts with no expiration..."
    $accNeverExpires = Get-ADUserAccountHealth -DomainName $domainName -Mode AccountNeverExpires
    if ($null -ne $accNeverExpires) {
        foreach ($user in $accNeverExpires) {
            if ($user -is [System.DirectoryServices.SearchResult]) {
                $script:AccountNeverExpires += [PSCustomObject]@{
                    Name = $user.Properties['name'][0]
                    SamAccountName = $user.Properties['sAMAccountName'][0]
                    DistinguishedName = $user.Properties['distinguishedName'][0]
                }
            } else {
                $script:AccountNeverExpires += [PSCustomObject]@{
                    Name = $user.Name
                    SamAccountName = $user.SamAccountName
                    DistinguishedName = $user.DistinguishedName
                }
            }
        }
    }
    
    # Check Disabled Users
    Write-Verbose "Checking Disabled user accounts..."
    $disabled = Get-ADUserAccountHealth -DomainName $domainName -Mode Disabled
    if ($null -ne $disabled) {
        foreach ($user in $disabled) {
            if ($user -is [System.DirectoryServices.SearchResult]) {
                $script:DisabledUsers += [PSCustomObject]@{
                    Name = $user.Properties['name'][0]
                    SamAccountName = $user.Properties['sAMAccountName'][0]
                    DistinguishedName = $user.Properties['distinguishedName'][0]
                }
            } else {
                $script:DisabledUsers += [PSCustomObject]@{
                    Name = $user.Name
                    SamAccountName = $user.SamAccountName
                    DistinguishedName = $user.DistinguishedName
                }
            }
        }
    }
    
    # Determine check status
    $totalIssues = $script:PasswordNeverExpires.Count + $script:PasswordNotRequired.Count + $script:PasswordChangeNextLogon.Count + $script:NoKerberosAuth.Count
    $script:CheckPassed = $totalIssues -eq 0
    
    # Calculate risk level
    $riskLevel = if ($totalIssues -gt 50) {
        "Critical"
    } elseif ($totalIssues -gt 20) {
        "High"
    } elseif ($totalIssues -gt 10) {
        "Medium"
    } elseif ($totalIssues -gt 0) {
        "Low"
    } else {
        "None"
    }
    
    $status = if ($script:CheckPassed) { "Pass" } else { "Fail" }
    
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
            TotalIssues = $totalIssues
            PasswordNeverExpires = @{
                Count = $script:PasswordNeverExpires.Count
                Users = $script:PasswordNeverExpires | Select-Object Name, SamAccountName | Sort-Object Name | Select-Object -First 20
                Recommendation = "$($script:PasswordNeverExpires.Count) users have passwords set to never expire."
            }
            PasswordNotRequired = @{
                Count = $script:PasswordNotRequired.Count
                Users = $script:PasswordNotRequired | Select-Object Name, SamAccountName | Sort-Object Name
                Recommendation = "$($script:PasswordNotRequired.Count) users don't require passwords. This is a critical security issue."
            }
            PasswordChangeNextLogon = @{
                Count = $script:PasswordChangeNextLogon.Count
                Users = $script:PasswordChangeNextLogon | Select-Object Name, SamAccountName | Sort-Object Name
                Recommendation = "$($script:PasswordChangeNextLogon.Count) users are required to change password at next logon."
            }
            PasswordExpiringSoon = @{
                Count = $script:PasswordExpiringSoon.Count
                Users = $script:PasswordExpiringSoon | Sort-Object PasswordAgeDays -Descending | Select-Object -First 20
                Recommendation = "$($script:PasswordExpiringSoon.Count) users have passwords older than 30 days."
            }
            NoKerberosAuth = @{
                Count = $script:NoKerberosAuth.Count
                Users = $script:NoKerberosAuth | Select-Object Name, SamAccountName | Sort-Object Name | Select-Object -First 20
                Recommendation = "$($script:NoKerberosAuth.Count) users don't require Kerberos authentication (weaker security)."
            }
            AccountNeverExpires = @{
                Count = $script:AccountNeverExpires.Count
                Users = $script:AccountNeverExpires | Select-Object Name, SamAccountName | Sort-Object Name | Select-Object -First 20
                Recommendation = "$($script:AccountNeverExpires.Count) accounts have no expiration date set."
            }
            DisabledUsers = @{
                Count = $script:DisabledUsers.Count
                Users = $script:DisabledUsers | Select-Object Name, SamAccountName | Sort-Object Name | Select-Object -First 20
                Recommendation = if ($script:DisabledUsers.Count -gt 0) {
                    "$($script:DisabledUsers.Count) disabled accounts found. Review for cleanup."
                } else {
                    "No disabled user accounts found."
                }
            }
            OverallRecommendation = if ($totalIssues -gt 0) {
                "Address $totalIssues security concerns. Focus on Password Not Required ($($script:PasswordNotRequired.Count) accounts) and Password Never Expires ($($script:PasswordNeverExpires.Count) accounts) first as they represent highest risk."
            } else {
                "All user accounts have compliant password and account settings."
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
            TotalIssues = -1
        }
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
}
