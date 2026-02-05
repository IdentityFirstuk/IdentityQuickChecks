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
    Analyzes member server account health in Active Directory.

.DESCRIPTION
    Identifies member servers with security concerns including:
    - Password Never Expires enabled
    - Passwords due to expire within 30 days
    - Accounts set to never expire
    - Disabled server accounts

.NOTES
    File Name      : Invoke-MemberServerHealth.ps1
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
$CheckId = "AD-SERVER-HEALTH-001"
$CheckName = "Member Server Account Health"
$CheckCategory = "Active Directory"
$CheckSeverity = "Medium"
$CheckDescription = "Analyzes member server account security posture"

# Initialize result collections
$script:PasswordNeverExpires = @()
$script:PasswordExpiringSoon = @()
$script:AccountNeverExpires = @()
$script:DisabledServers = @()
$script:CheckPassed = $true

function Get-AllADMemberServerObjects {
    <#
    .SYNOPSIS
        Gets member server objects with specific security conditions.
    .DESCRIPTION
        Uses LDAP filters to find member servers with:
        - Password Never Expires enabled
        - Passwords expiring soon
        - Accounts set to never expire
        - Disabled server accounts
    #>
    
    param(
        [Parameter(Mandatory)]
        [string]$DomainName,
        
        [Parameter(Mandatory)]
        [string]$DomainFQDN,
        
        [Parameter(Mandatory)]
        [string]$Mode
    )
    
    try {
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            # PowerShell 7 approach
            switch ($Mode) {
                "PasswordNeverExpires" {
                    $filter = "(&(objectCategory=computer)(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(userAccountControl:1.2.840.113556.1.4.803:=65536))"
                    $servers = Get-ADComputer -Filter $filter -Properties Name, DNSHostName, PasswordLastSet, AccountExpires, Enabled -ErrorAction SilentlyContinue
                }
                "PasswordExpiration" {
                    $filter = "(&(objectCategory=computer)(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))"
                    $allServers = Get-ADComputer -Filter $filter -Properties Name, DNSHostName, PasswordLastSet, AccountExpires -ErrorAction SilentlyContinue
                    $servers = $allServers | Where-Object {
                        $pwdAge = (Get-Date) - $_.PasswordLastSet
                        $pwdAge.Days -ge 30
                    }
                }
                "AccountNeverExpires" {
                    $filter = "(&(objectCategory=computer)(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(|(accountExpires=0)(accountExpires=9223372036854775807)))"
                    $servers = Get-ADComputer -Filter $filter -Properties Name, DNSHostName, AccountExpires -ErrorAction SilentlyContinue
                }
                "Disabled" {
                    $filter = "(&(objectCategory=computer)(objectClass=computer)(operatingSystem=*server*)(userAccountControl:1.2.840.113556.1.4.803:=2))"
                    $servers = Get-ADComputer -Filter $filter -Properties Name, DNSHostName -ErrorAction SilentlyContinue
                }
            }
            
            return $servers
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
                    $searcher.Filter = "(&(objectCategory=computer)(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(userAccountControl:1.2.840.113556.1.4.803:=65536))"
                }
                "PasswordExpiration" {
                    $searcher.Filter = "(&(objectCategory=computer)(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))"
                }
                "AccountNeverExpires" {
                    $searcher.Filter = "(&(objectCategory=computer)(operatingSystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=8192))(|(accountExpires=0)(accountExpires=9223372036854775807)))"
                }
                "Disabled" {
                    $searcher.Filter = "(&(&(objectCategory=computer)(objectClass=computer)(operatingSystem=*server*)(useraccountcontrol:1.2.840.113556.1.4.803:=2)))"
                }
            }
            
            $searcher.PropertiesToLoad.Add("name") | Out-Null
            $searcher.PropertiesToLoad.Add("dNSHostName") | Out-Null
            $searcher.PropertiesToLoad.Add("pwdLastSet") | Out-Null
            $searcher.PropertiesToLoad.Add("accountExpires") | Out-Null
            $searcher.PropertiesToLoad.Add("userAccountControl") | Out-Null
            
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
        Write-Warning "Error querying member servers ($Mode): $($_.Exception.Message)"
        return $null
    }
}

# Main execution
try {
    Write-Verbose "Starting Member Server Health check..."
    
    # Get domain information
    $domain = Get-ADDomain -ErrorAction Stop
    $domainName = $domain.Name
    $domainFQDN = $domain.DNSRoot
    
    Write-Verbose "Querying domain: $domainFQDN"
    
    # Check Password Never Expires
    Write-Verbose "Checking Password Never Expires..."
    $pwdNeverExpires = Get-AllADMemberServerObjects -DomainName $domainName -DomainFQDN $domainFQDN -Mode PasswordNeverExpires
    if ($null -ne $pwdNeverExpires) {
        foreach ($server in $pwdNeverExpires) {
            if ($server -is [System.DirectoryServices.SearchResult]) {
                $script:PasswordNeverExpires += [PSCustomObject]@{
                    Name = $server.Properties['name'][0]
                    DNSHostName = $server.Properties['dNSHostName'][0]
                    Domain = $domainFQDN
                }
            } else {
                $script:PasswordNeverExpires += [PSCustomObject]@{
                    Name = $server.Name
                    DNSHostName = $server.DNSHostName
                    Domain = $domainFQDN
                }
            }
        }
    }
    
    # Check Password Expiring Soon (30+ days old)
    Write-Verbose "Checking Passwords expiring soon..."
    $pwdExpiring = Get-AllADMemberServerObjects -DomainName $domainName -DomainFQDN $domainFQDN -Mode PasswordExpiration
    if ($null -ne $pwdExpiring) {
        foreach ($server in $pwdExpiring) {
            if ($server -is [System.DirectoryServices.SearchResult]) {
                $pwdLastSet = $server.Properties['pwdLastSet'][0]
                $fileTime = if ($pwdLastSet) { [DateTime]::FromFileTime($pwdLastSet) } else { $null }
                $script:PasswordExpiringSoon += [PSCustomObject]@{
                    Name = $server.Properties['name'][0]
                    DNSHostName = $server.Properties['dNSHostName'][0]
                    PasswordLastSet = $fileTime
                    PasswordAgeDays = if ($fileTime) { (Get-Date).Subtract($fileTime).Days } else { -1 }
                    Domain = $domainFQDN
                }
            } else {
                $script:PasswordExpiringSoon += [PSCustomObject]@{
                    Name = $server.Name
                    DNSHostName = $server.DNSHostName
                    PasswordLastSet = $server.PasswordLastSet
                    PasswordAgeDays = if ($server.PasswordLastSet) { (Get-Date).Subtract($server.PasswordLastSet).Days } else { -1 }
                    Domain = $domainFQDN
                }
            }
        }
    }
    
    # Check Account Never Expires
    Write-Verbose "Checking Accounts with never expiration..."
    $accNeverExpires = Get-AllADMemberServerObjects -DomainName $domainName -DomainFQDN $domainFQDN -Mode AccountNeverExpires
    if ($null -ne $accNeverExpires) {
        foreach ($server in $accNeverExpires) {
            if ($server -is [System.DirectoryServices.SearchResult]) {
                $script:AccountNeverExpires += [PSCustomObject]@{
                    Name = $server.Properties['name'][0]
                    DNSHostName = $server.Properties['dNSHostName'][0]
                    Domain = $domainFQDN
                }
            } else {
                $script:AccountNeverExpires += [PSCustomObject]@{
                    Name = $server.Name
                    DNSHostName = $server.DNSHostName
                    Domain = $domainFQDN
                }
            }
        }
    }
    
    # Check Disabled Servers
    Write-Verbose "Checking Disabled server accounts..."
    $disabled = Get-AllADMemberServerObjects -DomainName $domainName -DomainFQDN $domainFQDN -Mode Disabled
    if ($null -ne $disabled) {
        foreach ($server in $disabled) {
            if ($server -is [System.DirectoryServices.SearchResult]) {
                $script:DisabledServers += [PSCustomObject]@{
                    Name = $server.Properties['name'][0]
                    DNSHostName = $server.Properties['dNSHostName'][0]
                    Domain = $domainFQDN
                }
            } else {
                $script:DisabledServers += [PSCustomObject]@{
                    Name = $server.Name
                    DNSHostName = $server.DNSHostName
                    Domain = $domainFQDN
                }
            }
        }
    }
    
    # Determine check status
    $totalIssues = $script:PasswordNeverExpires.Count + $script:PasswordExpiringSoon.Count + $script:AccountNeverExpires.Count
    $script:CheckPassed = $totalIssues -eq 0
    
    # Calculate risk level
    $riskLevel = if ($totalIssues -gt 20) {
        "High"
    } elseif ($totalIssues -gt 10) {
        "Medium"
    } elseif ($totalIssues -gt 0) {
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
            TotalIssues = $totalIssues
            PasswordNeverExpires = @{
                Count = $script:PasswordNeverExpires.Count
                Servers = $script:PasswordNeverExpires
                Recommendation = "Enable password expiration for $($script:PasswordNeverExpires.Count) servers to ensure regular rotation."
            }
            PasswordExpiringSoon = @{
                Count = $script:PasswordExpiringSoon.Count
                Servers = $script:PasswordExpiringSoon | Sort-Object PasswordAgeDays -Descending
                Recommendation = "$($script:PasswordExpiringSoon.Count) servers have passwords older than 30 days. Consider initiating password reset."
            }
            AccountNeverExpires = @{
                Count = $script:AccountNeverExpires.Count
                Servers = $script:AccountNeverExpires
                Recommendation = "Review $($script:AccountNeverExpires.Count) servers with no expiration policy applied."
            }
            DisabledServers = @{
                Count = $script:DisabledServers.Count
                Servers = $script:DisabledServers
                Recommendation = if ($script:DisabledServers.Count -gt 0) {
                    "$($script:DisabledServers.Count) disabled server accounts found. Consider removal if no longer needed."
                } else {
                    "No orphaned disabled servers detected."
                }
            }
            OverallRecommendation = if ($totalIssues -gt 0) {
                "Address $totalIssues security concerns across member servers. Focus on Password Never Expires accounts first as they represent the highest risk."
            } else {
                "All member servers have compliant password and account settings."
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
            PasswordNeverExpires = @{ Count = -1; Servers = @() }
            PasswordExpiringSoon = @{ Count = -1; Servers = @() }
            AccountNeverExpires = @{ Count = -1; Servers = @() }
            DisabledServers = @{ Count = -1; Servers = @() }
        }
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
}
