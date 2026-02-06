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

# SIG # Begin signature block
# MIIf3QYJKoZIhvcNAQcCoIIfzjCCH8oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBywvRp+HeWHYLA
# ZYG/ngzrXh3E7OwgDh72ZoERlO+N96CCGNwwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggWeMIIDhqADAgECAhAfb4XAeia2j0f08ahQbRKXMA0GCSqG
# SIb3DQEBCwUAMGcxCzAJBgNVBAYTAkdCMRcwFQYDVQQHDA5Ob3J0aHVtYmVybGFu
# ZDEaMBgGA1UECgwRSWRlbnRpdHlGaXJzdCBMdGQxIzAhBgNVBAMMGklkZW50aXR5
# Rmlyc3QgQ29kZSBTaWduaW5nMB4XDTI2MDEyOTIwNTAyM1oXDTI5MDEyOTIxMDAy
# M1owZzELMAkGA1UEBhMCR0IxFzAVBgNVBAcMDk5vcnRodW1iZXJsYW5kMRowGAYD
# VQQKDBFJZGVudGl0eUZpcnN0IEx0ZDEjMCEGA1UEAwwaSWRlbnRpdHlGaXJzdCBD
# b2RlIFNpZ25pbmcwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDV9YyY
# z49V2ipI5ePMgWVHs5h89pYHRk60XSkSOUrCXYH+83sOhTgzKnpvwo7Mzuchbf6f
# q4+85DpydvkLD1L/ZMAF3x1oP74iZ28JZYv/3PwrwLsUDAAiqFQlZk7YrDxgMhdO
# Z90dXpnK+xLTfbaRGLaqB40xnCMAozxHwIm1ClEOOlhC/I+BoPZqG6GRCcOXIdzU
# UQFWRGw8o33e2YyvDfCpwZlFHTgbD1Zmsx/SE7x9LiKi3UdnAyOMlrfHgSeJRIss
# omIVDKheB5MuAHlZQm//DMNBV7o+jO3prF4MJJygD+scND5ZImw+3L2BJEPYyBLZ
# Jum+fnKp4obGnMafQWyEk77bR+ebX3hIyglqcEwalVFdPQsIMeNQ7ervsFy7NOU0
# wBPIuEgLifGWwTVPHy70T2Ci+rz5+93qSljOWvOeT4LdQ/hpqH9JS4Eu4SpJrJ+U
# 6pwdbB3rZnFLax57w/Uh/ayZ74FZDvZhCg8KaV5sJo7XgbwZ44b3OPo6bXAWV7Jl
# yIWrO4h1q3QbgSXVWui3fWxfNmHgW3CEPTzKJlRM88wCvcPe/gQYx4aDFUKtEoiE
# JKmbuDFWoHyDAEuVo+ohUt03eRdEv73XZR/hwg9imN6NbaaR9aG1TV8C3/uMD5ET
# jBmdlUcGEztyHDLzVyIad+RQGh3nDmq2vhGLfQIDAQABo0YwRDAOBgNVHQ8BAf8E
# BAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFHZkS4haGPdZn+Um
# 4fJ/zeQU7kJzMA0GCSqGSIb3DQEBCwUAA4ICAQAnWa5k8D/hKdPn9IIZNY15hX6B
# NQylhSEPNRl4PT4vR1KKyX7Wl6c55c57z3egOC23wjOC6n0Nzt0JzZwgor9Do2V8
# 7R7APMQbXVMU2N1wDugVMNBsXbDbcS4AJz2IxRPmcW+CbMo32BoFeVbc6AODLhEr
# 1PEcAydxANk7E3rxXd1TD7pCLgp1XtRmZPx87SVJgYrRvr7J3VG0As/2KOO6Eu8n
# QTAwiyOZaRXh8MGmI/kd8SUZzFzwRpcafvSgjGqbQK6s4Tkvyxo9rkLKcS9xOww7
# hyEB6mmmV9Z0kPRBMk7llIKebFzN3exzhU8Jrdsnoas4dHl/O78VOl7nZEAbujhF
# l2IL+wFTicwrwCe9s4ZVtEhFZogUAxgGk6Ut00axJF5DgRuvc06YSRrrG7DvMKZw
# vSLWeeT9u+gbwmwEFLIjaEuF+PG0HQ2EgEaNxOKXP7xjJzLo58f5GWoFk+AKealG
# 8E1TuUfHLGJSl4m30vmenyjTlWtpcgbX5XBAb7BbYv3BrIsTiPwoqKY/X9orSDK8
# owFCw1x3Gy+K2DnaVR8JMtGv5KfC2hSobmjnc3nsryd0Bf0iEO/rcwtNbhAzjNEi
# rEKDng+bz5WEJ5HXVg3SXB7v73m+Q4xNVPfBT4WVV0YHxlbwtIk/Jpbsls43n5Uv
# 6aqzWFEZtlMMLRwTezCCBrQwggScoAMCAQICEA3HrFcF/yGZLkBDIgw6SYYwDQYJ
# KoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IElu
# YzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQg
# VHJ1c3RlZCBSb290IEc0MB4XDTI1MDUwNzAwMDAwMFoXDTM4MDExNDIzNTk1OVow
# aTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQD
# EzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1
# NiAyMDI1IENBMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALR4MdMK
# mEFyvjxGwBysddujRmh0tFEXnU2tjQ2UtZmWgyxU7UNqEY81FzJsQqr5G7A6c+Gh
# /qm8Xi4aPCOo2N8S9SLrC6Kbltqn7SWCWgzbNfiR+2fkHUiljNOqnIVD/gG3SYDE
# Ad4dg2dDGpeZGKe+42DFUF0mR/vtLa4+gKPsYfwEu7EEbkC9+0F2w4QJLVSTEG8y
# AR2CQWIM1iI5PHg62IVwxKSpO0XaF9DPfNBKS7Zazch8NF5vp7eaZ2CVNxpqumzT
# CNSOxm+SAWSuIr21Qomb+zzQWKhxKTVVgtmUPAW35xUUFREmDrMxSNlr/NsJyUXz
# dtFUUt4aS4CEeIY8y9IaaGBpPNXKFifinT7zL2gdFpBP9qh8SdLnEut/GcalNeJQ
# 55IuwnKCgs+nrpuQNfVmUB5KlCX3ZA4x5HHKS+rqBvKWxdCyQEEGcbLe1b8Aw4wJ
# khU1JrPsFfxW1gaou30yZ46t4Y9F20HHfIY4/6vHespYMQmUiote8ladjS/nJ0+k
# 6MvqzfpzPDOy5y6gqztiT96Fv/9bH7mQyogxG9QEPHrPV6/7umw052AkyiLA6tQb
# Zl1KhBtTasySkuJDpsZGKdlsjg4u70EwgWbVRSX1Wd4+zoFpp4Ra+MlKM2baoD6x
# 0VR4RjSpWM8o5a6D8bpfm4CLKczsG7ZrIGNTAgMBAAGjggFdMIIBWTASBgNVHRMB
# Af8ECDAGAQH/AgEAMB0GA1UdDgQWBBTvb1NK6eQGfHrK4pBW9i/USezLTjAfBgNV
# HSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYD
# VR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1Ud
# HwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwH
# ATANBgkqhkiG9w0BAQsFAAOCAgEAF877FoAc/gc9EXZxML2+C8i1NKZ/zdCHxYga
# MH9Pw5tcBnPw6O6FTGNpoV2V4wzSUGvI9NAzaoQk97frPBtIj+ZLzdp+yXdhOP4h
# CFATuNT+ReOPK0mCefSG+tXqGpYZ3essBS3q8nL2UwM+NMvEuBd/2vmdYxDCvwzJ
# v2sRUoKEfJ+nN57mQfQXwcAEGCvRR2qKtntujB71WPYAgwPyWLKu6RnaID/B0ba2
# H3LUiwDRAXx1Neq9ydOal95CHfmTnM4I+ZI2rVQfjXQA1WSjjf4J2a7jLzWGNqNX
# +DF0SQzHU0pTi4dBwp9nEC8EAqoxW6q17r0z0noDjs6+BFo+z7bKSBwZXTRNivYu
# ve3L2oiKNqetRHdqfMTCW/NmKLJ9M+MtucVGyOxiDf06VXxyKkOirv6o02OoXN4b
# FzK0vlNMsvhlqgF2puE6FndlENSmE+9JGYxOGLS/D284NHNboDGcmWXfwXRy4kbu
# 4QFhOm0xJuF2EZAOk5eCkhSxZON3rGlHqhpB/8MluDezooIs8CVnrpHMiD2wL40m
# m53+/j7tFaxYKIqL0Q4ssd8xHZnIn/7GELH3IdvG2XlM9q7WP/UwgOkw/HQtyRN6
# 2JK4S1C8uw3PdBunvAZapsiI5YKdvlarEvf8EA+8hcpSM9LHJmyrxaFtoza2zNaQ
# 9k+5t1wwggbtMIIE1aADAgECAhAKgO8YS43xBYLRxHanlXRoMA0GCSqGSIb3DQEB
# CwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8G
# A1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBT
# SEEyNTYgMjAyNSBDQTEwHhcNMjUwNjA0MDAwMDAwWhcNMzYwOTAzMjM1OTU5WjBj
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMT
# MkRpZ2lDZXJ0IFNIQTI1NiBSU0E0MDk2IFRpbWVzdGFtcCBSZXNwb25kZXIgMjAy
# NSAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0EasLRLGntDqrmBW
# sytXum9R/4ZwCgHfyjfMGUIwYzKomd8U1nH7C8Dr0cVMF3BsfAFI54um8+dnxk36
# +jx0Tb+k+87H9WPxNyFPJIDZHhAqlUPt281mHrBbZHqRK71Em3/hCGC5KyyneqiZ
# 7syvFXJ9A72wzHpkBaMUNg7MOLxI6E9RaUueHTQKWXymOtRwJXcrcTTPPT2V1D/+
# cFllESviH8YjoPFvZSjKs3SKO1QNUdFd2adw44wDcKgH+JRJE5Qg0NP3yiSyi5Mx
# gU6cehGHr7zou1znOM8odbkqoK+lJ25LCHBSai25CFyD23DZgPfDrJJJK77epTwM
# P6eKA0kWa3osAe8fcpK40uhktzUd/Yk0xUvhDU6lvJukx7jphx40DQt82yepyekl
# 4i0r8OEps/FNO4ahfvAk12hE5FVs9HVVWcO5J4dVmVzix4A77p3awLbr89A90/nW
# GjXMGn7FQhmSlIUDy9Z2hSgctaepZTd0ILIUbWuhKuAeNIeWrzHKYueMJtItnj2Q
# +aTyLLKLM0MheP/9w6CtjuuVHJOVoIJ/DtpJRE7Ce7vMRHoRon4CWIvuiNN1Lk9Y
# +xZ66lazs2kKFSTnnkrT3pXWETTJkhd76CIDBbTRofOsNyEhzZtCGmnQigpFHti5
# 8CSmvEyJcAlDVcKacJ+A9/z7eacCAwEAAaOCAZUwggGRMAwGA1UdEwEB/wQCMAAw
# HQYDVR0OBBYEFOQ7/PIx7f391/ORcWMZUEPPYYzoMB8GA1UdIwQYMBaAFO9vU0rp
# 5AZ8esrikFb2L9RJ7MtOMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggr
# BgEFBQcDCDCBlQYIKwYBBQUHAQEEgYgwgYUwJAYIKwYBBQUHMAGGGGh0dHA6Ly9v
# Y3NwLmRpZ2ljZXJ0LmNvbTBdBggrBgEFBQcwAoZRaHR0cDovL2NhY2VydHMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNI
# QTI1NjIwMjVDQTEuY3J0MF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly9jcmwzLmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZT
# SEEyNTYyMDI1Q0ExLmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1s
# BwEwDQYJKoZIhvcNAQELBQADggIBAGUqrfEcJwS5rmBB7NEIRJ5jQHIh+OT2Ik/b
# NYulCrVvhREafBYF0RkP2AGr181o2YWPoSHz9iZEN/FPsLSTwVQWo2H62yGBvg7o
# uCODwrx6ULj6hYKqdT8wv2UV+Kbz/3ImZlJ7YXwBD9R0oU62PtgxOao872bOySCI
# LdBghQ/ZLcdC8cbUUO75ZSpbh1oipOhcUT8lD8QAGB9lctZTTOJM3pHfKBAEcxQF
# oHlt2s9sXoxFizTeHihsQyfFg5fxUFEp7W42fNBVN4ueLaceRf9Cq9ec1v5iQMWT
# FQa0xNqItH3CPFTG7aEQJmmrJTV3Qhtfparz+BW60OiMEgV5GWoBy4RVPRwqxv7M
# k0Sy4QHs7v9y69NBqycz0BZwhB9WOfOu/CIJnzkQTwtSSpGGhLdjnQ4eBpjtP+XB
# 3pQCtv4E5UCSDag6+iX8MmB10nfldPF9SVD7weCC3yXZi/uuhqdwkgVxuiMFzGVF
# wYbQsiGnoa9F5AaAyBjFBtXVLcKtapnMG3VH3EmAp/jsJ3FVF3+d1SVDTmjFjLbN
# FZUWMXuZyvgLfgyPehwJVxwC+UpX2MSey2ueIu9THFVkT+um1vshETaWyQo8gmBt
# o/m3acaP9QsuLj3FNwFlTxq25+T4QwX9xa6ILs84ZPvmpovq90K8eWyG2N01c4Ih
# SOxqt81nMYIGVzCCBlMCAQEwezBnMQswCQYDVQQGEwJHQjEXMBUGA1UEBwwOTm9y
# dGh1bWJlcmxhbmQxGjAYBgNVBAoMEUlkZW50aXR5Rmlyc3QgTHRkMSMwIQYDVQQD
# DBpJZGVudGl0eUZpcnN0IENvZGUgU2lnbmluZwIQH2+FwHomto9H9PGoUG0SlzAN
# BglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqG
# SIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3
# AgEVMC8GCSqGSIb3DQEJBDEiBCAoeOjnHuhu2yStks1oMXzvB8UrOmy9O+M5p6C+
# 1uQaWzANBgkqhkiG9w0BAQEFAASCAgAHbBApWI8LZBEIx/sXIcdmcFggef7AjKIy
# GorLpB9VKjsHwdD5+U++0UMQ+yJl1xu3LuodTuZQ9tLYP9vQN74YBfk9LXhIRrc8
# Q5flMQdwGqaNLoBU14ZnEPYOxoAY4bwoa5yAMvpAxupT/uRC4MyP2khOQWITc3/7
# bT+IdfbLQf8nAQBc9LjVclJmOELF0ORN3MfmGnD9g9fCm2DkxSouptugzjagUp8w
# 9+DLF47oxhrdq5zXeB549J6rdTyyf3iY3ecULuQjEYDiCMDBbHCjpGxq37Ypky/r
# zzEevetd9k7H0XOXrUTGuBWnsmOjILGSC33o40tvS7ybpuWH/rdPnfZBow5+6BZo
# gpooWJM33ST/TmnpEa6oW8dV7pKvHQbJl0hbkU6+HC0+g1BIxZ636xqsOWoJDqcs
# tBSEGG7DnsyycGmFGrNWcOgSpjbd0w20kygErd7m0BvrZzpM97P0wjdiTltQiu4H
# /LOBWK2UD2zG62sls+93AqNfOhtEd6VLOE6gw/7mfkAfxLWw9rlDiNbQOVOalvru
# 9EOGqguPEHcfyGvDZYiBX2vgnHXxEOw8iPF7HvnHmyiGKzlMjBVkLlSJQBAinE+g
# N4dlzSvdRIkjJ5QFhi4BFF2DgkR9Nj4BYKwgmy5hti9qqvs8MqDiBSdCytMJspO+
# fcfqlfcXN6GCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAyMDUxNzEzMDZaMC8G
# CSqGSIb3DQEJBDEiBCDTC4/TZdv4VddunxHs2XQEq3GjZ5/K8wlhP3yw9iqP6jAN
# BgkqhkiG9w0BAQEFAASCAgB5I1u0Lhe+xNfi+D9InCChJkUsLzr81YJiRLnbMljN
# Xlm4suxtdRC4JuV9ZbaOOdXcgErJtDCNoUfua5Yx2UOIjLaOQl5wFxvdZY5fVzxr
# 1sFCZ/H35o7wdXmYG7vDh9XjYflhdR+xWP71eGs/2pSO3ibDUmMXdnQ62NERE+W/
# uahw6SZXx2VbObIyFHv3pTVpwm+tDtAfOAf3Zo/SCKaBtJORz5RIf2kUyKACgzTF
# ofMAHIK8Zrl2ai7v+IteFcRRwmYA6pLjZwYvdZNw8Mvi45/l3+saL8Ov/h6HMg/9
# 5A7P/v8QBgHd4EcHxUDNsfbPigamd3mQDumwcGVZN7nKrPutqAuKlzfZAt4+hfcg
# +U02UbrtxRNfFm6GaUotA2F72t5bW9ulkSP/x+ycNs9EUNTcTIM6sRdSgjtT1vKM
# Rv0sDQQWC6+m1RxWGa2o9OxETyMyVGLIaDJ2VGFxuj+DWzvz1XDV7QP8Rjy/Xmhp
# uCU+nn6hUx7aSJ0em+uQQKaDnJ7PCKUeotUCdYDvir9Ii3fILLJeisKKEFmnTb4j
# qMj49hDMjXP5tAB/exctMu7NoZDMFPlYY8Z7EIRAg+Z9u/53yRg2m4XDuwM/2t4Y
# VoVgyNINw0G1QS/H6tfs2Tu1XXSmmg3knty1G3xILS4Wuujag/6sEdiCmmxtMOgA
# gg==
# SIG # End signature block
