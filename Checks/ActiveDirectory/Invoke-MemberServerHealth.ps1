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

# SIG # Begin signature block
# MIIf3QYJKoZIhvcNAQcCoIIfzjCCH8oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDSt32FDq0JY4C/
# Bxl6qDcGk+TI77lsk7NsRAJGrv/FdKCCGNwwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# AgEVMC8GCSqGSIb3DQEJBDEiBCCApBNhrNoclheaUrJBSDBR47MTHuz0HgGg14UY
# fpzWMTANBgkqhkiG9w0BAQEFAASCAgDPK/AFwT/egH3OZX1NGFDgXf5syexsl94d
# rLjSMTeqpB7esEqTtiCuJqdBr8IOeMWnEgsNPQ8vW1sBcZkq+sbho7SJnUHHPFpS
# nyrDtWZ8wwhfmwU4OGqyFw+2+QaESprQhXe2foXuYjVBQYyqvfJePzCN4N4nU+uQ
# n9PvZ4aYVbaO6Blsq86lZD4mGl4SYrTIHYgCaS0mtEX7QW5sxn22LMRF8Uo9r+gj
# VkBuO3DnEJpmthw5t2S5WuQyqZvFwP00zCR54W6Xf4ypBpQt34P+JL8u0sj48Kfh
# ivqZDuMZvmftZbrgK7wZAL+8Sv/tX6J7tTMO4q/OX9LfWyVbWzX3scOcXNMOtl/W
# Ri6QqCvO0OYOACVsA+NJgmBPKddKPczJuXtQ20UvUbM+EQws8+7qmVFNfl0g8OWh
# NTAFbiGOkUSwcCK9y/GUTEeiJqPJmbXVw3SSxGX6q3XOivAoQHorBm5GTDYRxgg1
# mo9rgkH5gabiCYecoNqUJydCgi89oqjMD5/mOaCjOlW9WSzzwMA9uD+eu5GAu1Sg
# OPeNvTmGyf253CykWwhJfZ+o42kJ0odcUGuE6GZngxTVlxNoLYB2IJoFRDulfRXQ
# GnloVf3+KxL5Fyj9oJA2LmK/Ry8+iaQ5eZm+pSu8fq//K53vXZMV3TLCIe1Aktkx
# OzxxKym+xaGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAyMDUxNzEzMDJaMC8G
# CSqGSIb3DQEJBDEiBCBGTlD4pkkjHpTFQyObd2NF8kcwds15rLW/Dl8AY06RkDAN
# BgkqhkiG9w0BAQEFAASCAgAn5IXVS6PndxQNSuPHQYm2R/DnAnBsNjGwmFpPN6O2
# SRJJcljOFhuZUARkEX2kcJ7sRpWIu7pm8C2A252uuQUalsiePLD4GrzSoiuL3oHP
# Ut0ZO0JD95FcS1eNV+kpuzdburrBX/QHqYHNMrNvaQGDzNKuzIw3Cqv3W6trtEpD
# PMjmp7H2h+XY+i6axipSQgxjIiT3sS3JRJbGDhQnn6bsCvfbGvTiEdR4GcBetxcl
# L3HkmXmw/gYhSswrRvwFSWrWFVHgThkAFKzYJ5ndnuPvEMh934BhV4MMhUWOcGVG
# O7HxoUyP1AcBYzk6waAwy/Dv7L+jqzujHrl+g4oVecLZeN3OZmnYE0j3OiyBSMJG
# jJJKbXWOXJmezVsrJVEBjiP9P+I+vrRcLBrQVS0fEOqYaqHZuGC7oHFySL1b3bBR
# hiBfoQo3TRGkr/R9rFVP0P3Z2TNz3qRtyFw9CBcxI23CpKtvTjTuDedV4nT/TRQQ
# HwGgA1NQjoP4u4X7Yui+djVALeeTvuTzqFxZyAIlRY8+aYsqRst8CCyfDlXQ6nLm
# 9g9/mDW6erYE+t4Mt30zTrxB0p9TI+EuS8znc+oIvbVXHPGqOcJWEfkz4U5eYgI5
# aSvLLSwGprPGaiV0+jRWFFdhyYblTjMYhX2dlx0xwFgB+E8x9CKe8sf8lYuLw/Pg
# 3Q==
# SIG # End signature block
