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

# SIG # Begin signature block
# MIIf3QYJKoZIhvcNAQcCoIIfzjCCH8oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCALRO8dggJUduqG
# eSIXaEY4mTBR2SA3HnDi7n5miGV26KCCGNwwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# AgEVMC8GCSqGSIb3DQEJBDEiBCBpW/bkVbOdjgH3ZVfgP22PTnc77Jlm3C0rX6hQ
# 2uUfYzANBgkqhkiG9w0BAQEFAASCAgCDiY7GugZilmucVl4lE9T1B/0KMID+tvS/
# crcz/j/SMvO1SQd4bbnfIEQiKZVLrGNP4kGIVx/W1HlpLMnZwL+6QSoQynemTV1p
# Z+j0i7n602DiQKAfL3UZD5rUtDT58UJY2Rl5uNV9SAauvK+CYq3sWamXaTAKUxrF
# 0dsp/defCBnvidh3U3M5t0tZLFNUI7jGXM+3EDQswoTtFEvqQYXjuO6VOyLzVtS5
# 4Z4P/XTmS/+MeH3STjdI54CpWPzQtsWzTjyS8WEieUCHlS3CcmuKaF9ALiEBOxA+
# +pgigSZ7yh+Wdis2zn1nsv6IbC/NBLjHMqBqBVHhI2NDAe3Zx4BqO5eBblVPttal
# CKiB0d0z4BjICbYeUZNtS0LQpATuCIkmxkoLynf4qFdaLxDW2OvdUYrxFMxcjBie
# wtjh3feGDjvWkjstrR8bDKdNNlKzBgN9U3fU5KZBDvDanldjEJb9ExWbAIBmqxTI
# BMOTiPb4O7Rc1iIiI6LNfi0NtOTi5IwwtOYVTzP0vD8jSkT4k4cvBTEP3IawuQbk
# RmsTDrc38khZk8EuilJmVyROVmdEnpQoVQXHUs0iPOehca1LHta4oKMtP7yO20Xo
# srWzquBzSDkfs20Qlbkx5ZLzJsBsF7dUJG7FYTgWMAB2rWNnV3Ma03lnPkbLv8et
# ZgBJIB8LxqGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAyMDUxNzEyNThaMC8G
# CSqGSIb3DQEJBDEiBCAU4SwJeO4iMdU6YqCssKL3SwcnnvE7g97e+4bLEnSNCTAN
# BgkqhkiG9w0BAQEFAASCAgAIGAt0biMu9GQEB9fcXo6oijooG33LWD9ifKcqfXCa
# YzjpV4nF9tzkvH2sZv4orffwTdfBAb+ra2Rvg767MjbMrhftotHN+GOFrLr5VeP2
# utSYfExuj7XwcFQwt/aSm257k0J5O/lmQQJJeM6FmyxOTtI028zUk7tav7yx0Qow
# eZJ5Y1Kh4/ezZ7Ht2VhTWUSWT8Np9cetY7j8k3JbS287MdCqFaAHemSHhTNuV7cq
# CS/rmnV6tmbdYtjlfl8Yr9nyfqtp6B5GNiDDdF38XV3bVJkVN4/WQnZeKZtTuyD5
# rTGHRuivUzSNfM63wZ6wCF4JJt7tcmJ6RgvdsCeYB2Q9+xkV5SVqnwfQq4doPML6
# uKIT+tzmUFkQ+BweNw0EU4LXfkqftGhz6/2pYCptIivmjLw2j1M6ER0+MiNafTx7
# a3b1gwv7FzX0YGukYZJx2vwlERUwfiffyNKZadtVmrqsfP9c4GGqi427rkIOH4tT
# ZKmSOK3o4VXzqxEn3gk8t8LSvqXss2bKD2s7U/9dQ+OBM49Hcn0MI/NYE8QxXPIp
# ka92Rj1dqmhv2DpL8Os9n4Nh92C+5pM0ZosX4QrczX8264lFd3D9rjER1CCPXBJ6
# r+KaTpnMaWPTMkhB7Ilxuz21n+edmvHtc0ZHnpxFY9G3jnas2fDaflI5xltGsER8
# Qg==
# SIG # End signature block
