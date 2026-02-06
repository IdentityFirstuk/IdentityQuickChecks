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
    Analyzes Active Directory trust relationships.

.DESCRIPTION
    Identifies and assesses security of all trust relationships including:
    - Forest trusts, external trusts, realm trusts
    - Trust direction (inbound, outbound, bidirectional)
    - Trust attributes (selective authentication, SID filtering)
    - Potential security risks in trust configurations

.NOTES
    File Name      : Invoke-TrustRelationshipAnalysis.ps1
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
$CheckId = "AD-TRUST-001"
$CheckName = "Trust Relationship Analysis"
$CheckCategory = "Active Directory"
$CheckSeverity = "High"
$CheckDescription = "Analyzes AD trust relationships for security risks"

# Initialize results
$script:Trusts = @()
$script:CheckPassed = $true
$script:TrustIssues = @()

function Get-AllTrusts {
    <#
    .SYNOPSIS
        Retrieves all trust relationships for the domain/forest.
    .DESCRIPTION
        Gets inbound, outbound, and forest trusts with their security attributes.
    #>
    
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $forest = Get-ADForest -ErrorAction Stop
        
        $allTrusts = @()
        
        # Get domain trusts
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            $domainTrusts = Get-ADObject -Filter {objectClass -eq "trustedDomain"} `
                -Properties Name, DistinguishedName, TrustType, TrustDirection, `
                ObjectSID, SIDFilteringQuotas, SelectiveAuthentication -ErrorAction SilentlyContinue
            
            foreach ($trust in $domainTrusts) {
                $allTrusts += [PSCustomObject]@{
                    Name = $trust.Name
                    DistinguishedName = $trust.DistinguishedName
                    TrustType = $trust.TrustType
                    TrustDirection = $trust.TrustDirection
                    SIDFilteringQuotas = $trust.SIDFilteringQuotas
                    SelectiveAuth = $trust.SelectiveAuthentication
                    IsForestTrust = ($trust.TrustType -eq 4)
                }
            }
        }
        else {
            # PowerShell 5.1 approach
            $rootDSE = [ADSI]"LDAP://RootDSE"
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.SearchRoot = "LDAP://$($rootDSE.defaultNamingContext)"
            $searcher.Filter = "(objectClass=trustedDomain)"
            $searcher.PropertiesToLoad.Add("name") | Out-Null
            $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
            $searcher.PropertiesToLoad.Add("trustType") | Out-Null
            $searcher.PropertiesToLoad.Add("trustDirection") | Out-Null
            $searcher.PropertiesToLoad.Add("uSNChanged") | Out-Null
            $results = $searcher.FindAll()
            
            foreach ($r in $results) {
                $trustType = [int]$r.Properties['trustType'][0]
                $trustDirection = [int]$r.Properties['trustDirection'][0]
                
                $allTrusts += [PSCustomObject]@{
                    Name = $r.Properties['name'][0]
                    DistinguishedName = $r.Properties['distinguishedName'][0]
                    TrustType = $trustType
                    TrustDirection = $trustDirection
                    TrustTypeName = Get-TrustTypeName -TrustType $trustType
                    TrustDirectionName = Get-TrustDirectionName -Direction $trustDirection
                    IsForestTrust = ($trustType -eq 4)
                }
            }
        }
        
        # Get cross-forest trusts from other domains in forest
        foreach ($childDomain in $forest.Domains | Where-Object { $_ -ne $domain.Name }) {
            try {
                $dc = Get-ADDomainController -Discover -DomainName $_
                $childTrusts = Get-ADObject -Filter {objectClass -eq "trustedDomain"} `
                    -Server $dc.HostName[0] -Properties Name, TrustType, TrustDirection -ErrorAction SilentlyContinue
                
                foreach ($trust in $childTrusts) {
                    $allTrusts += [PSCustomObject]@{
                        Name = $trust.Name
                        SourceDomain = $_
                        TrustType = $trust.TrustType
                        TrustDirection = $trust.TrustDirection
                        IsForestTrust = ($trust.TrustType -eq 4)
                    }
                }
            }
            catch {
                Write-Warning "Could not query trusts from domain $_"
            }
        }
        
        return $allTrusts
    }
    catch {
        Write-Warning "Error querying trusts: $($_.Exception.Message)"
        return @()
    }
}

function Get-TrustTypeName {
    param([int]$TrustType)
    switch ($TrustType) {
        1 { return "Windows NT" }
        2 { return "Active Directory" }
        3 { return "External" }
        4 { return "Forest" }
        5 { return "Realm" }
        default { return "Unknown" }
    }
}

function Get-TrustDirectionName {
    param([int]$Direction)
    switch ($Direction) {
        1 { return "Inbound" }
        2 { return "Outbound" }
        3 { return "Bidirectional" }
        default { return "Unknown" }
    }
}

function Test-TrustSecurity {
    <#
    .SYNOPSIS
        Analyzes a trust for security issues.
    .DESCRIPTION
        Checks for common security misconfigurations in trust relationships.
    #>
    
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Trust
    )
    
    $issues = @()
    
    # Check for bidirectional trusts (higher risk)
    if ($Trust.TrustDirection -eq 3) {
        $issues += [PSCustomObject]@{
            Issue = "Bidirectional Trust"
            Severity = "Medium"
            Detail = "Bidirectional trusts allow authentication in both directions, increasing attack surface."
        }
    }
    
    # Check for forest trusts
    if ($Trust.IsForestTrust) {
        $issues += [PSCustomObject]@{
            Issue = "Forest Trust"
            Severity = "Low"
            Detail = "Forest trusts enable cross-forest authentication. Ensure the trusting forest is equally secure."
        }
    }
    
    # Check if SID filtering is disabled (0 means disabled for some trust types)
    if ($null -ne $Trust.SIDFiltering -and $Trust.SIDFiltering -eq 0) {
        $issues += [PSCustomObject]@{
            Issue = "SID Filtering Disabled"
            Severity = "High"
            Detail = "SID filtering is disabled, which could allow privilege escalation via SID History."
        }
    }
    
    # Check for Windows NT trusts (legacy and less secure)
    if ($Trust.TrustType -eq 1) {
        $issues += [PSCustomObject]@{
            Issue = "Legacy Trust Type"
            Severity = "Medium"
            Detail = "Windows NT trusts are legacy. Consider upgrading to Active Directory or Forest trusts."
        }
    }
    
    # Check for external trusts
    if ($Trust.TrustType -eq 3) {
        $issues += [PSCustomObject]@{
            Issue = "External Trust"
            Severity = "Medium"
            Detail = "External trusts connect to non-Windows domains. Verify the security of the trusted domain."
        }
    }
    
    return $issues
}

# Main execution
try {
    Write-Verbose "Starting Trust Relationship Analysis..."
    
    # Get all trusts
    Write-Verbose "Retrieving trust relationships..."
    $script:Trusts = Get-AllTrusts
    
    # Analyze each trust
    foreach ($trust in $script:Trusts) {
        $issues = Test-TrustSecurity -Trust $trust
        if ($issues.Count -gt 0) {
            $trust | Add-Member -MemberType NoteProperty -Name "SecurityIssues" -Value $issues
            $script:TrustIssues += $issues
            $script:CheckPassed = $false
        }
    }
    
    # Calculate risk level
    $highRiskIssues = ($script:TrustIssues | Where-Object { $_.Severity -eq "High" }).Count
    $mediumRiskIssues = ($script:TrustIssues | Where-Object { $_.Severity -eq "Medium" }).Count
    
    $riskLevel = if ($highRiskIssues -gt 0) {
        "Critical"
    } elseif ($mediumRiskIssues -gt 2) {
        "High"
    } elseif ($mediumRiskIssues -gt 0) {
        "Medium"
    } else {
        "Low"
    }
    
    $status = if ($script:TrustIssues.Count -gt 0) { "Warning" } else { "Pass" }
    
    # Group trusts by direction
    $inboundTrusts = ($script:Trusts | Where-Object { $_.TrustDirection -eq 1 }).Count
    $outboundTrusts = ($script:Trusts | Where-Object { $_.TrustDirection -eq 2 }).Count
    $bidirectionalTrusts = ($script:Trusts | Where-Object { $_.TrustDirection -eq 3 }).Count
    
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
            TotalTrusts = $script:Trusts.Count
            TrustSummary = @{
                InboundTrusts = $inboundTrusts
                OutboundTrusts = $outboundTrusts
                BidirectionalTrusts = $bidirectionalTrusts
                ForestTrusts = ($script:Trusts | Where-Object { $_.IsForestTrust }).Count
            }
            TrustList = $script:Trusts | Select-Object Name, @{Label="TrustType";Expression={Get-TrustTypeName -TrustType $_.TrustType}}, @{Label="Direction";Expression={Get-TrustDirectionName -Direction $_.TrustDirection}} | Sort-Object Name
            SecurityIssues = $script:TrustIssues
            HighRiskIssues = $highRiskIssues
            MediumRiskIssues = $mediumRiskIssues
            Recommendation = if ($script:TrustIssues.Count -gt 0) {
                "Found $($script:TrustIssues.Count) security issues across $($script:Trusts.Count) trusts. Review high-risk issues first. Consider enabling SID filtering and selective authentication where possible."
            } else {
                "$($script:Trusts.Count) trusts found with no critical security issues. Continue monitoring trust relationships."
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
            TotalTrusts = -1
            TrustSummary = @{
                InboundTrusts = -1
                OutboundTrusts = -1
                BidirectionalTrusts = -1
            }
            SecurityIssues = @()
        }
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
}

# SIG # Begin signature block
# MIIf3QYJKoZIhvcNAQcCoIIfzjCCH8oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD9zeNXAsz29yJ4
# /XVIshfdNRqVfodscIT3JBm0wCjZiKCCGNwwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# AgEVMC8GCSqGSIb3DQEJBDEiBCDBffbIW7l7NXvL3efhE0RhurAvFnXXOTHQJhiD
# +QYKATANBgkqhkiG9w0BAQEFAASCAgAkeaW82O7fwpezWMzLofu4JRj4OR6p0xyr
# Y8VtGfNp6KO6Oc43a8lK1cn9wv6tP2zADjGEDObPPNcXx05LR3viVTBOCtA7lnwG
# h+wtzd8jSCFsETyyaTbmhOEFHF7CGT5Sliqsh8JV/Ht+x/1PoG+iupF8mwqJtHZh
# i5xLKHnwOSmVoeM2S6uMU1yUL2vdK6uqy41mfFjGRYRwZkTJ5dXAB75JeTF7BD75
# oArHLPjgbr3lKdOOJQCFInszKc2PjSRdEmHTcLSCqpAnp6QPjum8ny7wVM+UZ85F
# O8uhFpjQpqN6RP/cWgbCkThwa54YuUEQhAOFJNTeh14sLQM5+oqpiFPx3/YBW9Nv
# aOGKwCCf8QvM0k4Xpz9nl0fddNXMIVGftb8Xz+4OQrbPVMwsPzJ8nfxZcknwhzgW
# dvD9ejc1oaI0hMQztrgk0vYHi/H80XUC/Ffc3PgU2QS8j4bpOgl0DdXFyD4PlAnz
# hmgabiJjwIJMilqRlUooQLdj3b8S42YsznCRjWgak61iFehZm0357s0tsMIJJAEM
# nlZrhU7BU8kKx7yYYaPAz243nhX6VY6oHDX+ddl45ZYgOWwAX0e9m17TrGjeBucB
# q9IG+q/xS0mznBC1YNu13ydMsloA+WsvNz6NUL94938i4SXHYylgL6XvfXkTbGGp
# lq823E5L1aGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAyMDUxNzEzMDRaMC8G
# CSqGSIb3DQEJBDEiBCBfx9bUgQziFWFPEBsko4U+ChENUSra/SSQyl/z8axYUzAN
# BgkqhkiG9w0BAQEFAASCAgADiSwK1v1P5+opywIU1PE0cQMkWWjyFIO62Rxh+F5P
# lm1YDyxvSOFXM+Neu0hKjphDMF/L/rTc0jlDk4jJFZreSzL8lfsLybZhp8DbsC9X
# 15jeyZmHuKRg2Qwr1qXdfCwXLi5udNK7yLToToFRlmA5l92Je7LTtgHEs6kZxdYC
# Upc/exWKXyDlAfCtK8SdAyCIe1QDn3JjyWE5MyJJW9d2ughZ5NoSAb8biq/vuOn+
# b34/1EsHC0ZpAWIgmbMxTt68nTxQyprggdtyMagorhZoGQ9KcXC7iaDoc4/303F5
# 713/Fv8XP2Ck06MBo3fGIJ4Mg75FFmZ2ShEw30vcdEB80QpddsDpzpQEalN1sxkl
# W1oO8hTAStP5sOweXmCzF52F6POolKJf05ALgReocJg98B/kK7Gecpu/wYITp1BR
# cC5YWXtH1FQQSztQG3lOuz/iLJUPq6aaiyH2U0b4HqTTghrnS9YnUXbOTS9iQtdz
# Cm9ReTrZunU6lNhrE8Nv5z0o+UUCpbzBemKlnEABKU3wkHXofTrMgvmPLl5u4F1g
# fQ6Xn8jtpmFOGGonQ2OfvYw9C4NmcfBTPmJNjtjI2v2lLW9qGXa/GnR+GGPG8Uze
# lWXRQkoAbnjZLwiQ9/azL6kAe+DhLHeOh4D/Iotz19tGOo/lFW5rL+tACvjbnAdE
# aA==
# SIG # End signature block
