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
