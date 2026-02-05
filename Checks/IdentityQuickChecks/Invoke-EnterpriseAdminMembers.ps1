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

function Invoke-EnterpriseAdminMembers {
    <#
    .SYNOPSIS
        Identifies members of the Enterprise Admins group in Active Directory.
    
    .DESCRIPTION
        This read-only check finds users who are members of the Enterprise Admins
        group, which has universal administrative rights across all domains in
        the forest.
    
    .PARAMETER OutputPath
        Path to save the results JSON file.
    
    .PARAMETER Export
        Export format: JSON, HTML, or None.
    
    .EXAMPLE
        Invoke-EnterpriseAdminMembers -OutputPath ".\Reports"
    
    .NOTES
        Read-only check - no modifications to AD.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = ".\Reports",
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('JSON', 'HTML', 'None')]
        [string]$Export = 'JSON'
    )
    
    $checkName = "Invoke-EnterpriseAdminMembers"
    $checkCategory = "ActiveDirectory"
    $findings = @()
    $startTime = Get-Date
    
    try {
        if (Get-Module -Name ActiveDirectory -ListAvailable -ErrorAction SilentlyContinue) {
            $entAdmins = Get-ADGroupMember -Identity "Enterprise Admins" -ErrorAction SilentlyContinue 2>$null
            if ($entAdmins) {
                foreach ($member in $entAdmins) {
                    $findings += [PSCustomObject]@{
                        MemberName = $member.Name
                        SamAccountName = $member.SamAccountName
                        MemberType = $member.objectClass
                        DistinguishedName = $member.DistinguishedName
                        RiskLevel = "Critical"
                        Recommendation = "IMMEDIATE REVIEW: Enterprise Admins have forest-wide administrative access."
                        SecurityNote = "Enterprise Admins can modify trust relationships and domain configuration"
                    }
                }
            }
        }
        else {
            # .NET fallback
            $domainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain")
            $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($domainContext)
            $root = $domain.GetDirectoryEntry()
            $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
            $searcher.Filter = "(&(objectClass=user)(memberOf=CN=Enterprise Admins,*))"
            $searcher.PropertiesToLoad.Add("samAccountName") | Out-Null
            $searcher.PropertiesToLoad.Add("displayName") | Out-Null
            $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
            
            $results = $searcher.FindAll()
            foreach ($result in $results) {
                $findings += [PSCustomObject]@{
                    MemberName = if ($result.Properties["displayName"]) { $result.Properties["displayName"][0] } else { $result.Properties["samAccountName"][0] }
                    SamAccountName = $result.Properties["samAccountName"][0]
                    MemberType = "User"
                    DistinguishedName = $result.Properties["distinguishedName"][0]
                    RiskLevel = "Critical"
                    Recommendation = "IMMEDIATE REVIEW: Enterprise Admins have forest-wide administrative access."
                    SecurityNote = "Enterprise Admins can modify trust relationships and domain configuration"
                }
            }
        }
        
        $findings += [PSCustomObject]@{
            Summary = "Enterprise Admins Group Membership"
            TotalMembers = $findings.Count
            RiskLevel = if ($findings.Count -gt 3) { "Critical" } elseif ($findings.Count -gt 1) { "High" } else { "Medium" }
            Recommendation = "Minimize Enterprise Admins membership. Use separate break-glass accounts."
        }
        
        $status = if ($findings.Count -eq 0) { "Pass" } elseif ($findings.Count -le 2) { "Warning" } else { "Fail" }
        
        $endTime = Get-Date
        $duration = [Math]::Round(($endTime - $startTime).TotalSeconds, 2)
        
        $result = [PSCustomObject]@{
            CheckName = $checkName
            Category = $checkCategory
            Status = $status
            FindingCount = $findings.Count
            Findings = $findings
            StartTime = $startTime
            EndTime = $endTime
            Duration = $duration
            Error = $null
        }
        
        if ($Export -ne 'None') {
            $exportPath = Join-Path $OutputPath "$checkName.$Export"
            if (-not (Test-Path $OutputPath)) {
                New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
            }
            if ($Export -eq 'JSON') {
                $result | ConvertTo-Json -Depth 10 | Set-Content -Path $exportPath -Encoding UTF8
            }
        }
        
        return $result
    }
    catch {
        return [PSCustomObject]@{
            CheckName = $checkName
            Category = $checkCategory
            Status = "Error"
            FindingCount = 0
            Findings = @()
            StartTime = $startTime
            EndTime = Get-Date
            Duration = 0
            Error = $_.Exception.Message
        }
    }
}
