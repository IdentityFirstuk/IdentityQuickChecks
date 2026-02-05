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

function Invoke-PasswordNotRequired {
    <#
    .SYNOPSIS
        Identifies accounts with "Password Not Required" flag set.
    
    .DESCRIPTION
        This read-only check queries Active Directory for accounts that have
        the "Password Not Required" attribute (userAccountControl bit 0x20).
        These accounts bypass password complexity requirements and represent
        a significant security risk.
    
    .PARAMETER OutputPath
        Path to save the results JSON file.
    
    .PARAMETER Export
        Export format: JSON, HTML, or None.
    
    .EXAMPLE
        Invoke-PasswordNotRequired -OutputPath ".\Reports" -Export JSON
    
    .NOTES
        Read-only check - no modifications to AD.
        Requires: ActiveDirectory module or LDAP access.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = ".\Reports",
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('JSON', 'HTML', 'None')]
        [string]$Export = 'JSON'
    )
    
    $checkName = "Invoke-PasswordNotRequired"
    $checkCategory = "ActiveDirectory"
    $findings = @()
    $startTime = Get-Date
    
    try {
        # Check if ActiveDirectory module is available
        $adModule = Get-Module -Name ActiveDirectory -ListAvailable -ErrorAction SilentlyContinue
        
        if ($adModule) {
            # Use ActiveDirectory module (Windows only)
            $users = Get-ADUser -Filter { UserAccountControl -band 0x20 } -Properties SamAccountName, DistinguishedName, LastPasswordSet, PasswordLastSet 2>$null
            foreach ($user in $users) {
                $findings += [PSCustomObject]@{
                    Identity = $user.SamAccountName
                    DistinguishedName = $user.DistinguishedName
                    Issue = "Password Not Required"
                    LastPasswordSet = $user.LastPasswordSet
                    RiskLevel = "High"
                    Recommendation = "Enable password requirement or disable account if not needed"
                }
            }
        }
        else {
            # Fallback: Use .NET DirectoryServices for cross-platform
            $domainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain")
            $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($domainContext)
            $root = $domain.GetDirectoryEntry()
            $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
            $searcher.Filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))"
            $searcher.PropertiesToLoad.Add("samAccountName") | Out-Null
            $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
            $searcher.PropertiesToLoad.Add("pwdLastSet") | Out-Null
            
            $results = $searcher.FindAll()
            foreach ($result in $results) {
                $pwdLastSet = if ($result.Properties["pwdLastSet"][0] -gt 0) {
                    [DateTime]::FromFileTime($result.Properties["pwdLastSet"][0]).ToString('yyyy-MM-dd')
                } else { "Never" }
                
                $findings += [PSCustomObject]@{
                    Identity = $result.Properties["samAccountName"][0]
                    DistinguishedName = $result.Properties["distinguishedName"][0]
                    Issue = "Password Not Required"
                    LastPasswordSet = $pwdLastSet
                    RiskLevel = "High"
                    Recommendation = "Enable password requirement or disable account if not needed"
                }
            }
        }
        
        $status = if ($findings.Count -eq 0) { "Pass" } elseif ($findings.Count -le 5) { "Warning" } else { "Fail" }
        
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
        
        # Export results
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
