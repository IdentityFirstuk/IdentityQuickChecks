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

function Invoke-PasswordNeverExpires {
    <#
    .SYNOPSIS
        Identifies accounts with passwords that never expire.
    
    .DESCRIPTION
        This read-only check finds user accounts configured with
        "Password Never Expires" setting, which violates security best
        practices and compliance requirements.
    
    .PARAMETER OutputPath
        Path to save the results JSON file.
    
    .PARAMETER Export
        Export format: JSON, HTML, or None.
    
    .EXAMPLE
        Invoke-PasswordNeverExpires -OutputPath ".\Reports" -Export JSON
    
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
    
    $checkName = "Invoke-PasswordNeverExpires"
    $checkCategory = "ActiveDirectory"
    $findings = @()
    $startTime = Get-Date
    
    try {
        if (Get-Module -Name ActiveDirectory -ListAvailable -ErrorAction SilentlyContinue) {
            $users = Get-ADUser -Filter { PasswordNeverExpires -eq $true } -Properties SamAccountName, DisplayName, DistinguishedName, PasswordLastSet, LastLogonDate 2>$null
            foreach ($user in $users) {
                $daysSinceChange = if ($user.PasswordLastSet) {
                    [Math]::Floor((New-TimeSpan -Start $user.PasswordLastSet -End (Get-Date)).TotalDays)
                } else { "Never" }
                
                $findings += [PSCustomObject]@{
                    Username = $user.SamAccountName
                    DisplayName = $user.DisplayName
                    DistinguishedName = $user.DistinguishedName
                    PasswordLastSet = $user.PasswordLastSet
                    DaysSincePasswordChange = $daysSinceChange
                    RiskLevel = if ($daysSinceChange -gt 365 -or $daysSinceChange -eq "Never") { "Critical" } else { "Medium" }
                    Recommendation = "Enable password expiration or implement fine-grained password policy"
                }
            }
        }
        else {
            # .NET fallback
            $domainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain")
            $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($domainContext)
            $root = $domain.GetDirectoryEntry()
            $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
            $searcher.Filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))"
            $searcher.PropertiesToLoad.Add("samAccountName") | Out-Null
            $searcher.PropertiesToLoad.Add("displayName") | Out-Null
            $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
            $searcher.PropertiesToLoad.Add("pwdLastSet") | Out-Null
            
            $results = $searcher.FindAll()
            foreach ($result in $results) {
                $pwdLastSet = if ($result.Properties["pwdLastSet"][0] -gt 0) {
                    [DateTime]::FromFileTime($result.Properties["pwdLastSet"][0])
                } else { $null }
                
                $daysSinceChange = if ($pwdLastSet) {
                    [Math]::Floor((New-TimeSpan -Start $pwdLastSet -End (Get-Date)).TotalDays)
                } else { "Never" }
                
                $findings += [PSCustomObject]@{
                    Username = $result.Properties["samAccountName"][0]
                    DisplayName = if ($result.Properties["displayName"]) { $result.Properties["displayName"][0] } else { "N/A" }
                    DistinguishedName = $result.Properties["distinguishedName"][0]
                    PasswordLastSet = if ($pwdLastSet) { $pwdLastSet.ToString('yyyy-MM-dd') } else { "Never" }
                    DaysSincePasswordChange = $daysSinceChange
                    RiskLevel = if ($daysSinceChange -gt 365 -or $daysSinceChange -eq "Never") { "Critical" } else { "Medium" }
                    Recommendation = "Enable password expiration or implement fine-grained password policy"
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
