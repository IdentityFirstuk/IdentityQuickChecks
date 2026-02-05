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

function Invoke-AdminCount {
    <#
    .SYNOPSIS
        Identifies accounts with AdminCount attribute set in Active Directory.
    
    .DESCRIPTION
        This read-only check finds accounts that have been assigned privileged
        roles (indicated by AdminCount=1), which is used for AdminSDHolder
        protection but may indicate stale privileged accounts.
    
    .PARAMETER OutputPath
        Path to save the results JSON file.
    
    .PARAMETER Export
        Export format: JSON, HTML, or None.
    
    .EXAMPLE
        Invoke-AdminCount -OutputPath ".\Reports"
    
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
    
    $checkName = "Invoke-AdminCount"
    $checkCategory = "ActiveDirectory"
    $findings = @()
    $startTime = Get-Date
    
    try {
        if (Get-Module -Name ActiveDirectory -ListAvailable -ErrorAction SilentlyContinue) {
            $adminUsers = Get-ADUser -Filter { AdminCount -eq 1 } -Properties SamAccountName, DisplayName, DistinguishedName, LastLogonDate, Enabled, MemberOf 2>$null
            foreach ($user in $adminUsers) {
                $groupCount = if ($user.MemberOf) { $user.MemberOf.Count } else { 0 }
                $findings += [PSCustomObject]@{
                    Username = $user.SamAccountName
                    DisplayName = $user.DisplayName
                    DistinguishedName = $user.DistinguishedName
                    IsEnabled = $user.Enabled
                    LastLogonDate = $user.LastLogonDate
                    ProtectedGroupCount = $groupCount
                    RiskLevel = if (-not $user.Enabled) { "High" } elseif ($groupCount -gt 10) { "Medium" } else { "Low" }
                    Recommendation = if (-not $user.Enabled) { "Review and remove protected status if account is disabled" } else { "Review necessity of privileged access" }
                }
            }
        }
        else {
            # .NET fallback
            $domainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain")
            $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($domainContext)
            $root = $domain.GetDirectoryEntry()
            $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
            $searcher.Filter = "(&(objectClass=user)(adminCount=1))"
            $searcher.PropertiesToLoad.Add("samAccountName") | Out-Null
            $searcher.PropertiesToLoad.Add("displayName") | Out-Null
            $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
            $searcher.PropertiesToLoad.Add("lastLogonTimeStamp") | Out-Null
            $searcher.PropertiesToLoad.Add("userAccountControl") | Out-Null
            
            $results = $searcher.FindAll()
            foreach ($result in $results) {
                $uac = [int]$result.Properties["userAccountControl"][0]
                $isEnabled = ($uac -band 2) -eq 0
                $lastLogon = $result.Properties["lastLogonTimeStamp"][0]
                $lastLogonDate = if ($lastLogon) { [DateTime]::FromFileTime($lastLogon).ToString('yyyy-MM-dd') } else { "Never" }
                
                $findings += [PSCustomObject]@{
                    Username = $result.Properties["samAccountName"][0]
                    DisplayName = if ($result.Properties["displayName"]) { $result.Properties["displayName"][0] } else { "N/A" }
                    DistinguishedName = $result.Properties["distinguishedName"][0]
                    IsEnabled = $isEnabled
                    LastLogonDate = $lastLogonDate
                    ProtectedGroupCount = 0
                    RiskLevel = if (-not $isEnabled) { "High" } else { "Medium" }
                    Recommendation = "Review necessity of privileged access"
                }
            }
        }
        
        $findings += [PSCustomObject]@{
            Summary = "AdminCount Protected Accounts"
            TotalProtectedAccounts = $findings.Count
            DisabledProtectedAccounts = ($findings | Where-Object { $_.IsEnabled -eq $false }).Count
            RiskLevel = if ($findings.Count -gt 20) { "High" } elseif ($findings.Count -gt 10) { "Medium" } else { "Low" }
            Recommendation = "Review all AdminCount-protected accounts regularly"
        }
        
        $status = if ($findings.Count -eq 0) { "Pass" } elseif ($findings.Count -le 10) { "Warning" } else { "Fail" }
        
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
