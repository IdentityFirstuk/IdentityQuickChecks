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

function Invoke-PasswordNotChanged {
    <#
    .SYNOPSIS
        Identifies accounts with passwords that haven't changed in a long time.
    
    .DESCRIPTION
        This read-only check finds user accounts whose passwords have not been
        changed within the specified threshold, indicating potential security risk.
    
    .PARAMETER DaysThreshold
        Number of days since password change to flag (default: 90).
    
    .PARAMETER OutputPath
        Path to save the results JSON file.
    
    .PARAMETER Export
        Export format: JSON, HTML, or None.
    
    .EXAMPLE
        Invoke-PasswordNotChanged -DaysThreshold 90 -OutputPath ".\Reports"
    
    .NOTES
        Read-only check - no modifications to AD.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$DaysThreshold = 90,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = ".\Reports",
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('JSON', 'HTML', 'None')]
        [string]$Export = 'JSON'
    )
    
    $checkName = "Invoke-PasswordNotChanged"
    $checkCategory = "ActiveDirectory"
    $findings = @()
    $startTime = Get-Date
    $thresholdDate = (Get-Date).AddDays(-$DaysThreshold)
    
    try {
        if (Get-Module -Name ActiveDirectory -ListAvailable -ErrorAction SilentlyContinue) {
            $users = Get-ADUser -Filter { PasswordLastSet -lt $thresholdDate } -Properties SamAccountName, DisplayName, DistinguishedName, PasswordLastSet, Enabled, LastLogonDate 2>$null
            foreach ($user in $users) {
                $daysSinceChange = [Math]::Floor((New-TimeSpan -Start $user.PasswordLastSet -End (Get-Date)).TotalDays)
                $findings += [PSCustomObject]@{
                    Username = $user.SamAccountName
                    DisplayName = $user.DisplayName
                    DistinguishedName = $user.DistinguishedName
                    PasswordLastSet = $user.PasswordLastSet
                    DaysSinceChange = $daysSinceChange
                    IsEnabled = $user.Enabled
                    LastLogon = $user.LastLogonDate
                    RiskLevel = if ($daysSinceChange -gt 180) { "Critical" } elseif ($daysSinceChange -gt $DaysThreshold) { "High" } else { "Medium" }
                    Recommendation = "Enforce password change or investigate account"
                }
            }
        }
        else {
            # .NET fallback
            $domainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain")
            $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($domainContext)
            $root = $domain.GetDirectoryEntry()
            $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
            $searcher.Filter = "(objectClass=user)"
            $searcher.PropertiesToLoad.Add("samAccountName") | Out-Null
            $searcher.PropertiesToLoad.Add("displayName") | Out-Null
            $searcher.PropertiesToLoad.Add("pwdLastSet") | Out-Null
            $searcher.PropertiesToLoad.Add("userAccountControl") | Out-Null
            
            $results = $searcher.FindAll()
            foreach ($result in $results) {
                $pwdLastSet = $result.Properties["pwdLastSet"][0]
                if ($pwdLastSet) {
                    $pwdDate = [DateTime]::FromFileTime($pwdLastSet)
                    if ($pwdDate -lt $thresholdDate) {
                        $daysSinceChange = [Math]::Floor((New-TimeSpan -Start $pwdDate -End (Get-Date)).TotalDays)
                        $uac = [int]$result.Properties["userAccountControl"][0]
                        $isEnabled = ($uac -band 2) -eq 0
                        
                        $findings += [PSCustomObject]@{
                            Username = $result.Properties["samAccountName"][0]
                            DisplayName = if ($result.Properties["displayName"]) { $result.Properties["displayName"][0] } else { "N/A" }
                            DistinguishedName = $result.Properties["distinguishedName"][0]
                            PasswordLastSet = $pwdDate.ToString('yyyy-MM-dd')
                            DaysSinceChange = $daysSinceChange
                            IsEnabled = $isEnabled
                            RiskLevel = if ($daysSinceChange -gt 180) { "Critical" } elseif ($daysSinceChange -gt $DaysThreshold) { "High" } else { "Medium" }
                            Recommendation = "Enforce password change or investigate account"
                        }
                    }
                }
            }
        }
        
        $findings += [PSCustomObject]@{
            Summary = "Password Age Analysis"
            TotalAccountsAffected = $findings.Count
            CriticalRiskAccounts = ($findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
            HighRiskAccounts = ($findings | Where-Object { $_.RiskLevel -eq "High" }).Count
            DaysThreshold = $DaysThreshold
            RiskLevel = if ($findings.Count -gt 20) { "Critical" } elseif ($findings.Count -gt 10) { "High" } else { "Medium" }
            Recommendation = "Implement password aging policy and enforce regular password changes"
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
