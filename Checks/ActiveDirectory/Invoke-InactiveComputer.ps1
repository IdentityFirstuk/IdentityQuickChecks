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

function Invoke-InactiveComputer {
    <#
    .SYNOPSIS
        Identifies inactive computer accounts in Active Directory.
    
    .DESCRIPTION
        This read-only check queries AD for computer accounts that have not
        authenticated within the specified number of days. Inactive computers
        may indicate decommissioned systems or potential security risks.
    
    .PARAMETER DaysInactive
        Number of days of inactivity to flag (default: 90).
    
    .PARAMETER OutputPath
        Path to save the results JSON file.
    
    .PARAMETER Export
        Export format: JSON, HTML, or None.
    
    .EXAMPLE
        Invoke-InactiveComputer -DaysInactive 90 -OutputPath ".\Reports"
    
    .NOTES
        Read-only check - no modifications to AD.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$DaysInactive = 90,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = ".\Reports",
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('JSON', 'HTML', 'None')]
        [string]$Export = 'JSON'
    )
    
    $checkName = "Invoke-InactiveComputer"
    $checkCategory = "ActiveDirectory"
    $findings = @()
    $startTime = Get-Date
    $inactiveDate = (Get-Date).AddDays(-$DaysInactive)
    
    try {
        # Get inactive computers
        if (Get-Module -Name ActiveDirectory -ListAvailable -ErrorAction SilentlyContinue) {
            $computers = Get-ADComputer -Filter { LastLogonDate -lt $inactiveDate } -Properties Name, DNSHostName, LastLogonDate, OperatingSystem, DistinguishedName 2>$null
            foreach ($computer in $computers) {
                $findings += [PSCustomObject]@{
                    ComputerName = $computer.Name
                    DNSHostName = $computer.DNSHostName
                    LastLogonDate = $computer.LastLogonDate
                    OperatingSystem = $computer.OperatingSystem
                    DistinguishedName = $computer.DistinguishedName
                    DaysInactive = [Math]::Floor((New-TimeSpan -Start $computer.LastLogonDate -End (Get-Date)).TotalDays)
                    RiskLevel = if ((New-TimeSpan -Start $computer.LastLogonDate -End (Get-Date)).TotalDays -gt 365) { "Critical" } else { "Medium" }
                    Recommendation = "Verify if computer is still needed, then delete or re-activate"
                }
            }
        }
        else {
            # .NET fallback
            $domainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain")
            $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($domainContext)
            $root = $domain.GetDirectoryEntry()
            $searcher = New-Object System.DirectoryServices.DirectorySearcher($root)
            $searcher.Filter = "(objectClass=computer)"
            $searcher.PropertiesToLoad.Add("name") | Out-Null
            $searcher.PropertiesToLoad.Add("dNSHostName") | Out-Null
            $searcher.PropertiesToLoad.Add("lastLogonTimeStamp") | Out-Null
            $searcher.PropertiesToLoad.Add("operatingSystem") | Out-Null
            
            $results = $searcher.FindAll()
            foreach ($result in $results) {
                $lastLogon = $result.Properties["lastLogonTimeStamp"][0]
                if ($lastLogon) {
                    $lastLogonDate = [DateTime]::FromFileTime($lastLogon)
                    if ($lastLogonDate -lt $inactiveDate) {
                        $daysInactive = [Math]::Floor((New-TimeSpan -Start $lastLogonDate -End (Get-Date)).TotalDays)
                        $findings += [PSCustomObject]@{
                            ComputerName = $result.Properties["name"][0]
                            DNSHostName = if ($result.Properties["dNSHostName"]) { $result.Properties["dNSHostName"][0] } else { "N/A" }
                            LastLogonDate = $lastLogonDate.ToString('yyyy-MM-dd')
                            OperatingSystem = if ($result.Properties["operatingSystem"]) { $result.Properties["operatingSystem"][0] } else { "Unknown" }
                            DistinguishedName = $result.Properties["distinguishedName"][0]
                            DaysInactive = $daysInactive
                            RiskLevel = if ($daysInactive -gt 365) { "Critical" } else { "Medium" }
                            Recommendation = "Verify if computer is still needed, then delete or re-activate"
                        }
                    }
                }
            }
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
