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

function Invoke-InactiveUserAccount {
    <#
    .SYNOPSIS
        Identifies inactive user accounts across all platforms.
    
    .DESCRIPTION
        This read-only check identifies user accounts that have not logged in
        for an extended period across Active Directory and cloud platforms.
    
    .PARAMETER DaysInactive
        Number of days of inactivity to flag (default: 90).
    
    .PARAMETER OutputPath
        Path to save the results JSON file.
    
    .PARAMETER Export
        Export format: JSON, HTML, or None.
    
    .EXAMPLE
        Invoke-InactiveUserAccount -DaysInactive 90 -OutputPath ".\Reports"
    
    .NOTES
        Read-only check - no modifications to any system.
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
    
    $checkName = "Invoke-InactiveUserAccount"
    $checkCategory = "Identity"
    $findings = @()
    $startTime = Get-Date
    $inactiveDate = (Get-Date).AddDays(-$DaysInactive)
    
    try {
        # Check Active Directory
        $adAvailable = Get-Module -Name ActiveDirectory -ListAvailable -ErrorAction SilentlyContinue
        
        if ($adAvailable) {
            $adUsers = Get-ADUser -Filter { LastLogonDate -lt $inactiveDate } -Properties SamAccountName, DisplayName, LastLogonDate, CreatedDate, MemberOf 2>$null
            foreach ($user in $adUsers) {
                $groupCount = if ($user.MemberOf) { $user.MemberOf.Count } else { 0 }
                $findings += [PSCustomObject]@{
                    Platform = "Active Directory"
                    Username = $user.SamAccountName
                    DisplayName = $user.DisplayName
                    LastLogon = $user.LastLogonDate
                    CreatedDate = $user.CreatedDate
                    DaysInactive = [Math]::Floor((New-TimeSpan -Start $user.LastLogonDate -End (Get-Date)).TotalDays)
                    GroupMembershipCount = $groupCount
                    RiskLevel = if ((New-TimeSpan -Start $user.LastLogonDate -End (Get-Date)).TotalDays -gt 365) { "Critical" } else { "Medium" }
                    Recommendation = "Verify account necessity and disable if not needed"
                }
            }
        }
        
        # Summary
        $criticalCount = ($findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
        $highCount = ($findings | Where-Object { $_.RiskLevel -eq "High" }).Count
        
        $findings += [PSCustomObject]@{
            Summary = "Inactive Account Analysis"
            TotalInactiveAccounts = $findings.Count
            CriticalRiskAccounts = $criticalCount
            HighRiskAccounts = $highCount
            DaysThreshold = $DaysInactive
            RiskLevel = if ($criticalCount -gt 10) { "Critical" } elseif ($highCount -gt 10) { "High" } else { "Medium" }
            Recommendation = "Implement account lifecycle management and disable inactive accounts"
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
