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

function Invoke-AwsIamAccessKeyReport {
    <#
    .SYNOPSIS
        Reports on AWS IAM access keys and their age.
    
    .DESCRIPTION
        This read-only check identifies old access keys that should be rotated,
        inactive keys, and keys that have been used recently.
    
    .PARAMETER MaxKeyAgeDays
        Maximum age in days for access keys (default: 90).
    
    .PARAMETER OutputPath
        Path to save the results JSON file.
    
    .PARAMETER Export
        Export format: JSON, HTML, or None.
    
    .EXAMPLE
        Invoke-AwsIamAccessKeyReport -MaxKeyAgeDays 90 -OutputPath ".\Reports"
    
    .NOTES
        Read-only check - requires AWS Tools for PowerShell.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$MaxKeyAgeDays = 90,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = ".\Reports",
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('JSON', 'HTML', 'None')]
        [string]$Export = 'JSON'
    )
    
    $checkName = "Invoke-AwsIamAccessKeyReport"
    $checkCategory = "AWS"
    $findings = @()
    $startTime = Get-Date
    
    try {
        # Check for AWS module
        $awsModule = Get-Module -Name AWS.Tools.Common -ListAvailable -ErrorAction SilentlyContinue
        if (-not $awsModule) {
            $awsModule = Get-Module -Name AWSPowerShell -ListAvailable -ErrorAction SilentlyContinue
        }
        
        if (-not $awsModule) {
            return [PSCustomObject]@{
                CheckName = $checkName
                Category = $checkCategory
                Status = "Error"
                FindingCount = 0
                Findings = @()
                StartTime = $startTime
                EndTime = Get-Date
                Duration = 0
                Error = "AWS Tools for PowerShell not installed"
            }
        }
        
        # Get IAM users
        $iamUsers = Get-IAMUserList 2>$null
        
        if ($iamUsers) {
            foreach ($user in $iamUsers) {
                $userName = $user.UserName
                
                # Get access keys for user
                $accessKeys = Get-IAMAccessKey -UserName $userName 2>$null
                
                if ($accessKeys) {
                    foreach ($key in $accessKeys) {
                        $keyAge = (New-TimeSpan -Start $key.CreateDate -End (Get-Date)).TotalDays
                        $keyAgeDays = [Math]::Round($keyAge, 0)
                        
                        $findings += [PSCustomObject]@{
                            UserName = $userName
                            UserId = $user.UserId
                            AccessKeyId = $key.AccessKeyId
                            KeyStatus = $key.Status
                            CreateDate = $key.CreateDate
                            AgeDays = $keyAgeDays
                            IsOverAge = $keyAgeDays -gt $MaxKeyAgeDays
                            LastUsedDate = $key.LastUsedDate
                            ServiceLastUsed = $key.ServiceName
                            RegionLastUsed = $key.Region
                            RiskLevel = if ($keyAgeDays -gt 180) { "Critical" } elseif ($keyAgeDays -gt $MaxKeyAgeDays) { "High" } elseif ($key.Status -eq "Inactive") { "Medium" } else { "Low" }
                            Recommendation = if ($keyAgeDays -gt $MaxKeyAgeDays) { "Rotate access key immediately" } elseif ($key.Status -eq "Inactive") { "Delete inactive access key" } else { "No immediate action required" }
                        }
                    }
                }
            }
            
            # Summary
            $keysOverAge = ($findings | Where-Object { $_.IsOverAge -eq $true }).Count
            $inactiveKeys = ($findings | Where-Object { $_.KeyStatus -eq "Inactive" }).Count
            $findings += [PSCustomObject]@{
                Summary = "Access Key Rotation Report"
                TotalKeys = $findings.Count
                KeysOverAgeThreshold = $keysOverAge
                InactiveKeys = $inactiveKeys
                MaxAgeThreshold = $MaxKeyAgeDays
                RiskLevel = if ($keysOverAge -gt 5) { "Critical" } elseif ($keysOverAge -gt 0) { "High" } else { "Low" }
                Recommendation = "Implement access key rotation policy and automate key rotation"
            }
        }
        else {
            $findings += [PSCustomObject]@{
                Issue = "No IAM users found or unable to retrieve"
                RiskLevel = "Info"
                Recommendation = "N/A"
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
