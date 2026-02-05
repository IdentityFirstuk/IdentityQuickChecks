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

function Invoke-AwsIamUserReport {
    <#
    .SYNOPSIS
        Generates a comprehensive report of AWS IAM users and their permissions.
    
    .DESCRIPTION
        This read-only check retrieves information about IAM users, their groups,
        attached policies, and access keys to identify potential security risks.
    
    .PARAMETER OutputPath
        Path to save the results JSON file.
    
    .PARAMETER Export
        Export format: JSON, HTML, or None.
    
    .EXAMPLE
        Invoke-AwsIamUserReport -OutputPath ".\Reports"
    
    .NOTES
        Read-only check - requires AWS Tools for PowerShell.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = ".\Reports",
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('JSON', 'HTML', 'None')]
        [string]$Export = 'JSON'
    )
    
    $checkName = "Invoke-AwsIamUserReport"
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
                Error = "AWS Tools for PowerShell not installed. Run: Install-Module -Name AWS.Tools.Common"
            }
        }
        
        # Get IAM users
        $iamUsers = Get-IAMUserList 2>$null
        
        if ($iamUsers) {
            foreach ($user in $iamUsers) {
                $userName = $user.UserName
                
                # Get groups for user
                $userGroups = Get-IAMUserGroupList -UserName $userName 2>$null
                
                # Get attached policies
                $attachedPolicies = Get-IAMUserAttachedPolicyList -UserName $userName 2>$null
                
                # Get access keys
                $accessKeys = Get-IAMAccessKey -UserName $userName 2>$null
                
                # Get login profile (console access)
                $loginProfile = Get-IAMLoginProfile -UserName $userName 2>$null
                
                # Calculate age of access keys
                $keyAges = @()
                if ($accessKeys) {
                    foreach ($key in $accessKeys) {
                        $keyAge = (New-TimeSpan -Start $key.CreateDate -End (Get-Date)).TotalDays
                        $keyAges += [PSCustomObject]@{
                            KeyId = $key.AccessKeyId
                            Status = $key.Status
                            AgeDays = [Math]::Round($keyAge, 0)
                        }
                    }
                }
                
                $findings += [PSCustomObject]@{
                    UserName = $userName
                    UserId = $user.UserId
                    Arn = $user.Arn
                    GroupsCount = if ($userGroups) { $userGroups.Count } else { 0 }
                    AttachedPoliciesCount = if ($attachedPolicies) { $attachedPolicies.Count } else { 0 }
                    AccessKeysCount = if ($accessKeys) { $accessKeys.Count } else { 0 }
                    HasConsoleAccess = $null -ne $loginProfile
                    AccessKeyDetails = $keyAges
                    CreateDate = $user.CreateDate
                    RiskLevel = if ($accessKeys.Count -gt 2) { "High" } elseif ($attachedPolicies.Count -gt 5) { "Medium" } else { "Low" }
                    Recommendation = if ($accessKeys.Count -gt 2) { "Remove unused access keys" } elseif ($attachedPolicies.Count -gt 5) { "Review excessive permissions" } else { "No immediate action required" }
                }
            }
            
            # Summary
            $usersWithKeys = ($findings | Where-Object { $_.AccessKeysCount -gt 0 }).Count
            $usersWithConsole = ($findings | Where-Object { $_.HasConsoleAccess -eq $true }).Count
            $findings += [PSCustomObject]@{
                Summary = "IAM User Security Report"
                TotalUsers = $iamUsers.Count
                UsersWithAccessKeys = $usersWithKeys
                UsersWithConsoleAccess = $usersWithConsole
                RiskLevel = if ($iamUsers.Count -gt 100) { "Medium" } else { "Low" }
                Recommendation = "Review IAM users regularly and remove unused accounts"
            }
        }
        else {
            $findings += [PSCustomObject]@{
                Issue = "No IAM users found or unable to retrieve"
                RiskLevel = "Info"
                Recommendation = "N/A"
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
