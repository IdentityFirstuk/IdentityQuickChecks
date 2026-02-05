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

function Invoke-AwsIamPolicyReport {
    <#
    .SYNOPSIS
        Analyzes AWS IAM policies for overly permissive actions.
    
    .DESCRIPTION
        This read-only check reviews IAM policies to identify potentially
        dangerous permissions such as "*:*", "iam:*", or "s3:*" access.
    
    .PARAMETER OutputPath
        Path to save the results JSON file.
    
    .PARAMETER Export
        Export format: JSON, HTML, or None.
    
    .EXAMPLE
        Invoke-AwsIamPolicyReport -OutputPath ".\Reports"
    
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
    
    $checkName = "Invoke-AwsIamPolicyReport"
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
        
        # Dangerous policy patterns
        $dangerousPatterns = @(
            "iam:*",
            "s3:*",
            "ec2:*",
            "*:*",
            "sts:AssumeRole",
            "kms:*",
            "secretsmanager:*"
        )
        
        # Get customer managed policies
        $policies = Get-IAMPolicyList 2>$null
        
        if ($policies) {
            foreach ($policy in $policies) {
                $policyArn = $policy.Arn
                $policyName = $policy.PolicyName
                
                # Get policy versions
                $versions = Get-IAMPolicyVersion -PolicyArn $policyArn 2>$null
                
                if ($versions) {
                    # Use the default version
                    $defaultVersion = $versions | Where-Object { $_.IsDefaultVersion }
                    
                    if ($defaultVersion) {
                        $document = $defaultVersion.Document
                        $statements = $document.Statement
                        
                        $sensitiveActions = @()
                        foreach ($pattern in $dangerousPatterns) {
                            $documentJson = $document | ConvertTo-Json -Depth 10
                            if ($documentJson -like "*$pattern*") {
                                $sensitiveActions += $pattern
                            }
                        }
                        
                        $findings += [PSCustomObject]@{
                            PolicyName = $policyName
                            PolicyArn = $policyArn
                            DefaultVersion = $defaultVersion.VersionId
                            HasDangerousPermissions = $sensitiveActions.Count -gt 0
                            SensitivePatterns = $sensitiveActions
                            CreateDate = $policy.CreateDate
                            UpdateDate = $policy.UpdateDate
                            RiskLevel = if ($sensitiveActions -contains "iam:*" -or $sensitiveActions -contains "*:*") { "Critical" } elseif ($sensitiveActions.Count -gt 0) { "High" } else { "Low" }
                            Recommendation = if ($sensitiveActions.Count -gt 0) { "Review and restrict sensitive permissions" } else { "No immediate action required" }
                        }
                    }
                }
            }
            
            # Summary
            $criticalCount = ($findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
            $highCount = ($findings | Where-Object { $_.RiskLevel -eq "High" }).Count
            $findings += [PSCustomObject]@{
                Summary = "IAM Policy Security Analysis"
                TotalPolicies = $policies.Count
                PoliciesWithDangerousPerms = ($findings | Where-Object { $_.HasDangerousPermissions -eq $true }).Count
                CriticalPolicies = $criticalCount
                HighRiskPolicies = $highCount
                RiskLevel = if ($criticalCount -gt 0) { "Critical" } elseif ($highCount -gt 0) { "High" } else { "Medium" }
                Recommendation = "Review and remediate policies with dangerous permissions"
            }
        }
        else {
            $findings += [PSCustomObject]@{
                Issue = "No IAM policies found or unable to retrieve"
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
