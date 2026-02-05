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

function Invoke-GcpIamRoleReport {
    <#
    .SYNOPSIS
        Analyzes GCP IAM roles for overly permissive permissions.
    
    .DESCRIPTION
        This read-only check reviews custom IAM roles in GCP to identify
        potentially dangerous permissions.
    
    .PARAMETER OutputPath
        Path to save the results JSON file.
    
    .PARAMETER Export
        Export format: JSON, HTML, or None.
    
    .EXAMPLE
        Invoke-GcpIamRoleReport -OutputPath ".\Reports"
    
    .NOTES
        Read-only check - requires gcloud CLI.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = ".\Reports",
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('JSON', 'HTML', 'None')]
        [string]$Export = 'JSON'
    )
    
    $checkName = "Invoke-GcpIamRoleReport"
    $checkCategory = "GCP"
    $findings = @()
    $startTime = Get-Date
    
    try {
        # Check for gcloud CLI
        $gcloudPath = (Get-Command gcloud -ErrorAction SilentlyContinue).Path
        if (-not $gcloudPath) {
            return [PSCustomObject]@{
                CheckName = $checkName
                Category = $checkCategory
                Status = "Error"
                FindingCount = 0
                Findings = @()
                StartTime = $startTime
                EndTime = Get-Date
                Duration = 0
                Error = "gcloud CLI not found. Install from: https://cloud.google.com/sdk/docs/install"
            }
        }
        
        # Dangerous permissions patterns
        $dangerousPermissions = @(
            "iam.roles.*",
            "resourcemanager.projects.*",
            "compute.*",
            "storage.*",
            "bigquery.*",
            "cloudkms.*"
        )
        
        # Get custom roles
        $rolesJson = & gcloud iam roles list --format=json 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $rolesJson) {
            return [PSCustomObject]@{
                CheckName = $checkName
                Category = $checkCategory
                Status = "Error"
                FindingCount = 0
                Findings = @()
                StartTime = $startTime
                EndTime = Get-Date
                Duration = 0
                Error = "Failed to retrieve GCP IAM roles"
            }
        }
        
        $roles = $rolesJson | ConvertFrom-Json
        
        if ($roles) {
            foreach ($role in $roles) {
                $roleName = $role.Name
                $roleId = $role.RoleId
                $stage = $role.Stage
                $includedPermissions = $role.IncludedPermissions
                
                $sensitivePerms = @()
                foreach ($perm in $includedPermissions) {
                    foreach ($pattern in $dangerousPermissions) {
                        if ($perm -like $pattern) {
                            $sensitivePerms += $perm
                            break
                        }
                    }
                }
                
                $findings += [PSCustomObject]@{
                    RoleName = $roleName
                    RoleId = $roleId
                    Stage = $stage
                    TotalPermissions = $includedPermissions.Count
                    SensitivePermissions = $sensitivePerms
                    HasDangerousPerms = $sensitivePerms.Count -gt 0
                    RiskLevel = if ($sensitivePerms.Count -gt 10) { "High" } elseif ($sensitivePerms.Count -gt 0) { "Medium" } else { "Low" }
                    Recommendation = if ($sensitivePerms.Count -gt 0) { "Review role permissions and apply least privilege" } else { "No immediate action required" }
                }
            }
            
            # Summary
            $highRiskCount = ($findings | Where-Object { $_.RiskLevel -eq "High" }).Count
            $findings += [PSCustomObject]@{
                Summary = "GCP IAM Role Security Analysis"
                TotalCustomRoles = $roles.Count
                RolesWithSensitivePerms = ($findings | Where-Object { $_.HasDangerousPerms -eq $true }).Count
                HighRiskRoles = $highRiskCount
                RiskLevel = if ($highRiskCount -gt 5) { "High" } elseif ($highRiskCount -gt 0) { "Medium" } else { "Low" }
                Recommendation = "Review custom IAM roles and apply least privilege principle"
            }
        }
        else {
            $findings += [PSCustomObject]@{
                Issue = "No custom IAM roles found"
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
