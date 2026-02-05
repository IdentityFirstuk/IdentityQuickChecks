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

function Invoke-EntraRoleAssignments {
    <#
    .SYNOPSIS
        Analyzes Entra ID directory role assignments for over-privileged users.
    
    .DESCRIPTION
        This read-only check reviews directory role assignments to identify
        users with excessive administrative privileges.
    
    .PARAMETER OutputPath
        Path to save the results JSON file.
    
    .PARAMETER Export
        Export format: JSON, HTML, or None.
    
    .EXAMPLE
        Invoke-EntraRoleAssignments -OutputPath ".\Reports"
    
    .NOTES
        Read-only check - requires Microsoft.Graph module.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = ".\Reports",
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('JSON', 'HTML', 'None')]
        [string]$Export = 'JSON'
    )
    
    $checkName = "Invoke-EntraRoleAssignments"
    $checkCategory = "Entra"
    $findings = @()
    $startTime = Get-Date
    
    try {
        # Check for Microsoft.Graph module
        $graphModule = Get-Module -Name Microsoft.Graph -ListAvailable -ErrorAction SilentlyContinue
        if (-not $graphModule) {
            return [PSCustomObject]@{
                CheckName = $checkName
                Category = $checkCategory
                Status = "Error"
                FindingCount = 0
                Findings = @()
                StartTime = $startTime
                EndTime = Get-Date
                Duration = 0
                Error = "Microsoft.Graph module not installed"
            }
        }
        
        # Connect to Graph if not connected
        try {
            $null = Get-MgContext -ErrorAction Stop
        }
        catch {
            Connect-MgGraph -Scopes "RoleManagement.Read.Directory" -ErrorAction Stop | Out-Null
        }
        
        # Sensitive roles to flag
        $sensitiveRoles = @(
            "Global Administrator",
            "Privileged Role Administrator",
            "Security Administrator",
            "Exchange Administrator",
            "SharePoint Administrator",
            "User Administrator",
            "Billing Administrator",
            "Conditional Access Administrator",
            "Security Reader"
        )
        
        # Get all directory roles
        $roles = Get-MgDirectoryRole 2>$null
        
        if ($roles) {
            foreach ($role in $roles) {
                $roleTemplateId = $role.RoleTemplateId
                $displayName = $role.DisplayName
                
                # Get members of this role
                $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -ErrorAction SilentlyContinue
                
                if ($members) {
                    foreach ($member in $members) {
                        $isPrivileged = $sensitiveRoles -contains $displayName
                        
                        $findings += [PSCustomObject]@{
                            UserId = $member.Id
                            UserDisplayName = $member.AdditionalProperties.displayName
                            UserPrincipalName = $member.AdditionalProperties.userPrincipalName
                            RoleName = $displayName
                            RoleId = $roleTemplateId
                            IsSensitiveRole = $isPrivileged
                            RiskLevel = if ($isPrivileged) { "High" } else { "Medium" }
                            Recommendation = if ($isPrivileged) { "Review necessity of privileged role assignment" } else { "No immediate action required" }
                        }
                    }
                }
            }
            
            # Summary
            $privilegedCount = ($findings | Where-Object { $_.IsSensitiveRole -eq $true }).Count
            $findings += [PSCustomObject]@{
                Summary = "Directory Role Assignment Review"
                TotalRoleAssignments = $findings.Count
                PrivilegedAssignments = $privilegedCount
                UniquePrivilegedUsers = ($findings | Where-Object { $_.IsSensitiveRole -eq $true } | Select-Object -Property UserId -Unique).Count
                RiskLevel = if ($privilegedCount -gt 10) { "High" } elseif ($privilegedCount -gt 5) { "Medium" } else { "Low" }
                Recommendation = "Implement Privileged Identity Management for privileged roles"
            }
        }
        else {
            $findings += [PSCustomObject]@{
                Issue = "No directory roles found or unable to retrieve"
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
