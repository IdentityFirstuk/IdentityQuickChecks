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

function Invoke-EntraConditionalAccess {
    <#
    .SYNOPSIS
        Analyzes Conditional Access policies in Microsoft Entra ID.
    
    .DESCRIPTION
        This read-only check reviews Conditional Access policies to identify
        gaps in protection, overly permissive policies, or missing controls.
    
    .PARAMETER OutputPath
        Path to save the results JSON file.
    
    .PARAMETER Export
        Export format: JSON, HTML, or None.
    
    .EXAMPLE
        Invoke-EntraConditionalAccess -OutputPath ".\Reports"
    
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
    
    $checkName = "Invoke-EntraConditionalAccess"
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
                Error = "Microsoft.Graph module not installed. Run: Install-Module Microsoft.Graph"
            }
        }
        
        # Connect to Graph if not connected
        try {
            $null = Get-MgContext -ErrorAction Stop
        }
        catch {
            Connect-MgGraph -Scopes "Policy.Read.All" -ErrorAction Stop | Out-Null
        }
        
        # Get all Conditional Access policies
        $policies = Get-MgIdentityConditionalAccessPolicy -All 2>$null
        
        if ($policies) {
            foreach ($policy in $policies) {
                $status = $policy.State
                $grantControls = $policy.GrantControls
                $sessionControls = $policy.SessionControls
                
                # Check for gaps
                $findings += [PSCustomObject]@{
                    PolicyName = $policy.DisplayName
                    PolicyId = $policy.Id
                    State = $status
                    GrantControlsValue = if ($grantControls) { $grantControls.BuiltInControls } else { $null }
                    SessionControlsValue = if ($sessionControls) { $sessionControls } else { $null }
                    RiskLevel = if ($status -eq "Enabled") { "Info" } else { "Warning" }
                    Recommendation = if ($status -eq "Enabled") { "Policy is active - review regularly" } else { "Enable policy for full protection" }
                }
            }
            
            # Check for specific gaps
            $hasMFARequired = $false
            $hasBlockLegacy = $false
            $hasExclusionRisk = $false
            
            foreach ($policy in $policies) {
                if ($policy.GrantControls -and $policy.GrantControls.BuiltInControls -contains "mfa") {
                    $hasMFARequired = $true
                }
                if ($policy.Conditions -and $policy.Conditions.ClientApplications) {
                    $hasBlockLegacy = $true
                }
                if ($policy.Conditions -and $policy.Conditions.Users -and $policy.Conditions.Users.ExcludeUsers) {
                    $hasExclusionRisk = $true
                }
            }
            
            $findings += [PSCustomObject]@{
                GapAnalysis = "Conditional Access Policy Review"
                MFARequired = $hasMFARequired
                LegacyAuthBlocked = $hasBlockLegacy
                UserExclusions = $hasExclusionRisk
                TotalPolicies = $policies.Count
                RiskLevel = if (-not $hasMFARequired) { "Critical" } elseif (-not $hasBlockLegacy) { "High" } else { "Medium" }
                Recommendation = "Implement MFA requirement and block legacy authentication for all users"
            }
        }
        else {
            $findings += [PSCustomObject]@{
                Issue = "No Conditional Access policies found"
                RiskLevel = "Critical"
                Recommendation = "Implement Conditional Access policies immediately"
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
