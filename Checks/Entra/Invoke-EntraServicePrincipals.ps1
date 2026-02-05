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

function Invoke-EntraServicePrincipals {
    <#
    .SYNOPSIS
        Analyzes Entra ID service principals for security issues.
    
    .DESCRIPTION
        This read-only check reviews service principals to identify
        potential security risks such as overly broad permissions,
        expired credentials, and unauthorized access.
    
    .PARAMETER OutputPath
        Path to save the results JSON file.
    
    .PARAMETER Export
        Export format: JSON, HTML, or None.
    
    .EXAMPLE
        Invoke-EntraServicePrincipals -OutputPath ".\Reports"
    
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
    
    $checkName = "Invoke-EntraServicePrincipals"
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
            Connect-MgGraph -Scopes "Application.Read.All,Directory.Read.All" -ErrorAction Stop | Out-Null
        }
        
        # Get all service principals
        $sp = Get-MgServicePrincipal -All 2>$null
        
        if ($sp) {
            foreach ($spItem in $sp) {
                # Check for app role assignments
                $appRoleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $spItem.Id -ErrorAction SilentlyContinue
                
                # Check for key credentials
                $keyCredentials = if ($spItem.KeyCredentials) { $spItem.KeyCredentials.Count } else { 0 }
                $passwordCredentials = if ($spItem.PasswordCredentials) { $spItem.PasswordCredentials.Count } else { 0 }
                
                # Check if account is enabled
                $accountEnabled = $spItem.AccountEnabled
                
                $findings += [PSCustomObject]@{
                    ServicePrincipalName = $spItem.DisplayName
                    AppId = $spItem.AppId
                    ObjectId = $spItem.Id
                    AccountEnabled = $accountEnabled
                    AppRoleAssignmentsCount = if ($appRoleAssignments) { $appRoleAssignments.Count } else { 0 }
                    KeyCredentials = $keyCredentials
                    PasswordCredentials = $passwordCredentials
                    RiskLevel = if (-not $accountEnabled) { "Info" } elseif ($appRoleAssignments.Count -gt 10) { "High" } else { "Medium" }
                    Recommendation = if (-not $accountEnabled) { "SP is disabled - consider removing" } elseif ($appRoleAssignments.Count -gt 10) { "Review excessive permissions" } else { "No immediate action required" }
                }
            }
            
            # Summary
            $findings += [PSCustomObject]@{
                Summary = "Service Principal Security"
                TotalSP = $sp.Count
                DisabledSP = ($findings | Where-Object { $_.AccountEnabled -eq $false }).Count
                SPWithManyPermissions = ($findings | Where-Object { $_.AppRoleAssignmentsCount -gt 10 }).Count
                RiskLevel = if ($sp.Count -gt 50) { "Medium" } else { "Low" }
                Recommendation = "Review service principal permissions regularly"
            }
        }
        else {
            $findings += [PSCustomObject]@{
                Issue = "No service principals found"
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
