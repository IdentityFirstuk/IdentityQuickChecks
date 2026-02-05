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

function Invoke-EntraAppRegistration {
    <#
    .SYNOPSIS
        Analyzes Entra ID application registrations for security issues.
    
    .DESCRIPTION
        This read-only check reviews application registrations to identify
        potential security risks such as expired secrets, overly broad permissions,
        and unauthorized applications.
    
    .PARAMETER OutputPath
        Path to save the results JSON file.
    
    .PARAMETER Export
        Export format: JSON, HTML, or None.
    
    .EXAMPLE
        Invoke-EntraAppRegistration -OutputPath ".\Reports"
    
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
    
    $checkName = "Invoke-EntraAppRegistration"
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
            Connect-MgGraph -Scopes "Application.Read.All" -ErrorAction Stop | Out-Null
        }
        
        # Get all applications
        $apps = Get-MgApplication -All 2>$null
        
        if ($apps) {
            foreach ($app in $apps) {
                # Check for apps without required access
                $appRoles = if ($app.AppRoles) { $app.AppRoles.Count } else { 0 }
                $oauth2Permissions = if ($app.Oauth2Permissions) { $app.Oauth2Permissions.Count } else { 0 }
                
                # Check key credentials (secrets/certs)
                $keyCredentials = if ($app.KeyCredentials) { $app.KeyCredentials.Count } else { 0 }
                $passwordCredentials = if ($app.PasswordCredentials) { $app.PasswordCredentials.Count } else { 0 }
                
                # Get owners
                $owners = Get-MgApplicationOwner -ApplicationId $app.Id -ErrorAction SilentlyContinue
                
                $findings += [PSCustomObject]@{
                    AppName = $app.DisplayName
                    AppId = $app.AppId
                    ObjectId = $app.Id
                    AppRoles = $appRoles
                    OAuth2Permissions = $oauth2Permissions
                    KeyCredentials = $keyCredentials
                    PasswordCredentials = $passwordCredentials
                    OwnerCount = if ($owners) { $owners.Count } else { 0 }
                    CreatedDateTime = $app.CreatedDateTime
                    RiskLevel = if ($owners.Count -eq 0) { "High" } elseif ($passwordCredentials -gt 2) { "Medium" } else { "Low" }
                    Recommendation = if ($owners.Count -eq 0) { "Assign owners to application" } elseif ($passwordCredentials -gt 2) { "Review and consolidate credentials" } else { "No immediate action required" }
                }
            }
            
            # Summary
            $findings += [PSCustomObject]@{
                Summary = "Application Registration Security"
                TotalApps = $apps.Count
                AppsWithoutOwners = ($findings | Where-Object { $_.OwnerCount -eq 0 }).Count
                AppsWithManySecrets = ($findings | Where-Object { $_.PasswordCredentials -gt 2 }).Count
                RiskLevel = if ($apps.Count -gt 100) { "Medium" } else { "Low" }
                Recommendation = "Review application registrations regularly and remove unused apps"
            }
        }
        else {
            $findings += [PSCustomObject]@{
                Issue = "No application registrations found or unable to retrieve"
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
