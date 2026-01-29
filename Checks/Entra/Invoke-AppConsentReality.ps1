<#
.SYNOPSIS
    Microsoft 365 App Consent Patterns Detection.

.DESCRIPTION
    Detects applications that users have consented to in Entra ID.
    Identifies over-privileged apps, admin vs user consent patterns,
    and risky permission scopes granted to third-party applications.

.OUTPUTS
    - JSON report
    - HTML report
    - Log file

.NOTES
    Author: mark.ahearne@identityfirst.net | Owner: IdentityFirst Ltd
    Safety: Read-only. No changes to app registrations or consent grants.
    Requires: Microsoft Graph with "Directory.Read.All", "User.Read.All", "Application.Read.All"
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path $PWD "IFQC-Output"),
    
    [Parameter()]
    [ValidateSet("Normal","Detailed")]
    [string]$DetailLevel = "Normal"
)

$modulePath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $modulePath "Module\IdentityFirst.QuickChecks.psm1") -Force

$ctx = New-IFQCContext -ToolName "AppConsentReality" -OutputDirectory $OutputDirectory -DetailLevel $DetailLevel
Add-IFQCNote -Context $ctx -Note "Read-only detection of application consent patterns."
Add-IFQCNote -Context $ctx -Note "Does not modify or revoke any application permissions."
Add-IFQCNote -Context $ctx -Note "Shows which apps users have consented to and their permission scopes."

function Get-EvidenceLimit {
    param([string]$DetailLevel)
    if ($DetailLevel -eq "Detailed") { return 50 }
    return 15
}

Invoke-IFQCSafe -Context $ctx -Name "App consent patterns detection" -Block {
    try {
        Import-Module Microsoft.Graph.Applications -Force -ErrorAction Stop
        Import-Module Microsoft.Graph.Identity.DirectoryManagement -Force -ErrorAction Stop
        Connect-MgGraph -Scopes "Directory.Read.All", "User.Read.All", "Application.Read.All" -ErrorAction Stop | Out-Null
    } catch {
        throw "Microsoft Graph modules required. Install Microsoft.Graph and connect first."
    }
    
    $ctx.Data.connected = $true
    
    # High-risk permission scopes to watch for
    $highRiskScopes = @(
        "User.ReadWrite.All",           # Write to all user accounts
        "Directory.ReadWrite.All",      # Full directory access
        "Files.ReadWrite.All",          # All file access
        "Mail.ReadWrite",               # Read/write all mail
        "Sites.ReadWrite.All",          # All SharePoint sites
        "Teamwork.ReadWrite.All",       # Teams management
        "Calendars.ReadWrite",          # Modify calendars
        "Contacts.ReadWrite",           # Modify contacts
        "Directory.AccessAsUser.All"    # Act as directory
    )
    
    $moderateRiskScopes = @(
        "User.Read",                    # Sign in and read profile
        "User.ReadBasic.All",           # Read basic profiles
        "Mail.Read",                    # Read mail
        "Files.Read",                   # Read files
        "Sites.Read.All"                # Read SharePoint sites
    )
    
    # Collect consent grants
    $consentGrants = @{
        byUser = @{}      # User consents
        byApp = @{}       # Aggregated by app
        totalGrants = 0
        highRiskApps = @()
        adminConsents = @()
        userConsents = @()
    }
    
    Write-IFQCLog -Context $ctx -Level INFO -Message "Fetching service principal consent grants..."
    
    # Get all service principals with oauth2 permission grants
    try {
        $servicePrincipals = Get-MgServicePrincipal -All -ErrorAction SilentlyContinue
        
        foreach ($sp in $servicePrincipals) {
            $appId = $sp.AppId
            $displayName = $sp.DisplayName
            
            # Get app owner
            $owners = Get-MgServicePrincipalOwner -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue
            $ownerCount = ($owners | Measure-Object).Count
            
            # Check for admin consent (permissions that don't require user assignment)
            $hasHighRiskPermissions = $false
            $permissionDetails = @()
            
            if ($sp.Oauth2PermissionScopes) {
                foreach ($scope in $sp.Oauth2PermissionScopes) {
                    $scopeId = $scope.Id
                    $scopeValue = $scope.Value
                    $isAdminConsentRequired = $scope.IsAdminConsentRequired
                    
                    $permInfo = [PSCustomObject]@{
                        Scope = $scopeValue
                        AdminConsentRequired = $isAdminConsentRequired
                        IsEnabled = $scope.IsEnabled
                    }
                    $permissionDetails += $permInfo
                    
                    if ($scopeValue -in $highRiskScopes -and $scope.IsEnabled) {
                        $hasHighRiskPermissions = $true
                    }
                }
            }
            
            # Check delegated permissions used
            $delegatedPermissions = @()
            if ($sp.AppRoles | Where-Object { $_.AllowedMemberTypes -contains "User" }) {
                foreach ($role in $sp.AppRoles | Where-Object { $_.AllowedMemberTypes -contains "User" }) {
                    $delegatedPermissions += [PSCustomObject]@{
                        Role = $role.DisplayName
                        Value = $role.Value
                        Description = $role.Description
                    }
                }
            }
            
            # Store app info
            $consentGrants.byApp[$appId] = [PSCustomObject]@{
                AppId = $appId
                DisplayName = $displayName
                Owners = $ownerCount
                HasHighRiskPermissions = $hasHighRiskPermissions
                PermissionDetails = $permissionDetails
                DelegatedPermissions = $delegatedPermissions
            }
            
            if ($hasHighRiskPermissions) {
                $consentGrants.highRiskApps += [PSCustomObject]@{
                    AppId = $appId
                    DisplayName = $displayName
                    Owners = $ownerCount
                    Permissions = ($permissionDetails | Where-Object { $_.Scope -in $highRiskScopes } | ForEach-Object { $_.Scope })
                }
            }
        }
    } catch {
        Write-IFQCLog -Context $ctx -Level WARN -Message "Failed to fetch service principals: $($_.Exception.Message)"
    }
    
    # Get user consent requests (if available)
    Write-IFQCLog -Context $ctx -Level INFO -Message "Fetching user consent requests..."
    try {
        $consentRequests = Get-MgUserConsentRequest -All -ExpandProperty "app" -ErrorAction SilentlyContinue
        foreach ($req in $consentRequests) {
            $consentGrants.userConsents += [PSCustomObject]@{
                UserId = $req.UserId
                AppDisplayName = $req.AppDisplayName
                AppId = $req.AppId
                Status = $req.Status
                CreatedDateTime = $req.CreatedDateTime
            }
        }
    } catch {
        Write-IFQCLog -Context $ctx -Level WARN -Message "Failed to fetch consent requests: $($_.Exception.Message)"
    }
    
    # Get oauth2 permission grants (specific consent grants)
    Write-IFQCLog -Context $ctx -Level INFO -Message "Fetching oauth2 permission grants..."
    try {
        $oauthGrants = Get-MgOauth2PermissionGrant -All -ErrorAction SilentlyContinue
        foreach ($grant in $oauthGrants) {
            $consentGrants.byUser[$grant.Id] = [PSCustomObject]@{
                ClientId = $grant.ClientId
                ResourceId = $grant.ResourceId
                Scope = $grant.Scope
                ConsentType = $grant.ConsentType  # Principal, Global, or Specific
                PrincipalId = $grant.PrincipalId
            }
            
            if ($grant.ConsentType -eq "Global") {
                $sp = Get-MgServicePrincipal -Filter "AppId eq '$($grant.ClientId)'" -ErrorAction SilentlyContinue
                $consentGrants.adminConsents += [PSCustomObject]@{
                    GrantId = $grant.Id
                    ClientId = $grant.ClientId
                    ClientName = $sp.DisplayName
                    Scope = $grant.Scope
                }
            }
        }
    } catch {
        Write-IFQCLog -Context $ctx -Level WARN -Message "Failed to fetch oauth2 grants: $($_.Exception.Message)"
    }
    
    $consentGrants.totalGrants = ($consentGrants.byUser.Keys | Measure-Object).Count
    
    $ctx.Data.consents = $consentGrants
    
    # ---------------------------
    # Findings
    # ---------------------------
    $evidenceLimit = Get-EvidenceLimit -DetailLevel $DetailLevel
    
    # Finding: Apps with high-risk permissions
    if ($consentGrants.highRiskApps.Count -gt 0) {
        Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
            -Id "APP-CONSENT-HIGHRISK" `
            -Title "Applications with high-risk permissions detected" `
            -Severity "High" `
            -Description "$($consentGrants.highRiskApps.Count) applications have been granted high-risk permission scopes (User.ReadWrite.All, Directory.ReadWrite.All, etc.)." `
            -Count $consentGrants.highRiskApps.Count `
            -Evidence ($consentGrants.highRiskApps | Select-Object -First $evidenceLimit) `
            -Recommendation "Review each high-risk application. Verify business need. Remove unnecessary permissions. Consider restricting to specific users."
        )
    }
    
    # Finding: Global admin consents
    if ($consentGrants.adminConsents.Count -gt 0) {
        Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
            -Id "APP-CONSENT-ADMIN" `
            -Title "Global admin consent grants detected" `
            -Severity "Medium" `
            -Description "$($consentGrants.adminConsents.Count) applications have been granted admin consent for the entire organisation." `
            -Count $consentGrants.adminConsents.Count `
            -Evidence ($consentGrants.adminConsents | Select-Object -First $evidenceLimit) `
            -Recommendation "Review global consent grants. Ensure they are documented and approved. Consider shifting to specific user/group consent."
        )
    }
    
    # Finding: Apps with no owners
    $orphanApps = $consentGrants.byApp.Values | Where-Object { $_.Owners -eq 0 }
    if ($orphanApps.Count -gt 0) {
        Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
            -Id "APP-CONSENT-ORPHAN" `
            -Title "Applications with no owners detected" `
            -Severity "Low" `
            -Description "$($orphanApps.Count) applications have no assigned owners. These may be orphaned or shadow IT." `
            -Count $orphanApps.Count `
            -Evidence ($orphanApps | Select-Object -First $evidenceLimit) `
            -Recommendation "Assign owners to all applications. Remove applications that are no longer needed."
        )
    }
    
    # Summary stats
    $ctx.Data.summary = @{
        totalServicePrincipals = ($consentGrants.byApp.Keys | Measure-Object).Count
        highRiskApps = $consentGrants.highRiskApps.Count
        adminConsents = $consentGrants.adminConsents.Count
        userConsentRequests = $consentGrants.userConsents.Count
        oauthGrants = $consentGrants.totalGrants
    }
}

$output = Save-IFQCReport -Context $ctx

Write-Host ""
Write-Host "AppConsentReality check complete." -ForegroundColor Green
Write-Host "  JSON: $($output.Json)" -ForegroundColor Cyan
Write-Host "  HTML: $($output.Html)" -ForegroundColor Cyan

# Cleanup
try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
