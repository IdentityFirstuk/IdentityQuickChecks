<#
.SYNOPSIS
    Azure AD Connect Hybrid Sync Reality Check.

.DESCRIPTION
    Checks Azure AD Connect sync status, connector health, and attribute flow patterns.
    Identifies sync issues, attribute drift, and staging concerns.

.OUTPUTS
    - JSON report
    - HTML report
    - Log file

.NOTES
    Author: mark.ahearne@identityfirst.net | Owner: IdentityFirst Ltd
    Safety: Read-only. No changes to sync configuration.
    Requires: AzureAD module (Get-Msol* cmdlets) or Microsoft Graph
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

$ctx = New-IFQCContext -ToolName "HybridSyncReality" -OutputDirectory $OutputDirectory -DetailLevel $DetailLevel
Add-IFQCNote -Context $ctx -Note "Read-only check of Azure AD Connect sync status."
Add-IFQCNote -Context $ctx -Note "Does not modify sync rules or force synchronisation."
Add-IFQCNote -Context $ctx -Note "Uses Azure AD module or Microsoft Graph for visibility."

function Get-EvidenceLimit {
    param([string]$DetailLevel)
    if ($DetailLevel -eq "Detailed") { return 50 }
    return 15
}

Invoke-IFQCSafe -Context $ctx -Name "Hybrid sync reality check" -Block {
    $useGraph = $false
    $useMsol = $false
    
    # Try MSOL first (classic), then Graph
    try {
        if (Get-Module -ListAvailable -Name AzureAD -ErrorAction SilentlyContinue) {
            Import-Module AzureAD -ErrorAction Stop
            $useMsol = $true
            $ctx.Data.method = "AzureAD (MSOnline)"
        }
    } catch { }
    
    if (-not $useMsol) {
        try {
            if (Get-Module -ListAvailable -Name Microsoft.Graph.Identity.DirectoryManagement -ErrorAction SilentlyContinue) {
                Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop
                Connect-MgGraph -Scopes "Directory.Read.All" -ErrorAction Stop | Out-Null
                $useGraph = $true
                $ctx.Data.method = "Microsoft Graph"
            }
        } catch { }
    }
    
    if (-not $useMsol -and -not $useGraph) {
        throw "Neither AzureAD module nor Microsoft Graph available. Install AzureAD or Microsoft.Graph modules."
    }
    
    $ctx.Data.connected = $true
    
    # Get sync status
    $syncStatus = @{
        lastSyncTime = $null
        syncEnabled = $null
        connectorInfo = @()
        syncErrors = @()
    }
    
    if ($useMsol) {
        try {
            $dirSync = Get-MsolDirSyncStatus -ErrorAction SilentlyContinue
            if ($dirSync) {
                $syncStatus.lastSyncTime = $dirSync.LastSyncDateTime
                $syncStatus.syncEnabled = $true
                $ctx.Data.tenantId = $dirSync.TenantId
            }
            
            # Get connector configuration
            $connectors = Get-MsolConnector -ErrorAction SilentlyContinue
            foreach ($c in $connectors) {
                $syncStatus.connectorInfo += [PSCustomObject]@{
                    Name = $c.Name
                    Type = $c.Type
                    LastSync = $c.LastSyncTime
                    ConnectorVersion = $c.ConnectorVersion
                }
            }
            
            # Check for sync errors
            $syncErrors = Get-MsolDirSyncConfiguration -ErrorAction SilentlyContinue | Where-Object {$_.Errors}
            foreach ($e in $syncErrors) {
                $syncStatus.syncErrors += $e.Errors
            }
        } catch {
            Write-IFQCLog -Context $ctx -Level WARN -Message "MSOL commands failed: $($_.Exception.Message)"
        }
    }
    
    if ($useGraph) {
        try {
            # Get directory sync configuration via Graph
            $organization = Get-MgOrganization -ErrorAction SilentlyContinue
            if ($organization) {
                $ctx.Data.tenantId = $organization.Id
                $ctx.Data.tenantName = $organization.DisplayName
                
                # Check if directory sync is enabled
                $dirSync = $organization.DirectorySynchronizationEnabled
                $syncStatus.syncEnabled = $dirSync
                
                if ($organization.DirectorySynchronizationLastUpdatedDateTime) {
                    $syncStatus.lastSyncTime = $organization.DirectorySynchronizationLastUpdatedDateTime
                }
            }
            
            # Get synchronization metadata
            $syncQuotas = Get-MgDirectorySynchronizationQuota -All -ErrorAction SilentlyContinue
            foreach ($q in $syncQuotas) {
                $syncStatus.connectorInfo += [PSCustomObject]@{
                    ServicePrincipal = $q.ServicePrincipal
                    Status = $q.Status
                    AttributeName = $q.AttributeName
                }
            }
        } catch {
            Write-IFQCLog -Context $ctx -Level WARN -Message "Graph commands failed: $($_.Exception.Message)"
        }
    }
    
    # Store raw data
    $ctx.Data.syncStatus = $syncStatus
    
    # Check for stale sync
    $staleThreshold = (Get-Date).AddHours(-24)
    $isStaleSync = $false
    if ($syncStatus.lastSyncTime) {
        if ([DateTime]$syncStatus.lastSyncTime -lt $staleThreshold) {
            $isStaleSync = $true
        }
    }
    
    # Check for sync disabled
    $isSyncDisabled = $false
    if ($null -eq $syncStatus.syncEnabled -or $syncStatus.syncEnabled -eq $false) {
        $isSyncDisabled = $true
    }
    
    # Findings
    $evidenceLimit = Get-EvidenceLimit -DetailLevel $DetailLevel
    
    # Finding: Sync disabled
    if ($isSyncDisabled) {
        Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
            -Id "HYBRID-SYNC-DISABLED" `
            -Title "Azure AD Connect sync is disabled" `
            -Severity "High" `
            -Description "Directory synchronisation is not enabled. On-premises identities may not be provisioned in Entra ID." `
            -Count 1 `
            -Recommendation "Verify if hybrid identity is intended. If yes, enable Azure AD Connect sync."
        )
    }
    
    # Finding: Stale sync
    if ($isStaleSync) {
        $hoursStale = if ($syncStatus.lastSyncTime) {
            [Math]::Round((New-TimeSpan -Start $syncStatus.lastSyncTime -End (Get-Date)).TotalHours, 1)
        } else { "Unknown" }
        
        Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
            -Id "HYBRID-SYNC-STALE" `
            -Title "Azure AD Connect has not synced in over 24 hours" `
            -Severity "High" `
            -Description "Last sync occurred $hoursStale hours ago. Identity changes are not flowing to Entra ID." `
            -Count 1 `
            -Recommendation "Check Azure AD Connect service status. Verify no errors in event logs. Force delta sync if needed."
        )
    }
    
    # Finding: Sync errors
    if ($syncStatus.syncErrors.Count -gt 0) {
        Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
            -Id "HYBRID-SYNC-ERRORS" `
            -Title "Azure AD Connect configuration errors detected" `
            -Severity "Medium" `
            -Description "$($syncStatus.syncErrors.Count) sync configuration errors found." `
            -Count $syncStatus.syncErrors.Count `
            -Evidence ($syncStatus.syncErrors | Select-Object -First $evidenceLimit) `
            -Recommendation "Review sync errors in Azure AD Connect configuration. Common causes: attribute conflicts, rule violations."
        )
    }
    
    # Finding: Connector count
    $connectorCount = ($syncStatus.connectorInfo | Measure-Object).Count
    if ($connectorCount -eq 0) {
        Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
            -Id "HYBRID-NO-CONNECTORS" `
            -Title "No sync connectors detected" `
            -Severity "Medium" `
            -Description "Azure AD Connect appears to have no configured connectors." `
            -Count 0 `
            -Recommendation "Verify Azure AD Connect configuration includes directories to sync."
        )
    }
    
    # Summary stats
    $ctx.Data.stats = @{
        syncEnabled = $syncStatus.syncEnabled
        lastSyncTime = $syncStatus.lastSyncTime
        connectorCount = $connectorCount
        errorCount = $syncStatus.syncErrors.Count
        isStaleSync = $isStaleSync
        isSyncDisabled = $isSyncDisabled
    }
}

$output = Save-IFQCReport -Context $ctx

Write-Host ""
Write-Host "HybridSyncReality check complete." -ForegroundColor Green
Write-Host "  JSON: $($output.Json)" -ForegroundColor Cyan
Write-Host "  HTML: $($output.Html)" -ForegroundColor Cyan

# Cleanup Graph connection
try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
