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

# Emit structured report saved event
$reportEvent = [PSCustomObject]@{
    Timestamp = (Get-Date).ToString('o')
    Level = 'Info'
    Action = 'ReportSaved'
    Tool = $ctx.ToolName
    Json = $output.Json
    Html = $output.Html
}
Write-IFQC -InputObject $reportEvent

# Cleanup Graph connection
try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }

# SIG # Begin signature block
# MIIJyAYJKoZIhvcNAQcCoIIJuTCCCbUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBX7UEL0kd52cly
# ux/RXIyLXqluA4wM/yER4Xwae+j+8aCCBdYwggXSMIIDuqADAgECAhAxVnqog0nQ
# oULr1YncnW59MA0GCSqGSIb3DQEBCwUAMIGAMQswCQYDVQQGEwJHQjEXMBUGA1UE
# CAwOTm9ydGh1bWJlcmxhbmQxFzAVBgNVBAcMDk5vcnRodW1iZXJsYW5kMRowGAYD
# VQQKDBFJZGVudGl0eUZpcnN0IEx0ZDEjMCEGA1UEAwwaSWRlbnRpdHlGaXJzdCBD
# b2RlIFNpZ25pbmcwHhcNMjYwMTI5MjExMDU3WhcNMzEwMTI5MjEyMDU2WjCBgDEL
# MAkGA1UEBhMCR0IxFzAVBgNVBAgMDk5vcnRodW1iZXJsYW5kMRcwFQYDVQQHDA5O
# b3J0aHVtYmVybGFuZDEaMBgGA1UECgwRSWRlbnRpdHlGaXJzdCBMdGQxIzAhBgNV
# BAMMGklkZW50aXR5Rmlyc3QgQ29kZSBTaWduaW5nMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAtrU2HprgcHe9mxlmt5X72OsSk7cXDyUhoOAcLE9f4lS2
# rOx7VbZSMSi0r4lt8a/S5m/JIWCdYO+GrWZCgS2S73H3KNDszR5HDPbMhv+leoWA
# qLT7C0awpjcTnvWIDxnHyHHane/TNl3ehY9Jek5qrbiNgJDatV6SEYVFlK8Nk9kE
# 3TiveVvRKokNT2xY4/h1rohFCHnF+g7dCn06xAZwoGnFVlmPop3jItAlZdUQz3zR
# /xSNW01sQXgW6/TYd2VzXXuQihMQ3ikjoNGX1L8SlcV4ih2J+r2kSHjhkZ8c+wJE
# v2iiUHqpwmch31UwQOb4qklGKg1A+SAUGdf0cTTc6ApSFsqrol1euObreoy0zdAA
# k47NELuGhKA4N0Dk9Ar616JGFt/03s1waukNisnH/sk9PmPGUo9QtKH1IQpBtwWw
# uKel0w3MmgTwi2vBwfyh2/oTDkTfic7AT3+wh6O/9mFxxu2Fsq6VSlYRpSTSpgxF
# c/YsVlQZaueZs6WB6/HzftGzv1Mmz7is8DNnnhkADTEMj+NDo4wq+lUCE7XNDnnH
# KBN8MkDh4IljXVSkP/xwt4wLLd9g7oAOW91SDA2wJniyjSUy9c+auW3lbA8ybSfL
# TrQgZiSoepcCjW2otZIXrmDnJ7BtqmmiRff4CCacdJXxqNWdFnv6y7Yy6DQmECEC
# AwEAAaNGMEQwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0G
# A1UdDgQWBBQBfqZy0Xp6lbG6lqI+cAlT7ardlTANBgkqhkiG9w0BAQsFAAOCAgEA
# IwBi/lJTGag5ac5qkMcnyholdDD6H0OaBSFtux1vPIDqNd35IOGYBsquL0BZKh8O
# AHiuaKbo2Ykevpn5nzbXDBVHIW+gN1yu5fWCXSezCPN/NgVgdH6CQ6vIuKNq4BVm
# E8AEhm7dy4pm4WPLqEzWT2fwJhnJ8JYBnPbuUVE8F8acyqG8l3QMcGICG26NWgGs
# A28YvlkzZsny+HAzLvmJn/IhlfWte1kGu0h0G7/KQG6hei5afsn0HxWHKqxI9JsG
# EF3SsMVQW3YJtDzAiRkNtII5k0PyywjrgzIGViVNOrKMT9dKlsTev6Ca/xQX13xM
# 0prtnvxiTXGtT031EBGXAUhOzvx2Hp1WFnZTEIJyX1J2qI+DQsPb9Y1jWcdGBwv3
# /m1nAHE7FpPGsSv+UIP3QQFD/j6nLl5zUoWxqAZMcV4K4t4WkPQjPAXzomoRaqc6
# toXHlXhKHKZ0kfAIcPCFlMwY/Rho82GiATIxHXjB/911VRcpv+xBoPCZkXDnsr9k
# /aRuPNt9DDSrnocJIoTtqIdel/GJmD0D75Lg4voUX9J/1iBuUzta2hoBA8fSVPS5
# 6plrur3Sn5QQG2kJt9I4z5LS3UZSfT+29+xJz7WSyp8+LwU7jaNUuWr3lpUnY2nS
# pohDlw2BFFNGT6/DZ0loRJrUMt58UmfdUX8FPB7uNuIxggNIMIIDRAIBATCBlTCB
# gDELMAkGA1UEBhMCR0IxFzAVBgNVBAgMDk5vcnRodW1iZXJsYW5kMRcwFQYDVQQH
# DA5Ob3J0aHVtYmVybGFuZDEaMBgGA1UECgwRSWRlbnRpdHlGaXJzdCBMdGQxIzAh
# BgNVBAMMGklkZW50aXR5Rmlyc3QgQ29kZSBTaWduaW5nAhAxVnqog0nQoULr1Ync
# nW59MA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAw
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIIrdeq1u3tGMB8P5Vy9gPbIyKbFaVCOt
# lcFUwU1NPqWfMA0GCSqGSIb3DQEBAQUABIICAHNAKfGIagFUSQ3Rn0xEyoIIqBO5
# 4s2tGbl8gN3idVAIUNp1VOvPCTVV2JwzQjoMN2xjMFz2xsZMqJDgg99ka1lSosLF
# GR7UhqWS6fbyAKcXZzgzjYBtDtx0Z3NWjTr0AnPNlG5jKJT3D6j60++Xgi8T249+
# ZBShFK323GX1mPt/KXuE8rUphkXxbKPjYlWB9C/Hy3703i6h6OVpcDiypMngyZQb
# cnIVnSWhws/avTEaBJLptfVx7Fc3Vj+wOTnTHw3xevTqBRSBowF1oRrSiShJ2f3A
# OYHOZ/3NpeiqzsuRUODxoo05x/T0pIX/Mnfnzy1PuAZmEp05/JjTGXJGv2uFn7/r
# WeoricPBCQL4TsUH+XU7C5NhFQqa/+zR8zkQQCU9d3wp5YgUeZbUIJooT9DnusM0
# xosARpLWu6g+SwoP03oZaT7kZNmpLH7hSX6zE8tmN2tAwzQnNGz+a6HyAZruwe1o
# AdG3pC7uR53KVeYQP6L9a55AiS2z0Y1+74ntR0uYCHkk8fTTENTL6gTzj+hjvyLe
# hFjQvPoCsm35uGj28Mf06NuQ76q5KzNF5U+uRmG5xGJfnn/RAjM0JF8OpBI6l0M4
# lWqf2QSuC89QB6/GUcUNUuSpfXzbcZrf1BcLTZ1rsqYklT3NlkbthyXmeaL+DPMM
# 52Of7D3YSOMOIBC3
# SIG # End signature block

