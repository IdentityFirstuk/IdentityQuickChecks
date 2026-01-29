<#
.SYNOPSIS
    Legacy Authentication Detection - Basic Auth, SMTP, IMAP, POP3, etc.

.DESCRIPTION
    Detects legacy authentication protocols being used in Entra ID.
    Legacy auth (basic auth, SMTP, IMAP, POP3, EAS, EWS, PowerShell) bypass 
    Modern Authentication and is a common attack vector.

.OUTPUTS
    - JSON report
    - HTML report
    - Log file

.NOTES
    Author: mark.ahearne@identityfirst.net | Owner: IdentityFirst Ltd
    Safety: Read-only. No changes to authentication policies.
    Requires: Microsoft Graph with "AuditLog.Read.All" and "Directory.Read.All"
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path $PWD "IFQC-Output"),
    
    [Parameter()]
    [ValidateSet("Normal","Detailed")]
    [string]$DetailLevel = "Normal",
    
    [Parameter()]
    [int]$LookbackDays = 30
)

$modulePath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $modulePath "Module\IdentityFirst.QuickChecks.psm1") -Force

$ctx = New-IFQCContext -ToolName "LegacyAuthReality" -OutputDirectory $OutputDirectory -DetailLevel $DetailLevel
Add-IFQCNote -Context $ctx -Note "Read-only detection of legacy authentication usage."
Add-IFQCNote -Context $ctx -Note "Does not block or modify authentication methods."
Add-IFQCNote -Context $ctx -Note "Legacy auth includes: Basic Auth, SMTP, IMAP, POP3, EAS, EWS, PowerShell."
Add-IFQCNote -Context $ctx -Note "Requires Microsoft Graph with AuditLog.Read.All permission."

function Get-EvidenceLimit {
    param([string]$DetailLevel)
    if ($DetailLevel -eq "Detailed") { return 50 }
    return 15
}

Invoke-IFQCSafe -Context $Context $ctx -Name "Legacy authentication detection" -Block {
    try {
        Import-Module Microsoft.Graph.Identity.DirectoryManagement -Force -ErrorAction Stop
        Import-Module Microsoft.Graph.Reports -Force -ErrorAction Stop
        Connect-MgGraph -Scopes "AuditLog.Read.All", "Directory.Read.All" -ErrorAction Stop | Out-Null
    } catch {
        throw "Microsoft Graph modules required. Install Microsoft.Graph and connect first."
    }
    
    $ctx.Data.connected = $true
    $ctx.Data.lookbackDays = $LookbackDays
    
    $startDate = (Get-Date).AddDays(-$LookbackDays).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $ctx.Data.startDate = $startDate
    
    # Define legacy auth protocols
    $legacyProtocols = @{
        "SMTP" = "SMTP protocol authentication"
        "IMAP" = "IMAP protocol authentication"
        "POP"  = "POP protocol authentication"
        "EAS"  = "Exchange ActiveSync"
        "EWS"  = "Exchange Web Services"
        "PowerShell" = "Remote PowerShell (basic auth)"
        "BasicAuth" = "Basic authentication (generic)"
        "MAPI" = "MAPI over HTTP"
    }
    
    $legacyUsage = @{}
    foreach ($proto in $legacyProtocols.Keys) {
        $legacyUsage[$proto] = @{
            users = @()
            count = 0
            lastSeen = $null
        }
    }
    
    Write-IFQCLog -Context $ctx -Level INFO -Message "Querying sign-in logs for legacy auth..."
    
    # Query all sign-ins (this can take time for large tenants)
    $allSignIns = @()
    try {
        # Get the last 30 days of non-interactive sign-ins where legacy auth was used
        $signIns = Get-MgAuditLogSignIn `
            -Filter "createdDateTime gt $startDate and clientAppUsed ne 'Browser' and clientAppUsed ne 'MobileApps'" `
            -All `
            -ErrorAction SilentlyContinue
        
        $allSignIns = $signIns
    } catch {
        Write-IFQCLog -Context $ctx -Level WARN -Message "Failed to query sign-ins: $($_.Exception.Message)"
        # Try broader query
        try {
            $allSignIns = Get-MgAuditLogSignIn -Filter "createdDateTime gt $startDate" -All -ErrorAction SilentlyContinue
        } catch {
            Write-IFQCLog -Context $ctx -Level ERROR -Message "All sign-in queries failed"
        }
    }
    
    Write-IFQCLog -Context $ctx -Level INFO -Message "Processing $($allSignIns.Count) sign-in records..."
    
    foreach ($signIn in $allSignIns) {
        $clientApp = $signIn.ClientAppUsed
        $user = $signIn.UserPrincipalName
        $created = [DateTime]$signIn.CreatedDateTime
        
        # Detect legacy auth based on client app or auth methods
        $isLegacy = $false
        $detectedProtocols = @()
        
        # Check client app used
        foreach ($proto in $legacyProtocols.Keys) {
            if ($clientApp -match $proto -or $clientApp -match $legacyProtocols[$proto]) {
                $isLegacy = $true
                $detectedProtocols += $proto
            }
        }
        
        # Check for basic auth in authentication methods
        $authMethods = $signIn.AuthenticationMethodsUsed
        if ($authMethods -contains "Password" -and $authMethods.Count -eq 1) {
            # Single factor password only - could be legacy
            if ($clientApp -match "Mobile|Desktop|App") {
                $isLegacy = $true
                $detectedProtocols += "BasicAuth"
            }
        }
        
        # Check for legacy client
        $legacyClients = @("Exchange ActiveSync", "IMAP", "POP", "SMTP", "MAPI", "Exchange Web Services")
        foreach ($client in $legacyClients) {
            if ($clientApp -match $client) {
                $isLegacy = $true
                $protoName = $client -replace " Exchange| protocol| over HTTP", ""
                if (-not ($detectedProtocols -contains $protoName)) {
                    $detectedProtocols += $protoName
                }
            }
        }
        
        if ($isLegacy) {
            foreach ($proto in $detectedProtocols) {
                if ($legacyUsage.ContainsKey($proto)) {
                    # Check if user already recorded
                    $existing = $legacyUsage[$proto].users | Where-Object { $_.UserPrincipalName -eq $user }
                    if (-not $existing) {
                        $legacyUsage[$proto].users += [PSCustomObject]@{
                            UserPrincipalName = $user
                            DisplayName = $signIn.UserDisplayName
                            LastSignIn = $created
                            ClientApp = $clientApp
                            IPAddress = $signIn.IPAddress
                            Location = $signIn.Location.City + ", " + $signIn.Location.State + ", " + $signIn.Location.CountryOrRegion
                        }
                    }
                    
                    # Update last seen
                    if ($null -eq $legacyUsage[$proto].lastSeen -or $created -gt $legacyUsage[$proto].lastSeen) {
                        $legacyUsage[$proto].lastSeen = $created
                    }
                }
            }
        }
    }
    
    # Count per protocol
    foreach ($proto in $legacyUsage.Keys) {
        $legacyUsage[$proto].count = ($legacyUsage[$proto].users | Measure-Object).Count
    }
    
    $ctx.Data.protocols = $legacyUsage
    $ctx.Data.totalLegacyUsers = (($legacyUsage.Values | ForEach-Object { $_.users.UserPrincipalName }) | Sort-Object -Unique).Count
    
    # ---------------------------
    # Findings
    # ---------------------------
    $evidenceLimit = Get-EvidenceLimit -DetailLevel $DetailLevel
    $totalLegacyEvents = ($legacyUsage.Values | Measure-Object -Property count -Sum).Sum
    
    # Finding: Any legacy auth detected
    if ($totalLegacyEvents -gt 0) {
        $highRiskProtocols = @("SMTP", "IMAP", "POP", "EAS")
        $hasHighRisk = $false
        foreach ($proto in $highRiskProtocols) {
            if ($legacyUsage[$proto].count -gt 0) {
                $hasHighRisk = $true
                break
            }
        }
        
        $severity = if ($hasHighRisk) { "High" } else { "Medium" }
        
        $protoSummary = ($legacyUsage.Keys | Where-Object { $legacyUsage[$_].count -gt 0 } | ForEach-Object {
            "$($_): $($legacyUsage[$_].count) users"
        }) -join ", "
        
        Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
            -Id "LEGACY-AUTH-DETECTED" `
            -Title "Legacy authentication usage detected" `
            -Severity $severity `
            -Description "Legacy authentication protocols are being used in your tenant. $totalLegacyEvents events from $($ctx.Data.totalLegacyUsers) unique users.`n`n$protoSummary" `
            -Count $ctx.Data.totalLegacyUsers `
            -Evidence ($legacyUsage.Keys | Where-Object { $legacyUsage[$_].count -gt 0-Object {
                $ } | ForEachproto = $_
                $legacyUsage[$proto].users | Select-Object -First $evidenceLimit | ForEach-Object {
                    [PSCustomObject]@{
                        Protocol = $proto
                        UserPrincipalName = $_.UserPrincipalName
                        LastSignIn = $_.LastSignIn
                        ClientApp = $_.ClientApp
                        IPAddress = $_.IPAddress
                    }
                }
            }) `
            -Recommendation "Plan migration to Modern Authentication. Block legacy auth in Conditional Access policies. Notify users of deprecated clients."
        )
    } else {
        # Finding: No legacy auth (good news)
        Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
            -Id "LEGACY-AUTH-CLEAN" `
            -Title "No legacy authentication detected" `
            -Severity "Low" `
            -Description "No legacy authentication events were found in the past $LookbackDays days." `
            -Count 0 `
            -Recommendation "Continue monitoring. Ensure Conditional Access policies block legacy auth."
        )
    }
    
    # Summary stats
    $ctx.Data.summary = @{
        totalLegacyUsers = $ctx.Data.totalLegacyUsers
        totalEvents = $totalLegacyEvents
        byProtocol = $legacyUsage.Keys | ForEach-Object {
            @{
                Protocol = $_
                UserCount = $legacyUsage[$_].count
                LastSeen = $legacyUsage[$_].lastSeen
            }
        }
    }
}

$output = Save-IFQCReport -Context $ctx

Write-Host ""
Write-Host "LegacyAuthReality check complete." -ForegroundColor Green
Write-Host "  JSON: $($output.Json)" -ForegroundColor Cyan
Write-Host "  HTML: $($output.Html)" -ForegroundColor Cyan

# Cleanup
try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
