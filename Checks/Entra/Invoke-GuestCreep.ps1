<#
.SYNOPSIS
    Checks for external guest lifecycle issues in Entra ID.

.DESCRIPTION
    Identifies guest accounts and their age. Requires Microsoft Graph.
    Does NOT change Conditional Access or guest policies.

.OUTPUTS
    - JSON report
    - HTML report
    - Log file

.NOTES
    Author: IdentityFirst Ltd
    Safety: Read-only. No changes are made.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path $PWD "IFQC-Output"),
    
    [Parameter()]
    [ValidateSet("Normal","Detailed")]
    [string]$DetailLevel = "Normal",
    
    [Parameter()]
    [int]$GuestAgeDays = 180
)

$modulePath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $modulePath "Module\IdentityFirst.QuickChecks.psm1") -Force

$ctx = New-IFQCContext -ToolName "GuestCreep" -OutputDirectory $OutputDirectory -DetailLevel $DetailLevel
Add-IFQCNote -Context $ctx -Note "Requires Microsoft Graph PowerShell SDK. Licensing/permissions may limit what can be retrieved."
Add-IFQCNote -Context $ctx -Note "This does not change Conditional Access or guest policies."

function Get-EvidenceLimit {
    param([string]$DetailLevel)
    if ($DetailLevel -eq "Detailed") { return 250 }
    return 40
}

Invoke-IFQCSafe -Context $ctx -Name "Entra guest access checks" -Block {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw "Microsoft Graph SDK not found. Install-Module Microsoft.Graph -Scope CurrentUser"
    }

    Import-Module Microsoft.Graph.Authentication
    Import-Module Microsoft.Graph.Users

    $scopes = @("User.Read.All","Directory.Read.All")
    Connect-MgGraph -Scopes $scopes | Out-Null
    $mg = Get-MgContext
    $ctx.Data.entra = [ordered]@{ tenantId=$mg.TenantId; account=$mg.Account }

    $cutoff = (Get-Date).AddDays(-$GuestAgeDays)

    $guests = Get-MgUser -Filter "userType eq 'Guest'" -All -Property DisplayName,UserPrincipalName,AccountEnabled,CreatedDateTime,ExternalUserState |
        Select-Object DisplayName, UserPrincipalName, AccountEnabled, CreatedDateTime, ExternalUserState

    $oldGuests = $guests | Where-Object { $_.CreatedDateTime -and $_.CreatedDateTime -lt $cutoff }

    $evidenceLimit = Get-EvidenceLimit -DetailLevel $DetailLevel

    # 1) All guests
    Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
        -Id "ENTRA-GUESTS-ALL" `
        -Title "Guest users present" `
        -Severity "Medium" `
        -Description "Guest accounts expand the trust boundary and often outlive their purpose." `
        -Count ($guests.Count) `
        -Evidence ($guests | Select-Object -First $evidenceLimit) `
        -Recommendation "Implement guest lifecycle, expiry, sponsorship and periodic review. Apply Conditional Access for externals."
    )

    # 2) Old guests
    Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
        -Id "ENTRA-GUESTS-OLD" `
        -Title "Guest users older than threshold" `
        -Severity "High" `
        -Description "Long-lived guests are a frequent source of 'permanent external access' risk." `
        -Count ($oldGuests.Count) `
        -Evidence ($oldGuests | Select-Object -First $evidenceLimit) `
        -Recommendation "Expire unused guests, validate sponsorship and access purpose, and enforce review cadence."
    )
}

$output = Save-IFQCReport -Context $ctx

Write-Host ""
Write-Host "GuestCreep check complete." -ForegroundColor Green
Write-Host "  JSON: $($output.Json)" -ForegroundColor Cyan
Write-Host "  HTML: $($output.Html)" -ForegroundColor Cyan
