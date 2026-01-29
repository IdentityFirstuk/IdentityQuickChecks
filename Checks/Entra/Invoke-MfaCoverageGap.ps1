<#
.SYNOPSIS
    Checks for MFA registration gaps in Entra ID.

.DESCRIPTION
    Attempts to identify users without registered authentication methods.
    MFA state retrieval varies by tenant and API capabilities.

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
    [string]$DetailLevel = "Normal"
)

$modulePath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $modulePath "Module\IdentityFirst.QuickChecks.psm1") -Force

$ctx = New-IFQCContext -ToolName "MfaCoverageGap" -OutputDirectory $OutputDirectory -DetailLevel $DetailLevel
Add-IFQCNote -Context $ctx -Note "MFA state retrieval varies by tenant and API. This attempts best-effort visibility."
Add-IFQCNote -Context $ctx -Note "Full enforcement design belongs in IdentityHealthCheck."

Invoke-IFQCSafe -Context $ctx -Name "Graph MFA coverage (best effort)" -Block {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw "Microsoft Graph SDK not found."
    }

    Import-Module Microsoft.Graph.Authentication
    Import-Module Microsoft.Graph.Users
    Import-Module Microsoft.Graph.Identity.SignIns

    $scopes = @("User.Read.All","Reports.Read.All","Directory.Read.All")
    Connect-MgGraph -Scopes $scopes | Out-Null
    $mg = Get-MgContext
    $ctx.Data.entra = [ordered]@{ tenantId=$mg.TenantId; account=$mg.Account }

    $noMethods = @()
    try {
        Import-Module Microsoft.Graph.Identity.SignIns
        $scopes2 = @("User.Read.All","Directory.Read.All","UserAuthenticationMethod.Read.All")
        Connect-MgGraph -Scopes $scopes2 | Out-Null

        $users = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,AccountEnabled | Where-Object AccountEnabled -eq $true
        $sampleLimit = 5000
        $i = 0

        foreach ($u in $users) {
            $i++
            if ($i -gt $sampleLimit) { break }
            $methods = Get-MgUserAuthenticationMethod -UserId $u.Id -ErrorAction Stop
            if (-not $methods -or $methods.Count -eq 0) {
                $noMethods += [PSCustomObject]@{ DisplayName=$u.DisplayName; UPN=$u.UserPrincipalName }
            }
        }
    } catch {
        Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
            -Id "ENTRA-MFA-TELEMETRY-UNAVAILABLE" `
            -Title "Cannot enumerate authentication methods" `
            -Severity "Medium" `
            -Description "Authentication method visibility could not be retrieved." `
            -Count 1 `
            -Evidence @(@{ note = $_.Exception.Message }) `
            -Recommendation "Grant least-privileged read scopes for auth methods."
        )
        return
    }

    $evidenceLimit = if ($DetailLevel -eq "Detailed") { 200 } else { 40 }
    Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
        -Id "ENTRA-NO-AUTH-METHODS" `
        -Title "Users with no registered authentication methods (sampled)" `
        -Severity "High" `
        -Description "Users with no registered auth methods indicate weak MFA coverage." `
        -Count $noMethods.Count `
        -Evidence ($noMethods | Select-Object -First $evidenceLimit) `
        -Recommendation "Enforce registration, require MFA for privileged accounts first."
    )
}

$output = Save-IFQCReport -Context $ctx

Write-Host ""
Write-Host "MfaCoverageGap check complete." -ForegroundColor Green
Write-Host "  JSON: $($output.Json)" -ForegroundColor Cyan
Write-Host "  HTML: $($output.Html)" -ForegroundColor Cyan
