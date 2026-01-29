<#
.SYNOPSIS
    Entra ID PIM Role Eligibility and Conditional Access visibility.

.DESCRIPTION
    Reads PIM-eligible roles and Conditional Access policies (read-only).

.OUTPUTS
    - JSON report
    - HTML report
    - Log file

.NOTES
    Author: mark.ahearne@identityfirst.net | Owner: IdentityFirst Ltd
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

$ctx = New-IFQCContext -ToolName "EntraEnhancedIdentity" -OutputDirectory $OutputDirectory -DetailLevel $DetailLevel
Add-IFQCNote -Context $ctx -Note "Read-only Entra ID PIM and Conditional Access visibility."

function Get-EvidenceLimit {
    if ($DetailLevel -eq "Detailed") { return 200 }
    return 40
}

Invoke-IFQCSafe -Context $ctx -Name "Entra PIM and CA inventory" -Block {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw "Microsoft Graph SDK not found."
    }
    
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Identity.Governance -ErrorAction Stop
    
    $scopes = @("RoleManagement.Read.Directory", "Policy.Read.ConditionalAccess", "User.Read.All")
    Connect-MgGraph -Scopes $scopes | Out-Null
    
    $mgCtx = Get-MgContext
    $ctx.Data.tenantId = $mgCtx.TenantId
    
    $eligibleAssignments = @()
    try {
        $assignments = Get-MgIdentityGovernanceRoleEligibilitySchedule -All -ErrorAction SilentlyContinue
        foreach ($a in $assignments) {
            $eligibleAssignments += [PSCustomObject]@{
                PrincipalId = $a.PrincipalId
                RoleId = $a.RoleDefinitionId
                MemberType = $a.MemberType
                EndDateTime = $a.EndDateTime
            }
        }
    } catch {
        Write-IFQCLog -Context $ctx -Level WARN -Message "PIM not accessible"
    }
    
    $caPolicies = Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue |
        Select-Object DisplayName, State, Id
    
    $ctx.Data.eligibleAssignmentCount = ($eligibleAssignments | Measure-Object).Count
    $ctx.Data.caPolicyCount = ($caPolicies | Measure-Object).Count
    
    $evidenceLimit = Get-EvidenceLimit
    
    $permanentEligible = $eligibleAssignments | Where-Object {
        $_.MemberType -eq "Eligible" -and (-not $_.EndDateTime)
    }
    
    Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
        -Id "ENTRA-PIM-PERMANENT" `
        -Title "PIM eligible assignments without expiration" `
        -Severity "High" `
        -Description "Permanent PIM eligibility removes time-bound access control." `
        -Count ($permanentEligible.Count) `
        -Evidence ($permanentEligible | Select-Object -First $evidenceLimit) `
        -Recommendation "Configure assignment expiry for PIM roles."
    )
}

$output = Save-IFQCReport -Context $ctx
Write-Host ""
Write-Host "EntraEnhancedIdentity complete." -ForegroundColor Green
