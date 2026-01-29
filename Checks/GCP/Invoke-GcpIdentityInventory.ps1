<#
.SYNOPSIS
    GCP Identity Inventory using gcloud CLI.

.DESCRIPTION
    Reads service accounts, keys, and project-level IAM bindings.

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

$ctx = New-IFQCContext -ToolName "GcpIdentityInventory" -OutputDirectory $OutputDirectory -DetailLevel $DetailLevel
Add-IFQCNote -Context $ctx -Note "Read-only GCP IAM inventory using gcloud CLI."

function Get-EvidenceLimit {
    if ($DetailLevel -eq "Detailed") { return 200 }
    return 40
}

Invoke-IFQCSafe -Context $ctx -Name "GCP IAM inventory" -Block {
    try {
        $null = gcloud version --format=json 2>$null | ConvertFrom-Json
    } catch {
        throw "gcloud CLI not found."
    }
    
    $defaultProject = (gcloud config get-value project 2>$null).Trim()
    if (-not $defaultProject) { $defaultProject = "Not set" }
    $ctx.Data.defaultProject = $defaultProject
    
    # Get accessible projects
    $projectsToScan = @()
    try {
        $projJson = gcloud projects list --format=json 2>$null | ConvertFrom-Json
        $projectsToScan = $projJson | Select-Object -ExpandProperty projectId
    } catch {
        $projectsToScan = @($defaultProject)
    }
    
    $ctx.Data.projectsScanned = $projectsToScan.Count
    $allServiceAccounts = @()
    $allKeys = @()
    $externalBindings = @()
    $cutoff = (Get-Date).AddDays(-180)
    
    foreach ($proj in $projectsToScan) {
        Write-IFQCLog -Context $ctx -Level INFO -Message "Scanning: $proj"
        gcloud config set project $proj 2>$null | Out-Null
        
        $saJson = gcloud iam service-accounts list --format=json 2>$null
        if ($saJson) {
            $sas = $saJson | ConvertFrom-Json
            foreach ($sa in $sas) {
                $allServiceAccounts += [PSCustomObject]@{
                    Project = $proj
                    Email = $sa.email
                    DisplayName = $sa.displayName
                    Disabled = $sa.disabled
                }
            }
        }
        
        foreach ($sa in $sas) {
            $keysJson = gcloud iam service-accounts keys list --iam-account $sa.email --format=json 2>$null
            if ($keysJson) {
                $keys = $keysJson | ConvertFrom-Json
                foreach ($k in $keys) {
                    $keyObj = [PSCustomObject]@{
                        Project = $proj
                        ServiceAccount = $sa.email
                        KeyId = $k.name.Split('/')[-1]
                        ValidAfterTime = $k.validAfterTime
                    }
                    $allKeys += $keyObj
                }
            }
        }
        
        $policyJson = gcloud projects get-iam-policy $proj --format=json 2>$null
        if ($policyJson) {
            $policy = $policyJson | ConvertFrom-Json
            if ($policy.bindings) {
                foreach ($binding in $policy.bindings) {
                    foreach ($member in $binding.members) {
                        if ($member -match "^(user:|group:).*@[^@]+.com") {
                            $emailPart = $member -replace "^(user:|group:)", ""
                            $domain = ($emailPart -split "@")[-1]
                            if ($domain -notmatch "google.com|gmail.com$") {
                                $externalBindings += [PSCustomObject]@{
                                    Project = $proj
                                    Role = $binding.role
                                    Member = $member
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    $oldKeys = $allKeys | Where-Object { $_.ValidAfterTime -and [DateTime]$_.ValidAfterTime -lt $cutoff }
    $disabledSas = $allServiceAccounts | Where-Object { $_.Disabled -eq $true }
    
    $ctx.Data.serviceAccountCount = ($allServiceAccounts | Measure-Object).Count
    $ctx.Data.keyCount = ($allKeys | Measure-Object).Count
    $ctx.Data.oldKeyCount = ($oldKeys | Measure-Object).Count
    
    $evidenceLimit = Get-EvidenceLimit
    
    Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
        -Id "GCP-SA-KEYS-OLD" `
        -Title "Service account keys older than 180 days" `
        -Severity "High" `
        -Description "Long-lived keys increase compromise risk." `
        -Count ($oldKeys.Count) `
        -Evidence ($oldKeys | Select-Object -First $evidenceLimit) `
        -Recommendation "Rotate service account keys regularly."
    )
    
    Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
        -Id "GCP-IAM-EXTERNAL" `
        -Title "External domain IAM bindings" `
        -Severity "Medium" `
        -Description "External domain IAM bindings expand trust boundary." `
        -Count ($externalBindings.Count) `
        -Evidence ($externalBindings | Select-Object -First $evidenceLimit) `
        -Recommendation "Review external access. Remove unnecessary bindings."
    )
}

$output = Save-IFQCReport -Context $ctx
Write-Host ""
Write-Host "GcpIdentityInventory complete." -ForegroundColor Green
