<#
.SYNOPSIS
    IdentityHealthCheck - high-level runner that invokes the audit engine and prints a concise health summary.
.DESCRIPTION
    Runs `Identity-Audit-Engine.ps1` (collects evidence, runs assertions, applies framework lenses), then summarizes the results into a simple health score and actionable bullets for operators.
#>
[CmdletBinding()]
param(
    [string[]]$Frameworks = @('GDPR'),
    [string]$OutputDir = (Join-Path $PWD 'IFQC-Audit-Out'),
    [switch]$RunEngine = $true,
    [switch]$ReadOnly = $true,
    [int]$CriticalThreshold = 1,
    [int]$HighThreshold = 5
)

function SafeWrite($obj) {
    try { Write-IFQC -InputObject $obj } catch { Write-Output ($obj | ConvertTo-Json -Depth 3) }
}

if ($RunEngine) {
    SafeWrite -obj ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Info'; Action='HealthCheckStart'; Frameworks=$Frameworks })
    $engine = Join-Path $PSScriptRoot 'Identity-Audit-Engine.ps1'
    if (-not (Test-Path $engine)) { Write-Output "Audit engine not found: $engine"; exit 2 }
    $pw = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$engine,'-Frameworks',$Frameworks)
    if ($ReadOnly) { $pw += '-ReadOnly' }
    & pwsh @pw | Out-Null
}

# Load reports
$reportsPath = Join-Path $OutputDir 'reports.json'
$findingsPath = Join-Path $OutputDir 'findings.json'

if (-not (Test-Path $reportsPath)) { Write-Output "Reports not found at $reportsPath"; exit 2 }

$reports = Get-Content $reportsPath -Raw | ConvertFrom-Json
$findings = @()
if (Test-Path $findingsPath) { $findings = Get-Content $findingsPath -Raw | ConvertFrom-Json }

# Compute overall summary
$overallAvg = 0
if ($reports -and $reports.Count -gt 0) {
    $scores = $reports | ForEach-Object { $_.overallScore }
    $overallAvg = [int]([Math]::Round(($scores | Measure-Object -Average).Average,0))
} else {
    $overallAvg = 100
}

$critCount = ($findings | Where-Object { $_.severity -match '(?i)critical' } | Measure-Object).Count
$highCount = ($findings | Where-Object { $_.severity -match '(?i)high' } | Measure-Object).Count

# Health status
$status = 'Good'
if ($critCount -ge $CriticalThreshold -or $overallAvg -lt 60) { $status = 'Critical' }
elseif ($highCount -ge $HighThreshold -or $overallAvg -lt 80) { $status = 'Warning' }

$summary = [PSCustomObject]@{
    Timestamp = (Get-Date).ToString('o')
    HealthStatus = $status
    OverallScore = $overallAvg
    CriticalFindings = $critCount
    HighFindings = $highCount
    Reports = (($reports | ForEach-Object { [PSCustomObject]@{ Framework = $_.framework; Overall = $_.overallScore } }))
}

SafeWrite -obj ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Info'; Action='HealthSummary'; Summary=$summary })

# Human-friendly output
Write-Output "Identity Health: $($summary.HealthStatus) — Score: $($summary.OverallScore)"
Write-Output "Critical findings: $($summary.CriticalFindings); High findings: $($summary.HighFindings)"

# Actionable bullets
if ($summary.HealthStatus -eq 'Critical') {
    Write-Output "- Immediate actions: investigate critical findings, restrict privileged accounts, enforce MFA."
} elseif ($summary.HealthStatus -eq 'Warning') {
    Write-Output "- Near-term actions: review high-severity findings, plan mitigations."
} else {
    Write-Output "- No immediate action; maintain monitoring and run regular scans."
}

# Exit code: non-zero if critical
if ($summary.HealthStatus -eq 'Critical') { exit 3 } else { exit 0 }
