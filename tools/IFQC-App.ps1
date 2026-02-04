<#
.SYNOPSIS
  Lightweight read-only runner app for IdentityFirst QuickChecks

.DESCRIPTION
  Imports the module and runs the IdentityHealthCheck in enforced read-only mode.
  This app explicitly disallows any fixer or apply operations.
#>

param(
    [string[]]$Frameworks = @('GDPR'),
    [string]$OutputDir = '.\IFQC-App-Out'
)

Set-Location -Path (Split-Path -Parent $MyInvocation.MyCommand.Definition)

# Enforce read-only guard for all child processes
[Environment]::SetEnvironmentVariable('IFQC_READONLY','1','Process')

function Write-IFQC-Info { param($m) Write-Output ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Info'; Message=$m }) }

Write-IFQC-Info "Starting IFQC-App (read-only). OutputDir=$OutputDir; Frameworks=$($Frameworks -join ',')"

$engine = Join-Path -Path '..' -ChildPath 'IdentityHealthCheck.ps1'
if (-not (Test-Path $engine)) { Write-IFQC-Info "Engine script not found: $engine"; exit 2 }

# Ensure output dir exists (no writes to repo files)
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

# Build args - always include -ReadOnly
$argsList = @('-Frameworks', ($Frameworks -join ','), '-OutputDir', $OutputDir, '-ReadOnly')

Write-IFQC-Info "Invoking IdentityHealthCheck in read-only mode"
& pwsh -NoProfile -ExecutionPolicy Bypass -File $engine @argsList

Write-IFQC-Info "IFQC-App run complete. Reports written to $OutputDir"

exit 0
