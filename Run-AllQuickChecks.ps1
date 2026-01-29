<#
    IdentityFirst QuickChecks - Main Launcher
    Runs all available quick checks and generates combined report
#>

param(
    [string]$OutputPath = ".\QuickChecks_Report",
    [switch]$CoreOnly,
    [switch]$Help
)

if ($Help) {
    Write-Host @"
IdentityFirst QuickChecks Launcher
===================================

Usage: .\Run-AllQuickChecks.ps1 [-OutputPath <path>] [-CoreOnly]

Options:
  -OutputPath  Path for report output (default: .\QuickChecks_Report)
  -CoreOnly    Run only Core modules (IdentityQuickChecks, IdentityTrustQuickChecks)
  -Help        Show this help message

Modules:
  Core:     IdentityQuickChecks, IdentityTrustQuickChecks
  Advanced: IdentityBoundaryQuickChecks, IdentityAssumptionQuickChecks

Examples:
  .\Run-AllQuickChecks.ps1
  .\Run-AllQuickChecks.ps1 -OutputPath "C:\Reports\Identity" -CoreOnly

"@
    exit 0
}

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$scriptRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║         IdentityFirst QuickChecks - Complete Suite         ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Output: $OutputPath" -ForegroundColor Gray
Write-Host "  Time:   $timestamp" -ForegroundColor Gray
Write-Host ""

# Define module paths
$coreModules = @(
    @{ Name = "IdentityQuickChecks"; Path = Join-Path $scriptRoot "IdentityQuickChecks" },
    @{ Name = "IdentityTrustQuickChecks"; Path = Join-Path $scriptRoot "IdentityTrustQuickChecks" }
)

$advancedModules = @(
    @{ Name = "IdentityBoundaryQuickChecks"; Path = Join-Path $scriptRoot "IdentityBoundaryQuickChecks" },
    @{ Name = "IdentityAssumptionQuickChecks"; Path = Join-Path $scriptRoot "IdentityAssumptionQuickChecks" }
)

$modulesToRun = if ($CoreOnly) { $coreModules } else { $coreModules + $advancedModules }

$results = @{
    timestamp = $timestamp
    modules = @()
}

foreach ($module in $modulesToRun) {
    Write-Host "────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  Module: $($module.Name)" -ForegroundColor White
    Write-Host "────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    
    $moduleResult = @{
        name = $module.Name
        checks = @()
        issuesFound = 0
    }
    
    $psFiles = Get-ChildItem -Path $module.Path -Filter "*.ps1" -ErrorAction SilentlyContinue
    
    if (-not $psFiles) {
        Write-Host "  ⚠ No scripts found in $($module.Path)" -ForegroundColor Yellow
    }
    
    foreach ($psFile in $psFiles) {
        Write-Host "  → Running: $($psFile.Name)" -ForegroundColor Gray
        
        $checkResult = @{
            script = $psFile.Name
            status = "success"
            issues = 0
        }
        
        try {
            $output = & $psFile.FullName -OutputPath $OutputPath 2>&1 | Out-String
            
            $issueCount = ($output | Select-String "⚠ Found" -AllMatches).Matches.Count
            $checkResult.issues = $issueCount
            $moduleResult.issuesFound += $issueCount
        }
        catch {
            $checkResult.status = "error"
            $checkResult.error = $_.Exception.Message
            Write-Host "    ✗ Error: $($_.Exception.Message)" -ForegroundColor Red
        }
        
        $moduleResult.checks += $checkResult
    }
    
    $results.modules += $moduleResult
    
    $issueText = if ($moduleResult.issuesFound -gt 0) { 
        "⚠ $($moduleResult.issuesFound) potential issues" 
    } else { 
        "✓ No issues detected" 
    }
    Write-Host ""
    Write-Host "  $($module.Name): $issueText" -ForegroundColor $(if ($moduleResult.issuesFound -gt 0) { "Yellow" } else { "Green" })
    Write-Host ""
}

# Generate summary report
$summaryPath = Join-Path $OutputPath "QuickChecks_Summary_$timestamp.json"
$results | ConvertTo-Json -Depth 10 | Out-File -FilePath $summaryPath -Encoding UTF8

Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  QuickChecks Complete" -ForegroundColor White
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Summary report: $summaryPath" -ForegroundColor Cyan
Write-Host ""

$totalIssues = ($results.modules | Measure-Object -Property issuesFound -Sum).Sum

if ($totalIssues -gt 0) {
    Write-Host "  ℹ Total: $totalIssues potential issues found" -ForegroundColor Yellow
} else {
    Write-Host "  ✓ No issues detected across all checks" -ForegroundColor Green
}

Write-Host ""
Write-Host "  ─────────────────────────────────────────────────────────────"
Write-Host "  ℹ  These scripts show identity conditions."
Write-Host "     For governance analysis, run IdentityHealthCheck."
Write-Host "  ─────────────────────────────────────────────────────────────"
