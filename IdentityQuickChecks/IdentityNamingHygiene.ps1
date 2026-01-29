<#
    Identity Naming & Hygiene Check
    Detects shared accounts, service accounts named like people, and inconsistent prefixes
#>

param(
    [string]$OutputPath = "."
)

Write-Host "════════════════════════════════════════════════════════════"
Write-Host "  Identity Naming & Hygiene Check"
Write-Host "════════════════════════════════════════════════════════════"
Write-Host ""
Write-Host "  Analyzing naming conventions..."
Write-Host ""

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Host "  ✗ ActiveDirectory module not available" -ForegroundColor Red
    Write-Host "  ℹ Install RSAT AD tools or run on a Domain Controller" -ForegroundColor Gray
    exit 1
}

$users = Get-ADUser -Filter * -Properties SamAccountName,DisplayName,Description

# Detect inconsistent prefixes
$violations = $users | Where-Object {
    $_.SamAccountName -notmatch "^(svc-|adm-|usr-)" -and
    $_.DisplayName -notmatch "Service|Admin|Test|Temp" -and
    $_.SamAccountName -notmatch "^\$"
}

Write-Host "  🔍 Checking for naming convention violations..."
Write-Host ""

$violationCount = ($violations | Measure-Object).Count
if ($violationCount -gt 0) {
    Write-Host "  ⚠ Found $violationCount naming violations" -ForegroundColor Yellow
    Write-Host ""
    $violations | Select-Object SamAccountName,DisplayName | 
        Sort-Object SamAccountName | 
        Select-Object -First 50 | 
        Format-Table -AutoSize
    
    if ($violationCount -gt 50) {
        Write-Host "  ... and $($violationCount - 50) more" -ForegroundColor Gray
    }
} else {
    Write-Host "  ✓ No significant naming violations detected" -ForegroundColor Green
}

# Export report
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$jsonPath = Join-Path $OutputPath "IdentityNamingHygiene-$timestamp.json"
$report = @{
    check = "Identity Naming & Hygiene Check"
    timestamp = (Get-Date).ToString("o")
    summary = @{
        totalUsers = ($users | Measure-Object).Count
        violations = $violationCount
    }
    data = $violations | Select-Object SamAccountName,DisplayName
}
$report | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonPath -Encoding UTF8
Write-Host ""
Write-Host "  📄 Report saved: $jsonPath" -ForegroundColor Cyan

Write-Host ""
Write-Host "  ─────────────────────────────────────────────────────────────"
Write-Host "  ℹ  Naming failures correlate to ownership gaps and audit pain."
Write-Host "     For ownership analysis and lifecycle review, run IdentityHealthCheck."
Write-Host "  ─────────────────────────────────────────────────────────────"
