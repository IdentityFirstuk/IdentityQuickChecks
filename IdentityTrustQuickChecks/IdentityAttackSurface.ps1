<#
    Identity Attack Surface Indicator
    Flags accounts with elevated exposure risk
#>

param(
    [string]$OutputPath = "."
)

Write-Host "════════════════════════════════════════════════════════════"
Write-Host "  Identity Attack Surface Indicator"
Write-Host "════════════════════════════════════════════════════════════"
Write-Host ""
Write-Host "  Analyzing identity exposure risk..."
Write-Host ""

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Host "  ✗ ActiveDirectory module not available" -ForegroundColor Red
    exit 1
}

$users = Get-ADUser -Filter * -Properties ServicePrincipalName,SamAccountName,Enabled,Description

# Find accounts with Service Principal Names (exposed to delegation)
$spnAccounts = $users | Where-Object {
    $_.ServicePrincipalName -and $_.Enabled
} | Select-Object SamAccountName,Enabled,ServicePrincipalName

Write-Host "  Accounts with Service Principal Names (delegation exposure):"
if ($spnAccounts) {
    Write-Host "  ⚠ Found $($spnAccounts.Count) accounts with SPNs" -ForegroundColor Yellow
    $spnAccounts | Format-Table -AutoSize
} else {
    Write-Host "  ✓ No accounts with Service Principal Names" -ForegroundColor Green
}

# Export report
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$jsonPath = Join-Path $OutputPath "IdentityAttackSurface-$timestamp.json"
$report = @{
    check = "Identity Attack Surface Indicator"
    timestamp = (Get-Date).ToString("o")
    summary = @{ spnAccounts = ($spnAccounts | Measure-Object).Count }
    spnAccounts = $spnAccounts
}
$report | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
Write-Host ""
Write-Host "  📄 Report saved: $jsonPath" -ForegroundColor Cyan

Write-Host ""
Write-Host "  ─────────────────────────────────────────────────────────────"
Write-Host "  ℹ  Exposure is visible. Impact is not."
Write-Host "     For risk assessment, run IdentityHealthCheck."
Write-Host "  ─────────────────────────────────────────────────────────────"
