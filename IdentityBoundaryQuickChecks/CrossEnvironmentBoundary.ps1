<#
    Cross-Environment Boundary Check
    Identifies identities existing in multiple environments without coordination
#>

param(
    [string]$OutputPath = "."
)

Write-Host "════════════════════════════════════════════════════════════"
Write-Host "  Cross-Environment Boundary Check"
Write-Host "════════════════════════════════════════════════════════════"
Write-Host ""
Write-Host "  Checking for identities in multiple environments..."
Write-Host ""

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Host "  ✗ ActiveDirectory module not available" -ForegroundColor Red
    exit 1
}

$users = Get-ADUser -Filter * -Properties SamAccountName,UserPrincipalName,DisplayName,Description

# Check for same UPN pattern in multiple naming conventions
$upnSuffixes = $users | ForEach-Object { 
    if ($_.UserPrincipalName -match "@(.+)$") { $matches[1] } 
} | Sort-Object -Unique

Write-Host "  Detected UPN Suffixes:"
$upnSuffixes | ForEach-Object { Write-Host "     $_" -ForegroundColor Gray }
Write-Host ""

# Flag potential cross-environment issues
$boundaryViolations = @()

# Check for service accounts with human-like names
$humanLikeService = $users | Where-Object {
    $_.SamAccountName -notmatch "^(svc-|adm-|usr-|app-)" -and
    $_.DisplayName -match "^[A-Z][a-z]+(\s+[A-Z][a-z]+)?$" -and
    $_.Description -match "service|app|system|automation"
}

if ($humanLikeService) {
    Write-Host "  ⚠ Human-named accounts used as service identities:"
    $humanLikeService | Select-Object SamAccountName,DisplayName,Description | Format-Table -AutoSize
}

# Check for duplicate samaccountname patterns
$duplicatePatterns = $users | Group-Object { $_.SamAccountName -replace "\d+$", "" } | 
    Where-Object { $_.Count -gt 1 }

if ($duplicatePatterns) {
    Write-Host ""
    Write-Host "  Potential duplicate identity patterns:"
    $duplicatePatterns | Select-Object -First 10 | Format-Table -AutoSize
}

# Export report
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$jsonPath = Join-Path $OutputPath "CrossEnvironmentBoundary-$timestamp.json"
$report = @{
    check = "Cross-Environment Boundary Check"
    timestamp = (Get-Date).ToString("o")
    upnSuffixes = $upnSuffixes
    humanLikeServiceAccounts = $humanLikeService
    duplicatePatterns = $duplicatePatterns | Select-Object -First 10
}
$report | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
Write-Host ""
Write-Host "  📄 Report saved: $jsonPath" -ForegroundColor Cyan

Write-Host ""
Write-Host "  ─────────────────────────────────────────────────────────────"
Write-Host "  ℹ  Cross-environment identities need authoritative ownership."
Write-Host "     For boundary governance, run IdentityHealthCheck."
Write-Host "  ─────────────────────────────────────────────────────────────"
