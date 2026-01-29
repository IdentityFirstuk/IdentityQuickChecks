<#
    Identity Tiering Drift Check
    Checks if Tier 0 / admin identities touch Tier 1/2 systems
#>

param(
    [string]$OutputPath = "."
)

Write-Host "════════════════════════════════════════════════════════════"
Write-Host "  Identity Tiering Drift Check"
Write-Host "════════════════════════════════════════════════════════════"
Write-Host ""
Write-Host "  Checking for tiering violations..."
Write-Host ""

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Host "  ✗ ActiveDirectory module not available" -ForegroundColor Red
    exit 1
}

# Identify Tier 0 privileged accounts
$tier0Groups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
$tier0Members = @()

foreach ($group in $tier0Groups) {
    try {
        $members = Get-ADGroupMember $group -ErrorAction Stop | 
            Where-Object objectClass -eq "user"
        foreach ($member in $members) {
            $tier0Members += $member.SamAccountName
        }
    }
    catch { }
}

Write-Host "  Tier 0 privileged accounts found: $($tier0Members.Count)"

# Check for admin accounts with potential tiering concerns
$users = Get-ADUser -Filter * -Properties Description,SamAccountName

$tieringConcerns = $users | Where-Object {
    $_.Description -match "admin|privileged|domain admin" -and $_.SamAccountName -notmatch "^ZD"
}

if ($tieringConcerns) {
    Write-Host ""
    Write-Host "  ⚠ Potential tiering concerns (admin in description, no tier prefix):"
    $tieringConcerns | Select-Object SamAccountName,Description | Format-Table -AutoSize
}
else {
    Write-Host ""
    Write-Host "  ✓ No obvious tiering concerns detected" -ForegroundColor Green
}

# Export report
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$jsonPath = Join-Path $OutputPath "IdentityTieringDrift-$timestamp.json"
$report = @{
    check = "Identity Tiering Drift Check"
    timestamp = (Get-Date).ToString("o")
    tier0Count = ($tier0Members | Measure-Object).Count
    tieringConcerns = $tieringConcerns
}
$report | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
Write-Host ""
Write-Host "  📄 Report saved: $jsonPath" -ForegroundColor Cyan

Write-Host ""
Write-Host "  ─────────────────────────────────────────────────────────────"
Write-Host "  ℹ  Tiering violations need frequency and context analysis."
Write-Host "     For tiering governance, run IdentityHealthCheck."
Write-Host "  ─────────────────────────────────────────────────────────────"
