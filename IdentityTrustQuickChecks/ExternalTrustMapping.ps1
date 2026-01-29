<#
    External Trust Mapping
    Lists AD trusts and flags external / forest trusts
#>

param(
    [string]$OutputPath = "."
)

Write-Host "════════════════════════════════════════════════════════════"
Write-Host "  External Trust Mapping"
Write-Host "════════════════════════════════════════════════════════════"
Write-Host ""
Write-Host "  Identifying domain and forest trusts..."
Write-Host ""

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Host "  ✗ ActiveDirectory module not available" -ForegroundColor Red
    Write-Host "  ℹ Install RSAT AD tools or run on a Domain Controller" -ForegroundColor Gray
    exit 1
}

$trusts = Get-ADTrust | Select-Object Name,TrustType,TrustDirection,IntraForest,
    @{Name="Created";Expression={$_.WhenCreated.ToString("yyyy-MM-dd")}},
    @{Name="Modified";Expression={$_.Modified.ToString("yyyy-MM-dd")}}

Write-Host "  Found $($trusts.Count) trust relationships:"
Write-Host ""

if ($trusts) {
    $trusts | Format-Table -AutoSize
    
    # Flag external trusts
    $externalTrusts = $trusts | Where-Object { $_.TrustType -notin @("Forest", "None") -or $_.TrustDirection -ne "WithinForest" }
    
    if ($externalTrusts) {
        Write-Host ""
        Write-Host "  ⚠ External/Cross-realm trusts detected:" -ForegroundColor Yellow
        $externalTrusts | Format-Table -AutoSize
    }
} else {
    Write-Host "  ✓ No external trusts configured" -ForegroundColor Green
}

# Export report
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$jsonPath = Join-Path $OutputPath "ExternalTrustMapping-$timestamp.json"
$report = @{
    check = "External Trust Mapping"
    timestamp = (Get-Date).ToString("o")
    totalTrusts = ($trusts | Measure-Object).Count
    externalTrusts = $trusts | Where-Object { $_.TrustType -notin @("Forest", "None") }
    data = $trusts
}
$report | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
Write-Host ""
Write-Host "  📄 Report saved: $jsonPath" -ForegroundColor Cyan

Write-Host ""
Write-Host "  ─────────────────────────────────────────────────────────────"
Write-Host "  ℹ  Trust existing ≠ trust justified."
Write-Host "     For trust justification review, run IdentityHealthCheck."
Write-Host "  ─────────────────────────────────────────────────────────────"
