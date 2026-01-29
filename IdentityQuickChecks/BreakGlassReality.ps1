<#
    Break-Glass Reality Check
    Identifies accounts named/described as break-glass and checks their posture
#>

param(
    [string]$OutputPath = "."
)

Write-Host "════════════════════════════════════════════════════════════"
Write-Host "  Break-Glass Reality Check"
Write-Host "════════════════════════════════════════════════════════════"
Write-Host ""
Write-Host "  Finding accounts named/described as break-glass..."
Write-Host ""

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Host "  ✗ ActiveDirectory module not available" -ForegroundColor Red
    Write-Host "  ℹ Install RSAT AD tools or run on a Domain Controller" -ForegroundColor Gray
    exit 1
}

$breakGlass = Get-ADUser -Filter * -Properties Description,PasswordNeverExpires,lastLogonTimestamp |
    Where-Object {
        $_.SamAccountName -match "break|emerg|bg-" -or
        $_.Description -match "break|emerg"
    } |
    Select-Object SamAccountName,Enabled,
        @{Name="PasswordNeverExpires";Expression={$_.PasswordNeverExpires}},
        @{Name="LastLogon";Expression={
            if($_.lastLogonTimestamp) {
                [DateTime]::FromFileTime($_.lastLogonTimestamp).ToString("yyyy-MM-dd")
            } else { "Never" }
        }},
        Description

if ($breakGlass) {
    Write-Host "  ⚠ Found $($breakGlass.Count) break-glass accounts" -ForegroundColor Yellow
    Write-Host ""
    $breakGlass | Format-Table -AutoSize
    
    # Export report
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $jsonPath = Join-Path $OutputPath "BreakGlassReality-$timestamp.json"
    $report = @{
        check = "Break-Glass Reality Check"
        timestamp = (Get-Date).ToString("o")
        count = ($breakGlass | Measure-Object).Count
        data = $breakGlass
    }
    $report | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Host ""
    Write-Host "  📄 Report saved: $jsonPath" -ForegroundColor Cyan
}
else {
    Write-Host "  ✓ No break-glass accounts found" -ForegroundColor Green
}

Write-Host ""
Write-Host "  ─────────────────────────────────────────────────────────────"
Write-Host "  ℹ  This script shows break-glass accounts exist."
Write-Host "     It cannot answer: Who approved them? When tested? Controls?"
Write-Host "     For governance analysis, run IdentityHealthCheck."
Write-Host "  ─────────────────────────────────────────────────────────────"
