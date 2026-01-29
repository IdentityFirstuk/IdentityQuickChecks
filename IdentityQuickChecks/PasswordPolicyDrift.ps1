<#
    Password Policy Drift Snapshot
    Identifies accounts bypassing default password policies
#>

param(
    [string]$OutputPath = "."
)

Write-Host "════════════════════════════════════════════════════════════"
Write-Host "  Password Policy Drift Snapshot"
Write-Host "════════════════════════════════════════════════════════════"
Write-Host ""
Write-Host "  Identifying password policy exceptions..."
Write-Host ""

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Host "  ✗ ActiveDirectory module not available" -ForegroundColor Red
    Write-Host "  ℹ Install RSAT AD tools or run on a Domain Controller" -ForegroundColor Gray
    exit 1
}

# Get Fine-Grained Password Policies
$fgpp = Get-ADFineGrainedPasswordPolicy -Filter * | 
    Select-Object Name,MinPasswordLength,PasswordHistoryCount,ComplexityEnabled

Write-Host "  Fine-Grained Password Policies configured:"
if ($fgpp) {
    $fgpp | Format-Table -AutoSize
} else {
    Write-Host "     None configured (using default domain policy)" -ForegroundColor Gray
}
Write-Host ""

# Find accounts with password never expires
$users = Get-ADUser -Filter * -Properties PasswordNeverExpires,MemberOf,lastLogonTimestamp

$weakPolicy = $users | Where-Object {
    $_.PasswordNeverExpires -eq $true
} | Select-Object SamAccountName,Enabled,
    @{Name="LastLogon";Expression={
        if($_.lastLogonTimestamp) {
            [DateTime]::FromFileTime($_.lastLogonTimestamp).ToString("yyyy-MM-dd")
        } else { "Never" }
    }},
    @{Name="MemberOf";Expression={ ($_.MemberOf | Measure-Object).Count }}

Write-Host "  Accounts with PasswordNeverExpires = True:"
if ($weakPolicy) {
    Write-Host "  ⚠ Found $($weakPolicy.Count) accounts with password never expires" -ForegroundColor Yellow
    Write-Host ""
    $weakPolicy | Format-Table -AutoSize
} else {
    Write-Host "  ✓ No accounts found with password never expires" -ForegroundColor Green
}

# Find privileged users with weak policy
$privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
$privilegedUsers = @()

foreach ($group in $privilegedGroups) {
    try {
        $members = Get-ADGroupMember $group -ErrorAction Stop | 
            Where-Object objectClass -eq "user"
        foreach ($member in $members) {
            $user = Get-ADUser $member -Properties PasswordNeverExpires
            if ($user.PasswordNeverExpires) {
                $privilegedUsers += [PSCustomObject]@{
                    SamAccountName = $user.SamAccountName
                    Group = $group
                    PasswordNeverExpires = $true
                }
            }
        }
    }
    catch { }
}

if ($privilegedUsers) {
    Write-Host ""
    Write-Host "  ⚠ Privileged accounts with password never expires:" -ForegroundColor Yellow
    $privilegedUsers | Format-Table -AutoSize
}

# Export report
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$jsonPath = Join-Path $OutputPath "PasswordPolicyDrift-$timestamp.json"
$report = @{
    check = "Password Policy Drift Snapshot"
    timestamp = (Get-Date).ToString("o")
    fineGrainedPolicies = $fgpp
    weakPolicyAccounts = $weakPolicy
    privilegedWithWeakPolicy = $privilegedUsers
}
$report | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
Write-Host ""
Write-Host "  📄 Report saved: $jsonPath" -ForegroundColor Cyan

Write-Host ""
Write-Host "  ─────────────────────────────────────────────────────────────"
Write-Host "  ℹ  Password exceptions exist. Whether they're acceptable"
Write-Host "     requires governance review. Run IdentityHealthCheck."
Write-Host "  ─────────────────────────────────────────────────────────────"
