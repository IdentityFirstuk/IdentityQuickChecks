param([string]$OutputPath = ".")

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================================================"
Write-Host "  Password Policy Drift Snapshot"
Write-Host "========================================================================"

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "  ActiveDirectory module loaded" -ForegroundColor Green
}
catch {
    Write-Host "  ERROR: ActiveDirectory module not available" -ForegroundColor Red
    exit 1
}

try {
    $fgpp = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction Stop
    Write-Host "  Fine-Grained Password Policies configured: $($fgpp.Count)" -ForegroundColor Gray
    if ($fgpp) { $fgpp | Format-Table -AutoSize }
}
catch {
    Write-Host "     Unable to retrieve FGPP" -ForegroundColor Yellow
    $fgpp = @()
}

try {
    $users = Get-ADUser -Filter * -Properties PasswordNeverExpires, lastLogonTimestamp
    Write-Host "  Found $($users.Count) users" -ForegroundColor Gray
}
catch {
    Write-Host "  ERROR: Failed to query users" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "  Accounts with PasswordNeverExpires = True:"

$weakPolicy = @()
$errors = @()

foreach ($u in $users) {
    if ($u.PasswordNeverExpires -eq $true) {
        try {
            $ll = "Never"
            if ($u.lastLogonTimestamp) {
                $ll = [DateTime]::FromFileTime($u.lastLogonTimestamp).ToString("yyyy-MM-dd")
            }
            $weakPolicy += New-Object PSObject -Property @{
                SamAccountName = $u.SamAccountName
                Enabled = $u.Enabled
                LastLogon = $ll
            }
        }
        catch {
            $errors += $_.Exception.Message
        }
    }
}

if ($weakPolicy) {
    Write-Host "  Found $($weakPolicy.Count) accounts" -ForegroundColor Yellow
    $weakPolicy | Format-Table -AutoSize
}
else {
    Write-Host "  No accounts found" -ForegroundColor Green
}

$privilegedGroups = @("Domain Admins", "Enterprise Admins", "Administrators")
$privilegedUsers = @()

foreach ($g in $privilegedGroups) {
    try {
        $members = Get-ADGroupMember $g -ErrorAction Stop | Where-Object { $_.objectClass -eq "user" }
        foreach ($m in $members) {
            try {
                $u = Get-ADUser $m -Properties PasswordNeverExpires -ErrorAction Stop
                if ($u.PasswordNeverExpires) {
                    $privilegedUsers += New-Object PSObject -Property @{
                        SamAccountName = $u.SamAccountName
                        Group = $g
                    }
                }
            }
            catch {
                $errors += $_.Exception.Message
            }
        }
    }
    catch {
        Write-Host "     WARNING: Unable to access $g" -ForegroundColor Yellow
    }
}

if ($privilegedUsers) {
    Write-Host ""
    Write-Host "  Privileged accounts with password never expires:" -ForegroundColor Red
    $privilegedUsers | Format-Table -AutoSize
}

if ($errors) {
    Write-Host ""
    Write-Host "  Errors encountered:" -ForegroundColor Yellow
    $errors | ForEach-Object { Write-Host "     - $_" -ForegroundColor Gray }
}

$ts = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$rp = Join-Path $OutputPath "PasswordPolicyDrift-$ts.json"

$report = @{
    CheckName = "Password Policy Drift Snapshot"
    Timestamp = Get-Date -Format "o"
    Summary = @{
        TotalWeakPolicyAccounts = @($weakPolicy).Count
        PrivilegedWithWeakPolicyCount = @($privilegedUsers).Count
    }
    WeakPolicyAccounts = $weakPolicy
    PrivilegedWithWeakPolicy = $privilegedUsers
}

try {
    $json = $report | ConvertTo-Json -Depth 10
    $json | Set-Content -Path $rp
    Write-Host ""
    Write-Host "  Report saved: $rp" -ForegroundColor Cyan
}
catch {
    Write-Host ""
    Write-Host "  ERROR: Failed to save report" -ForegroundColor Red
}

Write-Host ""
Write-Host "========================================================================"

exit 0
