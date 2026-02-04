param([string]$OutputPath = ".")

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================================================"
Write-Host "  Identity Review Debt Check"
Write-Host "========================================================================"

<#
.SYNOPSIS
    Find privileged access that hasn't been reviewed in years.

.DESCRIPTION
    Identifies accounts and group memberships that have remained unchanged
    for extended periods, potentially representing "review debt" where
    access hasn't been validated against current needs.

.NOTES
    - Read-only: YES
    - Requires: ActiveDirectory module (RSAT)
    - Permissions: Domain Admin recommended

.EXAMPLE
    .\IdentityReviewDebt.ps1
#>

# Initialize tracking variables
$reviewDebt = @()
$recentReviews = @()
$errors = @()
$processedCount = 0

Write-Host ""
Write-Host "  Analyzing identity review debt..." -ForegroundColor Gray

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "  ActiveDirectory module loaded" -ForegroundColor Green
}
catch {
    Write-Host "  ERROR: ActiveDirectory module not available" -ForegroundColor Red
    exit 1
}

# Define thresholds
$Thresholds = @{
    NoLogonWarning = 180    # Days without logon
    NoLogonCritical = 365   # Days without logon (highly suspicious)
    PasswordNeverChanged = 365  # Days with same password
    GroupMembershipOld = 730     # Days in same privileged group
}

# ============================================================================
# Check 1: Accounts with no logon in extended period
# ============================================================================

Write-Host ""
Write-Host "  Checking for dormant accounts (>180 days)..." -ForegroundColor Gray

try {
    $dormantThreshold = (Get-Date).AddDays(-$Thresholds.NoLogonWarning)
    $allUsers = Get-ADUser -Filter * -Properties SamAccountName, Name, LastLogonTimestamp, Enabled, PasswordLastSet, whenCreated -ErrorAction Stop
    
    $dormantAccounts = $allUsers | Where-Object {
        $_.Enabled -eq $true -and
        $_.LastLogonTimestamp -and
        ([DateTime]::FromFileTime($_.LastLogonTimestamp)) -lt $dormantThreshold
    }
    
    $processedCount += $allUsers.Count
    
    if ($dormantAccounts) {
        $highDebt = $dormantAccounts | Where-Object {
            $lastLogon = [DateTime]::FromFileTime($_.LastLogonTimestamp)
            ((Get-Date) - $lastLogon).Days -gt $Thresholds.NoLogonCritical
        }
        
        $reviewDebt += New-Object PSObject -Property @{
            Category = "Dormant Enabled Accounts"
            Count = $dormantAccounts.Count
            CriticalCount = $highDebt.Count
            Threshold = "$($Thresholds.NoLogonWarning) days"
            Sample = ($dormantAccounts | Select-Object -First 10 | ForEach-Object {
                $lastLogon = [DateTime]::FromFileTime($_.LastLogonTimestamp)
                @{
                    SamAccountName = $_.SamAccountName
                    Name = $_.Name
                    DaysSinceLogon = ((Get-Date) - $lastLogon).Days
                    Critical = $highDebt -contains $_
                }
            })
        }
        
        Write-Host "    ⚠ $($dormantAccounts.Count) enabled accounts dormant >$($Thresholds.NoLogonWarning) days" -ForegroundColor $(if ($highDebt.Count -gt 0) { "Red" } else { "Yellow" })
        Write-Host "       ($($highDebt.Count) dormant >$($Thresholds.NoLogonCritical) days - CRITICAL)" -ForegroundColor Red
    }
    else {
        $recentReviews += "No dormant enabled accounts found"
        Write-Host "    ✅ No dormant enabled accounts found" -ForegroundColor Green
    }
}
catch {
    $errors += "Failed to check dormant accounts: $($_.Exception.Message)"
    Write-Host "    ⚠ ERROR: $($_.Exception.Message)" -ForegroundColor Yellow
}

# ============================================================================
# Check 2: Privileged group membership unchanged
# ============================================================================

Write-Host ""
Write-Host "  Checking privileged group membership age..." -ForegroundColor Gray

$privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
$privilegedMembers = @{}

try {
    foreach ($group in $privilegedGroups) {
        try {
            $members = Get-ADGroupMember -Identity $group -ErrorAction Stop
            $privilegedMembers[$group] = $members
        }
        catch {
            Write-Host "    ⚠ Cannot access $group" -ForegroundColor Yellow
        }
    }
    
    $allPrivilegedMembers = $privilegedMembers.Values | ForEach-Object { $_ }
    $uniquePrivileged = $allPrivilegedMembers | Sort-Object -Property ObjectGUID -Unique
    
    if ($uniquePrivileged) {
        $reviewDebt += New-Object PSObject -Property @{
            Category = "Privileged Group Membership"
            TotalMembers = $uniquePrivileged.Count
            ByGroup = $privilegedGroups | ForEach-Object {
                @{
                    Group = $_
                    Count = ($privilegedMembers[$_] | Measure-Object).Count
                }
            }
        }
        
        Write-Host "    ℹ $($uniquePrivileged.Count) total privileged members found" -ForegroundColor Gray
        foreach ($group in $privilegedGroups) {
            $count = ($privilegedMembers[$group] | Measure-Object).Count
            Write-Host "       $group : $count members" -ForegroundColor Gray
        }
    }
}
catch {
    $errors += "Failed to check privileged groups: $($_.Exception.Message)"
}

# ============================================================================
# Check 3: Service accounts with old passwords
# ============================================================================

Write-Host ""
Write-Host "  Checking service account password age..." -ForegroundColor Gray

$svcIndicators = @("SVC-", "svc-", "Service_", "svc_", "$")

try {
    $serviceAccounts = $allUsers | Where-Object {
        $indicatorFound = $false
        foreach ($indicator in $svcIndicators) {
            if ($_.SamAccountName -like "*$indicator*") {
                $indicatorFound = $true
                break
            }
        }
        $indicatorFound
    }
    
    if ($serviceAccounts) {
        $pwdThreshold = (Get-Date).AddDays(-$Thresholds.PasswordNeverChanged)
        $oldPwdSvc = $serviceAccounts | Where-Object {
            $_.PasswordLastSet -and ([DateTime]::FromFileTime($_.PasswordLastSet)) -lt $pwdThreshold
        }
        
        if ($oldPwdSvc) {
            $reviewDebt += New-Object PSObject -Property @{
                Category = "Service Accounts With Old Passwords"
                Count = $oldPwdSvc.Count
                Threshold = "$($Thresholds.PasswordNeverChanged) days"
                Sample = ($oldPwdSvc | Select-Object -First 10 | ForEach-Object {
                    $pwdDate = [DateTime]::FromFileTime($_.PasswordLastSet)
                    @{
                        SamAccountName = $_.SamAccountName
                        Name = $_.Name
                        DaysSincePasswordChange = ((Get-Date) - $pwdDate).Days
                    }
                })
            }
            Write-Host "    ⚠ $($oldPwdSvc.Count) service accounts with passwords >$($Thresholds.PasswordNeverChanged) days old" -ForegroundColor Yellow
        }
        else {
            Write-Host "    ✅ All service account passwords are current" -ForegroundColor Green
        }
    }
}
catch {
    $errors += "Failed to check service account passwords: $($_.Exception.Message)"
}

# ============================================================================
# Check 4: Stale computer accounts
# ============================================================================

Write-Host ""
Write-Host "  Checking for stale computer accounts..." -ForegroundColor Gray

try {
    $computers = Get-ADComputer -Filter { Enabled -eq $true } -Properties Name, LastLogonTimestamp, OperatingSystem -ErrorAction Stop
    $processedCount += $computers.Count
    
    $staleComputers = $computers | Where-Object {
        $_.LastLogonTimestamp -and
        ([DateTime]::FromFileTime($_.LastLogonTimestamp)) -lt $dormantThreshold
    }
    
    if ($staleComputers) {
        $reviewDebt += New-Object PSObject -Property @{
            Category = "Stale Computer Accounts"
            Count = $staleComputers.Count
            Threshold = "$($Thresholds.NoLogonWarning) days without logon"
            Sample = ($staleComputers | Select-Object -First 5 | ForEach-Object {
                $lastLogon = [DateTime]::FromFileTime($_.LastLogonTimestamp)
                @{
                    Name = $_.Name
                    OperatingSystem = $_.OperatingSystem
                    DaysSinceLogon = ((Get-Date) - $lastLogon).Days
                }
            })
        }
        Write-Host "    ⚠ $($staleComputers.Count) enabled computers dormant >$($Thresholds.NoLogonWarning) days" -ForegroundColor Yellow
    }
    else {
        Write-Host "    ✅ No stale computer accounts found" -ForegroundColor Green
    }
}
catch {
    $errors += "Failed to check computer accounts: $($_.Exception.Message)"
}

# ============================================================================
# Summary Output
# ============================================================================

Write-Host ""
Write-Host "  Review Debt Summary"
Write-Host "  =================="
Write-Host "  Items analyzed: $processedCount"
Write-Host "  Review debt items: $($reviewDebt.Count)" -ForegroundColor $(if ($reviewDebt.Count -gt 0) { "Yellow" } else { "Green" })
Write-Host "  Recent reviews verified: $($recentReviews.Count)"

if ($reviewDebt) {
    Write-Host ""
    Write-Host "  REVIEW DEBT ITEMS:"
    $reviewDebt | ForEach-Object {
        Write-Host ""
        Write-Host "    Category: $($_.Category)" -ForegroundColor Gray
        if ($_.Count) {
            Write-Host "    Impact: $($_.Count) items" -ForegroundColor Yellow
        }
        if ($_.Threshold) {
            Write-Host "    Threshold: $($_.Threshold)" -ForegroundColor Gray
        }
    }
}

if ($errors) {
    Write-Host ""
    Write-Host "  Errors encountered:" -ForegroundColor Yellow
    foreach ($err in $errors) {
        Write-Host "    - $err" -ForegroundColor Gray
    }
}

# ============================================================================
# Generate Report
# ============================================================================

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$reportPath = Join-Path $OutputPath "IdentityReviewDebt-$timestamp.json"

$report = @{
    CheckName = "Identity Review Debt"
    Timestamp = Get-Date -Format "o"
    Summary = @{
        ItemsAnalyzed = $processedCount
        ReviewDebtItems = $reviewDebt.Count
        Errors = $errors.Count
    }
    ReviewDebt = $reviewDebt
    RecentReviews = $recentReviews
    Errors = $errors
    Thresholds = $Thresholds
}

try {
    $jsonOutput = $report | ConvertTo-Json -Depth 10
    $jsonOutput | Set-Content -Path $reportPath -ErrorAction Stop
    Write-Host ""
    Write-Host "  Report saved: $reportPath" -ForegroundColor Cyan
}
catch {
    Write-Host ""
    Write-Host "  ERROR: Failed to save report" -ForegroundColor Red
}

Write-Host ""
Write-Host "  ─────────────────────────────────────────────────────────────"
Write-Host "  ℹ  Review debt items should be validated periodically." -ForegroundColor Gray
Write-Host "     For governance automation, run IdentityHealthCheck." -ForegroundColor Gray
Write-Host "  ─────────────────────────────────────────────────────────────"

exit 0
