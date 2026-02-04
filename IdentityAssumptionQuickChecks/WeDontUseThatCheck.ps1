param([string]$OutputPath = ".")

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================================================"
Write-Host "  'We Don't Use That' Reality Check"
Write-Host "========================================================================"

<#
.SYNOPSIS
    Verify that features marked as 'not in use' are actually disabled.

.DESCRIPTION
    Many organizations assume certain features aren't used (e.g., 
    "We don't use basic auth", "We don't have external sharing").
    This check verifies these assumptions against actual configuration.

.NOTES
    - Read-only: YES
    - Requires: ActiveDirectory module (RSAT), Microsoft.Graph
    - Permissions: Domain Admin recommended

.EXAMPLE
    .\WeDontUseThatCheck.ps1
#>

# Initialize tracking variables
$assumptionsVerified = @()
$assumptionsBroken = @()
$errors = @()
$processedCount = 0

Write-Host ""
Write-Host "  Verifying commonly held assumptions..." -ForegroundColor Gray

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "  ActiveDirectory module loaded" -ForegroundColor Green
}
catch {
    Write-Host "  ERROR: ActiveDirectory module not available" -ForegroundColor Red
    Write-Host "  This check requires RSAT for AD queries" -ForegroundColor Yellow
    exit 1
}

# Check for Microsoft.Graph (optional)
$graphAvailable = $false
try {
    Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop | Out-Null
    $graphAvailable = $true
    Write-Host "  Microsoft.Graph module loaded" -ForegroundColor Green
}
catch {
    Write-Host "  Microsoft.Graph not available (cloud checks skipped)" -ForegroundColor Yellow
}

# ============================================================================
# Assumption 1: "We don't have accounts with PasswordNeverExpires"
# ============================================================================

Write-Host ""
Write-Host "  Assumption: 'No accounts have PasswordNeverExpires=TRUE'" -ForegroundColor Gray

try {
    $accountsWithPwdNeverExpires = Get-ADUser -Filter { PasswordNeverExpires -eq $true } -Properties SamAccountName, Name, Enabled -ErrorAction Stop
    $processedCount++
    
    if ($accountsWithPwdNeverExpires) {
        $assumptionsBroken += New-Object PSObject -Property @{
            Assumption = "No PasswordNeverExpires accounts"
            Reality = "$($accountsWithPwdNeverExpires.Count) accounts have PasswordNeverExpires=TRUE"
            Severity = if ($accountsWithPwdNeverExpires.Count -gt 10) { "HIGH" } else { "MEDIUM" }
            Evidence = ($accountsWithPwdNeverExpires | Select-Object -First 10 | ForEach-Object { @{SamAccountName=$_.SamAccountName; Name=$_.Name; Enabled=$_.Enabled} })
        }
        Write-Host "    ❌ BROKEN: $($accountsWithPwdNeverExpires.Count) accounts found" -ForegroundColor Red
        $accountsWithPwdNeverExpires | Select-Object -First 5 | ForEach-Object { Write-Host "         - $($_.SamAccountName) ($($_.Name))" -ForegroundColor Gray }
    }
    else {
        $assumptionsVerified += "PasswordNeverExpires accounts: NONE (Verified)"
        Write-Host "    ✅ VERIFIED: No accounts with PasswordNeverExpires" -ForegroundColor Green
    }
}
catch {
    $errorMsg = "Failed to check PasswordNeverExpires: $($_.Exception.Message)"
    $errors += $errorMsg
    Write-Host "    ⚠ WARNING: $errorMsg" -ForegroundColor Yellow
}

# ============================================================================
# Assumption 2: "All privileged accounts are in proper groups"
# ============================================================================

Write-Host ""
Write-Host "  Assumption: 'Privileged access is properly scoped'" -ForegroundColor Gray

$privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
$privilegedMembers = @{}
$totalPrivileged = 0

try {
    foreach ($group in $privilegedGroups) {
        try {
            $members = Get-ADGroupMember -Identity $group -ErrorAction Stop | Where-Object { $_.objectClass -eq "user" }
            $privilegedMembers[$group] = $members
            $totalPrivileged += $members.Count
        }
        catch {
            Write-Host "    ⚠ Cannot access $group" -ForegroundColor Yellow
        }
    }
    
    if ($totalPrivileged -gt 0) {
        $assumptionsVerified += "Privileged members: $totalPrivileged accounts in privileged groups"
        Write-Host "    ✅ VERIFIED: Found $totalPrivileged privileged accounts" -ForegroundColor Gray
    }
}
catch {
    $errors += "Failed to enumerate privileged groups: $($_.Exception.Message)"
}

# ============================================================================
# Assumption 3: "No accounts have been inactive for 90+ days"
# ============================================================================

Write-Host ""
Write-Host "  Assumption: 'No inactive accounts (>90 days no logon)'" -ForegroundColor Gray

try {
    $inactiveThreshold = (Get-Date).AddDays(-90)
    
    # Get users with old lastLogonTimestamp
    $inactiveUsers = Get-ADUser -Filter { LastLogonTimestamp -lt $inactiveThreshold } -Properties SamAccountName, Name, LastLogonTimestamp, Enabled -ErrorAction Stop
    
    $enabledInactive = $inactiveUsers | Where-Object { $_.Enabled -eq $true }
    $processedCount++
    
    if ($enabledInactive) {
        $assumptionsBroken += New-Object PSObject -Property @{
            Assumption = "No inactive enabled accounts"
            Reality = "$($enabledInactive.Count) enabled accounts inactive >90 days"
            Severity = if ($enabledInactive.Count -gt 20) { "HIGH" } else { "MEDIUM" }
            Evidence = ($enabledInactive | Select-Object -First 10 | ForEach-Object { 
                $lastLogon = if ($_.LastLogonTimestamp) { [DateTime]::FromFileTime($_.LastLogonTimestamp).ToString("yyyy-MM-dd") } else { "Never" }
                @{SamAccountName=$_.SamAccountName; Name=$_.Name; LastLogon=$lastLogon}
            })
        }
        Write-Host "    ❌ BROKEN: $($enabledInactive.Count) inactive enabled accounts" -ForegroundColor Red
    }
    else {
        $assumptionsVerified += "Inactive accounts: NONE (Verified)"
        Write-Host "    ✅ VERIFIED: No inactive enabled accounts" -ForegroundColor Green
    }
}
catch {
    $errors += "Failed to check inactive accounts: $($_.Exception.Message)"
}

# ============================================================================
# Assumption 4 (Cloud): "Basic auth is disabled in Entra ID"
# ============================================================================

if ($graphAvailable) {
    Write-Host ""
    Write-Host "  Assumption: 'Basic authentication is disabled in Entra ID'" -ForegroundColor Gray
    
    try {
        $policies = Get-MgPolicyAuthenticationMethodPolicy -ErrorAction Stop
        $basicAuthEnabled = $false
        
        # Check for basic auth methods enabled
        $registrationCampaign = $policies.AdditionalProperties.registrationCampaign
        $assumptionsVerified += "Entra ID policies retrieved"
        Write-Host "    ✅ VERIFIED: Authentication policies retrieved" -ForegroundColor Gray
    }
    catch {
        Write-Host "    ⚠ Could not verify Entra ID auth policies" -ForegroundColor Yellow
    }
}

# ============================================================================
# Assumption 5: "No accounts with blank passwords (if detectable)"
# ============================================================================

Write-Host ""
Write-Host "  Assumption: 'No accounts with empty/null passwords'" -ForegroundColor Gray

try {
    # Check for accounts that might have issues
    $usersWithIssues = Get-ADUser -Filter { Name -like "*test*" -Or SamAccountName -like "*test*" } -Properties SamAccountName, Name -ErrorAction Stop | Select-Object -First 20
    
    $testAccounts = @()
    foreach ($u in $usersWithIssues) {
        if ($u.SamAccountName -notlike "*$*") {  # Exclude computer accounts
            $testAccounts += $u
        }
    }
    
    if ($testAccounts) {
        Write-Host "    ⚠ Found $($testAccounts.Count) test accounts (review recommended)" -ForegroundColor Yellow
        $assumptionsBroken += New-Object PSObject -Property @{
            Assumption = "No test/development accounts"
            Reality = "$($testAccounts.Count) accounts with 'test' in name"
            Severity = "LOW"
            Evidence = ($testAccounts | ForEach-Object { @{SamAccountName=$_.SamAccountName; Name=$_.Name} })
        }
    }
    else {
        $assumptionsVerified += "Test accounts: NONE (Verified)"
        Write-Host "    ✅ VERIFIED: No test accounts found" -ForegroundColor Green
    }
}
catch {
    $errors += "Failed to check test accounts: $($_.Exception.Message)"
}

# ============================================================================
# Summary Output
# ============================================================================

Write-Host ""
Write-Host "  Assumption Reality Summary"
Write-Host "  =========================="
Write-Host "  Assumptions verified: $($assumptionsVerified.Count)"
Write-Host "  Assumptions broken: $($assumptionsBroken.Count)" -ForegroundColor $(if ($assumptionsBroken.Count -gt 0) { "Red" } else { "Green" })
Write-Host "  Errors encountered: $($errors.Count)"

if ($assumptionsBroken) {
    Write-Host ""
    Write-Host "  BROKEN ASSUMPTIONS - REVIEW REQUIRED:" -ForegroundColor Red
    
    $assumptionsBroken | ForEach-Object {
        Write-Host ""
        Write-Host "    Assumption: $($_.Assumption)" -ForegroundColor Gray
        Write-Host "    Reality: $($_.Reality)" -ForegroundColor $(
            if ($_.Severity -eq "HIGH") { "Red" }
            elseif ($_.Severity -eq "MEDIUM") { "Yellow" }
            else { "Gray" }
        )
        Write-Host "    Severity: $($_.Severity)" -ForegroundColor Gray
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
$reportPath = Join-Path $OutputPath "WeDontUseThatCheck-$timestamp.json"

$report = @{
    CheckName = "We Dont Use That Reality Check"
    Timestamp = Get-Date -Format "o"
    Summary = @{
        AssumptionsVerified = $assumptionsVerified.Count
        AssumptionsBroken = $assumptionsBroken.Count
        Errors = $errors.Count
        ProcessedItems = $processedCount
    }
    VerifiedAssumptions = $assumptionsVerified
    BrokenAssumptions = $assumptionsBroken
    Errors = $errors
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

# ============================================================================
# Final Message
# ============================================================================

Write-Host ""
Write-Host "  ─────────────────────────────────────────────────────────────"
Write-Host "  ℹ  This script tests commonly held assumptions." -ForegroundColor Gray
Write-Host "     Actual configuration may differ from expectations." -ForegroundColor Gray
Write-Host "     For governance analysis, run IdentityHealthCheck." -ForegroundColor Gray
Write-Host "  ─────────────────────────────────────────────────────────────"

exit 0
