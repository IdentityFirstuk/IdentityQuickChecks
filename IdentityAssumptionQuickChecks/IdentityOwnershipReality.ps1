param([string]$OutputPath = ".")

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================================================"
Write-Host "  Identity Ownership Reality Check"
Write-Host "========================================================================"

<#
.SYNOPSIS
    Verify that identity ownership can actually be determined.

.DESCRIPTION
    Many organizations claim to have ownership tracking for accounts,
    but in practice, descriptions are empty, managers are missing,
    and no one knows who owns critical accounts.

.NOTES
    - Read-only: YES
    - Requires: ActiveDirectory module (RSAT)
    - Permissions: Domain Admin recommended

.EXAMPLE
    .\IdentityOwnershipReality.ps1
#>

# Initialize tracking variables
$ownershipData = @()
$ownershipGaps = @()
$ownershipVerified = @()
$errors = @()
$processedCount = 0

Write-Host ""
Write-Host "  Analyzing identity ownership capabilities..." -ForegroundColor Gray

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "  ActiveDirectory module loaded" -ForegroundColor Green
}
catch {
    Write-Host "  ERROR: ActiveDirectory module not available" -ForegroundColor Red
    exit 1
}

# ============================================================================
# Check 1: Accounts with missing descriptions (no ownership info)
# ============================================================================

Write-Host ""
Write-Host "  Checking for accounts with missing descriptions..." -ForegroundColor Gray

try {
    $allUsers = Get-ADUser -Filter * -Properties SamAccountName, Name, Description, ManagedBy, Created -ErrorAction Stop
    $processedCount += $allUsers.Count
    
    $missingDescription = $allUsers | Where-Object { [string]::IsNullOrWhiteSpace($_.Description) }
    
    if ($missingDescription) {
        $ownershipGaps += New-Object PSObject -Property @{
            GapType = "Missing Description"
            Count = $missingDescription.Count
            Percentage = [math]::Round(($missingDescription.Count / $allUsers.Count) * 100, 1)
            Sample = ($missingDescription | Select-Object -First 10 | ForEach-Object { @{SamAccountName=$_.SamAccountName; Name=$_.Name} })
        }
        Write-Host "    ⚠ $($missingDescription.Count) accounts ($($ownershipGaps[-1].Percentage)%) have no description" -ForegroundColor Yellow
    }
    else {
        $ownershipVerified += "All accounts have descriptions"
        Write-Host "    ✅ All accounts have descriptions" -ForegroundColor Green
    }
}
catch {
    $errorMsg = "Failed to check descriptions: $($_.Exception.Message)"
    $errors += $errorMsg
    Write-Host "    ⚠ WARNING: $errorMsg" -ForegroundColor Yellow
}

# ============================================================================
# Check 2: Accounts with missing ManagedBy (no owner assigned)
# ============================================================================

Write-Host ""
Write-Host "  Checking for accounts with missing ManagedBy..." -ForegroundColor Gray

try {
    $allUsers = Get-ADUser -Filter * -Properties SamAccountName, Name, ManagedBy, Description -ErrorAction Stop
    
    $missingManagedBy = $allUsers | Where-Object { [string]::IsNullOrEmpty($_.ManagedBy) }
    
    if ($missingManagedBy) {
        $ownershipGaps += New-Object PSObject -Property @{
            GapType = "Missing ManagedBy"
            Count = $missingManagedBy.Count
            Percentage = [math]::Round(($missingManagedBy.Count / $allUsers.Count) * 100, 1)
            Sample = ($missingManagedBy | Select-Object -First 10 | ForEach-Object { @{SamAccountName=$_.SamAccountName; Name=$_.Name} })
        }
        Write-Host "    ⚠ $($missingManagedBy.Count) accounts ($($ownershipGaps[-1].Percentage)%) have no ManagedBy" -ForegroundColor Yellow
    }
    else {
        $ownershipVerified += "All accounts have ManagedBy set"
        Write-Host "    ✅ All accounts have ManagedBy assigned" -ForegroundColor Green
    }
}
catch {
    $errors += "Failed to check ManagedBy: $($_.Exception.Message)"
}

# ============================================================================
# Check 3: Service accounts without known ownership
# ============================================================================

Write-Host ""
Write-Host "  Checking service accounts for ownership..." -ForegroundColor Gray

$svcIndicators = @("SVC-", "svc-", "Service_", "svc_", "ServiceAccount", "-SA", "_SA")
$serviceAccounts = @()

try {
    foreach ($indicator in $svcIndicators) {
        $svc = $allUsers | Where-Object { $_.SamAccountName -like "*$indicator*" -Or $_.Name -like "*$indicator*" }
        $serviceAccounts += $svc
    }
    $serviceAccounts = $serviceAccounts | Sort-Object -Property SamAccountName -Unique
    
    if ($serviceAccounts) {
        $svcNoOwner = $serviceAccounts | Where-Object { [string]::IsNullOrEmpty($_.ManagedBy) -Or [string]::IsNullOrWhiteSpace($_.Description) }
        
        if ($svcNoOwner) {
            $ownershipGaps += New-Object PSObject -Property @{
                GapType = "Service Accounts Without Ownership"
                Count = $svcNoOwner.Count
                TotalServiceAccounts = $serviceAccounts.Count
                Sample = ($svcNoOwner | Select-Object -First 10 | ForEach-Object { @{SamAccountName=$_.SamAccountName; Name=$_.Name; HasDescription=(-not [string]::IsNullOrWhiteSpace($_.Description))} })
            }
            Write-Host "    ⚠ $($svcNoOwner.Count) of $($serviceAccounts.Count) service accounts lack ownership" -ForegroundColor Yellow
        }
        else {
            $ownershipVerified += "All $($serviceAccounts.Count) service accounts have ownership"
            Write-Host "    ✅ All $($serviceAccounts.Count) service accounts have ownership" -ForegroundColor Green
        }
    }
    else {
        Write-Host "    ℹ No service accounts detected (based on naming patterns)" -ForegroundColor Gray
    }
}
catch {
    $errors += "Failed to check service accounts: $($_.Exception.Message)"
}

# ============================================================================
# Check 4: Privileged accounts ownership
# ============================================================================

Write-Host ""
Write-Host "  Checking privileged accounts for ownership..." -ForegroundColor Gray

$privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
$privilegedMembers = @()

try {
    foreach ($group in $privilegedGroups) {
        try {
            $members = Get-ADGroupMember -Identity $group -ErrorAction Stop | Where-Object { $_.objectClass -eq "user" }
            $privilegedMembers += $members
        }
        catch {
            Write-Host "    ⚠ Cannot access $group" -ForegroundColor Yellow
        }
    }
    $privilegedMembers = $privilegedMembers | Sort-Object -Property SamAccountName -Unique
    
    if ($privilegedMembers) {
        $privNoOwner = $privilegedMembers | Where-Object { 
            $user = Get-ADUser -Identity $_.DistinguishedName -Properties ManagedBy -ErrorAction SilentlyContinue
            [string]::IsNullOrEmpty($user.ManagedBy)
        }
        
        if ($privNoOwner) {
            $ownershipGaps += New-Object PSObject -Property @{
                GapType = "Privileged Accounts Without Owner"
                Count = $privNoOwner.Count
                TotalPrivileged = $privilegedMembers.Count
                Severity = "HIGH"
                Sample = ($privNoOwner | Select-Object -First 10 | ForEach-Object { @{SamAccountName=$_.SamAccountName; Name=$_.Name} })
            }
            Write-Host "    ⚠ $($privNoOwner.Count) of $($privilegedMembers.Count) privileged accounts have no owner" -ForegroundColor Red
        }
        else {
            $ownershipVerified += "All $($privilegedMembers.Count) privileged accounts have owners"
            Write-Host "    ✅ All $($privilegedMembers.Count) privileged accounts have owners" -ForegroundColor Green
        }
    }
}
catch {
    $errors += "Failed to check privileged accounts: $($_.Exception.Message)"
}

# ============================================================================
# Check 5: Accounts with managers (HR traceability)
# ============================================================================

Write-Host ""
Write-Host "  Checking manager attribute population..." -ForegroundColor Gray

try {
    $usersWithManager = $allUsers | Where-Object { -not [string]::IsNullOrEmpty($_.Manager) }
    $usersWithoutManager = $allUsers.Count - $usersWithManager.Count
    
    $percentWithManager = [math]::Round(($usersWithManager.Count / $allUsers.Count) * 100, 1)
    
    if ($percentWithManager -lt 50) {
        $ownershipGaps += New-Object PSObject -Property @{
            GapType = "Low Manager Coverage"
            Count = $usersWithoutManager
            Percentage = [math]::Round(($usersWithoutManager / $allUsers.Count) * 100, 1)
            Severity = if ($percentWithManager -lt 25) { "HIGH" } else { "MEDIUM" }
        }
        Write-Host "    ⚠ Only $percentWithManager% of accounts have managers assigned" -ForegroundColor Yellow
    }
    else {
        $ownershipVerified += "Manager coverage: $percentWithManager%"
        Write-Host "    ✅ $percentWithManager% of accounts have managers" -ForegroundColor Green
    }
}
catch {
    $errors += "Failed to check manager attribute: $($_.Exception.Message)"
}

# ============================================================================
# Summary Output
# ============================================================================

Write-Host ""
Write-Host "  Ownership Reality Summary"
Write-Host "  ========================="
Write-Host "  Total users analyzed: $processedCount"
Write-Host "  Ownership verified: $($ownershipVerified.Count) areas"
Write-Host "  Ownership gaps found: $($ownershipGaps.Count)" -ForegroundColor $(if ($ownershipGaps.Count -gt 0) { "Red" } else { "Green" })
Write-Host "  Errors: $($errors.Count)"

if ($ownershipGaps) {
    Write-Host ""
    Write-Host "  OWNERSHIP GAPS REQUIRING REVIEW:" -ForegroundColor Red
    
    foreach ($gap in $ownershipGaps) {
        $sevColor = if ($gap.Severity -eq "HIGH") { "Red" } elseif ($gap.Severity -eq "MEDIUM") { "Yellow" } else { "Gray" }
        Write-Host ""
        Write-Host "    Gap: $($gap.GapType)" -ForegroundColor Gray
        Write-Host "    Impact: $($gap.Count) accounts ($($gap.Percentage)%)" -ForegroundColor $sevColor
        if ($gap.Severity) {
            Write-Host "    Severity: $($gap.Severity)" -ForegroundColor $sevColor
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
$reportPath = Join-Path $OutputPath "IdentityOwnershipReality-$timestamp.json"

$report = @{
    CheckName = "Identity Ownership Reality Check"
    Timestamp = Get-Date -Format "o"
    Summary = @{
        TotalUsersAnalyzed = $processedCount
        OwnershipVerified = $ownershipVerified.Count
        OwnershipGaps = $ownershipGaps.Count
        Errors = $errors.Count
    }
    VerifiedAreas = $ownershipVerified
    OwnershipGaps = $ownershipGaps
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
Write-Host "  ℹ  This script shows where ownership information is incomplete." -ForegroundColor Gray
Write-Host "     It cannot answer: Who should own these accounts?" -ForegroundColor Gray
Write-Host "     For ownership governance, run IdentityHealthCheck." -ForegroundColor Gray
Write-Host "  ─────────────────────────────────────────────────────────────"

exit 0
