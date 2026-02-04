param(
    [string]$OutputPath = "."
)

$ErrorActionPreference = "Stop"

<#
.SYNOPSIS
    Find break-glass accounts and check their posture.

.DESCRIPTION
    Searches for accounts named or described as break-glass,
    emergency, or firecall accounts. Reports on their posture
    including password never expires, last logon, and risk factors.

.NOTES
    - Read-only: YES
    - Requires: ActiveDirectory module (RSAT)
    - Permissions: Domain Admin recommended

.EXAMPLE
    .\BreakGlassReality.ps1

.EXAMPLE
    # As module command
    Invoke-BreakGlassReality -OutputPath ".\Reports"
#>

# =============================================================================
# Pre-flight Checks
# =============================================================================

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Validates all prerequisites before running the check.
    #>
    [CmdletBinding()]
    param()

    $prerequisites = @{
        ActiveDirectoryModule = $false
        AdminRights = $false
        PowerShellVersion = $false
    }

    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -ge 5) {
        $prerequisites.PowerShellVersion = $true
    }

    # Check ActiveDirectory module
    try {
        $module = Get-Module -Name ActiveDirectory -ListAvailable -ErrorAction Stop
        $prerequisites.ActiveDirectoryModule = $true
        Write-Verbose "ActiveDirectory module found: $($module.Version)"
    }
    catch {
        Write-Warning "ActiveDirectory module not available: $($_.Exception.Message)"
    }

    # Check admin rights
    try {
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
        $prerequisites.AdminRights = $principal.IsInRole(
            [System.Security.Principal.WindowsBuiltInRole]::Administrator
        )
    }
    catch {
        Write-Warning "Could not determine admin status: $($_.Exception.Message)"
    }

    return $prerequisites
}

# =============================================================================
# Security Validation
# =============================================================================

function Test-SecureExecution {
    <#
    .SYNOPSIS
        Validates secure execution context.
    #>
    [CmdletBinding()]
    param()

    $securityChecks = @{
        ExecutionPolicy = "Unknown"
        ConstrainedLanguage = $false
        TranscriptStatus = "NotRunning"
    }

    # Check execution policy
    try {
        $policy = Get-ExecutionPolicy -Scope CurrentUser -ErrorAction Stop
        $securityChecks.ExecutionPolicy = $policy.ToString()
    }
    catch {
        $securityChecks.ExecutionPolicy = "Unknown"
    }

    # Check constrained language mode
    if ($ExecutionContext.SessionState.LanguageMode -eq 'ConstrainedLanguage') {
        $securityChecks.ConstrainedLanguage = $true
    }

    # Check transcript
    try {
        $transcript = Get-Transcript -ErrorAction Stop
        if ($transcript) {
            $securityChecks.TranscriptStatus = "Running"
        }
    }
    catch {
        $securityChecks.TranscriptStatus = "NotRunning"
    }

    return $securityChecks
}

# =============================================================================
# Main Logic
# =============================================================================

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  Break-Glass Reality Check" -ForegroundColor Cyan
Write-Host "  Identity Security Assessment" -ForegroundColor Gray
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

# Run pre-flight checks
Write-Host "[PRE-FLIGHT] Running prerequisite checks..." -ForegroundColor Yellow
$prereqs = Test-Prerequisites

Write-Host "  PowerShell $($PSVersionTable.PSVersion): $($prereqs.PowerShellVersion)" -ForegroundColor $(if ($prereqs.PowerShellVersion) { 'Green' } else { 'Red' })
Write-Host "  ActiveDirectory Module: $($prereqs.ActiveDirectoryModule)" -ForegroundColor $(if ($prereqs.ActiveDirectoryModule) { 'Green' } else { 'Red' })
Write-Host "  Admin Rights: $($prereqs.AdminRights)" -ForegroundColor $(if ($prereqs.AdminRights) { 'Green' } else { 'Yellow' })

# Run security checks
Write-Host ""
Write-Host "[SECURITY] Validating execution context..." -ForegroundColor Yellow
$security = Test-SecureExecution
Write-Host "  Execution Policy: $($security.ExecutionPolicy)" -ForegroundColor $(if ($security.ExecutionPolicy -in @('RemoteSigned', 'AllSigned')) { 'Green' } else { 'Yellow' })
Write-Host "  Constrained Mode: $($security.ConstrainedLanguage)" -ForegroundColor $(if ($security.ConstrainedLanguage) { 'Green' } else { 'Yellow' })
Write-Host "  Transcript: $($security.TranscriptStatus)" -ForegroundColor Gray

# Validate prerequisites
if (-not $prereqs.ActiveDirectoryModule) {
    Write-Host ""
    Write-Host "[ERROR] ActiveDirectory module is required. Install RSAT and retry." -ForegroundColor Red
    Write-Host "        Run: Install-WindowsFeature -Name RSAT-AD-PowerShell" -ForegroundColor Gray
    exit 1
}

$breakGlassAccounts = @()
$errors = @()
$processedCount = 0

Write-Host ""
Write-Host "[SCAN] Searching for break-glass account patterns..." -ForegroundColor Yellow

# Load ActiveDirectory module
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "  ActiveDirectory module loaded successfully" -ForegroundColor Green
}
catch {
    Write-Host "  ERROR: Failed to load ActiveDirectory module: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Define search patterns for break-glass accounts
$bgPatterns = @(
    "*break*glass*",
    "*bg-*",
    "*breakglass*",
    "*emergency*",
    "*firewall*",
    "*disaster*recovery*",
    "*dr-*",
    "*escrow*",
    "*hold*",
    "*admin*break*",
    "*fire*call*",
    "*breakout*",
    "*critical*",
    "*fortress*"
)

$searchResults = @()

foreach ($pattern in $bgPatterns) {
    try {
        Write-Host "  Scanning pattern: $pattern" -ForegroundColor Gray
        $found = Get-ADUser -Filter {
            SamAccountName -like $pattern -Or
            Name -like $pattern -Or
            Description -like $pattern
        } -Properties SamAccountName, Name, Description, Enabled, PasswordNeverExpires,
                      LastLogonTimestamp, whenCreated, DistinguishedName, pwdLastSet,
                      MemberOf -ErrorAction Stop

        if ($found) {
            $searchResults += $found
            Write-Host "    Found $($found.Count) matches" -ForegroundColor Green
        }
    }
    catch {
        $errorMsg = "Pattern '$pattern' failed: $($_.Exception.Message)"
        $errors += $errorMsg
        Write-Host "    ERROR: $errorMsg" -ForegroundColor Red
    }
}

# Remove duplicates
if ($searchResults) {
    $searchResults = $searchResults | Sort-Object -Property ObjectGUID -Unique
}

Write-Host ""
Write-Host "[ANALYSIS] Analyzing $($searchResults.Count) potential break-glass accounts..." -ForegroundColor Yellow

foreach ($account in $searchResults) {
    try {
        $processedCount++

        # Calculate last logon
        $lastLogon = "Never"
        if ($account.LastLogonTimestamp) {
            try {
                $lastLogonDate = [DateTime]::FromFileTime($account.LastLogonTimestamp)
                $lastLogon = $lastLogonDate.ToString("yyyy-MM-dd")
            }
            catch {
                $lastLogon = "Unknown"
            }
        }

        # Calculate password age
        $pwdAge = "N/A"
        if ($account.pwdLastSet -and $account.pwdLastSet -ne 0) {
            try {
                $pwdDate = [DateTime]::FromFileTime($account.pwdLastSet)
                $pwdAge = (New-TimeSpan -Start $pwdDate -End (Get-Date)).Days
            }
            catch {
                $pwdAge = "Unknown"
            }
        }

        # Calculate group membership count
        $groupCount = ($account.MemberOf | Measure-Object).Count

        # Calculate risk indicators
        $riskIndicators = @()
        $riskScore = 0

        if ($account.Enabled -eq $true) {
            $riskIndicators += "Account is ENABLED"
            $riskScore += 10
        }
        else {
            $riskIndicators += "Account is DISABLED"
        }

        if ($account.PasswordNeverExpires -eq $true) {
            $riskIndicators += "PasswordNeverExpires=TRUE"
            $riskScore += 15
        }

        if ($pwdAge -ne "N/A" -and $pwdAge -gt 90) {
            $riskIndicators += "Password age: $pwdAge days (>90)"
            $riskScore += 10
        }

        if ($lastLogon -ne "Never") {
            try {
                $lastLogonDate = [DateTime]::Parse($lastLogon)
                $daysSinceLogon = (New-TimeSpan -Start $lastLogonDate -End (Get-Date)).Days
                if ($daysSinceLogon -gt 180) {
                    $riskIndicators += "Last logon: $lastLogon (>180 days)"
                    $riskScore += 10
                }
            }
            catch {
                # Ignore parsing errors
            }
        }

        if ($groupCount -gt 10) {
            $riskIndicators += "MemberOf groups: $groupCount (>10)"
            $riskScore += 5
        }

        # Determine risk level
        $riskLevel = if ($riskScore -ge 25) { "HIGH" } elseif ($riskScore -ge 10) { "MEDIUM" } else { "LOW" }

        # Build finding object
        $finding = New-Object PSObject -Property @{
            Id = "BGA-$(Get-Date -Format 'yyyyMMdd')-$(Get-Random -Minimum 1000 -Maximum 9999)"
            SamAccountName = $account.SamAccountName
            Name = $account.Name
            Description = $account.Description
            Enabled = $account.Enabled
            PasswordNeverExpires = $account.PasswordNeverExpires
            LastLogon = $lastLogon
            PasswordAgeDays = $pwdAge
            GroupMembershipCount = $groupCount
            Created = $account.whenCreated
            DistinguishedName = $account.DistinguishedName
            RiskLevel = $riskLevel
            RiskScore = $riskScore
            RiskIndicators = $riskIndicators -join "; "
            Timestamp = [datetime]::UtcNow
        }

        $breakGlassAccounts += $finding

        Write-Host "  [$riskLevel] $($account.SamAccountName) - Risk Score: $riskScore" -ForegroundColor $(if ($riskLevel -eq 'HIGH') { 'Red' } elseif ($riskLevel -eq 'MEDIUM') { 'Yellow' } else { 'Green' })
    }
    catch {
        $errorMsg = "Failed to process account $($account.SamAccountName): $($_.Exception.Message)"
        $errors += $errorMsg
        Write-Host "  WARNING: $errorMsg" -ForegroundColor Yellow
    }
}

# =============================================================================
# Report Generation
# =============================================================================

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  BREAK-GLASS ACCOUNT ASSESSMENT RESULTS" -ForegroundColor White
Write-Host "========================================================================" -ForegroundColor Cyan

# Summary statistics
$highRisk = ($breakGlassAccounts | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
$mediumRisk = ($breakGlassAccounts | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
$lowRisk = ($breakGlassAccounts | Where-Object { $_.RiskLevel -eq "LOW" }).Count

Write-Host ""
Write-Host "  ASSESSMENT SUMMARY" -ForegroundColor White
Write-Host "  ─────────────────────────────────────────" -ForegroundColor Gray
Write-Host "  Total accounts found:      $($breakGlassAccounts.Count)" -ForegroundColor $(if ($breakGlassAccounts.Count -gt 0) { "Yellow" } else { "Green" })
Write-Host "  Accounts processed:        $processedCount"
Write-Host ""
Write-Host "  Risk Breakdown:" -ForegroundColor White
Write-Host "    HIGH Risk:   $highRisk" -ForegroundColor $(if ($highRisk -gt 0) { 'Red' } else { 'Green' })
Write-Host "    MEDIUM Risk: $mediumRisk" -ForegroundColor $(if ($mediumRisk -gt 0) { 'Yellow' } else { 'Green' })
Write-Host "    LOW Risk:    $lowRisk" -ForegroundColor Green

if ($errors.Count -gt 0) {
    Write-Host ""
    Write-Host "  Errors encountered: $($errors.Count)" -ForegroundColor Yellow
}

# Detailed findings table
if ($breakGlassAccounts) {
    Write-Host ""
    Write-Host "  DETAILED FINDINGS" -ForegroundColor White
    Write-Host "  ─────────────────────────────────────────" -ForegroundColor Gray

    $breakGlassAccounts | Sort-Object RiskScore -Descending | Format-Table -AutoSize -Wrap @{
        Name = "Account"
        Expression = { $_.SamAccountName }
        Width = 18
    },
    @{
        Name = "Enabled"
        Expression = { $_.Enabled }
        Width = 8
    },
    @{
        Name = "PwdExp"
        Expression = { $_.PasswordNeverExpires }
        Width = 7
    },
    @{
        Name = "LastLogon"
        Expression = { $_.LastLogon }
        Width = 12
    },
    @{
        Name = "PwdAge"
        Expression = { if ($_.PasswordAgeDays -eq 'N/A') { 'N/A' } else { "$($_.PasswordAgeDays)d" } }
        Width = 7
    },
    @{
        Name = "Risk"
        Expression = { $_.RiskLevel }
        Width = 8
    }

    # Show risk indicators for high-risk accounts
    $highRiskAccounts = $breakGlassAccounts | Where-Object { $_.RiskLevel -eq 'HIGH' }
    if ($highRiskAccounts) {
        Write-Host ""
        Write-Host "  HIGH RISK ACCOUNTS - ACTION REQUIRED" -ForegroundColor Red
        Write-Host "  ─────────────────────────────────────────" -ForegroundColor Gray

        foreach ($account in $highRiskAccounts) {
            Write-Host ""
            Write-Host "  Account: $($account.SamAccountName)" -ForegroundColor Red
            Write-Host "    Risk Indicators: $($account.RiskIndicators)" -ForegroundColor Gray
            Write-Host "    Created: $($account.Created)" -ForegroundColor Gray
            Write-Host "    DN: $($account.DistinguishedName)" -ForegroundColor DarkGray
        }
    }
}
else {
    Write-Host ""
    Write-Host "  No accounts matching break-glass patterns were found." -ForegroundColor Green
    Write-Host "  This is typically a positive security indicator." -ForegroundColor Gray
}

# Error details
if ($errors) {
    Write-Host ""
    Write-Host "  ERROR DETAILS" -ForegroundColor Yellow
    Write-Host "  ─────────────────────────────────────────" -ForegroundColor Gray
    foreach ($err in $errors | Select-Object -First 5) {
        Write-Host "    - $err" -ForegroundColor DarkGray
    }
    if ($errors.Count -gt 5) {
        Write-Host "    ... and $($errors.Count - 5) more errors" -ForegroundColor Gray
    }
}

# =============================================================================
# JSON Report
# =============================================================================

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$reportPath = Join-Path $OutputPath "BreakGlassReality-$timestamp.json"

$report = @{
    CheckName = "Break-Glass Reality Check"
    CheckVersion = "2.0.0"
    Timestamp = [datetime]::UtcNow
    Prerequisites = @{
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        ActiveDirectoryModule = $prereqs.ActiveDirectoryModule
        AdminRights = $prereqs.AdminRights
    }
    SecurityContext = @{
        ExecutionPolicy = $security.ExecutionPolicy
        ConstrainedLanguage = $security.ConstrainedLanguage
        TranscriptRunning = $security.TranscriptStatus -eq "Running"
    }
    Summary = @{
        TotalAccountsFound = $breakGlassAccounts.Count
        SuccessfullyProcessed = $processedCount
        HighRisk = $highRisk
        MediumRisk = $mediumRisk
        LowRisk = $lowRisk
        ErrorsEncountered = $errors.Count
    }
    Findings = $breakGlassAccounts
    Errors = $errors | Select-Object -First 50
}

try {
    $jsonOutput = $report | ConvertTo-Json -Depth 10 -ErrorAction Stop
    $jsonOutput | Set-Content -Path $reportPath -Encoding UTF8 -ErrorAction Stop
    Write-Host ""
    Write-Host "[OUTPUT] Report saved: $reportPath" -ForegroundColor Green
}
catch {
    Write-Host ""
    Write-Host "[ERROR] Failed to save report: $($_.Exception.Message)" -ForegroundColor Red
}

# =============================================================================
# Recommendations
# =============================================================================

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  RECOMMENDATIONS" -ForegroundColor White
Write-Host "========================================================================" -ForegroundColor Cyan

if ($highRisk -gt 0) {
    Write-Host ""
    Write-Host "  IMMEDIATE ACTION REQUIRED:" -ForegroundColor Red
    Write-Host "  ─────────────────────────────────────────" -ForegroundColor Gray
    Write-Host "  1. Review all HIGH risk accounts listed above" -ForegroundColor White
    Write-Host "  2. Disable accounts not currently needed" -ForegroundColor White
    Write-Host "  3. Reset passwords for accounts with password age > 90 days" -ForegroundColor White
    Write-Host "  4. Remove unnecessary group memberships" -ForegroundColor White
    Write-Host "  5. Document break-glass account justification" -ForegroundColor White
}

if ($mediumRisk -gt 0) {
    Write-Host ""
    Write-Host "  REVIEW WITHIN 7 DAYS:" -ForegroundColor Yellow
    Write-Host "  ─────────────────────────────────────────" -ForegroundColor Gray
    Write-Host "  1. Review MEDIUM risk accounts for necessity" -ForegroundColor White
    Write-Host "  2. Consider enabling password expiration" -ForegroundColor White
    Write-Host "  3. Test break-glass account activation procedures" -ForegroundColor White
}

Write-Host ""
Write-Host "  ONGOING:" -ForegroundColor Green
Write-Host "  ─────────────────────────────────────────" -ForegroundColor Gray
Write-Host "  1. Schedule quarterly review of break-glass accounts" -ForegroundColor White
Write-Host "  2. Document activation procedures and test annually" -ForegroundColor White
Write-Host "  3. Implement Just-In-Time access for break-glass scenarios" -ForegroundColor White
Write-Host "  4. Monitor break-glass account usage via SIEM" -ForegroundColor White

# =============================================================================
# Final Note
# =============================================================================

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  ℹ  NOTE" -ForegroundColor Gray
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  This check identifies break-glass accounts but cannot determine:" -ForegroundColor Gray
Write-Host "    - Who approved these accounts" -ForegroundColor Gray
Write-Host "    - When they were last tested" -ForegroundColor Gray
Write-Host "    - What controls are in place" -ForegroundColor Gray
Write-Host "" -ForegroundColor Gray
Write-Host "  For comprehensive governance analysis, consider IdentityHealthCheck." -ForegroundColor Gray

exit 0
