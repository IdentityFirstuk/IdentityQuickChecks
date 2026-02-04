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

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAJTHyTWYwMuzRg
# uzlWJex3kxC9rkZfE95grKRBiOWVVqCCFlIwggMUMIIB/KADAgECAhBDR0HvMFNE
# lkJ70azsYRwnMA0GCSqGSIb3DQEBCwUAMCIxIDAeBgNVBAMMF0lkZW50aXR5Rmly
# c3QgQ29kZSBTaWduMB4XDTI2MDIwNDE2NDE0OFoXDTI3MDIwNDE3MDE0OFowIjEg
# MB4GA1UEAwwXSWRlbnRpdHlGaXJzdCBDb2RlIFNpZ24wggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQDWJrlUCUN9yoS4qyJUFIIrjVVnfoFqTXwze3ijNE5q
# wUAAiypU86tc6ct9/wQ9Q9qOn6gjKU3vDhq8XojyQhi/q0ffxG1pP8bHfCQtrMFc
# kTOKLZRgQO73caKFxunCuRdAGxdDxy94NNjwITySkaaLFb3gULH1wbfmu5l2v9ga
# CgpRJGoofRbYbjBS5B7TTNVXlyxl5I3toq9cYRwauWq0Fqj2h6gZ/8izDVU6nMGX
# k+ZfsQwTsVSxfiiWHozhjU7Rt8ckxfVt1YLyPamewESLxw4ijFgHYZUrxNtbm2DP
# QUUG4ekzdDQlBLBzjdIJh8hIz+gcqvyXIQpoFjF2xyoFAgMBAAGjRjBEMA4GA1Ud
# DwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQU0LvUry7V
# 3WlfTmidD6yCOpbcmSQwDQYJKoZIhvcNAQELBQADggEBAAWDzEqYgCCQHZwHCMlU
# ob2Jkqcbk6GYylmfTwW9EQ7iJjyKHFJlbUGuDJxClDwDteBCVpxhfbi0fJjkib8r
# b4Fbk9Rex5rJxEMidBYbnASWnLuJD7dsHbwf6N4SM/LsYhiEtllGb0UsKET6PyuO
# f1sYdDY+UcTssCzDAElCrlVIl4Z4/JBlXOhInMD7AnP6Xx2r4hCAVEWhHtJ+ahY/
# bFAJ7v+EsTET2Pa34kiymxJ7yYRNSxwxyb1umUx/Q6pui0lYjyNXt8AAg4A0ybyj
# ABLNYct6zilczJ6JqPCBJLL0ZbCDpg8SkmAn3G3Y+bSztlOIUo4eXpjXV1DE7oB/
# kuAwggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUA
# MGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsT
# EHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQg
# Um9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqcl
# LskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YF
# PFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceIt
# DBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZX
# V59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1
# ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2Tox
# RJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdp
# ekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF
# 30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9
# t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQ
# UOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXk
# aS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud
# DgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEt
# UYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsG
# AQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0
# dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RD
# QS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAw
# DQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72arKGHLOyF
# XqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFIDyE7QKt76
# LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8L
# punyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2
# CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si
# /xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQwgga0MIIEnKADAgEC
# AhANx6xXBf8hmS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcw
# MDAwMDBaFw0zODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1l
# U3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZ
# loMsVO1DahGPNRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM
# 2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj
# 7GH8BLuxBG5AvftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQ
# Sku2Ws3IfDReb6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZ
# lDwFt+cVFBURJg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+
# 8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRx
# ykvq6gbylsXQskBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yG
# OP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqI
# MRvUBDx6z1ev+7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm
# 1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBj
# UwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729T
# SunkBnx6yuKQVvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4c
# D08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUF
# BwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEG
# CCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAX
# MAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaA
# HP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQ
# M2qEJPe36zwbSI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt
# 6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7
# bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmS
# Nq1UH410ANVko43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69
# M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnF
# RsjsYg39OlV8cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmM
# Thi0vw9vODRzW6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oa
# Qf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx
# 9yHbxtl5TPau1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3
# /BAPvIXKUjPSxyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN
# 8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQg
# VGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAw
# MDAwMFoXDTM2MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBU
# aW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx
# +wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvN
# Zh6wW2R6kSu9RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlL
# nh00Cll8pjrUcCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmn
# cOOMA3CoB/iUSROUINDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5KqCvpSduSwhw
# UmotuQhcg9tw2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL
# 4Q1OpbybpMe46YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdoRORVbPR1VVnD
# uSeHVZlc4seAO+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCy
# FG1roSrgHjSHlq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7rlRyTlaCCfw7a
# SUROwnu7zER6EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K096V1hE0yZIXe+gi
# AwW00aHzrDchIc2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGj
# ggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39/dfzkXFjGVBD
# z2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8E
# BAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGF
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUH
# MAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRH
# NFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBW
# MFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVk
# RzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkw
# FzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3x
# HCcEua5gQezRCESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh
# 8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim8/9yJmZS
# e2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUqW4daIqToXFE/
# JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMnxYOX8VBRKe1u
# NnzQVTeLni2nHkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq
# 8/gVutDojBIFeRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AWcIQfVjnzrvwi
# CZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJgddJ35XTxfUlQ
# +8Hggt8l2Yv7roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1
# R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVccAvlKV9jEnstr
# niLvUxxVZE/rptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8atufk+EMF/cWu
# iC7POGT75qaL6vdCvHlshtjdNXOCIUjsarfNZzGCBRIwggUOAgEBMDYwIjEgMB4G
# A1UEAwwXSWRlbnRpdHlGaXJzdCBDb2RlIFNpZ24CEENHQe8wU0SWQnvRrOxhHCcw
# DQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkq
# hkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGC
# NwIBFTAvBgkqhkiG9w0BCQQxIgQg0Mvy9CGdWjST6tmmX91DNeQguAEP/FrjxdrT
# a99yTvswDQYJKoZIhvcNAQEBBQAEggEAw4aDuWhoqKSl7LgiBjF8Nl7ef7ifM5vc
# t6lxzaXTTxW5npzH/PX5lcB76fz/2xO+p/swtyBgTr3QRIk2S0zXpPVamLCZxuy2
# kVtABwqQNPCqJATuvGJ7bx6sZlfpv8GFrZ1KavF/kw+v0eXR4j1DbeycX72aJ0w9
# RUHkHUKVgfFE5LG7nEYgm32Hq80ek3OjVThFWwSIbWJF8CVZ7X1YhUt6xngzwMY9
# K6CTaQgMl6tpGxFI1FzPZa7Jv94qlT2uKOpNGOQ3J88qy5M0OcqbhOzHk2dolajE
# WAkyicTRqwT7Ux1I+QHIAANoLm83ExBL50Gx1W5qvnckO2RUUGzEvKGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjAyMDQxNjUyMThaMC8GCSqGSIb3DQEJBDEiBCDm
# oPktj7h0F0uucPSJWjumyYhfuZjsYhwFVLwBG0czJjANBgkqhkiG9w0BAQEFAASC
# AgBieopb4d4F2AAuU8hnEgnCS1tDJOZLcs9K5UJFhVBYXSnyE44u5GePAN092u5I
# Kn9CtKuOdDRuqp3xbgoiylUzwfBBK0YwCq1q+EJhqM6yGlPCYcbWmVPqxa/N5y0v
# O7AOzr5PsJJeXG8NlZcKBsuM3YQ58rry0iMdSe5SBVpjzb3bAC8iRnzBiQJzQq1j
# /6B0UHEZr/70qBTzitBrTN2NKAFNXXIIewz24Z9LZ2X7ZAr0yeL9miPFr19vA0rO
# HQ6/wyxpHy5h/95prOpy3Pg+eDhjdfiJ6i9ZOU0qMP74f/17j4NWvDWfjYtByNHd
# +qb2Tuk4Lq3ruLsLXOLGRz9PoTVSTBSHid0FR7Mn40+y8S1Ll1SFoVZCyU9fOHRl
# 4T+5epeZFDq3s3zREoRO2cq0H8dYF1y0aTGKnU7qr/HbJ65A+q0mRLVudZ/qLqRq
# l8Rkw+7If1eMwy/JV/8hGCYzhhGheG9PMLvhB8ZcUapo85NTwW1zAtsJHecDKmw5
# qyetLe1FfxhMrdRkzxGJpb2WQ4/0BEmrel+/ZlaaRZGJOpjUaopAolmZk4E3QEi8
# BlCpiJHusln91iusLZQmLQVVfUE8iUH5bTCe+9SrRDqsw1w2MGMLraQ+B9ElJKUk
# rv9rfGUlxVVW2EF5kwwWCr/WsWzdY0H1iIGTq84gr728tA==
# SIG # End signature block
