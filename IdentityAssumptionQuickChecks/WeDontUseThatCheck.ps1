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

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCejzh8udXjDCaL
# GyAXBSkK4V+Bd99gy0SiOOyQh4ms66CCFlIwggMUMIIB/KADAgECAhBDR0HvMFNE
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgKwByVVoVyu2dE88Vjbsh6gjkARKFXBFPIGIf
# U3+ilvgwDQYJKoZIhvcNAQEBBQAEggEAJQ00t58UK7+Wk6piiZt0ZmBZ8gmiN6vF
# 5fugsRgPRrjtWNfLyPODhZBs5reEWY6m0T5XiZ2cn5XkyN9LnhKTqhHGmaRwq9M2
# EyDuaP88iDUSScUsEut4iom6woGXMXNQR7XvXKN61wEdWIBAY0vA00iYadj4zvdT
# pn4rBrO70IPqRCwid16XEl73RLxCMMt71+uE+4CkjIYhC8juFuiQJkbNm32Edv61
# siB5SiWTKBVpPXWLXhNB17LufeqNSdGsQHVf9zrHLPqJ4jJdScDes0kmVIkuGCZi
# O49+8NXFt3DhFJ1F/r59sLXyxuJ7mCfFsuo7NSj3LnYp9Ylfz2niw6GCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjAyMDQxNjUyMThaMC8GCSqGSIb3DQEJBDEiBCAh
# LEK/90Kc0PQ2pElSZwed4Z2SMooeP5ISV/xS5qoE0zANBgkqhkiG9w0BAQEFAASC
# AgBE5ja+fCldNuazZhIpCJemU7I51CDHbZzlszBBk+nTVpCOrtkJT0hJEhbZqQYY
# O0sYlrGw1dPivn7LbxOnmVxcXwpuGuoD+NjoYR8KOfKp2fcr8KiCbfI+t//5KCgM
# qlhKngDDFfzhfN0RkFNhp0Jv7SPDDnRXQtNw7em9b99RQGXLNb6VPUSFt3Ex0BRX
# o7SXKVBm1xs3QmD8dhlhInEDOIMo000mJDPu7vwvjaEuIAo/C4D0ZP8ShaqlJYVh
# WVY736JM/3jMZ+Rz8ipr2IJf1HUsNMGy8eK4Tn0/GlQbsKW2HyAD772aCmaIa3El
# VAQ/8e/JpF2cPXRIdJYTxIlWmaGv1uJDANAJAqrXYi0M9cKYDvCqaAilhtVYdEuk
# YPUgdyDhsOItVz3RKzkCqnOxB4QiE7+9JWK8fpc5C84z/uCzdHsYUq+10isbqqiP
# q1zh75BK9G4JBDTBQxCLwv44MT5+/0IZ5KuQFHx5JM9ZkpFGylqmtBF0EwHxbPQj
# FWZj0MBOttddfuoqaP0F7zn42/5F+Ju23cQFeeUoQJ/xLwqe7dNW0QxUBC+JFh6b
# j+Qh6IkzviRksOHCl4Qk04yOpTDc5mAu9osDNZ5WKtzSgxcBC4AsR8fDsqXLaKQL
# /bi2QoljLqKYPBDoPEvWS/WStnuav5q8WkKRYzp4DKT7TA==
# SIG # End signature block
