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

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAyOmu83yJB5LlE
# MLd7iYcAhDgqKl9n8PbsReMjtJqZ3KCCFlIwggMUMIIB/KADAgECAhBDR0HvMFNE
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgImKWrbsDaBvwiVczeg4393iRrRL0B7xFqZae
# NlErRLwwDQYJKoZIhvcNAQEBBQAEggEAEHeVtvyT+2E2uliZ+J5X6j1IxbTZop1I
# y81qHw2pj62nFHaD+gmDvNSVhfK+20Zz+jpFZzTpCfBBZbzM4e6RO0iOpJ9xmxGu
# 3Rt5rd5HusmUfoZGAU1ji5WhJlMOP2hc1i7NsZWibHfuMe/l1LyjpBb1GRBifXSH
# F4/M6XNpy9boDbmE868qfjCEkpDnjZS6da1GLyrvmIQlw3M2xg3VEvQtbE5WABxp
# Y/Yg0BYCbnzz0nQme8i334CE+3p2MMoT/dnd1IOzZstZIdnJItkaIb7GxqBeoMBm
# O55iRaI0ZHx7/yg9E7+WyCLdovEyDFLV2mUJQDzzexzHrGJT1H43WqGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjAyMDQxNjUyMjBaMC8GCSqGSIb3DQEJBDEiBCDX
# bifzL8isHkt2PDGvlKLNOG7mnrjwmoqC8QSQFL8efjANBgkqhkiG9w0BAQEFAASC
# AgBB5Rhrn+oQkPx44oWkhPPk5ngIqFN7AS3n/Bni3in+qZoRvPE4MG39FOqbS9/v
# ZZLgP+NU0i+SORNUoArzk2hhGkcqx8aF8Nod93Dlnw6IVYQ7ffnEvkfyZ4b5eQSW
# MgS8u46VqB7/yGGZvC7j12a7zR7dIwMuGa5e6AGseYsCvZEkkDTCgbjxbDxeIKR1
# OafDf+dW0IHnpLGJuo6rWAz/Tn0GgXXIOOBEbu8AG1mYG85vcRmM5mnI/LJ3kM4k
# GzbDF6d6LEl/nFCmhqkuVNzeco36ie7LUZGYJt+zZLFb5e8SsOUozZKr44Y+7t9e
# RcuTxtZeLMEeaJfbfAtikzq6YIBnkk+gUXOXZWhH1nKJjPNrhHKhAXEcUistHjrn
# l52QF7ZUUC+oK3qhkyv5sNedxzqct5X5gmWM3g0ilsJ67jpmd/heryN/wjBE5rua
# ONMLu33wn7UFvdNGqfRVcMsKXOmYnf9HIDs7+L1kLIiZeu60NjCN+AB5ElWj2Nex
# CbcneJ32vqLMvK+yMTdDTtgru3EkqStWJyu1+LbHDx7rhkitTmc0qWYW/zhiKeS9
# aM4UYI29v0tEG/7wiLacC64MLYT8HLLt027Te14bZfKJr8asdETjbGCN4Va39ptg
# jFrvuGNLP6Cd66jsxWgM1WIgXKB3jXGCtzeR7X8gkmD4IA==
# SIG # End signature block
