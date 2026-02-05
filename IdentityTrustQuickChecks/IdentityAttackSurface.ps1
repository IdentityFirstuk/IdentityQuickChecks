# ============================================================================
# ATTRIBUTION
# ============================================================================
# Author: Mark Ahearne
# Email: mark.ahearne@identityfirst.net
# Company: IdentityFirst Ltd
#
# This script is provided by IdentityFirst Ltd for identity security assessment.
# All rights reserved.
#
# License: See EULA.txt for license terms.
# ============================================================================
param([string]$OutputPath = ".")

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================================================"
Write-Host "  Identity Attack Surface Analysis"
Write-Host "========================================================================"

# Initialize tracking variables
$highRiskAccounts = @()
$serviceAccounts = @()
$errors = @()
$processedCount = 0

Write-Host ""
Write-Host "  Analyzing identity attack surface..." -ForegroundColor Gray

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "  ActiveDirectory module loaded" -ForegroundColor Green
}
catch {
    Write-Host "  ERROR: ActiveDirectory module not available" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "  Enumerating high-risk accounts..." -ForegroundColor Gray

# Define high-risk groups to monitor
$highRiskGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Server Operators",
    "Print Operators",
    "Backup Operators",
    "Replicator",
    "Cryptographic Operators"
)

# Get all users with additional properties
try {
    $allUsers = Get-ADUser -Filter * -Properties SamAccountName, Name, Description, Enabled, PasswordNeverExpires, LastLogonTimestamp, whenCreated, pwdLastSet, memberOf -ErrorAction Stop
    Write-Host "  Found $($allUsers.Count) user accounts" -ForegroundColor Gray
}
catch {
    Write-Host "  ERROR: Failed to retrieve users: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "  Checking privileged group memberships..." -ForegroundColor Gray

$privilegedMembers = @{}
$errors = @()

foreach ($group in $highRiskGroups) {
    try {
        $members = Get-ADGroupMember -Identity $group -ErrorAction Stop
        $privilegedMembers[$group] = $members
        Write-Host "    $group : $($members.Count) members" -ForegroundColor Gray
    }
    catch {
        $errorMsg = "Failed to get members of $group : $($_.Exception.Message)"
        $errors += $errorMsg
        Write-Host "    $group : ACCESS DENIED" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "  Analyzing account posture..." -ForegroundColor Gray

# Define risk indicators
$riskIndicators = @()

foreach ($user in $allUsers) {
    try {
        $processedCount++
        $userRiskFactors = @()
        $isPrivileged = $false
        
        # Check if user is in any high-risk group
        foreach ($group in $highRiskGroups) {
            $members = $privilegedMembers[$group]
            if ($members) {
                $isMember = $members | Where-Object { $_.SamAccountName -eq $user.SamAccountName }
                if ($isMember) {
                    $isPrivileged = $true
                    $userRiskFactors += "Member of $group"
                }
            }
        }
        
        # Check for service accounts
        $isServiceAccount = $false
        $svcIndicators = @("SVC-", "svc-", "$", "Service_", "svc_")
        foreach ($indicator in $svcIndicators) {
            if ($user.SamAccountName -like "*$indicator*") {
                $isServiceAccount = $true
                break
            }
        }
        
        if ($isServiceAccount) {
            $serviceAccounts += New-Object PSObject -Property @{
                SamAccountName = $user.SamAccountName
                Name = $user.Name
                Enabled = $user.Enabled
                PasswordNeverExpires = $user.PasswordNeverExpires
                LastLogon = if ($user.LastLogonTimestamp) { [DateTime]::FromFileTime($user.LastLogonTimestamp).ToString("yyyy-MM-dd") } else { "Never" }
            }
        }
        
        # Check risk factors for all accounts
        if ($user.Enabled -eq $true) {
            $userRiskFactors += "Account ENABLED"
        }
        
        if ($user.PasswordNeverExpires -eq $true) {
            $userRiskFactors += "PasswordNeverExpires=TRUE"
        }
        
        if ($user.pwdLastSet) {
            $pwdAgeDays = (New-TimeSpan -Start ([DateTime]::FromFileTime($user.pwdLastSet)) -End (Get-Date)).Days
            if ($pwdAgeDays -gt 90) {
                $userRiskFactors += "Password $pwdAgeDays days old"
            }
        }
        
        if ($user.LastLogonTimestamp) {
            $lastLogonDays = (New-TimeSpan -Start ([DateTime]::FromFileTime($user.LastLogonTimestamp)) -End (Get-Date)).Days
            if ($lastLogonDays -gt 90) {
                $userRiskFactors += "No logon for $lastLogonDays days"
            }
        }
        
        if ($user.whenCreated) {
            $ageDays = (New-TimeSpan -Start $user.whenCreated -End (Get-Date)).Days
            if ($ageDays -le 7) {
                $userRiskFactors += "Created within 7 days"
            }
        }
        
        # Check for accounts with many group memberships (potential escalation path)
        $memberOfCount = ($user.memberOf | Measure-Object).Count
        if ($memberOfCount -gt 50) {
            $userRiskFactors += "Member of $memberOfCount groups"
        }
        
        # Determine if this is a high-risk account
        $isHighRisk = $false
        $riskScore = 0
        
        if ($isPrivileged) { $riskScore += 5 }
        if ($user.PasswordNeverExpires -eq $true) { $riskScore += 2 }
        if ($user.Enabled -eq $true -and $isPrivileged) { $riskScore += 3 }
        
        if ($riskScore -ge 5) {
            $isHighRisk = $true
            $highRiskAccounts += New-Object PSObject -Property @{
                SamAccountName = $user.SamAccountName
                Name = $user.Name
                Enabled = $user.Enabled
                PasswordNeverExpires = $user.PasswordNeverExpires
                IsPrivileged = $isPrivileged
                RiskScore = $riskScore
                RiskFactors = $userRiskFactors -join "; "
                LastLogon = if ($user.LastLogonTimestamp) { [DateTime]::FromFileTime($user.LastLogonTimestamp).ToString("yyyy-MM-dd") } else { "Never" }
            }
        }
        
    }
    catch {
        $errorMsg = "Failed to analyze user $($user.SamAccountName): $($_.Exception.Message)"
        $errors += $errorMsg
        Write-Host "  WARNING: $errorMsg" -ForegroundColor Yellow
    }
}

# Summary
Write-Host ""
Write-Host "  Attack Surface Summary"
Write-Host "  ======================"
Write-Host "  Accounts analyzed: $processedCount"
Write-Host "  High-risk accounts: $($highRiskAccounts.Count)" -ForegroundColor $(if ($highRiskAccounts.Count -gt 0) { "Red" } else { "Green" })
Write-Host "  Service accounts: $($serviceAccounts.Count)"

# Show high-risk accounts
if ($highRiskAccounts) {
    Write-Host ""
    Write-Host "  HIGH RISK ACCOUNTS - IMMEDIATE REVIEW:" -ForegroundColor Red
    
    $highRiskAccounts | Sort-Object -Property RiskScore -Descending | Format-Table -AutoSize -Property `
        @{Name="SamAccountName"; Expression={$_.SamAccountName}; Width=20},
        @{Name="Enabled"; Expression={$_.Enabled}; Width=10},
        @{Name="PwdNeverExp"; Expression={$_.PasswordNeverExpires}; Width=12},
        @{Name="Privileged"; Expression={$_.IsPrivileged}; Width=12},
        @{Name="Score"; Expression={$_.RiskScore}; Width=8},
        @{Name="LastLogon"; Expression={$_.LastLogon}; Width=12}
    
    Write-Host ""
    Write-Host "  Risk Factor Details:"
    $highRiskAccounts | Where-Object { $_.RiskScore -ge 7 } | ForEach-Object {
        Write-Host "    $($_.SamAccountName): $($_.RiskFactors)" -ForegroundColor Gray
    }
}
else {
    Write-Host ""
    Write-Host "  No high-risk accounts identified." -ForegroundColor Green
}

# Show service account summary
if ($serviceAccounts) {
    Write-Host ""
    Write-Host "  Service Accounts Summary:"
    Write-Host "  ========================"
    
    $serviceWithIssues = $serviceAccounts | Where-Object { $_.PasswordNeverExpires -eq $true }
    Write-Host "  Total service accounts: $($serviceAccounts.Count)"
    Write-Host "  With password never expires: $($serviceWithIssues.Count)" -ForegroundColor $(if ($serviceWithIssues.Count -gt 0) { "Yellow" } else { "Green" })
    
    $inactiveSvc = $serviceAccounts | Where-Object { $_.LastLogon -ne "Never" -and (New-TimeSpan -Start ([DateTime]::ParseExact($_.LastLogon, "yyyy-MM-dd", $null)) -End (Get-Date)).Days -gt 90 }
    Write-Host "  Inactive (>90 days): $($inactiveSvc.Count)" -ForegroundColor $(if ($inactiveSvc.Count -gt 0) { "Yellow" } else { "Green" })
}

# Show privileged group summary
Write-Host ""
Write-Host "  Privileged Group Membership:"
Write-Host "  ============================"
foreach ($group in $highRiskGroups) {
    $members = $privilegedMembers[$group]
    if ($members) {
        Write-Host "    $group : $($members.Count) members" -ForegroundColor Gray
    }
}

# Show errors
if ($errors) {
    Write-Host ""
    Write-Host "  Errors encountered:" -ForegroundColor Yellow
    foreach ($err in $errors) {
        Write-Host "    - $err" -ForegroundColor Gray
    }
}

# Generate report
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$reportPath = Join-Path $OutputPath "IdentityAttackSurface-$timestamp.json"

$report = @{
    CheckName = "Identity Attack Surface Analysis"
    Timestamp = Get-Date -Format "o"
    Summary = @{
        TotalAccountsAnalyzed = $processedCount
        HighRiskAccounts = $highRiskAccounts.Count
        ServiceAccounts = $serviceAccounts.Count
        Errors = $errors.Count
    }
    HighRiskAccounts = $highRiskAccounts
    ServiceAccounts = $serviceAccounts
    PrivilegedGroupMembership = $privilegedMembers
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

exit 0

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD02MMmhPNIqwkb
# FPcuX2k2Xf3Fh6x2j2OmlXirJdetoaCCFlIwggMUMIIB/KADAgECAhBDR0HvMFNE
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgogVdbiz/6Cw8r0mn1+MPoH1W7FS1egrMcmpO
# c4+zgz8wDQYJKoZIhvcNAQEBBQAEggEAofvbhBk706ETLgpzqlr6BGP0ONRUGoOZ
# BUD6fvxHizj5I887DBsKv88aGL6Eht6awcYTYuALvwAO1YGLKaZmtd4hbdxGrBhT
# QnIKe2rSa2R/QK3ddIag5qUYQX29amXXOXLqSpVU0aRzdZVQodmqrkgpTmvOsMiy
# kaaFJsV+ZgxDTdVcol9531UPROrmhyDnUvmh14Ey4z5Bu1r4+KrZbhnRCXr/iPrz
# R6YQ1+QEegLWcVZsfTp9tWfwHoGo6lO/YAoLpLSQ248nnMTN/xAMqVCEZnyzTOX8
# tw8Oh75/O4RK/Knd6/XfW+kXjCBYoTQewlmCkjYnKIgD6+FAaoXJMaGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjAyMDQxNjUyMTlaMC8GCSqGSIb3DQEJBDEiBCAL
# PVovIpRVC3bxD+DnuG5aM240ZBxQq08r5n65IHbz5jANBgkqhkiG9w0BAQEFAASC
# AgC/p6qR/n4J73N94jogVVu+53l3utYNgETk/GG+Q3s6jevLW0g/9qW669ssQTJR
# hN0fSRfkBjIFzW5+WYc3S5EyRk3XpWJP1mXy89xjl36/LXStJuo/iXENqi9+n9oM
# 8l6Sy00zddApNWgdRL1lVq1eODTr6BDWp6F74N5EowKw1rZkRKjUS1nV2iJJiuJ5
# gcsaDZA0FBdCpSmxCKvW10tZ4DLmo1ldcxyjxheeh2s/x87xqX4qovhawxbKTLJ6
# dwW6yQCwLDR4Kv3KduH3T5lEL0Rt7M/O8/4mL5OULTHsFpsjuLiuPcEUzbn/V7HW
# 9CJ7Jm9AYG8BJ3y0iG3aqRGj4o1r6eHvUjWXK/k0H6bf4292y6OTaQsge/rDZwnl
# fbsk13ovcWZDptbz62e4bJ6dywaO0awgpBmYKV2ZoWQtnepjqPc0rb+z1GZmgpNL
# GoyNd8iyFOGZuABbCV79Ra7d/EKIGmLTFcrTY3ASFA+I0kZTkpP3TNrG2JhGltRj
# hGZu+kJZYJ1zhHq3olsgr2niBNok0AbhGOhnkIBtr6DLL5DiwYvUsUjIV4gsclHl
# XOYDoYANvNEKYk0QZ0V/MGMmnEKEdOCDd6apn7WT/z9V5Yoq7w2pyiLa3ysbjc3M
# fKun0oFrPMWigyHJMI1J/uXBOWWLuPHr2MLdrNlhjfaunw==
# SIG # End signature block
