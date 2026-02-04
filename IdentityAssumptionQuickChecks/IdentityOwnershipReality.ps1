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

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAPhJGHKcHj+th8
# WxxLJmEJoPKJEfrVn56xCMncMV4psaCCFlIwggMUMIIB/KADAgECAhBDR0HvMFNE
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgwqh731NRvhgkbTNpAhv00qWemnzHqxTKcF4K
# Aw8HwYkwDQYJKoZIhvcNAQEBBQAEggEA1ePX7lwFvrJqF/8WnyNqj+N3fqKo7emB
# /R9WrR8zHlhFP+8L1bUcOEdv5apsznIXe/a3STGcYyN8A/tBTkjH5NIY6kz9q/S6
# CmRLFEIQqlnyb4BT5m9yeKb8CnjaeonnpKzLbeOgmDX/1QcnhU4YTsgoJspGa9Cy
# 08zk6QjkHWpwqE9nbFA+xaqMMflSkuIrkKHQQD9mPUfYl2DxEAktGk3xaCgrVEWU
# 56bmDt794zLPXnKqXQ6PBChFiuT44XWPpYoYRNRSoaAdGRXa4RKa3ezI8TNWjOnj
# S6Cm/KpP1D+EnS266THz0QXWyKQOtZJDTrJBQ+C0E//9LfNHr8029qGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjAyMDQxNjUyMTdaMC8GCSqGSIb3DQEJBDEiBCDi
# I00zw1f1GLuxA4yWyfXISzxsNbrhpgKg1f2UMf3FwDANBgkqhkiG9w0BAQEFAASC
# AgB9xN4kpiPjaXKD8WHZWTKL8woh7F/THr9SmmlPQdwc8rLcQO7CIxagY0I/O16L
# 0JOeeJATQzvYgdjcv4q+/b6CGVKtZn49Eezj52h6EQTRuZ2WSqsMK99MyqfY/iql
# ecBXpWXo3RfGSwa0lzDyRaU7Y+Qtg7gm0QMoCzplusVoehu3xwaPcBws9hVNkaUv
# 1Y+Ibhlfe/EHBk+a6fOcJaA0Vx5bh187v/DipNFY5UK3kno7jPwHcWFbTfuNebAN
# +zPKLCMyz90Ecc3R5bbpQfXK2c5VQ0zSzOskAdvEQmTRr1geQi1NKh6jyFJDhSop
# dRtKDWpeWRII4q+KhZGOfx6OEQNqoFkITfCfKPRKCHxSE/1U31XsUJ2rPfmWAh/v
# HePhvbuyPpSP/kdJJffK8Qx0jDpG/XdtVm5tF2lClscNFE6HSvgpeLdxPLMGAFFJ
# syyf9kZfh7QmgI4XL0bACOwmVytJJeFXPixtCiNMNBafOQx/jRelWvMnEhcl8/nx
# G5LOI1POhTqD8b2St5Ri++Q5F8nh/5L3bSRsb6rk9CTKN3sVTOlUP6UFsCIIpNN0
# G5fd1/dTxkCtGvA11hfKaVUrAd+Hcy7v+HFOqtYnWuTLKOZnkwlfi41xl5W84R+8
# Dc8F6uey4jzC/YckcNAjV68P8oxqIlE7HvIxA/YGhKrXug==
# SIG # End signature block
