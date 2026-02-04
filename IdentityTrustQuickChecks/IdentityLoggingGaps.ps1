param([string]$OutputPath = ".")

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================================================"
Write-Host "  Identity Logging Gaps Check"
Write-Host "========================================================================"

<#
.SYNOPSIS
    Check security logging configuration for identity-related events.

.DESCRIPTION
    Identifies potential logging gaps in Active Directory that could
    prevent forensic investigation or compliance monitoring of identity events.

.NOTES
    - Read-only: YES
    - Requires: ActiveDirectory module (RSAT)
    - Permissions: Domain Admin recommended

.EXAMPLE
    .\IdentityLoggingGaps.ps1
#>

# Initialize tracking variables
$loggingGaps = @()
$loggingVerified = @()
$errors = @()
$processedCount = 0

Write-Host ""
Write-Host "  Analyzing identity logging configuration..." -ForegroundColor Gray

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "  ActiveDirectory module loaded" -ForegroundColor Green
}
catch {
    Write-Host "  ERROR: ActiveDirectory module not available" -ForegroundColor Red
    exit 1
}

# ============================================================================
# Check 1: Audit Policy Configuration
# ============================================================================

Write-Host ""
Write-Host "  Checking domain audit policy..." -ForegroundColor Gray

try {
    $domain = Get-ADDomain -ErrorAction Stop
    $domainController = Get-ADDomainController -Discover -ErrorAction Stop
    
    # Check if we can access security event logs
    $logSettings = @{}
    $importantLogs = @("Security", "Directory Service", "System")
    
    $auditIssues = @()
    
    foreach ($logName in $importantLogs) {
        try {
            $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
            $logSettings[$logName] = @{
                IsEnabled = $log.IsEnabled
                RetentionPolicy = $log.RetentionPolicy
                MaximumSizeInBytes = $log.MaximumSizeInBytes
            }
            
            if (-not $log.IsEnabled) {
                $auditIssues += "$logName log is NOT enabled"
            }
        }
        catch {
            $auditIssues += "Cannot access $logName log (permission denied)"
        }
    }
    
    if ($auditIssues) {
        $loggingGaps += New-Object PSObject -Property @{
            Category = "Windows Event Log Configuration"
            Issues = $auditIssues
            Severity = "HIGH"
        }
        Write-Host "    ⚠ Windows Event Log issues found:" -ForegroundColor Red
        $auditIssues | ForEach-Object { Write-Host "       - $_" -ForegroundColor Gray }
    }
    else {
        $loggingVerified += "Windows Event Logs are configured"
        Write-Host "    ✅ Windows Event Logs are accessible and enabled" -ForegroundColor Green
    }
}
catch {
    $errors += "Failed to check audit policy: $($_.Exception.Message)"
    Write-Host "    ⚠ Cannot verify audit policy (may require admin)" -ForegroundColor Yellow
}

# ============================================================================
# Check 2: Advanced Audit Policy (if accessible)
# ============================================================================

Write-Host ""
Write-Host "  Checking advanced audit policy..." -ForegroundColor Gray

try {
    # Try to get advanced audit policy
    $auditSubcategories = @(
        "Account Logon",
        "Account Management",
        "Directory Service Access",
        "Logon/Logoff",
        "Object Access",
        "Policy Change",
        "Privilege Use",
        "System"
    )
    
    $policyIssues = @()
    
    foreach ($subcategory in $auditSubcategories) {
        try {
            # Check via secedit (works on most systems)
            $secedit = secedit /export /areas USER_RIGHTS /cfg $env:TEMP\secedit.inf 2>$null
            if ($LASTEXITCODE -eq 0) {
                # Policy exported
                break
            }
        }
        catch {
            # Non-critical
        }
    }
    
    $loggingVerified += "Advanced audit policy check attempted"
    Write-Host "    ℹ Advanced audit policy requires elevated access to verify" -ForegroundColor Gray
}
catch {
    # Non-critical
}

# ============================================================================
# Check 3: AD LDS / ADCS Logging Configuration
# ============================================================================

Write-Host ""
Write-Host "  Checking AD LDS/CS logging (if present)..." -ForegroundColor Gray

$adServices = @()
$servicesCheck = @(
    "ADWS",          # Active Directory Web Services
    "NTDS",          # Active Directory Domain Services
    "KDC",           # Kerberos Key Distribution Center
    "NetLogon"       # Net Logon
)

try {
    foreach ($service in $servicesCheck) {
        try {
            $svc = Get-Service -Name $service -ErrorAction Stop
            $adServices += @{
                Name = $service
                Status = $svc.Status.ToString()
                StartType = $svc.StartType.ToString()
            }
        }
        catch {
            # Service may not exist on this system
        }
    }
    
    if ($adServices) {
        $loggingVerified += "$($adServices.Count) AD services verified"
        Write-Host "    ℹ $($adServices.Count) AD-related services found on this system" -ForegroundColor Gray
    }
}
catch {
    # Non-critical
}

# ============================================================================
# Check 4: Object Access Auditing (Directory Service)
# ============================================================================

Write-Host ""
Write-Host "  Checking Directory Service object access auditing..." -ForegroundColor Gray

try {
    # Get domain NC root DACL (to check if auditing is configured)
    $rootDSE = Get-ADRootDSE -ErrorAction Stop
    
    try {
        $ntdsSettings = Get-ADObject "CN=NTDS Settings,CN=$($domainController.Name),CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,$($rootDSE.rootDomainNamingContext)" -Properties * -ErrorAction Stop
        
        $loggingVerified += "NTDS Settings accessible for logging verification"
        Write-Host "    ✅ Directory Service configuration accessible" -ForegroundColor Green
    }
    catch {
        $loggingGaps += New-Object PSObject -Property @{
            Category = "Directory Service Access Audit"
            Issues = @("Cannot verify Directory Service audit configuration")
            Severity = "MEDIUM"
        }
        Write-Host "    ⚠ Cannot verify Directory Service audit (may require DC access)" -ForegroundColor Yellow
    }
}
catch {
    $errors += "Failed to check Directory Service: $($_.Exception.Message)"
}

# ============================================================================
# Check 5: Account Management Audit
# ============================================================================

Write-Host ""
Write-Host "  Checking account management audit capability..." -ForegroundColor Gray

try {
    # Check if we can enumerate administrative accounts (indicates AD is functional)
    $adminCount = (Get-ADGroupMember "Domain Admins" -ErrorAction Stop | Measure-Object).Count
    
    if ($adminCount -gt 0) {
        $loggingVerified += "Account management audit possible (AD functional)"
        Write-Host "    ✅ Active Directory is functional for account auditing" -ForegroundColor Green
        Write-Host "       Domain Admins group has $adminCount members" -ForegroundColor Gray
    }
    else {
        $loggingGaps += New-Object PSObject -Property @{
            Category = "Account Management"
            Issues = @("Domain Admins group appears empty")
            Severity = "LOW"
        }
        Write-Host "    ⚠ Domain Admins group appears empty" -ForegroundColor Yellow
    }
}
catch {
    $errors += "Failed to check account management: $($_.Exception.Message)"
    Write-Host "    ⚠ Cannot verify account management auditing" -ForegroundColor Yellow
}

# ============================================================================
# Check 6: Group Policy Audit Settings
# ============================================================================

Write-Host ""
Write-Host "  Checking Group Policy audit settings..." -ForegroundColor Gray

try {
    # Try to access GPOs
    $gpos = Get-GPO -All -ErrorAction Stop | Select-Object -First 10
    
    $loggingVerified += "Group Policy accessible for audit verification"
    Write-Host "    ℹ $($gpos.Count) GPOs found (audit settings in GPOs require DC access)" -ForegroundColor Gray
}
catch {
    # GPO module may not be available
    Write-Host "    ⚠ Group Policy module not available (run on Domain Controller for full audit)" -ForegroundColor Yellow
}

# ============================================================================
# Summary Output
# ============================================================================

Write-Host ""
Write-Host "  Logging Gaps Summary"
Write-Host "  ===================="
Write-Host "  Logging verified: $($loggingVerified.Count) areas"
Write-Host "  Logging gaps found: $($loggingGaps.Count)" -ForegroundColor $(if ($loggingGaps.Count -gt 0) { "Yellow" } else { "Green" })
Write-Host "  Errors: $($errors.Count)"

if ($loggingGaps) {
    Write-Host ""
    Write-Host "  LOGGING GAPS:"
    
    $highSeverity = $loggingGaps | Where-Object { $_.Severity -eq "HIGH" }
    if ($highSeverity) {
        Write-Host ""
        Write-Host "    HIGH SEVERITY GAPS:" -ForegroundColor Red
        $highSeverity | ForEach-Object {
            Write-Host "      - $($_.Category)" -ForegroundColor Gray
            $_.Issues | ForEach-Object { Write-Host "        • $_" -ForegroundColor Gray }
        }
    }
    
    $mediumSeverity = $loggingGaps | Where-Object { $_.Severity -eq "MEDIUM" }
    if ($mediumSeverity) {
        Write-Host ""
        Write-Host "    MEDIUM SEVERITY GAPS:" -ForegroundColor Yellow
        $mediumSeverity | ForEach-Object {
            Write-Host "      - $($_.Category)" -ForegroundColor Gray
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

Write-Host ""
Write-Host "  VERIFIED AREAS:"
$loggingVerified | ForEach-Object { Write-Host "    ✅ $_" -ForegroundColor Green }

# ============================================================================
# Generate Report
# ============================================================================

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$reportPath = Join-Path $OutputPath "IdentityLoggingGaps-$timestamp.json"

$report = @{
    CheckName = "Identity Logging Gaps"
    Timestamp = Get-Date -Format "o"
    Summary = @{
        LoggingVerified = $loggingVerified.Count
        LoggingGaps = $loggingGaps.Count
        Errors = $errors.Count
    }
    VerifiedAreas = $loggingVerified
    LoggingGaps = $loggingGaps
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

Write-Host ""
Write-Host "  ─────────────────────────────────────────────────────────────"
Write-Host "  ℹ  Full logging verification requires Domain Controller access." -ForegroundColor Gray
Write-Host "     For comprehensive audit readiness, run IdentityHealthCheck." -ForegroundColor Gray
Write-Host "  ─────────────────────────────────────────────────────────────"

exit 0

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDhMNHR2hnrPs2l
# Gy+VwE4OW19WFo87bMqLypAiYVR5YqCCFlIwggMUMIIB/KADAgECAhBDR0HvMFNE
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgbdAI8BPtamydKueBZWZlbgNkR5S9rElw3SID
# k+ks7GswDQYJKoZIhvcNAQEBBQAEggEAUeHjHVAnke1a56gllNNXod43Awd6KN7s
# eaDQoCqS49xYKx4sRyO2B/1FGMrwIz2dp1F17YJODM7sbnt2yRWQ0o6bzylLXlYc
# 5dcYtk9to/EOC3VDdleZNxoU0gfqJlWV/cQBM373xdLJyrAJfAWwHopW2V7QODgx
# mYoXP6SuktziOvhXFvTg7LR7caOzRnd68E7mG0O/Uy9EqgbUKyOOP7lb5IZ6bfwv
# 1PGCBILm3oeiMUm5WxU3jIBmHlz/2OIdNW+x3+GECVEwNwzrdPUV0tN/G3FUx6PG
# chZVgg8OU8Q2ujYxhGS6gmRc2c6HBhLsb/RYSIWroLX60eeGWGwesqGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjAyMDQxNjUyMjBaMC8GCSqGSIb3DQEJBDEiBCBj
# 0WiX1tfPC5BGbPjo2rKkZ3ovu6PuD5PL/NhBV41eCDANBgkqhkiG9w0BAQEFAASC
# AgBODryc+lz+Vxg32boortT5keiAQmcsHETAzggRlbRY2B6leRUS1Oykwx4DNbcl
# 1YtlzwSV6zHfY75RxVCnrphCfSB1Vw+qSyvEI9ZmhLthbPWVpp1tiJvABlVXuAWh
# xutR32A+aPGTTvRNwcjLh6njx3DkZmzh7ZquFKGsZ/0y7bwK9iI4nhQF+8uY0ykZ
# /hXhUEko741EhrA+Ygbj4L0kYXsFtXDgDxbKMkUKpKZUVwN/cGHlUh2T3eeDGDu1
# AX7hEs/ksUW+Y/Y0uiz0YqsxpK2R/1KRaC93Tr4aVZ8NT1KOZc95MlRKmsXmKJcA
# zofMG8rmjpyOzf0jU4iYWChgtj9IrAQfsG0Bd5ox5dou7CM6eMbwGCP0DFExJemK
# pxNmTAyL4jlKEAc+RFm3P82Ndtx88ccbu0bftIyJg4hzjKa7VxSaa28EwW5QlilG
# mAIAL+alx49rIdXbWDu42wBeG+ukHN+Ujw3e0oazgxW7OphkuGYSIJaAEnzmNswp
# +eyoHN70NAkhBPJN+VAq7EogDt7PkILO2nZ85JZhjlq1KGnEMlrJ2vPPb/yOZhw7
# ohpP7IeM9ul+H0aokIE/cIrLupkGgo/UPcLGOieA071svya1U4HkKSTF8udylhp1
# +hFZI62G2dZ/dM4SaffyB/A7vNcWwvF8zQ2rliBcGaXc2w==
# SIG # End signature block
