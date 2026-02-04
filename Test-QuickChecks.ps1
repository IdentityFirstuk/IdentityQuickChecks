# ============================================================================
# IdentityFirst QuickChecks - Test Suite
# ============================================================================
# Version: 1.0.0
# Date: 2026-01-29
# Description: Validates QuickChecks installation and functionality
# ============================================================================

[CmdletBinding()]
param(
    [switch]$All,
    [switch]$Syntax,
    [switch]$Security,
    [switch]$Launcher,
    [switch]$Quick
)

# ============================================================================
# Test Results
# ============================================================================

$script:TestsPassed = 0
$script:TestsFailed = 0
$script:TestsTotal = 0
$script:TestResults = @()

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Test {
    param(
        [string]$Name,
        [string]$Description,
        [string]$Status,
        [string]$Message = ""
    )

    $script:TestsTotal++

    if ($Status -eq "PASS") {
        $script:TestsPassed++
        $msg = ("[PASS] {0}" -f $Name)
        Write-Output $msg
    }
    else {
        $script:TestsFailed++
        $msg = ("[FAIL] {0}" -f $Name)
        Write-Output $msg
    }

    $suffix = if ($Message) { " - $Message" } else { "" }
    $msg = ("[{0}] {1}{2}" -f $Status, $Name, $suffix)
    Write-Output $msg

    $script:TestResults += [PSCustomObject]@{
        Name = $Name
        Description = $Description
        Status = $Status
        Message = $Message
    }
}

function Write-Header {
    param([string]$Message)
    Write-Output ""
    Write-Output (("=" * 70))
    Write-Output (" $Message")
    Write-Output (("=" * 70))
    Write-Output ""
}

# ============================================================================
# Syntax Tests
# ============================================================================

function Test-Syntax {
    Write-Header "Syntax Validation Tests"

    # Test all PS1 files
    $ps1Files = Get-ChildItem -Path "$PSScriptRoot" -Recurse -Filter "*.ps1" -ErrorAction SilentlyContinue

    foreach ($file in $ps1Files) {
        $name = $file.FullName.Replace("$PSScriptRoot\", "")

        try {
            $errors = $null
            $null = [System.Management.Automation.PSParser]::Tokenize(
                (Get-Content -Path $file.FullName -Raw),
                [ref]$errors
            )

            if ($errors.Count -eq 0) {
                Write-Test -Name $name -Description "Syntax check" -Status "PASS"
            }
            else {
                $errorCount = ($errors | Where-Object { $_.Severity -eq "Error" }).Count
                if ($errorCount -eq 0) {
                    Write-Test -Name $name -Description "Syntax check (warnings only)" -Status "PASS"
                }
                else {
                    Write-Test -Name $name -Description "Syntax check" -Status "FAIL" -Message "$errorCount errors"
                }
            }
        }
        catch {
            Write-Test -Name $name -Description "Syntax check" -Status "FAIL" -Message $_.Exception.Message
        }
    }
}

# ============================================================================
# Security Tests
# ============================================================================

function Test-Security {
    Write-Header "Security Module Tests"

    # Test 1: Module exists
    $securityModule = "$PSScriptRoot\Security\IdentityFirst.Security.psm1"
    if (Test-Path $securityModule) {
        Write-Test -Name "Security module exists" -Description "Verify security module file" -Status "PASS"

        # Test 2: Module loads
        try {
            Import-Module -Name $securityModule -Force -ErrorAction Stop
            Write-Test -Name "Security module loads" -Description "Import security module" -Status "PASS"

            # Test 3: Functions available
            $requiredFunctions = @(
                'ConvertTo-SecureStringIfNeeded',
                'Get-CredentialFromInput',
                'Test-ValidPath',
                'Write-SecureLog',
                'Get-SecureHtmlContent',
                'Set-OutputFileSecurity'
            )

            foreach ($func in $requiredFunctions) {
                if (Get-Command $func -ErrorAction SilentlyContinue) {
                    Write-Test -Name "Function: $func" -Description "Security function available" -Status "PASS"
                }
                else {
                    Write-Test -Name "Function: $func" -Description "Security function available" -Status "FAIL"
                }
            }

            # Test 4: Secure logging redaction
            $logOutput = & {
                $logMsg = Write-SecureLog -Message "API key: secret123" -Level INFO -LogFile $null 2>$null
                $logMsg
            } 2>$null

            if ($logOutput -match '\*\*\*REDACTED\*\*\*') {
                Write-Test -Name "Credential redaction" -Description "Sensitive data redacted in logs" -Status "PASS"
            }
            else {
                Write-Test -Name "Credential redaction" -Description "Sensitive data redacted in logs" -Status "FAIL"
            }

            # Test 5: HTML encoding
            $encoded = Get-SecureHtmlContent -Content "<script>alert('xss')</script>"
            if ($encoded -match '&lt;script' -or ($encoded -notmatch '<script>')) {
                Write-Test -Name "XSS protection" -Description "HTML special characters encoded" -Status "PASS"
            }
            else {
                Write-Test -Name "XSS protection" -Description "HTML special characters encoded" -Status "FAIL"
            }

            # Remove module
            Remove-Module -Name "IdentityFirst.Security" -ErrorAction SilentlyContinue
        }
        catch {
            Write-Test -Name "Security module loads" -Description "Import security module" -Status "FAIL" -Message $_.Exception.Message
        }
    }
    else {
        Write-Test -Name "Security module exists" -Description "Verify security module file" -Status "FAIL"
    }
}

# ============================================================================
# Launcher Tests
# ============================================================================

function Test-Launcher {
    Write-Header "Launcher Tests"

    # Test 1: Launcher exists
    $launcher = "$PSScriptRoot\Start-QuickChecks.ps1"
    if (Test-Path $launcher) {
        Write-Test -Name "Launcher exists" -Description "Start-QuickChecks.ps1 found" -Status "PASS"

        # Test 2: Launcher syntax
        try {
            $errors = $null
            $null = [System.Management.Automation.PSParser]::Tokenize(
                (Get-Content -Path $launcher -Raw),
                [ref]$errors
            )
            if ($errors.Count -eq 0) {
                Write-Test -Name "Launcher syntax" -Description "Valid PowerShell syntax" -Status "PASS"
            }
            else {
                Write-Test -Name "Launcher syntax" -Description "Valid PowerShell syntax" -Status "FAIL" -Message "$($errors.Count) issues"
            }
        }
        catch {
            Write-Test -Name "Launcher syntax" -Description "Valid PowerShell syntax" -Status "FAIL" -Message $_.Exception.Message
        }

        # Test 3: Help parameter
        try {
            $output = & $launcher -Help -ErrorAction SilentlyContinue 2>&1 | Out-String
            if ($output -match "USAGE:") {
                Write-Test -Name "Help parameter" -Description "Help output generated" -Status "PASS"
            }
            else {
                Write-Test -Name "Help parameter" -Description "Help output generated" -Status "FAIL"
            }
        }
        catch {
            Write-Test -Name "Help parameter" -Description "Help output generated" -Status "FAIL" -Message $_.Exception.Message
        }
    }
    else {
        Write-Test -Name "Launcher exists" -Description "Start-QuickChecks.ps1 found" -Status "FAIL"
    }

    # Test 4: Certificate script
    $certScript = "$PSScriptRoot\Create-SelfSignedCert.ps1"
    if (Test-Path $certScript) {
        Write-Test -Name "Certificate script exists" -Description "Create-SelfSignedCert.ps1 found" -Status "PASS"
    }
    else {
        Write-Test -Name "Certificate script exists" -Description "Create-SelfSignedCert.ps1 found" -Status "FAIL"
    }

    # Test 5: Sign script
    $signScript = "$PSScriptRoot\Sign-QuickChecks.ps1"
    if (Test-Path $signScript) {
        Write-Test -Name "Sign script exists" -Description "Sign-QuickChecks.ps1 found" -Status "PASS"
    }
    else {
        Write-Test -Name "Sign script exists" -Description "Sign-QuickChecks.ps1 found" -Status "FAIL"
    }
}

# ============================================================================
# Module Tests
# ============================================================================

function Test-Modules {
    Write-Header "Check Module Tests"

    $checkCount = 0

    # Test all check scripts
    $checkScripts = Get-ChildItem -Path "$PSScriptRoot\Checks" -Recurse -Filter "*.ps1" -ErrorAction SilentlyContinue

    foreach ($script in $checkScripts) {
        $name = $script.FullName.Replace("$PSScriptRoot\", "")
        $checkCount++

        # Syntax check
        try {
            $errors = $null
            $null = [System.Management.Automation.PSParser]::Tokenize(
                (Get-Content -Path $script.FullName -Raw),
                [ref]$errors
            )

            if ($errors.Count -eq 0) {
                Write-Test -Name $name -Description "Check script syntax" -Status "PASS"
            }
            else {
                Write-Test -Name $name -Description "Check script syntax" -Status "FAIL" -Message "$($errors.Count) issues"
            }
        }
        catch {
            Write-Test -Name $name -Description "Check script syntax" -Status "FAIL" -Message $_.Exception.Message
        }
    }

    Write-Output ""
    Write-Output ("Total check scripts: $checkCount")
}

# ============================================================================
# Configuration Tests
# ============================================================================

function Test-Configuration {
    Write-Header "Configuration Tests"

    # Test config file
    $configFile = "$PSScriptRoot\config\QuickChecks.config.psd1"
    if (Test-Path $configFile) {
        try {
            $config = Import-PowerShellDataFile -Path $configFile -ErrorAction Stop
            Write-Test -Name "Config file valid" -Description "QuickChecks.config.psd1 loads" -Status "PASS"

            if ($config.ModuleVersion) {
                Write-Test -Name "Config version" -Description "Version: $($config.ModuleVersion)" -Status "PASS"
            }
        }
        catch {
            Write-Test -Name "Config file valid" -Description "QuickChecks.config.psd1 loads" -Status "FAIL" -Message $_.Exception.Message
        }
    }
    else {
        Write-Test -Name "Config file exists" -Description "QuickChecks.config.psd1 found" -Status "FAIL"
    }

    # Test security manifest
    $manifestFile = "$PSScriptRoot\Security\IdentityFirst.Security.manifest.psd1"
    if (Test-Path $manifestFile) {
        try {
            $manifest = Import-PowerShellDataFile -Path $manifestFile -ErrorAction Stop
            Write-Test -Name "Security manifest" -Description "Security manifest loads" -Status "PASS"

            if ($manifest.SecurityFeatures) {
                Write-Test -Name "Security features" -Description "Security features defined" -Status "PASS"
            }
        }
        catch {
            Write-Test -Name "Security manifest" -Description "Security manifest loads" -Status "FAIL" -Message $_.Exception.Message
        }
    }
}

# ============================================================================
# Summary
# ============================================================================

function Show-Summary {
    Write-Header "Test Summary"

    Write-Output "  Total Tests:   $script:TestsTotal"
    Write-Output "  Passed:        $script:TestsPassed"
    Write-Output "  Failed:        $script:TestsFailed"
    Write-Output ""

    $passRate = if ($script:TestsTotal -gt 0) { [math]::Round(($script:TestsPassed / $script:TestsTotal) * 100, 1) } else { 0 }
    Write-Output ("  Pass Rate:     $passRate%")
    Write-Output ""

    if ($script:TestsFailed -eq 0) {
        Write-Output "  ✓ All tests passed!"
    }
    else {
        Write-Output "  ✗ Some tests failed. Review output above."
    }

    # Export results
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $reportPath = "$PSScriptRoot\Output\test-results-$timestamp.xml"

    $script:TestResults | Export-Clixml -Path $reportPath -Force -ErrorAction SilentlyContinue
    Write-Output ""
    Write-Output "Results exported to: $reportPath"
}

# ============================================================================
# Main Execution
# ============================================================================

Write-Logo
Write-Output " IdentityFirst QuickChecks - Test Suite"
Write-Output (Get-Date -Format 'yyyy-MM-dd')
Write-Output ""

# Run requested tests
if ($All -or (-not $Syntax -and -not $Security -and -not $Launcher -and -not $Quick)) {
    Test-Syntax
    Test-Security
    Test-Launcher
    Test-Modules
    Test-Configuration
}
else {
    if ($Syntax) { Test-Syntax }
    if ($Security) { Test-Security }
    if ($Launcher) { Test-Launcher }
    if ($Quick) {
        Test-Syntax
        Test-Launcher
    }
}

# Show summary
Show-Summary

# Exit with appropriate code
if ($script:TestsFailed -gt 0) {
    exit 1
}
exit 0

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBmLU1tSjhRAwI8
# dPEFBaVqWjV0b3bLTWy/LhGSAboisaCCFlIwggMUMIIB/KADAgECAhBDR0HvMFNE
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgcXXoW71v56+00DGuMYykqAW9Fzu9BpirCAfM
# xkeHouMwDQYJKoZIhvcNAQEBBQAEggEAWBsm1HAvHT6i6vcD6DrZdEpARiTxSrPX
# 6w6qoRoAAuRNSMvDpaf1faiOjEyc7iQJzRyP2VYWnAlCusvG+XOG8/aicXaYlQCZ
# rm30qGAGPrnH2CsZUG1RX1trSx6UHEMiJQMflG7qGQKTrMi57wGkus6JV9ckqt7D
# yzEVCKwadBvClfE/WLTn2XVaAATgg6VrGkpd7O/QLSYEagm/mQMCClms6rbhWr58
# kMR4JjJOlYkDTJSmhua0sSwoybkmsCG60FEX6CXcsJXZ4kcE2hZdikVSSkFAkkdB
# fdV0d+6llxG8tY8dMJ+0dSgNy2U8O4S36iH+QCeg3XLyLkl9D1CLKqGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjAyMDQxNjUyMTFaMC8GCSqGSIb3DQEJBDEiBCC3
# 4TyB7k0H1PtEWE1hp/pmqulbLO+BqbRymbJdiDJlczANBgkqhkiG9w0BAQEFAASC
# AgBzlLqtULNU3m9BniK4HmxX97tDuU8KlLODSuHsN7mTZEoziH3gW7PqHuHbANNQ
# H3lYujOfagolJTe6kPTaDb0N4mLHFNSamMXNcKTEU+EZEffUEpRXgFc911W8RMX3
# lfOYfYAfreIpT6gKMBEJ5xRxOocI8Ma6pidyplk1jBAZqUVlPd3dKBQ9Kdysx17h
# sbSKRNMXzgVP6a7GFdbMl4AuZTGKZmBBW0kea5CE4rMZ/aqqXgzo8n1uXhfhv0q0
# d7IR79NCDv2PlD5Sm1rB4LBpXmmwIUuqWTjJ87hACm5uAQ/dvQz5ZcUPm+fQix0C
# xKh7aZyeqZ90CTSesRuUuXXxeBn04YgacLRFmbeDV1eR8thg+bhOPRvFEloC7mVF
# 5WDpY1Mau25uyupnsir66oW60f1Pcuo9Qd8/P3N39OVV6eMIB76HQEf7G8rOlxZS
# JV8p8LTUg+vxPa5VzSPWNkYSLiDGjiFI4BVzmSQ2aGD44QNRdDGBTRW6E3r+lPRG
# YbgUUsQwOWppaargDiTmt4SvSyGIA+/L9IULCafjQZw20dMCiummGAI8OfXxoD8X
# XRmfu0ea0dvN9HO7L3UiQdfYbX0O8P3eI0EZJxQKGb6u9pQZ8jIbq1Ko9xSzBp7w
# Q/zo03OqYPZRJPgvcOO3pTeLTqJrpF4Gx+Tp22jDAQMLZA==
# SIG # End signature block
