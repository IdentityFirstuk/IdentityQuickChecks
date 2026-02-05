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
<#
.SYNOPSIS
    Sign all PowerShell scripts in a directory

.DESCRIPTION
    This script signs all .ps1 files in the specified directory using
    a code signing certificate. It also includes integrity checking
    and verification features.

.PARAMETER Path
    Root path to search for scripts (default: current directory)

.PARAMETER CertificatePath
    Path to PFX certificate file

.PARAMETER Password
    Password for PFX certificate (as SecureString)

.PARAMETER TimestampServer
    URL of timestamp server (default: http://timestamp.digicert.com)

.PARAMETER CheckOnly
    Only check signature status, do not sign

.PARAMETER CreateBaseline
    Create integrity baseline after signing

.EXAMPLE
    .\Sign-Scripts.ps1 -Path ".\IdentityQuickChecks" -CertificatePath ".\cert.pfx"

.EXAMPLE
    .\Sign-Scripts.ps1 -CheckOnly -Path ".\"

.NOTES
    This script is part of the IdentityFirst QuickChecks protection suite.
    All methods shown here are free to use.
#>

[CmdletBinding()]
param(
    [string]$Path = ".",
    [string]$CertificatePath,
    [SecureString]$Password,
    [string]$TimestampServer = "http://timestamp.digicert.com",
    [switch]$CheckOnly,
    [switch]$CreateBaseline
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  PowerShell Script Signer & Integrity" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Color definitions
$Green = [System.ConsoleColor]::Green
$Red = [System.ConsoleColor]::Red
$Yellow = [System.ConsoleColor]::Yellow
$Cyan = [System.ConsoleColor]::Cyan
$Gray = [System.ConsoleColor]::Gray

function Get-ScriptFiles {
    <#
    .SYNOPSIS
        Get all PowerShell script files recursively
    #>
    param([string]$SearchPath)
    Get-ChildItem -Path $SearchPath -Filter "*.ps1" -Recurse -ErrorAction SilentlyContinue
}

function Test-Certificate {
    <#
    .SYNOPSIS
        Test if certificate is valid for code signing
    #>
    param([string]$CertPath, [SecureString]$CertPassword)

    try {
        # Load certificate with or without password
        if ($CertPassword) {
            $cert = Get-PfxCertificate -FilePath $CertPath -Password $CertPassword -ErrorAction Stop
        }
        else {
            $cert = Get-PfxCertificate -FilePath $CertPath -ErrorAction Stop
        }

        # Check if certificate is valid for code signing
        if ($cert.EnhancedKeyUsageList) {
            $keyUsage = $cert.EnhancedKeyUsageList | Where-Object { $_.FriendlyName -eq "Code Signing" }
            if (-not $keyUsage) {
                Write-Host "  WARNING: Certificate may not be configured for code signing" -ForegroundColor $Yellow
            }
        }

        return $cert
    }
    catch {
        Write-Host "  ERROR: Failed to load certificate: $($_.Exception.Message)" -ForegroundColor $Red
        return $null
    }
}

function Test-Signature {
    <#
    .SYNOPSIS
        Check if a file has a valid signature
    #>
    param([string]$FilePath)

    try {
        $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction Stop

        if ($sig.Status -eq 'Valid') {
            return @{
                Signed = $true
                Signer = $sig.SignerCertificate.Subject
                Timestamp = $sig.TimeStamperCertificate.NotAfter
                Status = $sig.Status
            }
        }
        else {
            return @{
                Signed = $false
                Signer = $null
                Timestamp = $null
                Status = $sig.Status
            }
        }
    }
    catch {
        return @{
            Signed = $false
            Signer = $null
            Timestamp = $null
            Status = "Error: $($_.Exception.Message)"
        }
    }
}

function New-IntegrityBaseline {
    <#
    .SYNOPSIS
        Create SHA256 hash baseline for all scripts
    #>
    param([string]$BasePath, [string]$OutputFile)

    $baseline = @{
        Created = [datetime]::UtcNow
        Algorithm = "SHA256"
        Scripts = @{}
    }

    Get-ScriptFiles -SearchPath $BasePath | ForEach-Object {
        $hash = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash
        $baseline.Scripts[$_.FullName] = @{
            Hash = $hash
            Size = $_.Length
            LastModified = $_.LastWriteTimeUtc
            Signed = (Test-Signature -FilePath $_.FullName).Signed
        }
    }

    $baseline | ConvertTo-Json -Depth 5 | Out-File -Path $OutputFile -Encoding UTF8
    Write-Host "  Baseline created: $OutputFile" -ForegroundColor $Green
    Write-Host "  Scripts indexed: $($baseline.Scripts.Count)" -ForegroundColor $Gray
}

function Test-IntegrityBaseline {
    <#
    .SYNOPSIS
        Compare current files against baseline
    #>
    param([string]$BaselineFile)

    if (-not (Test-Path $BaselineFile)) {
        Write-Host "  ERROR: Baseline file not found" -ForegroundColor $Red
        return
    }

    $baseline = Get-Content -Path $BaselineFile | ConvertFrom-Json
    $violations = @()

    foreach ($script in $baseline.Scripts.PSObject.Properties) {
        $currentHash = (Get-FileHash -Path $script.Name -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
        $storedHash = $script.Value.Hash

        if ($currentHash -ne $storedHash) {
            $violations += @{
                File = $script.Name
                Issue = "Hash mismatch"
                Original = $storedHash
                Current = $currentHash
            }
        }

        # Check if signature status changed
        $currentSigned = (Test-Signature -FilePath $script.Name).Signed
        if ($currentSigned -ne $script.Value.Signed) {
            $violations += @{
                File = $script.Name
                Issue = "Signature status changed"
                WasSigned = $script.Value.Signed
                IsSigned = $currentSigned
            }
        }
    }

    if ($violations) {
        Write-Host "  Found $($violations.Count) integrity violations:" -ForegroundColor $Red
        foreach ($v in $violations) {
            Write-Host "    - $($v.File): $($v.Issue)" -ForegroundColor $Yellow
        }
    }
    else {
        Write-Host "  All files pass integrity check" -ForegroundColor $Green
    }

    return $violations
}

function Sign-Script {
    <#
    .SYNOPSIS
        Sign a single PowerShell script
    #>
    param(
        [string]$FilePath,
        $Certificate,
        [string]$TimestampServer
    )

    try {
        $sig = Set-AuthenticodeSignature `
            -FilePath $FilePath `
            -Certificate $Certificate `
            -TimestampServer $TimestampServer `
            -ErrorAction Stop

        return @{
            Success = $true
            File = $FilePath
            Status = $sig.Status
        }
    }
    catch {
        return @{
            Success = $false
            File = $FilePath
            Error = $_.Exception.Message
        }
    }
}

# Main execution
Write-Host "[INFO] Scanning for PowerShell scripts in: $Path" -ForegroundColor $Gray
$scripts = Get-ScriptFiles -SearchPath $Path
Write-Host "[INFO] Found $($scripts.Count) scripts" -ForegroundColor $Gray
Write-Host ""

if ($scripts.Count -eq 0) {
    Write-Host "No PowerShell scripts found." -ForegroundColor $Yellow
    exit 0
}

if ($CheckOnly) {
    # Check-only mode: verify signatures
    Write-Host "========================================" -ForegroundColor $Cyan
    Write-Host "  Signature Verification Results" -ForegroundColor $Cyan
    Write-Host "========================================" -ForegroundColor $Cyan
    Write-Host ""

    $signed = 0
    $unsigned = 0
    $errors = 0

    foreach ($script in $scripts) {
        $result = Test-Signature -FilePath $script.FullName

        if ($result.Signed) {
            Write-Host "[SIGNED]   $($script.Name)" -ForegroundColor $Green
            Write-Host "           Signer: $($result.Signer)" -ForegroundColor $Gray
            $signed++
        }
        else {
            Write-Host "[UNSIGNED] $($script.Name)" -ForegroundColor $Yellow
            Write-Host "           Status: $($result.Status)" -ForegroundColor $Gray
            $unsigned++
        }
    }

    Write-Host ""
    Write-Host "========================================" -ForegroundColor $Cyan
    Write-Host "  Summary" -ForegroundColor $Cyan
    Write-Host "========================================" -ForegroundColor $Cyan
    Write-Host "  Signed:   $signed" -ForegroundColor $Green
    Write-Host "  Unsigned: $unsigned" -ForegroundColor $Yellow
    Write-Host "  Total:    $($scripts.Count)" -ForegroundColor $Gray
}
else {
    # Signing mode: require certificate
    if (-not $CertificatePath) {
        Write-Host "[ERROR] Certificate path required for signing" -ForegroundColor $Red
        Write-Host "        Use: .\Sign-Scripts.ps1 -CertificatePath '.\cert.pfx'" -ForegroundColor $Gray
        exit 1
    }

    # Verify certificate file exists
    if (-not (Test-Path $CertificatePath -PathType Leaf)) {
        Write-Host "[ERROR] Certificate file not found: $CertificatePath" -ForegroundColor $Red
        Write-Host "        Please provide a valid path to a .pfx file" -ForegroundColor $Gray
        exit 1
    }

    if (-not $Password) {
        # Try loading certificate without password first
        try {
            $cert = Get-PfxCertificate -FilePath $CertificatePath -ErrorAction Stop
            Write-Host "  [INFO] Certificate loaded (no password required)" -ForegroundColor $Gray
        }
        catch {
            Write-Host "[ERROR] Certificate password required or invalid certificate" -ForegroundColor $Red
            Write-Host "        File: $CertificatePath" -ForegroundColor $Gray
            Write-Host "        Use: .\Sign-Scripts.ps1 -CertificatePath '.\cert.pfx' -Password (ConvertTo-SecureString 'password' -AsPlainText -Force)" -ForegroundColor $Gray
            exit 1
        }
    }
    else {
        # Load certificate with password
        Write-Host "[INFO] Loading certificate: $CertificatePath" -ForegroundColor $Gray
        $cert = Test-Certificate -CertPath $CertificatePath -CertPassword $Password
        if (-not $cert) {
            exit 1
        }
        Write-Host "  Certificate loaded: $($cert.Subject)" -ForegroundColor $Green
        Write-Host "  Valid from: $($cert.NotBefore) to $($cert.NotAfter)" -ForegroundColor $Gray
    }
    Write-Host ""

    # Sign all scripts
    Write-Host "========================================" -ForegroundColor $Cyan
    Write-Host "  Signing Scripts" -ForegroundColor $Cyan
    Write-Host "========================================" -ForegroundColor $Cyan
    Write-Host ""

    $success = 0
    $failed = 0

    foreach ($script in $scripts) {
        Write-Host "[SIGNING] $($script.Name)..." -ForegroundColor $Gray
        $result = Sign-Script `
            -FilePath $script.FullName `
            -Certificate $cert `
            -TimestampServer $TimestampServer

        if ($result.Success) {
            Write-Host "  [OK] Signed successfully" -ForegroundColor $Green
            $success++
        }
        else {
            Write-Host "  [FAILED] $($result.Error)" -ForegroundColor $Red
            $failed++
        }
    }

    Write-Host ""
    Write-Host "========================================" -ForegroundColor $Cyan
    Write-Host "  Signing Complete" -ForegroundColor $Cyan
    Write-Host "========================================" -ForegroundColor $Cyan
    Write-Host "  Success: $success" -ForegroundColor $Green
    Write-Host "  Failed:  $failed" -ForegroundColor $Red
    Write-Host "  Total:   $($scripts.Count)" -ForegroundColor $Gray
}

# Create integrity baseline if requested
if ($CreateBaseline -or (-not $CheckOnly)) {
    Write-Host ""
    Write-Host "[INFO] Creating integrity baseline..." -ForegroundColor $Gray
    $baselineFile = Join-Path $Path "integrity-baseline.json"
    New-IntegrityBaseline -BasePath $Path -OutputFile $baselineFile
}

Write-Host ""
Write-Host "Done!" -ForegroundColor $Green

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC8p7FmwPYA7WdT
# RtDuU+v9kOmnGhg56LWAtiutisiVQ6CCFlIwggMUMIIB/KADAgECAhBDR0HvMFNE
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgIuN708XJsihMj7FMVPrrEuNYo85sfRrezeDa
# k5EBVT0wDQYJKoZIhvcNAQEBBQAEggEAk5SHubimwfJTk1GlwFAC6GGu2OhTXX6v
# dRkcy7wF7i0ToXWWIjK+FfUt+1skVTWaLQOt8/YO6A7XTbWcXkIQGGzZ1Nv9x1J6
# zih96RC1l3jaxZUQHaAh8/zNyUS75gqJh5qfM+QSUGGZICIo57FW4WauB2X5DVNC
# hPBIUc8ktpvIjoFQE+H0ogOXZIExM804/c/6biQrd4sHsESCUvoB1tTWxTC4Vs5z
# Zyp5Q2nkVgzEzxg9QsvZtiKOP8R1ORXEPHc/gaDIYRPSaHT7ckrnkO/dBymP8SFu
# 8/6MjIHwCFasd5A92hHNE6PHZupgl+40er94kD2GQgUVtvIMz5CKvKGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjAyMDQxNjUyMTBaMC8GCSqGSIb3DQEJBDEiBCAi
# wA6zAFif02G/J2Asyd6EiQHMnvpwDntheM37Cec1oTANBgkqhkiG9w0BAQEFAASC
# AgA96elhJMYtUDABtTQZVJAUc01h+nFEgqY8k310iJMltknEYhqHsQY1mmq0xBii
# LvlsR2kzwh22tKtay5TyIjjG+05fCHV8H/NdMUSLEJKP0qtDhoaMoMHoAhBJsXQ6
# cdfj0YwcrZ7Bvf2lnHGxiRfS3pyORdSZoPGX15UGmQUJWwMp9+W5yQ9EaOhfjvjI
# pOKo90o5kXB4UIrANpyy+EyIyUKKmBTrc/a6xLvocVRAjlH5QXZfqedKThQJZImT
# PkhTZqRz0EYp3o4ZS8/9CS5egpAYDEDPJD8pbDUo9fMc+R1to7bsv93ykX2oXAzX
# BNnVBE2PCfhjgleyR2w1pR+SluLirNnCIjUyGgR+0eg15GSCvK7Uk+7N0xC6n/r3
# qOlRtrCMJIi0AOWoIFlNDs+tDQiSEsHHnjt7JLAJCCEouBcezNYwb0SVoWfmDxyB
# bLeMvNDxxSW3JjeLrJeztEVnNWc2RCCLFsf4PHioGNzcHfE9wv53K9Imxufj1kpI
# WQ11a549InnBmk0D0npIhHXoquVKYribT7mYJfnXipWY8x3rQgXvjdn79e1HqtJi
# 8+l0lqRwDzfjYZ5sPKEDvSja67hsTCmyIySVDRiwbUWK87cGTC2p0nEq3JasLXAQ
# WASf43v2C127GFqpMQsnTQGXpQwpbwERdeSRfXMyU1pfzg==
# SIG # End signature block
