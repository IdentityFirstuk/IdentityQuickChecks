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
# MIIf3QYJKoZIhvcNAQcCoIIfzjCCH8oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCwjlt6BKl7vwZZ
# s1zDnqOxG17MNW/MnK40AgqrjYNqW6CCGNwwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggWeMIIDhqADAgECAhAfb4XAeia2j0f08ahQbRKXMA0GCSqG
# SIb3DQEBCwUAMGcxCzAJBgNVBAYTAkdCMRcwFQYDVQQHDA5Ob3J0aHVtYmVybGFu
# ZDEaMBgGA1UECgwRSWRlbnRpdHlGaXJzdCBMdGQxIzAhBgNVBAMMGklkZW50aXR5
# Rmlyc3QgQ29kZSBTaWduaW5nMB4XDTI2MDEyOTIwNTAyM1oXDTI5MDEyOTIxMDAy
# M1owZzELMAkGA1UEBhMCR0IxFzAVBgNVBAcMDk5vcnRodW1iZXJsYW5kMRowGAYD
# VQQKDBFJZGVudGl0eUZpcnN0IEx0ZDEjMCEGA1UEAwwaSWRlbnRpdHlGaXJzdCBD
# b2RlIFNpZ25pbmcwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDV9YyY
# z49V2ipI5ePMgWVHs5h89pYHRk60XSkSOUrCXYH+83sOhTgzKnpvwo7Mzuchbf6f
# q4+85DpydvkLD1L/ZMAF3x1oP74iZ28JZYv/3PwrwLsUDAAiqFQlZk7YrDxgMhdO
# Z90dXpnK+xLTfbaRGLaqB40xnCMAozxHwIm1ClEOOlhC/I+BoPZqG6GRCcOXIdzU
# UQFWRGw8o33e2YyvDfCpwZlFHTgbD1Zmsx/SE7x9LiKi3UdnAyOMlrfHgSeJRIss
# omIVDKheB5MuAHlZQm//DMNBV7o+jO3prF4MJJygD+scND5ZImw+3L2BJEPYyBLZ
# Jum+fnKp4obGnMafQWyEk77bR+ebX3hIyglqcEwalVFdPQsIMeNQ7ervsFy7NOU0
# wBPIuEgLifGWwTVPHy70T2Ci+rz5+93qSljOWvOeT4LdQ/hpqH9JS4Eu4SpJrJ+U
# 6pwdbB3rZnFLax57w/Uh/ayZ74FZDvZhCg8KaV5sJo7XgbwZ44b3OPo6bXAWV7Jl
# yIWrO4h1q3QbgSXVWui3fWxfNmHgW3CEPTzKJlRM88wCvcPe/gQYx4aDFUKtEoiE
# JKmbuDFWoHyDAEuVo+ohUt03eRdEv73XZR/hwg9imN6NbaaR9aG1TV8C3/uMD5ET
# jBmdlUcGEztyHDLzVyIad+RQGh3nDmq2vhGLfQIDAQABo0YwRDAOBgNVHQ8BAf8E
# BAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFHZkS4haGPdZn+Um
# 4fJ/zeQU7kJzMA0GCSqGSIb3DQEBCwUAA4ICAQAnWa5k8D/hKdPn9IIZNY15hX6B
# NQylhSEPNRl4PT4vR1KKyX7Wl6c55c57z3egOC23wjOC6n0Nzt0JzZwgor9Do2V8
# 7R7APMQbXVMU2N1wDugVMNBsXbDbcS4AJz2IxRPmcW+CbMo32BoFeVbc6AODLhEr
# 1PEcAydxANk7E3rxXd1TD7pCLgp1XtRmZPx87SVJgYrRvr7J3VG0As/2KOO6Eu8n
# QTAwiyOZaRXh8MGmI/kd8SUZzFzwRpcafvSgjGqbQK6s4Tkvyxo9rkLKcS9xOww7
# hyEB6mmmV9Z0kPRBMk7llIKebFzN3exzhU8Jrdsnoas4dHl/O78VOl7nZEAbujhF
# l2IL+wFTicwrwCe9s4ZVtEhFZogUAxgGk6Ut00axJF5DgRuvc06YSRrrG7DvMKZw
# vSLWeeT9u+gbwmwEFLIjaEuF+PG0HQ2EgEaNxOKXP7xjJzLo58f5GWoFk+AKealG
# 8E1TuUfHLGJSl4m30vmenyjTlWtpcgbX5XBAb7BbYv3BrIsTiPwoqKY/X9orSDK8
# owFCw1x3Gy+K2DnaVR8JMtGv5KfC2hSobmjnc3nsryd0Bf0iEO/rcwtNbhAzjNEi
# rEKDng+bz5WEJ5HXVg3SXB7v73m+Q4xNVPfBT4WVV0YHxlbwtIk/Jpbsls43n5Uv
# 6aqzWFEZtlMMLRwTezCCBrQwggScoAMCAQICEA3HrFcF/yGZLkBDIgw6SYYwDQYJ
# KoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IElu
# YzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQg
# VHJ1c3RlZCBSb290IEc0MB4XDTI1MDUwNzAwMDAwMFoXDTM4MDExNDIzNTk1OVow
# aTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQD
# EzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1
# NiAyMDI1IENBMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALR4MdMK
# mEFyvjxGwBysddujRmh0tFEXnU2tjQ2UtZmWgyxU7UNqEY81FzJsQqr5G7A6c+Gh
# /qm8Xi4aPCOo2N8S9SLrC6Kbltqn7SWCWgzbNfiR+2fkHUiljNOqnIVD/gG3SYDE
# Ad4dg2dDGpeZGKe+42DFUF0mR/vtLa4+gKPsYfwEu7EEbkC9+0F2w4QJLVSTEG8y
# AR2CQWIM1iI5PHg62IVwxKSpO0XaF9DPfNBKS7Zazch8NF5vp7eaZ2CVNxpqumzT
# CNSOxm+SAWSuIr21Qomb+zzQWKhxKTVVgtmUPAW35xUUFREmDrMxSNlr/NsJyUXz
# dtFUUt4aS4CEeIY8y9IaaGBpPNXKFifinT7zL2gdFpBP9qh8SdLnEut/GcalNeJQ
# 55IuwnKCgs+nrpuQNfVmUB5KlCX3ZA4x5HHKS+rqBvKWxdCyQEEGcbLe1b8Aw4wJ
# khU1JrPsFfxW1gaou30yZ46t4Y9F20HHfIY4/6vHespYMQmUiote8ladjS/nJ0+k
# 6MvqzfpzPDOy5y6gqztiT96Fv/9bH7mQyogxG9QEPHrPV6/7umw052AkyiLA6tQb
# Zl1KhBtTasySkuJDpsZGKdlsjg4u70EwgWbVRSX1Wd4+zoFpp4Ra+MlKM2baoD6x
# 0VR4RjSpWM8o5a6D8bpfm4CLKczsG7ZrIGNTAgMBAAGjggFdMIIBWTASBgNVHRMB
# Af8ECDAGAQH/AgEAMB0GA1UdDgQWBBTvb1NK6eQGfHrK4pBW9i/USezLTjAfBgNV
# HSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYD
# VR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1Ud
# HwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwH
# ATANBgkqhkiG9w0BAQsFAAOCAgEAF877FoAc/gc9EXZxML2+C8i1NKZ/zdCHxYga
# MH9Pw5tcBnPw6O6FTGNpoV2V4wzSUGvI9NAzaoQk97frPBtIj+ZLzdp+yXdhOP4h
# CFATuNT+ReOPK0mCefSG+tXqGpYZ3essBS3q8nL2UwM+NMvEuBd/2vmdYxDCvwzJ
# v2sRUoKEfJ+nN57mQfQXwcAEGCvRR2qKtntujB71WPYAgwPyWLKu6RnaID/B0ba2
# H3LUiwDRAXx1Neq9ydOal95CHfmTnM4I+ZI2rVQfjXQA1WSjjf4J2a7jLzWGNqNX
# +DF0SQzHU0pTi4dBwp9nEC8EAqoxW6q17r0z0noDjs6+BFo+z7bKSBwZXTRNivYu
# ve3L2oiKNqetRHdqfMTCW/NmKLJ9M+MtucVGyOxiDf06VXxyKkOirv6o02OoXN4b
# FzK0vlNMsvhlqgF2puE6FndlENSmE+9JGYxOGLS/D284NHNboDGcmWXfwXRy4kbu
# 4QFhOm0xJuF2EZAOk5eCkhSxZON3rGlHqhpB/8MluDezooIs8CVnrpHMiD2wL40m
# m53+/j7tFaxYKIqL0Q4ssd8xHZnIn/7GELH3IdvG2XlM9q7WP/UwgOkw/HQtyRN6
# 2JK4S1C8uw3PdBunvAZapsiI5YKdvlarEvf8EA+8hcpSM9LHJmyrxaFtoza2zNaQ
# 9k+5t1wwggbtMIIE1aADAgECAhAKgO8YS43xBYLRxHanlXRoMA0GCSqGSIb3DQEB
# CwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8G
# A1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBT
# SEEyNTYgMjAyNSBDQTEwHhcNMjUwNjA0MDAwMDAwWhcNMzYwOTAzMjM1OTU5WjBj
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMT
# MkRpZ2lDZXJ0IFNIQTI1NiBSU0E0MDk2IFRpbWVzdGFtcCBSZXNwb25kZXIgMjAy
# NSAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0EasLRLGntDqrmBW
# sytXum9R/4ZwCgHfyjfMGUIwYzKomd8U1nH7C8Dr0cVMF3BsfAFI54um8+dnxk36
# +jx0Tb+k+87H9WPxNyFPJIDZHhAqlUPt281mHrBbZHqRK71Em3/hCGC5KyyneqiZ
# 7syvFXJ9A72wzHpkBaMUNg7MOLxI6E9RaUueHTQKWXymOtRwJXcrcTTPPT2V1D/+
# cFllESviH8YjoPFvZSjKs3SKO1QNUdFd2adw44wDcKgH+JRJE5Qg0NP3yiSyi5Mx
# gU6cehGHr7zou1znOM8odbkqoK+lJ25LCHBSai25CFyD23DZgPfDrJJJK77epTwM
# P6eKA0kWa3osAe8fcpK40uhktzUd/Yk0xUvhDU6lvJukx7jphx40DQt82yepyekl
# 4i0r8OEps/FNO4ahfvAk12hE5FVs9HVVWcO5J4dVmVzix4A77p3awLbr89A90/nW
# GjXMGn7FQhmSlIUDy9Z2hSgctaepZTd0ILIUbWuhKuAeNIeWrzHKYueMJtItnj2Q
# +aTyLLKLM0MheP/9w6CtjuuVHJOVoIJ/DtpJRE7Ce7vMRHoRon4CWIvuiNN1Lk9Y
# +xZ66lazs2kKFSTnnkrT3pXWETTJkhd76CIDBbTRofOsNyEhzZtCGmnQigpFHti5
# 8CSmvEyJcAlDVcKacJ+A9/z7eacCAwEAAaOCAZUwggGRMAwGA1UdEwEB/wQCMAAw
# HQYDVR0OBBYEFOQ7/PIx7f391/ORcWMZUEPPYYzoMB8GA1UdIwQYMBaAFO9vU0rp
# 5AZ8esrikFb2L9RJ7MtOMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggr
# BgEFBQcDCDCBlQYIKwYBBQUHAQEEgYgwgYUwJAYIKwYBBQUHMAGGGGh0dHA6Ly9v
# Y3NwLmRpZ2ljZXJ0LmNvbTBdBggrBgEFBQcwAoZRaHR0cDovL2NhY2VydHMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNI
# QTI1NjIwMjVDQTEuY3J0MF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly9jcmwzLmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZT
# SEEyNTYyMDI1Q0ExLmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1s
# BwEwDQYJKoZIhvcNAQELBQADggIBAGUqrfEcJwS5rmBB7NEIRJ5jQHIh+OT2Ik/b
# NYulCrVvhREafBYF0RkP2AGr181o2YWPoSHz9iZEN/FPsLSTwVQWo2H62yGBvg7o
# uCODwrx6ULj6hYKqdT8wv2UV+Kbz/3ImZlJ7YXwBD9R0oU62PtgxOao872bOySCI
# LdBghQ/ZLcdC8cbUUO75ZSpbh1oipOhcUT8lD8QAGB9lctZTTOJM3pHfKBAEcxQF
# oHlt2s9sXoxFizTeHihsQyfFg5fxUFEp7W42fNBVN4ueLaceRf9Cq9ec1v5iQMWT
# FQa0xNqItH3CPFTG7aEQJmmrJTV3Qhtfparz+BW60OiMEgV5GWoBy4RVPRwqxv7M
# k0Sy4QHs7v9y69NBqycz0BZwhB9WOfOu/CIJnzkQTwtSSpGGhLdjnQ4eBpjtP+XB
# 3pQCtv4E5UCSDag6+iX8MmB10nfldPF9SVD7weCC3yXZi/uuhqdwkgVxuiMFzGVF
# wYbQsiGnoa9F5AaAyBjFBtXVLcKtapnMG3VH3EmAp/jsJ3FVF3+d1SVDTmjFjLbN
# FZUWMXuZyvgLfgyPehwJVxwC+UpX2MSey2ueIu9THFVkT+um1vshETaWyQo8gmBt
# o/m3acaP9QsuLj3FNwFlTxq25+T4QwX9xa6ILs84ZPvmpovq90K8eWyG2N01c4Ih
# SOxqt81nMYIGVzCCBlMCAQEwezBnMQswCQYDVQQGEwJHQjEXMBUGA1UEBwwOTm9y
# dGh1bWJlcmxhbmQxGjAYBgNVBAoMEUlkZW50aXR5Rmlyc3QgTHRkMSMwIQYDVQQD
# DBpJZGVudGl0eUZpcnN0IENvZGUgU2lnbmluZwIQH2+FwHomto9H9PGoUG0SlzAN
# BglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqG
# SIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3
# AgEVMC8GCSqGSIb3DQEJBDEiBCALfijI+rEVQwtepEzLtSJIPFoEaarKu0JhXdcb
# Hf+EizANBgkqhkiG9w0BAQEFAASCAgC4oXwa9yJqRVqz61zwHyyZFCBiR8n2xJcy
# YliTzRlbyUlcTl8qWRss+IZ8Fo2NWjrZkaZaNtVHLr5pgPWn7SN364veNRo63Ex6
# hSecCve+3V3BOxT7gJNVHN7KXVlzo0ZPKq444vwZ8L5n/ZW6BvPAPl+YAMvxZ2TU
# 0CTVpvQNARV6suKOfX5E9UIPzxrIJdHoySVJvPT3Ra3Z+7krQZY8VKO6LMjApT7e
# X9g+vQ5StvkQX5sZ2e94k2Oitnw7JtStNcrmJu/bpzM/3l2b/FcJJD8UOEvW9GOk
# 0qt2mkugan2Bqxy3xLOcE1+JyZWtTJu8VImrFZewSOYlK6+0VicNoZFFgKt/owuj
# JYFCpo90TmsEsh/SbsbE85RBaKl6l7toWbKaNuUcZUkJc5XDna/Uc94mUukweGSf
# 5jYcsxlbKxp61GYXbDnaQKcnAeOzYCWhmGj6RmKjfuI2ZOdGns9agMYFpWud01zB
# 1jGH4SC/VMumXk42Zr+KFJEYS+8VBIdKq5IKsQeZARbN2xT2NaoyU4d1qwkUmthF
# aQY2kidjvCG9oaTetO4c3Z0KkIfAzQlRmta+84LiNhykp+wRw5gFExwXQvCUFBwQ
# 24PGlx+DyFAfOfnOhh8fjAglARQr3Xr+0UVyZIGKPr1IvqwVZpjLq8NcogMZjuHc
# oS33DfXZk6GCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAyMDUxNzEyNTFaMC8G
# CSqGSIb3DQEJBDEiBCBKRnS0rcciRgHScE6J0A1eR6+/6S0vQUv8ayFMiehqODAN
# BgkqhkiG9w0BAQEFAASCAgAE7wt2EisuWGxwbGrtbxu8/CyvhQyMAP95kYFGRywh
# aMdGJjrrBBeObsqLx2ZqkbVXTRvO8V8odqN3H1KIoU6FbMd35fWBFYGhXtEY/jOI
# BHAco1eQeWK3LVC/uG88C6E/OzCKC146ThlvbfgS/+JB1N4afcK9YJu04Wsfu4uR
# Pjidwc1xS//68MTPh8opNLVT/r5bLqftyU+fT3U7ng2lEz5Ya6baHwweihO+oo5h
# pOGbaclXCcz7pMH7PPaFUwPRTJa3OqrjpeXNbn9sL8IrzVCOploWFxcUIJvqVWY4
# K+vGNvXYg/7knPC8RB/kLW19snJbBYFpeTwOgqmMBjmJPGq9LMKZX23qKoDfOGR7
# 1RJZfWTvMzza//3AMzaNV5l/s6r88gvvjBL4iCJGsqRWfluC5odk/8mse3ze0X8F
# zspE7Ww/xH/DaRMxlEgwjKmFGgvxt8RJrHDPIhyhvjB7JFdm2bOveXID2Qs7tQ5K
# MyGecwOFIGuwybF+jrC/gRPXRZTP6iEdgAcc4bNOg5R1BmL44wK9XO6dSoE5R0FB
# Rdpy3hxS+HH7hugzVyZcj02Vm/38/jvrZXg6YA/epYohCwffp5SjGmlbQsg9zpo9
# GbDPZ0K7PKNOs4rFOKvIvn6syRJeD1MBJNSvIlEODGgNQ6evM0SM6WGDBXGvpT2M
# 4Q==
# SIG # End signature block
