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
#!/usr/bin/env pwsh
# IdentityFirst Maximum Security Self-Signed Certificate Generator
# Developer helper — creates 4096-bit RSA certificate for local code signing
# THIS SCRIPT IS FOR MAINTAINERS ONLY. Do NOT distribute this script
# or any generated private keys (PFX) to customers or include in production
# packages. It is intended for local development and testing.

param(
    [System.Security.SecureString]$CertPassword,
    [int]$CertYears = 3,
    [switch]$ReSignOnly = $false
)

$ErrorActionPreference = "Stop"
$CertSubject = "CN=IdentityFirst Code Signing, O=IdentityFirst Ltd, L=Northumberland, C=GB"
$CertFriendlyName = "IdentityFirst Code Signing Certificate (4096-bit RSA + SHA-256)"
$ScriptsPath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

function IFQCWriteHeader {
    param([string]$Message)
    Write-Output ""
    Write-Output ("=" * 70)
    Write-Output " $Message"
    Write-Output ("=" * 70)
    Write-Output ""
}

function IFQCWriteStep {
    param([string]$Message)
    Write-Output "[+] $Message"
}

function IFQCWriteSecurity {
    param([string]$Message)
    Write-Output "[🔒] $Message"
}

function IFQCWriteWarning {
    param([string]$Message)
    Write-Warning "[IFQC] $Message"
}

function IFQCWriteError {
    param([string]$Message)
    Write-Error "[IFQC] $Message"
}

# Display security settings
IFQCWriteHeader "IdentityFirst Maximum Security Certificate Generator"

IFQCWriteSecurity "Security Configuration:"
Write-Output "  Key Algorithm:    RSA (4096-bit) - Maximum strength"
Write-Output "  Hash Algorithm:   SHA-256 - Industry standard"
Write-Output "  Key Usage:        Digital Signature only"
Write-Output "  EKU:              Code Signing (1.3.6.1.5.5.7.3.3)"
Write-Output "  Validity:         $CertYears years"
Write-Output ""

# Step 1: Create self-signed certificate
if (-not $ReSignOnly) {
    IFQCWriteStep "Checking for existing certificate..."
    $existingCert = Get-ChildItem -Path "Cert:\CurrentUser\My" | Where-Object { $_.Subject -eq $CertSubject }

    if ($existingCert) {
        IFQCWriteWarning "Certificate already exists!"
        Write-Output "  Thumbprint:       $($existingCert.Thumbprint)"
        Write-Output "  Not After:        $($existingCert.NotAfter)"
        Write-Output "  Key Size:         $($existingCert.PublicKey.Key.KeySize) bits"

        $confirm = Read-Host "Replace existing certificate? (y/n)"
        if ($confirm -ne 'y' -and $confirm -ne 'Y') {
            Write-Output "Using existing certificate..."
            $cert = $existingCert
        } else {
            IFQCWriteStep "Removing existing certificate..."
            $existingCert | Remove-Item -Force
            IFQCWriteStep "Creating new certificate..."
            $cert = New-SelfSignedCertificate `
                -Type CodeSigningCert `
                -Subject $CertSubject `
                -KeyUsage DigitalSignature `
                -FriendlyName $CertFriendlyName `
                -CertStoreLocation "Cert:\CurrentUser\My" `
                -NotAfter (Get-Date).AddYears($CertYears) `
                -KeyLength 4096
        }
    } else {
        IFQCWriteStep "Creating new 4096-bit RSA certificate..."
        $cert = New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject $CertSubject `
            -KeyUsage DigitalSignature `
            -FriendlyName $CertFriendlyName `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -NotAfter (Get-Date).AddYears($CertYears) `
            -KeyLength 4096
    }

    IFQCWriteSecurity "Certificate Details:"
    Write-Output "  Thumbprint:       $($cert.Thumbprint)"
    Write-Output "  Key Size:         $($cert.PublicKey.Key.KeySize) bits"
    Write-Output "  Algorithm:        $($cert.SignatureAlgorithm)"
    Write-Output "  Not Before:       $($cert.NotBefore)"
    Write-Output "  Not After:        $($cert.NotAfter)"
    Write-Output ""

    # Step 2: Export PFX with strong encryption
    IFQCWriteStep "Exporting to PFX with AES-256 encryption..."
    if (-not $CertPassword) {
        # For developer convenience: if the IFQC_DEV_PFX_PASSWORD env var is set,
        # use it (converted to SecureString). This keeps the script secure for
        # customers while allowing faster local/dev runs when needed.
        if ($env:IFQC_DEV_PFX_PASSWORD) {
            try {
                # Build SecureString from developer-provided env var without using ConvertTo-SecureString -AsPlainText
                $devPwd = $env:IFQC_DEV_PFX_PASSWORD
                $ss = New-Object System.Security.SecureString
                foreach ($ch in $devPwd.ToCharArray()) { $ss.AppendChar($ch) }
                $ss.MakeReadOnly()
                $CertPassword = $ss
                Write-Output "Using developer PFX password from IFQC_DEV_PFX_PASSWORD (hidden)."
            } catch {
                $CertPassword = Read-Host "Enter password to protect the exported PFX (input hidden)" -AsSecureString
            }
        } else {
            $CertPassword = Read-Host "Enter password to protect the exported PFX (input hidden)" -AsSecureString
        }
    }
    $pfxPath = Join-Path $ScriptsPath "identityfirst-codesign.pfx"
    Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $CertPassword -CryptoAlgorithm AES256_AES -Force | Out-Null
    IFQCWriteStep "PFX exported: $pfxPath"

    # Step 3: Export public certificate
    IFQCWriteStep "Exporting public certificate (CER)..."
    $cerPath = Join-Path $ScriptsPath "identityfirst-codesign.cer"
    Export-Certificate -Cert $cert -FilePath $cerPath -Force | Out-Null
    IFQCWriteStep "CER exported: $cerPath"
}

# Step 4: Find and sign scripts
IFQCWriteHeader "Signing PowerShell Scripts"

$signableExtensions = @('.ps1', '.psm1')
$signingScripts = @()

Get-ChildItem -Path $ScriptsPath -Recurse -File | ForEach-Object {
    if ($signableExtensions -contains $_.Extension.ToLower()) {
        $signingScripts += $_.FullName
    }
}

IFQCWriteStep "Found $($signingScripts.Count) scripts to sign"
IFQCWriteSecurity "Using SHA-256 for all signatures"
Write-Output ""

# Step 5: Sign all scripts
$signCount = 0
$skipCount = 0
$errorCount = 0

foreach ($scriptPath in $signingScripts) {
    try {
        $scriptName = Split-Path -Leaf $scriptPath
        $relativePath = $scriptPath.Replace($ScriptsPath, "").TrimStart("\/")

        # Check if already signed
        $signature = Get-AuthenticodeSignature -FilePath $scriptPath
        if ($signature.Status -eq 'Valid') {
            Write-Output "  [=] $relativePath"
            $skipCount++
            continue
        }

        # Sign the script
        if (-not $ReSignOnly) {
            Set-AuthenticodeSignature -FilePath $scriptPath -Certificate $cert -HashAlgorithm SHA256 -TimestampServer "http://timestamp.digicert.com" | Out-Null
        } else {
            $pfxPath = Join-Path $ScriptsPath "identityfirst-codesign.pfx"
            if (Test-Path $pfxPath) {
                if (-not $CertPassword) {
                    if ($env:IFQC_DEV_PFX_PASSWORD) {
                        try {
                            $devPwd = $env:IFQC_DEV_PFX_PASSWORD
                            $ss = New-Object System.Security.SecureString
                            foreach ($ch in $devPwd.ToCharArray()) { $ss.AppendChar($ch) }
                            $ss.MakeReadOnly()
                            $CertPassword = $ss
                        } catch {
                            $CertPassword = Read-Host "Enter password for PFX used for re-signing (input hidden)" -AsSecureString
                        }
                    } else {
                        $CertPassword = Read-Host "Enter password for PFX used for re-signing (input hidden)" -AsSecureString
                    }
                }

                try {
                    $cert = Get-PfxCertificate -FilePath $pfxPath -Password $CertPassword -ErrorAction Stop
                } catch {
                    # fallback: try without password (some PFX may be unprotected)
                    $cert = Get-PfxCertificate -FilePath $pfxPath -ErrorAction Stop
                }

                Set-AuthenticodeSignature -FilePath $scriptPath -Certificate $cert -HashAlgorithm SHA256 -TimestampServer "http://timestamp.digicert.com" | Out-Null
            } else {
                throw "PFX not found: $pfxPath"
            }
        }

        Write-Output "  [+] $relativePath"
        $signCount++
    }
    catch {
        Write-Output "  [X] $(Split-Path -Leaf $scriptPath): $($_.Exception.Message)"
        $errorCount++
    }
}

# Step 6: Summary
IFQCWriteHeader "Signing Complete"

Write-Output "  Total scripts:   $($signingScripts.Count)"
Write-Output "  Signed:          $signCount"
Write-Output "  Already signed:  $skipCount"
Write-Output "  Errors:          $errorCount"
Write-Output ""

IFQCWriteSecurity "Certificate Security:"
Write-Output "  Algorithm:       RSA 4096-bit + SHA-256"
Write-Output "  Encryption:      AES-256 for PFX export"
Write-Output "  Timestamp:       Included (DigiCert)"
Write-Output ""

if (-not $ReSignOnly) {
    IFQCWriteStep "Files created:"
    Write-Output "  - identityfirst-codesign.pfx"
    Write-Output "    (KEEP SECURE - contains private key)"
    Write-Output "  - identityfirst-codesign.cer"
    Write-Output "    (safe to share with clients)"
    Write-Output ""

    IFQCWriteWarning "SECURITY RECOMMENDATIONS:"
    Write-Output "  1. Store PFX on encrypted drive"
    Write-Output "  2. Use strong password (change default)"
    Write-Output "  3. Limit access to authorized personnel only"
    Write-Output "  4. Rotate certificate annually"
    Write-Output "  5. Revoke and recreate if compromised"
    Write-Output ""

    Write-Output "To re-sign scripts in future:"
    Write-Output "  .\dev-tools\Create-SelfSignedCert.ps1 -ReSignOnly"
}

Write-Output ""
Write-Output "To verify signatures:"
Write-Output "  Get-AuthenticodeSignature .\scripts\*.ps1 | Format-Table Path, Status, SignerCertificate -Auto"

# SIG # Begin signature block
# MIIf3QYJKoZIhvcNAQcCoIIfzjCCH8oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB7DStq0kQOuhE7
# FDOZeL8pzz+LeJHE3AInPTOxdb8UJqCCGNwwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# AgEVMC8GCSqGSIb3DQEJBDEiBCAO6mBtse0tIrxtcqs3w50wcCbMu1HR8wZLSfu4
# 0lT3JzANBgkqhkiG9w0BAQEFAASCAgBQUEzw57FbODBArUzrLZywdNEsPj6caVV8
# KbHUDmsHxS5cKuxuZFqRBa4zQs1AtKHGP4qZEmVapKdAjPX8Z4QHY+lONTusMb7d
# 3CjIeTCSlL6/N+Ji446F+FzKAq4WHTY3dRKQvJGGr5FlBmgPVJ7DEJdcA/xRfdg2
# kyDLAKaZ29M94q58uoUWzHwL+vjfRiUOSW/f0NDk1rl2QB93esVYEZUoM5gCA2Kq
# jrfLl16HlfPjhAfPPsrIJJem4IR+vR1dYow7B+nPfO6utwc5Iv1c7p5xh3SLvWpI
# X9kDzydNXLff51niFhUfz4Qm7En3MvlnainTJOJdRjnEWVS+fFfGYlBxLOkIJf/1
# XbhRAGE/YL+xfyVcJrPEOCDiCCqMQ+4alH1EbL5PztLvmigMGCmBHtrTqeMmdcUa
# 0JcEvQ48Up8nbrtPhiM3mIud8FFKmgkyA7MHeI/XSr9nJgE0BaqDrPkesZ5ybhmi
# d63Ack9UzwmEPdZHTiAAEUicV0MkFZ/o9goKS0pYUzCQXai7N/p53hFZIEb84DxN
# PeabDW8Uwf8J8YmIsQ8UaHPkTd5H1iMX7BXMx5f4HXgJp5hEsj0Vjf4jFjYj2c9b
# vg7thgWMm78k9jDcbLMh+xtCUuMzteW5/JsZKN8FHnJ3GY4fnMN+S4DtNStDJZ9/
# uq+M6I2ShKGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAyMDUxNzEzMTRaMC8G
# CSqGSIb3DQEJBDEiBCD9uu86E9M3qPwk0cQV6LvK6tEJbbV0+8mClleIefqfKzAN
# BgkqhkiG9w0BAQEFAASCAgAljuX2ZvBY/EwQ+ftdFPfxHd2jDFxKglIBxUliJ2D+
# ur2p8wJDhnw403+yqAqkwGzECoho9Faex8q+odckimOJnRNwRyVEeU16Tbu6C+qP
# 630ii4LOVpVaWBpM/MMaS47OT8geF6cr6wJiSom7c+ZXEVhr+cWUjd1hHAdYVR0n
# JNa/MsbTIQc3OSzDcJ6ex4xHCuG8+bRX8UPMhPaNrYJxeNd6mPUpalwHEaKaQC8L
# t5+g8NyyI1SlHnEZB/ljJApOPkPwjA3ifSvOBaO1gnerP2tSD9UlSRmwvWKCKtOM
# iLQBGUsroENw3oELegDZ79FsAMUh1Cq5OxgGuvpXyyX7bJHqNgEztjK9HFOtpjPr
# ZdDUahMY7iQfa67nE3HSVbOvWEbFzPQbyyM04sNTxvmhyDzfRh/TF66DL5gCc5ug
# INj/UzW9167TnJhNEtHE7+LS+zRnkSlJiHetz7BJym0OZFtB8q9XYPFIbBZV1Fqa
# pHYTh2HcN41gY83i079ApQ3Qmyd26s6r3SIWPDoJCGuKbrmYSZmGjbwYM2oq0PEN
# FN8N7wNhVP8S8ogVs2j/d1WxSEeJnnj+3COW6UOsgc4J1RCY4WQmmAKHx8i7U6NM
# mtpkkfIeLrlgCUqcdIYxIxwXZgbc8AdA9UJJlboKe3qOQziW/S5pRK3rjdbigaVB
# 8Q==
# SIG # End signature block
