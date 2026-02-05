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
# IdentityFirst Maximum Security Self-Signed Certificate Generator
# Creates 4096-bit RSA certificate with SHA-256 for strongest PowerShell signing

param(
    [System.Security.SecureString]$CertPassword,
    [int]$CertYears = 3,
    [switch]$ReSignOnly = $false
)

$ErrorActionPreference = "Stop"
$CertSubject = "CN=IdentityFirst Code Signing, O=IdentityFirst Ltd, L=Northumberland, C=GB"
$CertFriendlyName = "IdentityFirst Code Signing Certificate (4096-bit RSA + SHA-256)"
$ScriptsPath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

function Write-Header {
    param([string]$Message)
    Write-Output ""
    Write-Output ("=" * 70)
    Write-Output " $Message"
    Write-Output ("=" * 70)
    Write-Output ""
}

function Write-Step {
    param([string]$Message)
    Write-Output "[+] $Message"
}

function Write-Security {
    param([string]$Message)
    Write-Output "[🔒] $Message"
}

function Write-Warning {
    param([string]$Message)
    Write-Output "[!] $Message"
}

function Write-Error {
    param([string]$Message)
    Write-Output "[X] $Message"
}

# Display security settings
Write-Header "IdentityFirst Maximum Security Certificate Generator"

Write-Security "Security Configuration:"
Write-Output "  Key Algorithm:    RSA (4096-bit) - Maximum strength"
Write-Output "  Hash Algorithm:   SHA-256 - Industry standard"
Write-Output "  Key Usage:        Digital Signature only"
Write-Output "  EKU:              Code Signing (1.3.6.1.5.5.7.3.3)"
Write-Output "  Validity:         $CertYears years"
Write-Output ""

# Step 1: Create self-signed certificate
if (-not $ReSignOnly) {
    Write-Step "Checking for existing certificate..."
    $existingCert = Get-ChildItem -Path "Cert:\CurrentUser\My" | Where-Object { $_.Subject -eq $CertSubject }

    if ($existingCert) {
        Write-Warning "Certificate already exists!"
        Write-Output "  Thumbprint:       $($existingCert.Thumbprint)"
        Write-Output "  Not After:        $($existingCert.NotAfter)"
        Write-Output "  Key Size:         $($existingCert.PublicKey.Key.KeySize) bits"

        $confirm = Read-Host "Replace existing certificate? (y/n)"
        if ($confirm -ne 'y' -and $confirm -ne 'Y') {
            Write-Output "Using existing certificate..."
            $cert = $existingCert
        } else {
            Write-Step "Removing existing certificate..."
            $existingCert | Remove-Item -Force
            Write-Step "Creating new certificate..."
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
        Write-Step "Creating new 4096-bit RSA certificate..."
        $cert = New-SelfSignedCertificate `
            -Type CodeSigningCert `
            -Subject $CertSubject `
            -KeyUsage DigitalSignature `
            -FriendlyName $CertFriendlyName `
            -CertStoreLocation "Cert:\CurrentUser\My" `
            -NotAfter (Get-Date).AddYears($CertYears) `
            -KeyLength 4096
    }

    Write-Security "Certificate Details:"
    Write-Output "  Thumbprint:       $($cert.Thumbprint)"
    Write-Output "  Key Size:         $($cert.PublicKey.Key.KeySize) bits"
    Write-Output "  Algorithm:        $($cert.SignatureAlgorithm)"
    Write-Output "  Not Before:       $($cert.NotBefore)"
    Write-Output "  Not After:        $($cert.NotAfter)"
    Write-Output ""

    # Step 2: Export PFX with strong encryption
    Write-Step "Exporting to PFX with AES-256 encryption..."
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
    Write-Step "PFX exported: $pfxPath"

    # Step 3: Export public certificate
    Write-Step "Exporting public certificate (CER)..."
    $cerPath = Join-Path $ScriptsPath "identityfirst-codesign.cer"
    Export-Certificate -Cert $cert -FilePath $cerPath -Force | Out-Null
    Write-Step "CER exported: $cerPath"
}

# Step 4: Find and sign scripts
Write-Header "Signing PowerShell Scripts"

$signableExtensions = @('.ps1', '.psm1')
$signingScripts = @()

Get-ChildItem -Path $ScriptsPath -Recurse -File | ForEach-Object {
    if ($signableExtensions -contains $_.Extension.ToLower()) {
        $signingScripts += $_.FullName
    }
}

Write-Step "Found $($signingScripts.Count) scripts to sign"
Write-Security "Using SHA-256 for all signatures"
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
Write-Header "Signing Complete"

Write-Output "  Total scripts:   $($signingScripts.Count)"
Write-Output "  Signed:          $signCount"
Write-Output "  Already signed:  $skipCount"
Write-Output "  Errors:          $errorCount"
Write-Output ""

Write-Security "Certificate Security:"
Write-Output "  Algorithm:       RSA 4096-bit + SHA-256"
Write-Output "  Encryption:      AES-256 for PFX export"
Write-Output "  Timestamp:       Included (DigiCert)"
Write-Output ""

if (-not $ReSignOnly) {
    Write-Step "Files created:"
    Write-Output "  - identityfirst-codesign.pfx"
    Write-Output "    (KEEP SECURE - contains private key)"
    Write-Output "  - identityfirst-codesign.cer"
    Write-Output "    (safe to share with clients)"
    Write-Output ""

    Write-Warning "SECURITY RECOMMENDATIONS:"
    Write-Output "  1. Store PFX on encrypted drive"
    Write-Output "  2. Use strong password (change default)"
    Write-Output "  3. Limit access to authorized personnel only"
    Write-Output "  4. Rotate certificate annually"
    Write-Output "  5. Revoke and recreate if compromised"
    Write-Output ""

    Write-Output "To re-sign scripts in future:"
    Write-Output "  .\Create-SelfSignedCert.ps1 -ReSignOnly"
}

Write-Output ""
Write-Output "To verify signatures:"
Write-Output "  Get-AuthenticodeSignature .\scripts\*.ps1 | Format-Table Path, Status, SignerCertificate -Auto"

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA5Nr5JOQAhcvz0
# OHNVPgu3Zg0sp+8s+Q6hfw1qOO6L26CCFlIwggMUMIIB/KADAgECAhBDR0HvMFNE
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgMU25A6q1w7HGhx/7Tl7R6XqXkXr5jQ71ktVz
# 7MZ/KG8wDQYJKoZIhvcNAQEBBQAEggEAoZ4bVqJUDC6bc7i8zMHVoh4QsWJFjBw9
# n9asPBFkSKyw+Gb1w6297dmgevySC3y2Ggq+woxXFFzDwLFhEiFxsrNt/R4xxHNo
# 2Dd/EDRTfg9DacImqHnLkOC9kQ2O784nHrF9KHc15ZBddH00v9gR3NoaWdPi+RJF
# ShRbeIQL95dMLp8YMgIwDlEagCJWtTsdY60oGZw/IV06GzOUSLNo7PC0FPFaWIoW
# Q9XMSHMOlprEojFoIyvb263laN+o6OrFRFiIrVY3MIduzhe0OH6MfHaHHPUVRvYR
# K1JV1bGp4vENhIu35AMlz4866XnM6DZxWt8gdZiKhqgeOdUIWE9sgKGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjAyMDQxNjUyMDdaMC8GCSqGSIb3DQEJBDEiBCD2
# FZP4K7XYDVFsr/rAGr+H2tjHFJ9iDp/Uy8u651K2XzANBgkqhkiG9w0BAQEFAASC
# AgBf2pT3s/f9XtEMem2z2SIee1dW3wtOGXJ9DqyIa9bX7XXxNleoNfXqVErdTxtu
# nSQT+1Z+hS1iJkGclvHvkMyq/jcFgQ4CVAdPCR+f3WWYOdkfenHL+Ft/jjt4Gtkm
# ChCY+hN+Fs5CwfP7eTNdKODkEuECEqc3FdzPYB8puEzeL/fEak2M7xioAiPA2hcu
# 2g68AGWWuRjigvM6btPmVmMwoWh5kupNDdUz5WS07D9+R5HTX1LXxvadCEgEQg4s
# QLw61WA9eQLidES9Amm6Jh/ZYcDl00rkglnDuwrb2zhy8qHGaN1yO6rdkuUNMoIp
# XBt0qTm0W9DL5UFA70lCWpRJ95ZYnIOaDzbbCrQUijxPoqvVKXllxWxr6+iJzOcs
# O3rbWRo+ZpOuOp7V0vqDAN1JQKXX/CI2xCErLKaoy1oahSAwv+0us9QJSSfijk/G
# CS+E8EUaBcmGXp5/NNUSjDJ+DyDgNo4I81XbjLtS5LqAlGF4i85HxZPEEzxaXs+P
# 4P5FBj6kSLVWFMz96wQ58vR0uFhZ4QaE3s8Y5GmxFok7yXHH2AVby3cHFQ3ePwwA
# QJUiAasAE0fXdS9yRjItjWPpHowFhdqkHO7zuWzsdxJfhFMMlwednL2tajCaZX93
# X0V0YpItKhj0CG7aIY66KqYioTXMiwGbx+SgrkV+Dh3h1A==
# SIG # End signature block
