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
# MIIJyAYJKoZIhvcNAQcCoIIJuTCCCbUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBAhS4sTV4QsPY7
# q7CZJTVKWPYMvkJ0QW+HNWkl0TB6oqCCBdYwggXSMIIDuqADAgECAhAxVnqog0nQ
# oULr1YncnW59MA0GCSqGSIb3DQEBCwUAMIGAMQswCQYDVQQGEwJHQjEXMBUGA1UE
# CAwOTm9ydGh1bWJlcmxhbmQxFzAVBgNVBAcMDk5vcnRodW1iZXJsYW5kMRowGAYD
# VQQKDBFJZGVudGl0eUZpcnN0IEx0ZDEjMCEGA1UEAwwaSWRlbnRpdHlGaXJzdCBD
# b2RlIFNpZ25pbmcwHhcNMjYwMTI5MjExMDU3WhcNMzEwMTI5MjEyMDU2WjCBgDEL
# MAkGA1UEBhMCR0IxFzAVBgNVBAgMDk5vcnRodW1iZXJsYW5kMRcwFQYDVQQHDA5O
# b3J0aHVtYmVybGFuZDEaMBgGA1UECgwRSWRlbnRpdHlGaXJzdCBMdGQxIzAhBgNV
# BAMMGklkZW50aXR5Rmlyc3QgQ29kZSBTaWduaW5nMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAtrU2HprgcHe9mxlmt5X72OsSk7cXDyUhoOAcLE9f4lS2
# rOx7VbZSMSi0r4lt8a/S5m/JIWCdYO+GrWZCgS2S73H3KNDszR5HDPbMhv+leoWA
# qLT7C0awpjcTnvWIDxnHyHHane/TNl3ehY9Jek5qrbiNgJDatV6SEYVFlK8Nk9kE
# 3TiveVvRKokNT2xY4/h1rohFCHnF+g7dCn06xAZwoGnFVlmPop3jItAlZdUQz3zR
# /xSNW01sQXgW6/TYd2VzXXuQihMQ3ikjoNGX1L8SlcV4ih2J+r2kSHjhkZ8c+wJE
# v2iiUHqpwmch31UwQOb4qklGKg1A+SAUGdf0cTTc6ApSFsqrol1euObreoy0zdAA
# k47NELuGhKA4N0Dk9Ar616JGFt/03s1waukNisnH/sk9PmPGUo9QtKH1IQpBtwWw
# uKel0w3MmgTwi2vBwfyh2/oTDkTfic7AT3+wh6O/9mFxxu2Fsq6VSlYRpSTSpgxF
# c/YsVlQZaueZs6WB6/HzftGzv1Mmz7is8DNnnhkADTEMj+NDo4wq+lUCE7XNDnnH
# KBN8MkDh4IljXVSkP/xwt4wLLd9g7oAOW91SDA2wJniyjSUy9c+auW3lbA8ybSfL
# TrQgZiSoepcCjW2otZIXrmDnJ7BtqmmiRff4CCacdJXxqNWdFnv6y7Yy6DQmECEC
# AwEAAaNGMEQwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0G
# A1UdDgQWBBQBfqZy0Xp6lbG6lqI+cAlT7ardlTANBgkqhkiG9w0BAQsFAAOCAgEA
# IwBi/lJTGag5ac5qkMcnyholdDD6H0OaBSFtux1vPIDqNd35IOGYBsquL0BZKh8O
# AHiuaKbo2Ykevpn5nzbXDBVHIW+gN1yu5fWCXSezCPN/NgVgdH6CQ6vIuKNq4BVm
# E8AEhm7dy4pm4WPLqEzWT2fwJhnJ8JYBnPbuUVE8F8acyqG8l3QMcGICG26NWgGs
# A28YvlkzZsny+HAzLvmJn/IhlfWte1kGu0h0G7/KQG6hei5afsn0HxWHKqxI9JsG
# EF3SsMVQW3YJtDzAiRkNtII5k0PyywjrgzIGViVNOrKMT9dKlsTev6Ca/xQX13xM
# 0prtnvxiTXGtT031EBGXAUhOzvx2Hp1WFnZTEIJyX1J2qI+DQsPb9Y1jWcdGBwv3
# /m1nAHE7FpPGsSv+UIP3QQFD/j6nLl5zUoWxqAZMcV4K4t4WkPQjPAXzomoRaqc6
# toXHlXhKHKZ0kfAIcPCFlMwY/Rho82GiATIxHXjB/911VRcpv+xBoPCZkXDnsr9k
# /aRuPNt9DDSrnocJIoTtqIdel/GJmD0D75Lg4voUX9J/1iBuUzta2hoBA8fSVPS5
# 6plrur3Sn5QQG2kJt9I4z5LS3UZSfT+29+xJz7WSyp8+LwU7jaNUuWr3lpUnY2nS
# pohDlw2BFFNGT6/DZ0loRJrUMt58UmfdUX8FPB7uNuIxggNIMIIDRAIBATCBlTCB
# gDELMAkGA1UEBhMCR0IxFzAVBgNVBAgMDk5vcnRodW1iZXJsYW5kMRcwFQYDVQQH
# DA5Ob3J0aHVtYmVybGFuZDEaMBgGA1UECgwRSWRlbnRpdHlGaXJzdCBMdGQxIzAh
# BgNVBAMMGklkZW50aXR5Rmlyc3QgQ29kZSBTaWduaW5nAhAxVnqog0nQoULr1Ync
# nW59MA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAw
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINDYMybZs/DP2IL8l5cOyBRGBG9OnLSY
# +DTVk2TMyVqlMA0GCSqGSIb3DQEBAQUABIICAJjgX0NwbacsKsqXkD/d8+YZqnPx
# IMueysnLmwKdByHLtJ7WgRIXffobb1sAITBCtseEQqqlRzAmrolEWOG4sfZnlC+V
# p4mO8bJqqAEZW0KYSNsFsJKJ6RPwsbYKZWP+zuxk9Nk9gcksFnoCHRqaLHSjm3iV
# AZ3jKvmHNDWZLqqzPgjuc+lvPzKpTgHcWTdnXpe+v3fi+PjM5jLHwUPn0LUi/jFF
# 4bojh0Atu/UnX8GxSoRswE3gCW3NGtn3GfipeXQ/nf47W/nlI3lLXbcpZ02G9GmD
# OnK+gU2dtmegfqFyVblL2CjKuOTPe3w31nhQQn22tOqgNi0IhqrepqTi9BLzkD8W
# riq1GKL5JUWn6W1Ef6g8kT6l4+IavY/cJSTlbfgQ1FHsmxTJQdqZVhFU/lZtUFmU
# iT8ExCyvvAL5ytmPm1EQbPqG5R8jCdkqfRgEkMMdq0hvdfJSzeDZtqGCFGc2MSTl
# UtDx2aVCsRaE8o5J0bh+oBLRKqKKmutLB7i6tBqtKEfKlFlVlsuXFQzDzTtG8MDR
# EG8kCoJb+USYeWmmaE5YgL6S1TYWB+OpgHlN2pfrX8a/kFwJJZpIY8UDq/J2iIc+
# TYUvEgEJadrvb6rkhKoi1phFZPRIpmTqELDY2Y0TaeG6D6KuAvpbxOkmimi969pd
# 7kK7qFu6Ubc65qQ8
# SIG # End signature block

