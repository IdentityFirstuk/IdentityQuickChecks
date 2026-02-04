<#
.SYNOPSIS
Bootstrap installer that downloads a release ZIP from a URL, verifies integrity and signatures,
and installs files to a target directory.

.DESCRIPTION
Designed for customers to install the read-only IFQC release from a website. It:
- Downloads the release ZIP
- Extracts to a temporary folder
- Verifies file SHA256 checksums using `SHA256SUMS.txt` included in the release
- Verifies Authenticode signatures for PowerShell scripts unless `-AllowUnsigned` is set
- Installs files to the requested install path

.PARAMETER ReleaseUrl
URL to the release ZIP (required).
.PARAMETER InstallPath
Destination folder. Defaults to `%ProgramFiles%\IdentityFirst\IFQC`.
.PARAMETER AllowUnsigned
If set, the installer will allow unsigned PowerShell files (useful for trusted internal builds).
.PARAMETER KeepStaging
If set, keep the temporary staging folder for inspection.

USAGE
pwsh -NoProfile -ExecutionPolicy Bypass -File .\installer\bootstrap_install.ps1 -ReleaseUrl "https://example.com/releases/IFQC-free-20260131.zip"
#
# SECURITY
# - Verify HTTPS URL and validate SHA256SUMS.txt before running any extracted scripts.
# - Prefer signed releases; do not set -AllowUnsigned in production environments.
#
#>

[param(
    [Parameter(Mandatory=$true)] [string]$ReleaseUrl,
    [string]$InstallPath = (Join-Path ${env:ProgramFiles} 'IdentityFirst\IFQC'),
    [switch]$AllowUnsigned,
    [switch]$KeepStaging,
    [switch]$VerifyCosign,
    [string]$RekorUrl = 'https://rekor.sigstore.dev'
)]

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Info { param($m) Write-Host "[INFO] $m" -ForegroundColor Cyan }
function Write-Success { param($m) Write-Host "[OK] $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Write-Err { param($m) Write-Host "[ERR] $m" -ForegroundColor Red }

# Prepare staging
$staging = Join-Path $env:TEMP ("ifqc_install_{0}" -f ([System.Guid]::NewGuid().ToString()))
New-Item -ItemType Directory -Path $staging | Out-Null
$zipPath = Join-Path $staging 'release.zip'

Write-Info "Downloading release: $ReleaseUrl"
try {
    Invoke-WebRequest -Uri $ReleaseUrl -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
} catch {
    Write-Err "Failed to download release: $($_.Exception.Message)"; exit 2
}

# Optionally verify cosign signature (keyless + Rekor). Do this BEFORE extraction.
if ($VerifyCosign) {
    Write-Info "Verifying cosign signature (keyless) against Rekor: $RekorUrl"
    $cosignExe = Join-Path $env:TEMP 'cosign.exe'
    if (-not (Test-Path $cosignExe)) {
        Write-Info "Downloading cosign to: $cosignExe"
        try {
            Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/sigstore/cosign/releases/latest/download/cosign-windows-amd64.exe' -OutFile $cosignExe -ErrorAction Stop
        } catch {
            Write-Err "Failed to download cosign: $($_.Exception.Message)"; exit 10
        }
    }

    try {
        $verifyOutput = & $cosignExe verify --keyless --rekor $RekorUrl $zipPath 2>&1
        Write-Output $verifyOutput
        if ($LASTEXITCODE -ne 0) {
            Write-Err "cosign verification failed (exit $LASTEXITCODE). Aborting install."; exit 11
        } else {
            Write-Success "cosign verification succeeded."
        }
    } catch {
        Write-Err "cosign verification failed: $($_.Exception.Message)"; exit 12
    }
}

Write-Info "Extracting release"
try {
    Expand-Archive -Path $zipPath -DestinationPath $staging -Force
} catch {
    Write-Err "Failed to extract release: $($_.Exception.Message)"; exit 3
}

# Locate SHA256SUMS.txt inside staging
$hashFile = Get-ChildItem -Path $staging -Filter 'SHA256SUMS.txt' -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $hashFile) {
    Write-Warn 'No SHA256SUMS.txt found in release; integrity cannot be verified.'
} else {
    Write-Info "Verifying checksums using: $($hashFile.FullName)"
    $lines = Get-Content -LiteralPath $hashFile.FullName -ErrorAction Stop
    $fail = $false
    foreach ($line in $lines) {
        if ($line -match '^([A-Fa-f0-9]{64})\s+(.+)$') {
            $expected = $matches[1]
            $rel = $matches[2].Trim()
            $path = Join-Path $staging $rel
            if (-not (Test-Path $path)) { Write-Err "Missing file listed in checksums: $rel"; $fail = $true; continue }
            $h = Get-FileHash -Path $path -Algorithm SHA256
            if ($h.Hash -ne $expected) { Write-Err "Checksum mismatch: $rel"; $fail = $true }
        }
    }
    if ($fail) { Write-Err 'Checksum verification failed.'; exit 4 } else { Write-Success 'All checksums verified.' }
}

# Verify Authenticode for scripts
$scriptFiles = Get-ChildItem -Path $staging -Include *.ps1,*.psm1 -Recurse -File -ErrorAction SilentlyContinue
if ($scriptFiles.Count -gt 0) {
    Write-Info "Verifying Authenticode signatures for $($scriptFiles.Count) script files"
    $unsigned = @()
    foreach ($f in $scriptFiles) {
        $sig = Get-AuthenticodeSignature -FilePath $f.FullName
        if ($sig.Status -ne 'Valid') { $unsigned += $f }
    }
    if ($unsigned.Count -gt 0) {
        if ($AllowUnsigned) {
            Write-Warn "Found $($unsigned.Count) unsigned or invalid-signed files; proceeding due to -AllowUnsigned."
        } else {
            Write-Err "Found $($unsigned.Count) unsigned or invalid-signed files. Aborting install."
            foreach ($u in $unsigned) { Write-Err " - $($u.FullName)" }
            exit 5
        }
    } else { Write-Success 'All PowerShell scripts are Authenticode-signed and valid.' }
}

# Install files
Write-Info "Installing to: $InstallPath"
try {
    if (-not (Test-Path $InstallPath)) { New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null }
    # copy extracted root contents (excluding SHA256SUMS.txt)
    Get-ChildItem -Path $staging -Recurse -File | ForEach-Object {
        $rel = $_.FullName.Substring($staging.Length).TrimStart('\\','/')
        if ($rel -ieq 'SHA256SUMS.txt') { return }
        $dest = Join-Path $InstallPath $rel
        $dedir = Split-Path -Parent $dest
        if (-not (Test-Path $dedir)) { New-Item -ItemType Directory -Path $dedir -Force | Out-Null }
        Copy-Item -LiteralPath $_.FullName -Destination $dest -Force
    }
} catch {
    Write-Err "Install failed: $($_.Exception.Message)"; exit 6
}

Write-Success "Installed files to $InstallPath"

if (-not $KeepStaging) {
    try { Remove-Item -Path $staging -Recurse -Force -ErrorAction SilentlyContinue } catch {}
} else { Write-Info "Kept staging folder: $staging" }

Write-Success 'Installation complete.'
exit 0

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAqhNtoOA0mByB+
# sqBr9udD6gnCrTxMtiyFQ8wvEQDBrqCCFlIwggMUMIIB/KADAgECAhBDR0HvMFNE
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgaNeDQcaWHTzAUW1oytv55duaRYAnCUGMFMh+
# koU8oYIwDQYJKoZIhvcNAQEBBQAEggEAkT0OrBKL22Oh3POoOIWDkJq8yQWWqjCg
# S/to3Pomzc/A+UBK6jlq2J3qfml95Jgr512t3+KMDdl8aAGdEXtthIpGzBFJJZJk
# n42lS0Q+fH8s7zhIDo2pdPWwW4j8rDumjYsijy0/uvUfWLi0DQe/ISfa9slTbsrR
# JHW++auHqAhYys3PoaTDCU7zSk65AgxQq6DWMFMN6lX24vGrE/zgus2ReJ9IaQ3e
# l7Lh6Q6IP08XXobIxIu/qBRxVn6EzDxaRfdMuP5nuSFnQ1x3j4E45wIsR/o0AANk
# IogFycEUo7hgeAUzbMVDYJUAdgja67x05Ad5hjShUzhtvWwIuaCmaaGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjAyMDQxNjUyMjBaMC8GCSqGSIb3DQEJBDEiBCAh
# Nt9FHjVxuFj3Hdbi/ANZk0aSgsYK9ad1NM+u5tNk1zANBgkqhkiG9w0BAQEFAASC
# AgBJlYDUOT8pvtDstFs9OO9k8T8VHQxwbgP3a+4+XL6ayjKJCDE0dR2w0XLKtIw7
# ONzSdBKSctedVX174obJy3fNKcdstR99m/ImgyBa7uVhMLZF0xZE0Te3kxUf+iQx
# BKtAVybZXXw2XPebvrGoHmGLDJCbBy/EIcPSyRvTn3yOnpFFDNqB9Zj5wqQ6ovUU
# U6O6Jsa3p2SKivQV8SJslr6bQp5Ap+i4pSE1O/iVq9gNaZc1NR/Eb/IsZNmtHXfS
# C1lSW/nT9WiCSUqP4zhfMsy2QS3W6M2nIN2nifaxjCArUVKSCfhvkwFi//n0LWyJ
# DdFCdl1jMaeW5F5BEw+gYReXB3h2Vnxvo00tj2WYnGzxk8yj35Uqpbbn3klUNLcF
# 0urQYgDA3Xs/3bvPtZJRywFl8my2SSGK4N6SuzmW3KV6MkhuHzCk6vXOgiCOI4SR
# W+egft3aM+ni7xeR1vNuNl+FGHqC+unY/WCGtV7nO3lpPyP3Zlphvmqfn0CdSG6V
# zhz1GR8gFEm9YFg3j37GwZ+f9TvA3Ysl9clm18VSQRiCFeXaDc/lroHNxVyg8v1x
# Br259Sax/UcVoHkE6loPadfGm9k1Mc6GqEkdO06KoatJWHaeZ6si/r4kk7J3TsmM
# O51Zb0QUW50O2Ac9+CQ5mL65PkI1NWGJS6xxsFKDy0fuJw==
# SIG # End signature block
