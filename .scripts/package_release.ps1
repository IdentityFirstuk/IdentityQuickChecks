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
param(
    [switch]$HtmlOnly,
    [string]$OutputRoot = "releases",
    [string]$SignPfxPath = $null,
    [string]$SignPfxPassword = $null,
    [switch]$UseVaultSecret,
    [string]$VaultSecretPath = $null,
    [string]$VaultAddr = $env:VAULT_ADDR,
    [string]$VaultToken = $env:VAULT_TOKEN,
    [switch]$DeleteTempPfx
    ,[switch]$UseCosign
    ,[string]$RekorUrl = 'https://rekor.sigstore.dev'
)

# Default to HTML-only release unless caller explicitly passed -HtmlOnly:$false
if (-not $PSBoundParameters.ContainsKey('HtmlOnly')) { $HtmlOnly = $true }

# If running in GitHub Actions and UseCosign was not explicitly set, enable it by default
if (-not $PSBoundParameters.ContainsKey('UseCosign')) {
    if ($env:GITHUB_ACTIONS -and $env:GITHUB_ACTIONS -eq 'true') { $UseCosign = $true }
}

Set-StrictMode -Version Latest

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Resolve-Path "$scriptRoot\.."

# read version
$versionFile = Join-Path $repoRoot 'VERSION.txt'
if (-not (Test-Path $versionFile)) { $version = (Get-Date -Format yyyyMMdd) } else { $version = (Get-Content $versionFile -ErrorAction SilentlyContinue | Select-Object -First 1).Trim() }

$releaseName = "IFQC-free-$version"
$temp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP $releaseName) -Force

Write-Output "Preparing release folder: $($temp.FullName)"

# Files/folders to include
$include = @(
    'IdentityHealthCheck.ps1',
    'Identity-Audit-Engine.ps1',
    'tools',
    'Module',
    'Shared',
    'Checks',
    'collectors',
    'dotnet',
    'config',
    'docs',
    'VERSION.txt',
    'README-Free.md',
    'EULA.txt',
    'README.md'
)

foreach ($item in $include) {
    $src = Join-Path $repoRoot $item
    if (Test-Path $src) {
        Write-Output "Copy: $item"
        Copy-Item -Path $src -Destination $temp.FullName -Recurse -Force
    }
}

# Ensure fixer scripts are not included
$fixerPaths = @( Join-Path $temp.FullName '.scripts' )
foreach ($p in $fixerPaths) { if (Test-Path $p) { Remove-Item -Path $p -Recurse -Force } }

if ($HtmlOnly) {
    Write-Output "Removing JSON artifacts for HTML-only release"
    Get-ChildItem -Path $temp.FullName -Include *.json -Recurse -Force | Remove-Item -Force
}

# Generate SHA256 checksums for release files (free verification method)
Write-Output "Generating SHA256SUMS.txt"
$hashLines = @()
Get-ChildItem -Path $temp.FullName -Recurse -File | ForEach-Object {
    $full = $_.FullName
    # compute relative path under temp folder
    if ($full.StartsWith($temp.FullName, [System.StringComparison]::OrdinalIgnoreCase)) {
        $rel = $full.Substring($temp.FullName.Length).TrimStart('\','/')
    } else {
        $rel = Split-Path -Leaf $full
    }
    $h = Get-FileHash -Path $full -Algorithm SHA256
    $hashLines += "$($h.Hash)  $rel"
}
$hashFile = Join-Path $temp.FullName 'SHA256SUMS.txt'
$hashLines | Set-Content -Path $hashFile -Encoding UTF8

# Create output folder
$outputDir = Join-Path $repoRoot $OutputRoot
New-Item -ItemType Directory -Path $outputDir -Force | Out-Null

if ($SignPfxPath) {
    Write-Output "Signing files using PFX: $SignPfxPath"
    try {
        $pwd = if ($SignPfxPassword) { ConvertTo-SecureString $SignPfxPassword -AsPlainText -Force } else { $null }
        $x509 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        if ($pwd) { $x509.Import($SignPfxPath, $SignPfxPassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable) }
        else { $x509.Import($SignPfxPath) }

        # sign all ps1/psm1 in temp folder
        Get-ChildItem -Path $temp.FullName -Include *.ps1,*.psm1 -Recurse -File | ForEach-Object {
            try {
                Write-Output "Signing: $($_.FullName)"
                Set-AuthenticodeSignature -FilePath $_.FullName -Certificate $x509 | Out-Null
            } catch {
                Write-Warning "Failed to sign $($_.FullName): $($_.Exception.Message)"
            }
        }
    } catch {
        Write-Warning "Signing step failed: $($_.Exception.Message)"
    }
}

# If requested, obtain PFX from Vault and run signing
if ($UseVaultSecret) {
    if (-not $VaultSecretPath) { Write-Error "-UseVaultSecret requires -VaultSecretPath"; exit 2 }
    $vaultHelper = Join-Path $repoRoot 'dev-tools\vault\get_pfx_from_vault.ps1'
    if (-not (Test-Path $vaultHelper)) { Write-Error "Vault helper not found: $vaultHelper"; exit 3 }

    $tempPfx = Join-Path $env:TEMP ("ifqc_vault_{0}.pfx" -f ([System.Guid]::NewGuid().ToString()))
    Write-Output "Fetching PFX from Vault to temporary path: $tempPfx"
    try {
        & pwsh -NoProfile -ExecutionPolicy Bypass -File $vaultHelper -SecretPath $VaultSecretPath -OutputPath $tempPfx -VaultAddr $VaultAddr -VaultToken $VaultToken
    } catch {
        Write-Error "Failed to fetch PFX from Vault: $($_.Exception.Message)"; exit 4
    }

    if (-not (Test-Path $tempPfx)) { Write-Error "Vault helper did not produce PFX at $tempPfx"; exit 5 }

    # use the fetched PFX for signing
    try {
        $pwd = if ($SignPfxPassword) { ConvertTo-SecureString $SignPfxPassword -AsPlainText -Force } else { $null }
        $x509 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        if ($pwd) { $x509.Import($tempPfx, $SignPfxPassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable) }
        else { $x509.Import($tempPfx) }

        Get-ChildItem -Path $temp.FullName -Include *.ps1,*.psm1 -Recurse -File | ForEach-Object {
            try {
                Write-Output "Signing: $($_.FullName)"
                Set-AuthenticodeSignature -FilePath $_.FullName -Certificate $x509 | Out-Null
            } catch {
                Write-Warning "Failed to sign $($_.FullName): $($_.Exception.Message)"
            }
        }
    } catch {
        Write-Warning "Signing step failed using Vault PFX: $($_.Exception.Message)"
    }

    if ($DeleteTempPfx) {
        Remove-Item -Path $tempPfx -Force -ErrorAction SilentlyContinue
        Write-Output "Deleted temporary PFX: $tempPfx"
    } else {
        Write-Output "Temporary PFX retained at: $tempPfx"
    }
}

$zipPath = Join-Path $outputDir "$releaseName.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

Write-Output "Creating ZIP: $zipPath"
Compress-Archive -Path (Join-Path $temp.FullName '*') -DestinationPath $zipPath -Force

if (Test-Path $zipPath) {
    $size = (Get-Item $zipPath).Length
    Write-Output "Release created: $zipPath ($([math]::Round($size/1KB,2)) KB)"
} else {
    Write-Error "Failed to create release ZIP"
}

# Optionally sign the produced ZIP(s) using cosign (keyless via OIDC recommended for CI)
if ($UseCosign) {
    Write-Output "Cosign signing requested. Rekor: $RekorUrl"
    $cosignExe = Join-Path $env:TEMP 'cosign.exe'
    if (-not (Test-Path $cosignExe)) {
        Write-Output "Downloading cosign to: $cosignExe"
        try {
            Invoke-WebRequest -Uri 'https://github.com/sigstore/cosign/releases/latest/download/cosign-windows-amd64.exe' -OutFile $cosignExe -UseBasicParsing -ErrorAction Stop
        } catch {
            Write-Warning "Failed to download cosign: $($_.Exception.Message)"
        }
    }

    if (-not (Test-Path $cosignExe)) {
        Write-Error "cosign binary not available at $cosignExe. Please install cosign or ensure network access."; exit 0
    }

    $rekorLines = @()
    Get-ChildItem -Path $outputDir -Filter '*.zip' -File | ForEach-Object {
        $artifact = $_.FullName
        Write-Output "Signing artifact with cosign (keyless): $artifact"
        try {
            $out = & $cosignExe sign --keyless --rekor $RekorUrl $artifact 2>&1
            $out | ForEach-Object { Write-Output $_ }
            # capture Rekor upload lines if present
            $out | ForEach-Object {
                if ($_ -match 'Entry created in Rekor') { $rekorLines += $_ }
                if ($_ -match 'Upload to Rekor succeeded|tlog entry created|Bundle uploaded') { $rekorLines += $_ }
            }
            Write-Output "cosign sign completed for: $artifact"
        } catch {
            Write-Warning "cosign signing failed for $artifact: $($_.Exception.Message)"
        }
    }

    if ($rekorLines.Count -gt 0) {
        $rekorFile = Join-Path $outputDir ("REKOR-ENTRIES-{0}.txt" -f $version)
        Write-Output "Writing Rekor entries to: $rekorFile"
        $rekorLines | Out-File -FilePath $rekorFile -Encoding UTF8
    }
}
# SIG # Begin signature block
# MIIf3QYJKoZIhvcNAQcCoIIfzjCCH8oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAtPCqCIt8KbXFS
# 2d38svQ+AjkOTxRNI/zIYboMzxgsyqCCGNwwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# AgEVMC8GCSqGSIb3DQEJBDEiBCDLsLODWZ7weAV1mPduWVOjlYCzqmh8eD4skjCu
# ERQYOzANBgkqhkiG9w0BAQEFAASCAgCKCNicViukjPuPVv0cqQgkQ3pSWEYNgxAA
# VCW6Cp+BTelE7rFkVaIXw9hnVjQGoLRGJIcT2aMI4RI59N49Hx3yboFDs9RqfMG6
# w44Y5x+d4FH4GZkKY/b8ywlpYvoctRYQnNfP1+R4tG2I4DByKLNR9Hs28daiXawW
# 9ItRydTnKeDM5/6CxlPk779H/Yqu+4eURk0U5zDEbWtleA0thbXrok2MNlqy0JRM
# QrAQgbB2krZI8xL66hUMtvztFAXO5ESRcqw/Mh0vnjIPHkHOEEAjHetq+tLXB+zT
# 3DTjb+tsDzq7nAlHcYxm+/DOfa6PggdfaKhqUwmG/MhQSZ8H+ozbIy2XI1zMGaS/
# VywH9Kk8abu+pF6GDxIEO6CuM3yPNlHWezVPYuKoR/HWFMeOkpG43JAQlBW5qHk1
# O5wlxhkILOmZwDJXQbRa6+Vx7fMHPTsNXqbN1qv4CI1AWwBbyeBfIba+b7KLzaMZ
# wmN1A31vTuo9CqCHJ/msd1UA5zgG74cKBQnEUift3MtManfZhvGXCKSnyC0I4Z+A
# CtfjSEF/tEL+4De0jFt6OSbSMrUCFnHg6oLhm2xs0KPePGXsAtGKXv5/n16ZLu7U
# NHSD7bVJuBYpxKWMeXxBVVVP9Uhs/gI5HH4S9PkUBaFoMx+D3Sj+8yuMkOKSdVr4
# 7qpWGpbRhqGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAyMDUxNzEyNTVaMC8G
# CSqGSIb3DQEJBDEiBCDicK+NXeIDXPwMuoPvmVAJh6Yp8Y0sSSmZMX8wX77cBTAN
# BgkqhkiG9w0BAQEFAASCAgCyk+ojHy5B6YHWqmUZ0CKJCqEng+Ualc1BOA+dYpwa
# lmo3TyypgvUhCRFGVo69NKZi4UAdLBaEulS2nQkMo9nlGetA1vgwEPgD+WdOfAJT
# Bp7qnsRxmARCVDfrx4iqLGUtxvsv6r7B//aKeu9ODlNokd0qtoUK717UyX7ybqFO
# R9RVoyMQoGpu6UFAhfGuROWkLLM+a42447w0vWS4+T3jT7NXsgiDwek3vqKJQG9r
# humHjlCS62ysBTgfgAajmIeVHWRwWlaVJKzUJz4Cpl+Qx7qTmQPb7MFfJbOf+g71
# 4dj1sZTcewuEs7b0Cu7WqPLDm1DKut2ev4/bMXvIFkfgkFY+DG3AgIfzGn0h5MEs
# lJvWaEQpe95q7Z8qTJKn5iVqtOVvYEyv6TKbLR+dIHa24GK5wxxNiuKllH39rZ7R
# KU3a6EmipO/gj4ayqolkvTdMuXiWNno1Cn4pXN6sTPIUc4K1njFYI501Rclsenwd
# Rgp90ince16WJEZZvcaZl5ynKm7EL4+haKKfZ+rSndtjOLYDgfG/A60MF438ZkNA
# IbsTniHvfkhcaK5GQ9eVCrPJXxHbdmSZqAsBnnleZYfo7ULVCLf/+lX9do7LjlTQ
# mEiNbqNAOUYpsmcNOK3ETsxBFytm+yWLquryEEVx0u5s4cQCH54+PompPgHUwTLJ
# Cw==
# SIG # End signature block
