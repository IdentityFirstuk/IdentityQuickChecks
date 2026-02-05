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
    Package IdentityFirst QuickChecks for distribution.

.DESCRIPTION
    Creates a ZIP archive of all QuickChecks scripts for easy download
    and distribution. Optionally signs scripts before packaging.

.OUTPUTS
    - IdentityFirst.QuickChecks-v{version}.zip

.NOTES
    Author: IdentityFirst Ltd
    Requirements: PowerShell 5.1+

.USAGE
    # Create package
    .\Package-QuickChecks.ps1

    # Create package with signed scripts
    .\Package-QuickChecks.ps1 -SignScripts

    # Specify version
    .\Package-QuickChecks.ps1 -Version "1.0.1"

    # Skip README/EULA from package
    .\Package-QuickChecks.ps1 -NoDocumentation

    # Custom output directory
    .\Package-QuickChecks.ps1 -OutputPath ".\dist"
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ModulePath = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),

    [Parameter()]
    [string]$Version = "1.0.0",

    [Parameter()]
    [string]$OutputPath = ".\package",

    [Parameter()]
    [switch]$SignScripts,

    [Parameter()]
    [switch]$IncludeDocs = $true,

    [parameter()]
    [string]$CertPath,

    [parameter()]
    [securestring]$CertPassword,
    [parameter()]
    [pscredential]$CertCredential,

    [Parameter()]
    [switch]$Help
)

if ($Help) {
    Write-Output @"
IdentityFirst QuickChecks - Packaging Script
=============================================

Creates a ZIP archive of all QuickChecks scripts for distribution.

USAGE:
  .\Package-QuickChecks.ps1                    # Basic package
  .\Package-QuickChecks.ps1 -Version "1.0.1"   # Custom version
  .\Package-QuickChecks.ps1 -SignScripts       # Sign before packaging
  .\Package-QuickChecks.ps1 -NoDocumentation   # Skip docs
  .\Package-QuickChecks.ps1 -OutputPath ".\dist"  # Custom output

OUTPUT:
  IdentityFirst.QuickChecks-v{version}.zip

CONTENTS:
  - Module/ (framework scripts)
  - Checks/ (all check scripts)
  - Run-AllQuickChecks.ps1 (launcher)
  - README.md (if included)
  - EULA.txt (if included)

AFTER PACKAGING:
1. Test the package by extracting and running
2. Upload to your website for download
3. Consider signing scripts for production use

"@
    exit 0
}

# Load version from module if not specified
if ($Version -eq "1.0.0") {
    $moduleFile = Join-Path $ModulePath "Module\IdentityFirst.QuickChecks.psd1"
    if (Test-Path $moduleFile) {
        $moduleData = Import-PowerShellDataFile $moduleFile -ErrorAction SilentlyContinue
        if ($moduleData.ModuleVersion) {
            $Version = $moduleData.ModuleVersion
        }
    }
}

$zipName = "IdentityFirst.QuickChecks-v$Version.zip"
$zipPath = Join-Path $OutputPath $zipName

Write-IFQC -InputObject ([PSCustomObject]@{
    Timestamp = (Get-Date).ToString('o')
    Level = 'Info'
    Action = 'PackageInfo'
    Version = $Version
    Output = $zipPath
    Signing = [bool]$SignScripts
    IncludeDocs = [bool]$IncludeDocs
})

# Emit structured packaging start event
$pkgStart = [PSCustomObject]@{
    Timestamp = (Get-Date).ToString('o')
    Level = 'Info'
    Action = 'PackageStart'
    ModulePath = $ModulePath
    Version = $Version
    OutputPath = $zipPath
    SignScripts = [bool]$SignScripts
    IncludeDocs = [bool]$IncludeDocs
}
Write-IFQC -InputObject $pkgStart

# Check for required files
$requiredPaths = @(
    "Module\IdentityFirst.QuickChecks.psm1",
    "Checks",
    "Run-AllQuickChecks.ps1"
)

foreach ($relPath in $requiredPaths) {
    $fullPath = Join-Path $ModulePath $relPath
    if (-not (Test-Path $fullPath)) {
        Write-IFQC -InputObject ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Error'; Action='MissingPath'; Path=$fullPath })
        exit 1
    }
}

# Create output directory
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    Write-IFQC -InputObject ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Info'; Action='CreatedOutputDir'; Path=$OutputPath })
}

# Create temporary working directory
$tempDir = Join-Path $OutputPath "temp_$([guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
    Write-IFQC -InputObject ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Info'; Action='CreatedTempDir'; Path=$tempDir })

try {
    # Copy module directory structure
    Write-IFQC -InputObject ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Info'; Action='CopyStart' })

    $copySpec = @(
        @{ From = "Module"; To = "Module" }
        @{ From = "Checks"; To = "Checks" }
        @{ From = "Run-AllQuickChecks.ps1"; To = "Run-AllQuickChecks.ps1" }
    )

    if ($IncludeDocs) {
        $copySpec += @{ From = "README.md"; To = "README.md" }
        $copySpec += @{ From = "EULA.txt"; To = "EULA.txt" }
    }

    foreach ($item in $copySpec) {
        $src = Join-Path $ModulePath $item.From
        $dst = Join-Path $tempDir $item.To

            if (Test-Path $src) {
            if (Test-Path $src -PathType Container) {
                Copy-Item -Path $src -Destination $dst -Recurse -Force
            } else {
                Copy-Item -Path $src -Destination $dst -Force
            }
                Write-IFQC -InputObject ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Info'; Action='Copied'; Item=$item.From; Destination=$dst })
        }
    }

    # Sign scripts if requested
    if ($SignScripts) {
        Write-IFQC -InputObject ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Info'; Action='SigningRequested' })

        $signScript = Join-Path $ModulePath "Sign-QuickChecks.ps1"
        if (-not (Test-Path $signScript)) {
            Write-Output "ERROR: Sign-QuickChecks.ps1 not found"
            exit 1
        }

        # If caller provided IFQC_DEV_PFX_PASSWORD as env var, build a SecureString for signing
        if ($CertPath -and -not $CertPassword -and $env:IFQC_DEV_PFX_PASSWORD) {
            $devPwd = $env:IFQC_DEV_PFX_PASSWORD
            $ss = New-Object System.Security.SecureString
            foreach ($c in $devPwd.ToCharArray()) { $ss.AppendChar($c) }
            $ss.MakeReadOnly()
            $CertPassword = $ss
            Write-IFQC -InputObject ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Info'; Action='UsingDevPfxPassword'; Source='IFQC_DEV_PFX_PASSWORD' })
        }

        # If a PSCredential was provided to the packager, forward it to the signing script
            if ($CertCredential -and -not $CertPassword) {
            $CertPassword = $CertCredential.Password
            Write-IFQC -InputObject ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Info'; Action='UsingPfxFromPSCredential' })
        }

        $signArgs = @("-ModulePath", $tempDir)
        if ($CertPath) { $signArgs += "-CertPath", $CertPath }
        if ($CertPassword) { $signArgs += "-CertPassword", $CertPassword }
        if ($CertCredential) { $signArgs += "-CertCredential", $CertCredential }

        # Run signing in temp directory context
            Push-Location $tempDir
        try {
            & $signScript @signArgs | ForEach-Object { Write-IFQC -InputObject ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Info'; Action='SignOutput'; Text=$_ }) }
        } finally {
            Pop-Location
        }
    }

    # Create ZIP file
    Write-IFQC -InputObject ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Info'; Action='CreateZip'; Path=$zipPath })

    # Remove existing ZIP
    if (Test-Path $zipPath) {
        Remove-Item $zipPath -Force
        Write-Output "  Removed existing: $zipName"
    }

    # Create ZIP using .NET compression
    $zip = [System.IO.Compression.ZipFile]::Open($zipPath, [System.IO.Compression.ZipArchiveMode]::Create)

    try {
        # Get all files to add
        $files = Get-ChildItem -Path $tempDir -Recurse -File

        foreach ($file in $files) {
            # Calculate relative path within ZIP
            $relativePath = $file.FullName.Substring($tempDir.Length + 1).Replace('\', '/')

            # Add to ZIP
            $entry = $zip.CreateEntry($relativePath)
            $stream = $entry.Open()
            try {
                $file.OpenRead().CopyTo($stream)
            } finally {
                $stream.Close()
            }

                Write-IFQC -InputObject ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Info'; Action='ZipAdd'; Path=$relativePath; Size=$file.Length })
        }
    } finally {
        $zip.Dispose()
    }

    # Get ZIP size
    $zipSize = (Get-Item $zipPath).Length
    $zipSizeStr = if ($zipSize -gt 1MB) { "{0:N1} MB" -f ($zipSize / 1MB) } else { "{0:N0} KB" -f ($zipSize / 1KB) }

    # Summary
    Write-IFQC -InputObject ([PSCustomObject]@{
        Timestamp = (Get-Date).ToString('o')
        Level = 'Info'
        Action = 'PackageComplete'
        File = $zipName
        Size = $zipSizeStr
        ScriptCount = $files.Count
    })
    Write-Output ([PSCustomObject]@{ Zip = $zipPath; Size = $zipSize; Scripts = $files.Count })

} finally {
    # Clean up temp directory
    if (Test-Path $tempDir) {
        Remove-Item -Path $tempDir -Recurse -Force
        Write-Output ""
        Write-Output "Cleaned up temp directory"
    }
}

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA5AO3H63itj65h
# sV/AS7C9zjOAJUdU7NlsaTa/GMPgWKCCFlIwggMUMIIB/KADAgECAhBDR0HvMFNE
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgrzBISI+TxlEhRBWcYlZxm+PLN+E+YpLmPZfl
# 39CsnPkwDQYJKoZIhvcNAQEBBQAEggEAojbjWFauMFXBMwJQRjeL0KbEDvvkDScf
# bcPk2Y33ggITFj4mIhcMywUYxLTp5Vivi7NNIDPhX0kcljghYXrsOxb0zZA7Hie2
# I/++cWDauOVsBjOSRp8VLN5A8MUyCIhmjU2EBnvGfew/xXbDKSkwVSoCnf1hhwzT
# cCpCGCLt1+omd716SLNrqtSgqSegd1CjonKkyeT0KIzqKwSNEZGExY4lf7EzTg+W
# WEHYTA0omZAlMgAn9wFECyqbTKh10dTjy7X7CkS1Voi40faPSXlFc3MsWvNRljXr
# EG48W8caOHv2GRTIRAkBQICoQIuza7UUb2s/hjMxcAuN1uu/6E0qtKGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjAyMDQxNjUyMDlaMC8GCSqGSIb3DQEJBDEiBCCx
# cHsEgYgVRKmSKjp/MTsMOyuOX7Tjbbw/y7bvuhSshDANBgkqhkiG9w0BAQEFAASC
# AgCjcKUAem8bllIb1iqws2CsTCEVAxZedNd2/hPLrbbMnxSa8WSTSItouchrckCN
# G5t5jYGqfELMIJ33y2XOaBcAAAkkJ5tfNbFSF7kmBpZfL16VWFapl94Cwka1Tp5U
# RyW53LmkhDZHNxFDMGi5FiMPyqdGyzKIBgbE35lsWv/Y+bthUL2IQei+2uyCBJZM
# aXARAemnvfqYfXyJ9PhPdHkM+0kOCyaYL20hFOa66rLjcTXkaF90oukun/lkCcqb
# VOdjpL0GtNTQpZhZwqT/HMpo1dnG1xNXojlI9uBXhGF1UYRu4faZ/75y6PpkBQnb
# ueUcP+8OCiaYX33lS61MEVEKyxr9KU52xFjZXOL4bZc/WgzBSpDFE3o//T0u6dmJ
# +i3LX/zs0qAWXl8y7P1W5HGrEXKWYuW6H+sMcMthx5Wk7Ok41gfGYb6AfuyJFzBO
# eXHerSlIsC0jMXoubP8gJ6speR0poQiiwDaFWFDcsdRy76meZJXZQinnwlbMUS46
# tS/vN4DrPl2KKPrbpwR+VfIvsvjBlSV87wYYqbAWSfsqWmOQhcRc913aCHikTD+6
# jiSIalkU4oO3w+hwJ+c7GC0rEh6TegZacj6bgoWQw274Pn3bPRhESCWUMGHBa1+2
# K5OFg93ZrThdS28L936ugvpRvQakIB5onJq7KpI0QWi/Jg==
# SIG # End signature block
