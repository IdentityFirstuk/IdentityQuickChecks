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
    Install IdentityFirst QuickChecks module.

.DESCRIPTION
    Installs the QuickChecks module to the local PowerShell modules directory.
    Supports both per-user and all-users installation.

.OUTPUTS
    - Module installed to PowerShell modules folder

.NOTES
    Author: IdentityFirst Ltd
    Requirements: PowerShell 5.1+

.USAGE
    # Install for current user only
    .\Install-QuickChecks.ps1

    # Install for all users (requires admin)
    .\Install-QuickChecks.ps1 -AllUsers

    # Install from extracted ZIP
    .\Install-QuickChecks.ps1 -SourcePath "C:\Downloads\IdentityFirst.QuickChecks-v1.0.0"
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$SourcePath = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),

    [Parameter()]
    [switch]$AllUsers,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [Parameter()]
    [switch]$Help,

    [Parameter()]
    [System.Security.SecureString]$CertPassword
    ,
    [Parameter()]
    [pscredential]$CertCredential
)

if ($Help) {
    Write-Output @"
IdentityFirst QuickChecks - Installation Script
================================================

Installs the QuickChecks module to your PowerShell modules directory.

USAGE:
  .\Install-QuickChecks.ps1                    # Current user
  .\Install-QuickChecks.ps1 -AllUsers          # All users (admin required)
  .\Install-QuickChecks.ps1 -Force             # Overwrite existing
  .\Install-QuickChecks.ps1 -SourcePath ".\path"  # From specific location

INSTALLATION LOCATIONS:
  Current User:  %USERPROFILE%\Documents\WindowsPowerShell\Modules\IdentityFirst.QuickChecks
  All Users:     %ProgramFiles%\WindowsPowerShell\Modules\IdentityFirst.QuickChecks

AFTER INSTALLATION:
  Import-Module IdentityFirst.QuickChecks
  Get-Command -Module IdentityFirst.QuickChecks

TO RUN CHECKS:
  Import-Module IdentityFirst.QuickChecks
  Invoke-BreakGlassReality.ps1
  .\Run-AllQuickChecks.ps1

"@
    exit 0
}

Write-IFQC -InputObject ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Info'; Action='InstallStart' })

# Determine installation path
$moduleName = "IdentityFirst.QuickChecks"
$moduleVersion = "1.0.0"

# Read version from file if exists
$versionFile = Join-Path $SourcePath "VERSION.txt"
if (Test-Path $versionFile) {
    $moduleVersion = (Get-Content $versionFile -Raw).Trim()
}

if ($AllUsers) {
    # All users installation
    $installPath = Join-Path $env:ProgramFiles "WindowsPowerShell\Modules\$moduleName"
} else {
    # Current user installation
    $documentsPath = [Environment]::GetFolderPath("MyDocuments")
    $installPath = Join-Path $documentsPath "WindowsPowerShell\Modules\$moduleName"
}

Write-IFQC -InputObject ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Info'; Action='InstallInfo'; Source=$SourcePath; Target=$installPath; Version=$moduleVersion; AllUsers=[bool]$AllUsers })

# Check if already installed
if (Test-Path $installPath) {
    $existingVersion = "Unknown"
    $existingVersionFile = Join-Path $installPath "VERSION.txt"
    if (Test-Path $existingVersionFile) {
        $existingVersion = (Get-Content $existingVersionFile -Raw).Trim()
    }

    Write-IFQC -InputObject ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Warn'; Action='ModuleExists'; ExistingVersion=$existingVersion })

    if (-not $Force) {
        Write-IFQC -InputObject ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Info'; Action='PromptOverwrite' })
        $response = Read-Host "  Continue with installation? (y/n)"
        if ($response.ToLower() -ne "y") {
            Write-Output "Installation cancelled."
            exit 0
        }
    }

    Write-IFQC -InputObject ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Info'; Action='RemovingExisting' ; Path=$installPath })
    Remove-Item -Path $installPath -Recurse -Force
}

# Create installation directory
Write-IFQC -InputObject ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Info'; Action='CreateModuleDir'; Path=$installPath })
New-Item -ItemType Directory -Path $installPath -Force | Out-Null

# Copy module files
Write-IFQC -InputObject ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Info'; Action='CopyStart' })

$copyItems = @(
    @{ Source = "Module"; Target = "Module" }
    @{ Source = "Checks"; Target = "Checks" }
    @{ Source = "Run-AllQuickChecks.ps1"; Target = "Run-AllQuickChecks.ps1" }
    @{ Source = "README.md"; Target = "README.md" }
    @{ Source = "EULA.txt"; Target = "EULA.txt" }
    @{ Source = "VERSION.txt"; Target = "VERSION.txt" }
)

foreach ($item in $copyItems) {
    $src = Join-Path $SourcePath $item.Source
    $dst = Join-Path $installPath $item.Target

    if (Test-Path $src) {
        if (Test-Path $src -PathType Container) {
            Copy-Item -Path $src -Destination $dst -Recurse -Force
        } else {
            Copy-Item -Path $src -Destination $dst -Force
        }
        Write-IFQC -InputObject ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Info'; Action='Copied'; Item=$item.Source; Destination=$dst })
    }
}

# Create version-specific directory (optional but good practice)
$versionedPath = Join-Path $installPath $moduleVersion
New-Item -ItemType Directory -Path $versionedPath -Force | Out-Null

# Copy files to versioned directory as well (PowerShellGet compatible)
Write-IFQC -InputObject ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Info'; Action='SetupVersionDir'; Path=$versionedPath })
foreach ($item in $copyItems) {
    $src = Join-Path $SourcePath $item.Source
    $dst = Join-Path $versionedPath $item.Target

    if (Test-Path $src) {
        if (Test-Path $src -PathType Container) {
            Copy-Item -Path $src -Destination $dst -Recurse -Force
        } else {
            Copy-Item -Path $src -Destination $dst -Force
        }
    }
}

# Verify installation
Write-IFQC -InputObject ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Info'; Action='VerifyInstallation' })

$manifestPath = Join-Path $installPath "IdentityFirst.QuickChecks.psd1"
if (Test-Path $manifestPath) {
    try {
        $manifest = Import-PowerShellDataFile $manifestPath -ErrorAction Stop
        Write-IFQC -InputObject ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Info'; Action='ManifestLoaded'; Version=$manifest.ModuleVersion })
    } catch {
        Write-IFQC -InputObject ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Warn'; Action='ManifestLoadFailed'; Message=$_.Exception.Message })
    }
}

# Install certificate to Trusted Root (for self-signed certs)
Write-Output ""
    Write-Output @"
$certPath = Join-Path $SourcePath "identityfirst-codesign.pfx"
if (Test-Path $certPath) {
            try {
                # Use provided secure password parameter first
                if ($CertPassword) {
                    $password = $CertPassword
                } elseif ($CertCredential) {
                    # If a PSCredential was provided, use its Password (SecureString)
                    $password = $CertCredential.Password
                    Write-IFQC -InputObject ([PSCustomObject]@{
                        Timestamp = (Get-Date).ToString('o'); Level='Info'; Action='UsingPfxFromPSCredential'
                    })
                    Write-Output "Using PFX password from provided PSCredential"
                } else {
                    # Prompt securely for PFX password (hidden input). If empty, support developer env var fallback `IFQC_DEV_PFX_PASSWORD`.
                    try {
                        $password = Read-Host "Enter password for PFX (press ENTER if none)" -AsSecureString
                    } catch {
                        $password = $null
                    }

                    # If no interactive password provided, check developer env var using helper
                    if (-not $password) {
                        try { Import-Module -Name Security\IdentityFirst.Security -ErrorAction SilentlyContinue } catch { }
                        if (Get-Command -Name Get-SecureStringFromEnv -ErrorAction SilentlyContinue) {
                            $ss = Get-SecureStringFromEnv -EnvVarName 'IFQC_DEV_PFX_PASSWORD'
                            if ($ss) {
                                $password = $ss
                                Write-IFQC -InputObject ([PSCustomObject]@{ Timestamp = (Get-Date).ToString('o'); Level='Info'; Action='UsingDevPfxPassword'; Source='IFQC_DEV_PFX_PASSWORD' })
                                Write-Output "Using developer PFX password from IFQC_DEV_PFX_PASSWORD (hidden)."
                            }
                        }
                    }
                }

                    try {
                        if ($password) {
                            $cert = Get-PfxCertificate -FilePath $certPath -Password $password -ErrorAction Stop
                        } else {
                            $cert = Get-PfxCertificate -FilePath $certPath -ErrorAction Stop
                        }
                    } catch {
                        # fallback try without password
                        Write-IFQC -InputObject ([PSCustomObject]@{
                            Timestamp = (Get-Date).ToString('o'); Level='Error'; Action='PfxLoadFailed'; Message=$_.Exception.Message
                        })
                        Write-Output "Installation cancelled."
                    }
            }

        # Check if certificate is already in Trusted Root
        $existingCert = Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object Thumbprint -eq $cert.Thumbprint
        if ($existingCert) {
            Write-Output "    ✓ Certificate already installed in Trusted Root"
        } else {
            # Export to temp file and import
            $tempCertPath = [System.IO.Path]::GetTempFileName()
            Export-Certificate -Cert $cert -FilePath $tempCertPath -Type CERT | Out-Null
Write-Output "════════════════════════════════════════════════════════════"
            Remove-Item -Path $tempCertPath -Force
Write-Output "════════════════════════════════════════════════════════════"
            Write-Output "    ✓ Thumbprint: $($cert.Thumbprint)"
        }
    } catch {
        Write-Output "    ⚠ Could not install certificate: $($_.Exception.Message)"
        Write-Output "    ℹ Run as administrator to install to machine root"
    }
} else {
    Write-Output "    ℹ Certificate file not found - signatures may show 'Unknown publisher'"
}

# Summary
Write-IFQC -InputObject ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Info'; Action='InstallComplete'; Path=$installPath })
Write-Output ([PSCustomObject]@{ InstalledPath = $installPath })
# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDjOOmdmMMEXP3z
# cQbgdvaXRQ12fRQuwrTmfiD0EVg6LKCCFlIwggMUMIIB/KADAgECAhBDR0HvMFNE
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgY73x7uY4xBAE30k39S7XM0ndMHUtuonTq8Qh
# V472owgwDQYJKoZIhvcNAQEBBQAEggEAE4IExakYQ9Ij/GmyylTOVOw8ccrTWvnT
# KgemsYmGqJEE1mm6m0cp2+Ms8oorwS6TgkO4xFF+HysNamATl4G6h7ii1j7QPfqM
# aD5D6/thu/HjuZwJ/VfqTzX+UrUEohViPeBXROSn9mJTUdMdLjSZ2ekaJOJszuKB
# L+jjCBEQYgR+Z5rCpJwempwLHTd+52dyawOkQ44OZGLd7bFZcv2ZM0T/kyre48Jw
# Il7AKS3GWrk6EFsZpRCXUn/aOlG5k/x+ODPndQX+nsG4nM6DIEN1hogAh63CqDFz
# 4JB3R1kdnNvzMSKwOc8NvTBiwC/GJwBXEJCNdYDzlsP5pUhGQlARQqGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjAyMDQxNjUyMDhaMC8GCSqGSIb3DQEJBDEiBCC3
# iuLCF17PDhz3EH2Ryb09AEYchv4pm/MaJC7Fa7M3YjANBgkqhkiG9w0BAQEFAASC
# AgBzPhmQp9LjiihmW03DklP7r15xv0VD0aYjS+AxGeK1c/h5baYKOPfs7O+aS8BX
# NBbQmoig3pw1fxiC0kLrYnjus7of469wt/Vbq9cn29a9vnuyaKJhGi9MSNG+5vKq
# sQd0Rfjl3+4guMgT3YpidqE3uH+g1hPDV4UHnPHdnJ1ATr/r4tDwEmOZWzrs7tWJ
# 2OwrkuncNeHM7bzeaXQjVGh0QonH4l8UU65mEmp7re8Wgk6rokHAOO0A6wLPKXhz
# rp7JC/lj4laKiqYD3g1O+j9icvQcViySY9CFK/2xT+DX6XPmQ2tzIFyC+/C/d2iB
# NqpMI0RecywRk0VTL7Vp+/k/xPqaYBRmgDZM9I35IPusrYJExg1lWTMoj99pVSxM
# t3/ip8kZrHoyYBmw1/PyXN1PiZweCiSSfleBiNMid+X6ipBYThEk1yAatoZlNPuI
# r1m2wocgLUwecLJi0IuPbORQNhcILmldlwBRlPWymu8KVq1GAgUWJBdxBpVAMYZF
# zrqEVep0eleTei3g43p5AyhC+yeuokBdJ2nZ8NZ8J+8s/Y3c0ooB7WxlC5JV5vCt
# vYz1mw0k9tytbK6h32XUr7S+7GngD/JtRTVQKauOKWcs9Lybuu1ARy4VokpTLP8b
# cxwrQUMji54Aka4oXDZqy1Cmbm5bSHwyCwnCpnSZwXAevQ==
# SIG # End signature block
