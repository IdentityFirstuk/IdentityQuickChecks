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
# MIIf3QYJKoZIhvcNAQcCoIIfzjCCH8oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDRfs/Ouo1a7H5S
# TGbklSg7C1ZJ0VSIFVz5SziqVd3i3KCCGNwwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# AgEVMC8GCSqGSIb3DQEJBDEiBCCH3H5E4miVwAVjwg/suHEdjPSEE8QFB89Dk6WZ
# OWctrjANBgkqhkiG9w0BAQEFAASCAgB5wLBE68kYsDgeLaTBuo1aBOGuCZNVigMK
# uLTJMgtrKbblXWxMM6CMIY8QgDeVbJE+jdvysC+KLRYeeQcT8FDd3iNN5Y0FNVvj
# rlDjzDG27gDpRnJruETF5JHb7v8VR92Gcmvdp9GPkCizND5+mxbrMhInkQpiDt+U
# 5CAxH8ohjnkWoBxiAh1wn1SE+fCC1WWW5y/3C0yaAUTB3qF+euMtjtMoMKE5v9QX
# slNKRITO6rCkcv3xRVI4P2vsbei+dTqxnsE7O/AolLU4bA+NhnHQG01gglhD4JAY
# ENMG3NJkLBb3gGHsaDtdZ5M5i3uLikJRQb8loXSEttShM0J3HgUm626lb7HYvM5J
# 6msjBEjlb7MGi3I8kRWLypr1FMczzdXr6WqgJx7iCKGBwQi9ZXvN+dsB4prJgR+J
# j9vWRQGpcj7DWLUOZBSRYtj+4HAfPe2lHgbSO43x0614GxOxzpOWZJER2O56u3BW
# xqQJ5gAL89X2ugBWD7VZkOBmCaTE2aoT9rdFu20kbUDlzXbzxMLmsvtEZPBv/r1e
# pQzXuWYhHIbduZIv1/6iODl03yqUk+BmJ94VFyDn5lWmJlXyEhqGg8gZk8MJmuM2
# U91NSy4fhGF/BktLwEnjQC8iyK6/7b7emWh8pfGAOr7dgTBcB3+JDbug4jlQAr/+
# Z55zEtuKf6GCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAyMDUxNzEyNDlaMC8G
# CSqGSIb3DQEJBDEiBCBqvfzf7RqTIDXM3HZNza4Ij/tSvKfnopDmc3kM6wza7TAN
# BgkqhkiG9w0BAQEFAASCAgCOIHHCDEdgjp8vHhDcD8yEMrvRhWbOcRHA8+Ja6zcm
# jeIRfRnWj7kKItb2u38PBRix0fFMAHsmag5/Z1pMybvg6h5S9ZFPYc4ZQfSRx8Y+
# IUMrcy8SNiiw2fYSXUOH/w9ZIewLGPH1XhnyTNcbPRQ+pRXdFgpnH/ElguYlq+MF
# iWpj8487bKMx6akip/r+CepHfmBLwChIn+gl1oDjkq4BO3fwuP+ckVwi5Gl9gyRP
# O6lY8Q08mNboLEzBciwL4884M412OyJT19L/mK9hltmVBFSH5RZRP47ZKuKvtriC
# bz4pEGAVjPqHuKIGZqE2Atfv7oBKpTN9XlebwIFrUdEGsqUZfLBbrZqYAY1QbZmn
# uZuCYTfjUn9V9/oI47YTTB+UuIsc0Kg695zyp31sHuLdt1Jtx4/VTiToUzwBQtg+
# D9jtS1iM8XoiZgjMSDZkQ1hN0ceW2nnW3s9NtzNRWMAfWaM80y/Ap6GmmUufHGlG
# 9Sz91Uy1fNKr8QmbvvnAcIaOfgG8H/aiuYkjzdQ2qK5AymBhLmuKXb1ATcSzB64+
# NBq64Vr2gIqWrlKrv1XyXJNsY0dkFR+Gta3BZNGjNzjydcl7+DWD+uCcQi5DBlz+
# Om+UYDSrQBu6XbAxN9Ih7Yk1KPUYKGp54elkHpIpNO6d++lmM4NDPu1FQoBFkQNY
# YA==
# SIG # End signature block
