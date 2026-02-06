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
    Install IdentityFirst QuickChecks Prerequisites.

.DESCRIPTION
    Installs all required PowerShell modules and CLI tools for QuickChecks:
    - ActiveDirectory (RSAT)
    - AzureAD
    - Microsoft.Graph
    - AWS Tools for PowerShell
    - AWS CLI
    - gcloud CLI

.OUTPUTS
    - Installed modules and tools

.NOTES
    Author: IdentityFirst Ltd
    Requirements: PowerShell 5.1+, Windows 10/Server 2016+

.USAGE
    # Install all prerequisites
    .\\Install-Prerequisites.ps1

    # Install specific prerequisites only
    .\\Install-Prerequisites.ps1 -ModulesOnly
    .\\Install-CliOnly
#>

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$ModulesOnly,

    [parameter()]
    [switch]$CliOnly,

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [switch]$Help
)

if ($Help) {
        Write-Output @"
IdentityFirst QuickChecks - Prerequisites Installer
====================================================

Installs all required PowerShell modules and CLI tools for QuickChecks.

PREREQUISITES INSTALLED:
    PowerShell Modules:
        - ActiveDirectory (via RSAT)
        - AzureAD
        - Microsoft.Graph (Identity.DirectoryManagement, Reports)
        - AWS Tools for PowerShell
        - PSScriptAnalyzer (for linting)

    CLI Tools:
        - AWS CLI (v2)
        - gcloud CLI

USAGE:
    .\\Install-Prerequisites.ps1           # Install all (modules + CLI)
    .\\Install-Prerequisites.ps1 -ModulesOnly  # PowerShell modules only
    .\\Install-Prerequisites.ps1 -CliOnly      # CLI tools only
    .\\Install-Prerequisites.ps1 -Force       # Reinstall even if present

SYSTEM REQUIREMENTS:
    - Windows 10/Server 2016+ (for RSAT)
    - PowerShell 5.1+
    - Internet connection
    - Admin rights for some installations

"@
        exit 0
}

Write-Output ""
Write-Output "IdentityFirst QuickChecks - Prerequisites Installer"
Write-Output "----------------------------------------------------"
Write-Output ""

$script:installCount = 0
$script:skipCount = 0
$script:failCount = 0

function Write-InstallLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $ts = Get-Date -Format "HH:mm:ss"
    $color = if ($Level -eq "ERROR") { "Red" } elseif ($Level -eq "WARN") { "Yellow" } elseif ($Level -eq "SUCCESS") { "Green" } else { "Gray" }
    Write-Output "[$ts] [$Level] $Message"
}

function Test-ModuleInstalled {
    param([string]$Name)
    return (Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue) -ne $null
}

function Install-PowerShellModule {
    param(
        [string]$Name,
        [string]$Repository = "PSGallery",
        [string]$Scope = "CurrentUser"
    )

    $isInstalled = Test-ModuleInstalled -Name $Name

    if ($isInstalled -and -not $Force) {
        Write-InstallLog -Message "$Name is already installed" -Level "INFO"
        $script:skipCount++
        return $true
    }

    Write-InstallLog -Message "Installing $Name..." -Level "INFO"

    try {
        # Check if NuGet provider is available
        if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -Force -Confirm:$false | Out-Null
        }

        # Set repository
        if ((Get-PSRepository -Name $Repository -ErrorAction SilentlyContinue).InstallationPolicy -ne "Trusted") {
            Set-PSRepository -Name $Repository -InstallationPolicy Trusted
        }

        # Install module
        Install-Module -Name $Name -Repository $Repository -Scope $Scope -Force -Confirm:$false -ErrorAction Stop

        Write-InstallLog -Message "✓ $Name installed successfully" -Level "SUCCESS"
        $script:installCount++
        return $true
    } catch {
        Write-InstallLog -Message "✗ Failed to install $Name: $($_.Exception.Message)" -Level "ERROR"
        $script:failCount++
        return $false
    }
}

function Install-RSAT {
    param([switch]$Force)

    Write-InstallLog -Message "Checking RSAT (Remote Server Administration Tools)..." -Level "INFO"

    # Check if RSAT is available (Windows 10/Server 2016+)
    $osVersion = [Version](Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue).Version
    if ($osVersion.Major -lt 10) {
        Write-InstallLog -Message "RSAT requires Windows 10 or later" -Level "WARN"
        return $false
    }

    # Check if RSAT is already enabled
    $rsatFeatures = Get-WindowsCapability -Name "Rsat*" -Online -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Installed" }

    if ($rsatFeatures -and -not $Force) {
        Write-InstallLog -Message "RSAT is already installed" -Level "INFO"
        $script:skipCount++
        return $true
    }

    # Get available RSAT features
    $availableFeatures = Get-WindowsCapability -Name "Rsat*" -Online -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "NotPresent" }

    # Install ActiveDirectory module
    $adFeature = $availableFeatures | Where-Object { $_.Name -match "ActiveDirectory" }
    if ($adFeature) {
        try {
            Write-InstallLog -Message "Installing RSAT: ActiveDirectory..." -Level "INFO"
            Add-WindowsCapability -Name $adFeature.Name -Online -ErrorAction Stop | Out-Null
            Write-InstallLog -Message "✓ RSAT ActiveDirectory installed" -Level "SUCCESS"
            $script:installCount++
        } catch {
            Write-InstallLog -Message "✗ Failed to install RSAT: $($_.Exception.Message)" -Level "ERROR"
            $script:failCount++
        }
    } else {
        Write-InstallLog -Message "RSAT ActiveDirectory feature not found" -Level "WARN"
    }

    return $true
}

function Install-AwsCli {
    param([switch]$Force)

    Write-InstallLog -Message "Checking AWS CLI..." -Level "INFO"

    # Check if already installed
    if (Get-Command "aws" -ErrorAction SilentlyContinue) {
        $version = aws --version 2>&1
        Write-InstallLog -Message "AWS CLI already installed: $version" -Level "INFO"
        $script:skipCount++
        return $true
    }

    if (-not $Force) {
        Write-InstallLog -Message "AWS CLI not found. Downloading..." -Level "INFO"
    }

    try {
        # Download AWS CLI v2 MSI
        $awsMsiUrl = "https://awscli.amazonaws.com/msi/v2/2.13.44/AWSCLIV2.msi"
        $awsMsiPath = Join-Path $env:TEMP "aws-cli.msi"

        Write-InstallLog -Message "Downloading AWS CLI v2..." -Level "INFO"
        Invoke-WebRequest -Uri $awsMsiUrl -OutFile $awsMsiPath -UseBasicParsing -ErrorAction Stop

        Write-InstallLog -Message "Installing AWS CLI..." -Level "INFO"
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$awsMsiPath`" /quiet" -Wait -PassThru

        if ($process.ExitCode -eq 0) {
            Write-InstallLog -Message "✓ AWS CLI installed successfully" -Level "SUCCESS"
            $script:installCount++

            # Clean up
            Remove-Item -Path $awsMsiPath -Force -ErrorAction SilentlyContinue
        } else {
            Write-InstallLog -Message "✗ AWS CLI installation failed (exit code: $($process.ExitCode))" -Level "ERROR"
            $script:failCount++
        }
    } catch {
        Write-InstallLog -Message "✗ Failed to install AWS CLI: $($_.Exception.Message)" -Level "ERROR"
        $script:failCount++
    }

    return $true
}

function Install-GcloudCli {
    param([switch]$Force)

    Write-InstallLog -Message "Checking gcloud CLI..." -Level "INFO"

    # Check if already installed
    if (Get-Command "gcloud" -ErrorAction SilentlyContinue) {
        $version = gcloud version 2>&1 | Select-Object -First 1
        Write-InstallLog -Message "gcloud CLI already installed: $version" -Level "INFO"
        $script:skipCount++
        return $true
    }

    if (-not $Force) {
        Write-InstallLog -Message "gcloud CLI not found. Downloading..." -Level "INFO"
    }

    try {
        # Download gcloud CLI
        $gcloudZipUrl = "https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-sdk-468.0.0-windows-x86_64-bundledpython.zip"
        $gcloudZipPath = Join-Path $env:TEMP "gcloud-sdk.zip"
        $gcloudInstallPath = Join-Path ${env:ProgramFiles} "Google\Cloud SDK"

        Write-InstallLog -Message "Downloading gcloud CLI..." -Level "INFO"
        Invoke-WebRequest -Uri $gcloudZipUrl -OutFile $gcloudZipPath -UseBasicParsing -ErrorAction Stop

        Write-InstallLog -Message "Installing gcloud CLI..." -Level "INFO"

        # Extract
        $gcloudTempPath = Join-Path $env:TEMP "gcloud-sdk"
        Expand-Archive -Path $gcloudZipPath -DestinationPath $gcloudTempPath -Force -ErrorAction Stop

        # Run installation script
        $installScript = Join-Path $gcloudTempPath "google-cloud-sdk\install.bat"
        if (Test-Path $installScript) {
            $process = Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$installScript`" --quiet" -Wait -PassThru -WorkingDirectory $gcloudTempPath
        }

        # Add to PATH (simplified approach)
        $gcloudPath = Join-Path $gcloudInstallPath "google-cloud-sdk\bin"
        if (Test-Path (Join-Path $gcloudPath "gcloud.ps1")) {
            # Add to PATH environment variable
            $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
            if ($currentPath -notmatch [regex]::Escape($gcloudPath)) {
                [Environment]::SetEnvironmentVariable("Path", "$currentPath;$gcloudPath", "Machine")
            }
            Write-InstallLog -Message "✓ gcloud CLI installed successfully" -Level "SUCCESS"
            $script:installCount++
        } else {
            Write-InstallLog -Message "✗ gcloud installation path not found" -Level "ERROR"
            $script:failCount++
        }

        # Clean up
        Remove-Item -Path $gcloudZipPath -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $gcloudTempPath -Recurse -Force -ErrorAction SilentlyContinue

    } catch {
        Write-InstallLog -Message "✗ Failed to install gcloud CLI: $($_.Exception.Message)" -Level "ERROR"
        $script:failCount++
    }

    return $true
}


# SIG # Begin signature block
# MIIf3QYJKoZIhvcNAQcCoIIfzjCCH8oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBHFw613VIfoHtg
# VbFWj/c1PvXn0HQDzz10KQs0Bz9RH6CCGNwwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# AgEVMC8GCSqGSIb3DQEJBDEiBCACdXeZFR+nyxke8Ua4D9y8DWR08PU73Gakrm3i
# oK114DANBgkqhkiG9w0BAQEFAASCAgC7b0xEtFIoBgc7MBveDieaAZAPIopdnWrP
# JIcOt7VPW4BNVD1L1IlbSE/TGftrpOnYd+FE6LIoO9hf9Oqel8UWbV6i1V7xvfpJ
# pW2x4rspnovBavTw6Jmi56rusHdH32fFKEHoz2wOg7czlFzgrM/SjXKO1lgRsEF0
# pWk39KIyO0J3DwYP3YuDkpAQvtkxabd3jkNCDQv51gA8jUXSVCBwbvLbCsWlt089
# RHbbybVsBimcD6Tr2lgz5UTH5BsQh8mNFVd6mFJ4Xii5L9AdRNqoCARqn/KsxIXf
# HbQGaLI+dX1FeYMadOQLAx+x+FVU7IwJd1VFOYgzbphe2FN+IHL7O2v1XNrxMPI3
# 2PgGIgGdAcXeYERYDPPE5YWCZ4pKBZ0/qFiOWRRG2lQKSI560xJoWVJbSRk2rvY5
# SXf1i3K1IXhQWNLMUg0qNbPmY3YixaNNb2IBM1paDTdidYm6YtL2D0R/X/UpcQsH
# B3Gt97o0hB0hzzyuUY5Pgxh3uS0+aLVPGREXuh5KJYojjWG7PaBLabT2PoJCzt1a
# ckOOACgnemoxtoGNLavkDItOTBBmfwEqmILKab+cY4lm58EpsDYACydkQYmxdNOm
# 4XUodijuQj0yX02O3gDEnhGJJbQ69TMrWcJyMFfg7dSQSV6hb9XTbRjosfbiX2zD
# ewlfw1smOKGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAyMDUxNzEyNDhaMC8G
# CSqGSIb3DQEJBDEiBCBaBx7KTHpu09YkFVMAY/nWAQSTg5ofcIfGdcJ9Sr1/rTAN
# BgkqhkiG9w0BAQEFAASCAgCZVZvqAr6x4mZDWL6FmH+M8Cg53cDzsaBjwAh6UTzR
# O5uEBV/31GZ/HpqqttT9X3SfJPnOS1X70WXSOBu2G71uiaiPVSa2gJbUVjHU5j3k
# +i0yptN8Rj9sdu2Z6Na1XTLlRPtl4c1LslKvn/opBwKVkbVe0E/ZcFg1h/TTQ6bu
# wDMG6bVhDHcxXydfOuGgedgIm2dLzuFjtOrZlkL5eC9RdwIIdnE8OivXsaV9cr5n
# ersYmPRgKOex20tvqfxB1mDV8Fb/FlqX8L4Rss3kAjZR6aPyICwvODVk2QhgVdjZ
# lLvDeWLLY5yli5kTdoHrPDU9ABwN4eV9wDwHkA3l34U+ZdAGtOhLZG63vG7tULh8
# VPU8e+nsXA+dxtV/0cFjpMZh+5C7IW6aHij1xMmNHSsvBeqowyJpJL8O1A2k9eoz
# YFPWdY/RobP8F/L2er3F4Y0PI2lBEqg/e+NXZscmPaHOyOwdvuzQwJqJDMX9/8E2
# wRqO3XfEK6ThNtUq5ulseZ0xQId3ymD2drzcmQTAbwC9JsdTVBkXN3u7AouXympI
# PAZdpX27fdhErVV6pJjIz57xNHHLOygL8W1/k7bhNw5X1N3du0rfVqNZ9yylyQYd
# DXiseorVlx2FRxy5TSPO3a+aWrLDfRzA1TDEeXkuER04PnDxLB9vfkR7Hkq+B29e
# Ow==
# SIG # End signature block
