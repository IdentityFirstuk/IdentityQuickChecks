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

# ============================================================================
# Main
# ============================================================================

function Main {
    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -lt 5) {
        Write-InstallLog -Message "PowerShell 5.1+ required. Current version: $psVersion" -Level "ERROR"
        Write-Output "Please update PowerShell before running this script."
        exit 1
    }

    Write-Output "  PowerShell version: $psVersion"
    Write-Output ""

    # Install PowerShell modules
    if (-not $CliOnly) {
        Write-SubHeader " INSTALLING POWERSHELL MODULES "

        # RSAT for ActiveDirectory
        if ($IsWindows -or $PSVersionTable.PSVersion.Major -ge 10 -or $env:OS -eq "Windows_NT") {
            Install-RSAT -Force:$Force
        }

        # AzureAD
        Install-PowerShellModule -Name "AzureAD" -Force:$Force

        # Microsoft.Graph modules
        Install-PowerShellModule -Name "Microsoft.Graph.Identity.DirectoryManagement" -Force:$Force
        Install-PowerShellModule -Name "Microsoft.Graph.Reports" -Force:$Force

        # AWS Tools
        Install-PowerShellModule -Name "AWS.Tools.IdentityManagement" -Force:$Force

        # PSScriptAnalyzer
        Install-PowerShellModule -Name "PSScriptAnalyzer" -Force:$Force
    }

    # Install CLI tools
    if (-not $ModulesOnly) {
        Write-SubHeader " INSTALLING CLI TOOLS "

        # AWS CLI
        Install-AwsCli -Force:$Force

        # gcloud CLI
        Install-GcloudCli -Force:$Force
    }

    # Summary
    Write-Output ""
    Write-Output "Installation Complete"
    Write-Output "---------------------"
    Write-Output ""
    Write-Output ("  Installed:  {0}" -f $script:installCount)
    Write-Output ("  Skipped:    {0}" -f $script:skipCount)
    Write-Output ("  Failed:     {0}" -f $script:failCount)
    Write-Output ""

    if ($script:failCount -gt 0) {
        Write-InstallLog -Message "Some installations failed. Check errors above." -Level "WARN"
    } else {
        Write-InstallLog -Message "All prerequisites installed successfully!" -Level "SUCCESS"
    }

    Write-Output ""
    Write-Output "  Next steps:"
    Write-Output "  1. Restart PowerShell (to load new modules)"
    Write-Output "  2. Run: .\\QuickChecks-Console.ps1"
    Write-Output ""
}

function Write-SubHeader {
    param([string]$Title)
    Write-Output ""
    Write-Output ("  " + $Title)
    Write-Output ""
}

# Run
Main

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBohvvybYiyzTkj
# LQrewglVWwKHy/GtFoWifQnBq2NZIKCCFlIwggMUMIIB/KADAgECAhBDR0HvMFNE
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQggJai0Rslj4SRLts0G+z24DjNJEW2QuS3Uozw
# 8Hx1NB4wDQYJKoZIhvcNAQEBBQAEggEA1BY+twvxNtMu4Inj39fg2dI8F4UwE8p/
# BxntEOoOBdvc3xSdejdNX4QydRh9XH/KYrjlqd7V7urf7HbjZGQ6oTVOEr4IqzKK
# KjaQhkRw+CGur71SteIwUmliMJCvwNYgSNdvACElEbYh+qEweB3FdokH4AjcUDf7
# 9hNMrKNruRADRK51b5s3BW1uXCRry4N6scp5v5+wo+anrDJ2fYJxvVlLJO0A2vgE
# wW7fNCQrUFnctNTXStrevwKmw0XHl0t1ftzMybmo85qh6DvKgOZVPV0t4nWL/c0y
# of6Jf1VVXUaRUYYw8Dhb+hCqckCo8bow5YCWclqCzRIVfLcV5R6Qi6GCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjAyMDQxNjUyMDhaMC8GCSqGSIb3DQEJBDEiBCD3
# cM8v7SJ+ccYaWNyc/UuEsuhO8MB34FJ8NUuKA7PvkTANBgkqhkiG9w0BAQEFAASC
# AgB5wfXqL3tBYv/QOmvWInpCAPAyz6ZB6SiUizDxhHzSB7FEqswJiZFwx/rqlKbY
# kQs9Yiexz3yx27mDufip1R9LS5sUSm5uz1Pcg0WoA+VYYpDP5jO7TuE7T+vG2SYq
# 9WzdeS86u3SkZBTBClHPqbMro1EjSDKo7qeT25Q+SSkm9cyPx/4ggOhTGKlTFTLw
# Ui0NMgcyxsDK36R3vzmVLzXw7y0jwDwSyy12nWWAxdNLdmIiJgPtRyFVwcBqNsFC
# Fr3ZaasohC6S7WmiWyvfQY0hob++XGlWw7jA6Nhcft31b50MoPxG5+kIJAdw7fwi
# lFBHpZUPr1HV9ruvsuig9R+GEsOLFOBDnmFnrX8ofWohSVvMOJqo+MjRbr41qubZ
# USQWGDyQJ7832VgCaSbnCuhG/9WKqp/xtfNP9JM4lq6/FLJOvkIKWnjon1ziN/NY
# NWc+n20zUPnk+fcTChstwSo7qKWYUPvotygaGZBCyxQw1oeSr3NigL+lN+FG0hsW
# swraBstG6HZU+RkOa6ugIyVBdjlkwdaKLRGbSPfXN6ZMCp+/dV9yO4xcEjDkq98q
# ZTOLziGpMwEziQyCP6LBfl6BCb4EWRODMitsxL5dZhnIUSmNBDp4rEwWQCOWQYoc
# klb3HwY73H5fQQdnQvzhCrFvP+RWzssLe94poxM3qf4FlQ==
# SIG # End signature block
