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
# MIIJyAYJKoZIhvcNAQcCoIIJuTCCCbUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDb3aORQUSxBwy7
# 8mBqsfBkpUAAeoc2yXDkYpK6eCSdiaCCBdYwggXSMIIDuqADAgECAhAxVnqog0nQ
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
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIC3JG/wEqGPuekTfhoUGBmwlfldAzNbt
# 7RD/ZGJ6V7a1MA0GCSqGSIb3DQEBAQUABIICAC3dNfejnQHeN9Du4yu5mBseL5OF
# HGl1AJUAPrOIuK1TOilYNLJ8+x+CQOBxFAscdB+GZaCKgpA3ItrmIcEys3ocY0Ah
# VMcjuko/ZxREiXWUNH2LmWQzSjELIjfJB4+EmfFp6FlYMwkOfqpkKg3sMnV9mDRT
# qjcvOIOr4sts22oMZcwnEZrVtfXSj3Xv/ac4LaKjtoe4kKnzX7jx8jDpIBL79gWT
# sFPeNQwQrKheqGL5UOsACb5UvxzPK3X72JhnJQcqqLPCV/9bDDdRTsx8pDkdXNsS
# /F4kDo97ENmq0HXXbKJymZGZ817rJN84GTAw229MZHr5P6ETqyzG8P88GrQJ0q2Q
# gLu7D376RSBoYCDQ2awAhC461t1Kf5Q17pPZs2SvCpEJmc5H+qq5KVXCW0pQ6Ql0
# d6Cir+mCfOkVxXqLRsq/udhr1UhZGyPmuFrjEkXI419dBAwxxCNWlLvkyEOeKIq9
# adRYFI5bog1RlUspr6W3OAdoe7iYjom66Usjh/qk0p6VBnZqECJ57GoY9FGApe3Y
# +izUob+aG9gll6Yn2RdiMa2jAFjKOPfITja53FYyXzBAcKeWy5n7cYn6DG6nvz1x
# X7iIRxy+SuiBKch5v49It1WmPJ3c3Z5/DkLWXKBFYNP1tNjDLQWSEwMXvXPvs2ha
# XN4mQgJT93Xocl2/
# SIG # End signature block

