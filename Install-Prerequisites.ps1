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

