# IdentityFirst QuickChecks - Deployment Guide

## Overview

This guide covers multiple methods for deploying and distributing IdentityFirst QuickChecks from GitHub to end users. Each approach has different use cases, automation levels, and maintenance requirements.

---

## Table of Contents

1. [Deployment Options Overview](#deployment-options-overview)
2. [Option 1: PowerShell Gallery](#option-1-powershell-gallery)
3. [Option 2: GitHub Release Package](#option-2-github-release-package)
4. [Option 3: Git Submodule](#option-3-git-submodule)
5. [Option 4: Direct Clone & Import](#option-4-direct-clone--import)
6. [Option 5: Chocolatey/NuGet](#option-5-chocolateynuget)
7. [Installation Scripts](#installation-scripts)
8. [CI/CD Pipeline Integration](#cicd-pipeline-integration)
9. [Containerized Deployment](#containerized-deployment)
10. [Enterprise Distribution](#enterprise-distribution)

---

## Deployment Options Overview

| Method | Pros | Cons | Best For |
|--------|------|------|----------|
| **PowerShell Gallery** | Auto-update, familiar to PowerShell users | Requires approval, limited control | Open source, community |
| **GitHub Release** | Full control, versioned releases | Manual updates | Enterprise, offline |
| **Git Submodule** | Version control integration | Complex setup | DevOps teams |
| **Direct Clone** | Simple, always latest | No auto-update | Quick start |
| **Chocolatey** | Windows ecosystem integration | Package maintenance | Desktop deployment |
| **Container** | Isolated environment | Additional complexity | CI/CD, automation |

---

## Option 1: PowerShell Gallery

### Prerequisites

1. Create PowerShell Gallery account: https://www.powershellgallery.com
2. Generate API key in account settings
3. Prepare module manifest

### Step 1: Create Module Manifest

```powershell
# IdentityFirst.QuickChecks.psd1

@{
    ModuleVersion = '1.0.0'
    GUID = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
    Author = 'IdentityFirst Ltd'
    CompanyName = 'IdentityFirst Ltd'
    Copyright = '© 2026 IdentityFirst Ltd. All rights reserved.'
    Description = 'Comprehensive identity security assessment platform with 106+ checks'
    
    PowerShellVersion = '5.1'
    PowerShellHostName = 'ConsoleHost'
    PowerShellHostVersion = '5.1'
    
    RequiredModules = @(
        @{ ModuleName = 'Az.Accounts'; ModuleVersion = '2.0.0' }
        @{ ModuleName = 'Az.Resources'; ModuleVersion = '6.0.0' }
        @{ ModuleName = 'AWS.Tools.Common'; ModuleVersion = '4.0.0' }
        @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '1.0' }
    )
    
    FunctionsToExport = @(
        'Invoke-AllIdentityQuickChecks',
        'Invoke-EntraIdMfaCheck',
        'Invoke-AzureRbacCheck',
        'Invoke-AwsIamCheck',
        'Invoke-GcpIamCheck',
        'New-QuickChecksDashboard'
    )
    
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    
    PrivateData = @{
        PSData = @{
            Tags = @(
                'Identity',
                'Security',
                'Azure',
                'AWS',
                'GCP',
                'ActiveDirectory',
                'EntraID',
                'Compliance',
                'Assessment'
            )
            ProjectURI = 'https://github.com/identityfirst/quickchecks'
            LicenseURI = 'https://github.com/identityfirst/quickchecks/blob/main/LICENSE'
            IconURI = 'https://raw.githubusercontent.com/identityfirst/quickchecks/main/docs/icon.png'
            ReleaseNotes = 'See CHANGELOG.md'
            RequireLicenseAcceptance = $false
            ExternalModuleDependencies = @(
                'Az.Accounts',
                'Az.Resources',
                'AWS.Tools.Common',
                'Microsoft.Graph.Authentication'
            )
        }
    }
}
```

### Step 2: Prepare for Publishing

```powershell
# Script: Publish-Module.ps1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ApiKey,
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'

Write-Host "Preparing IdentityFirst.QuickChecks for publication..." -ForegroundColor Cyan

# Verify module structure
$moduleRoot = "$PSScriptRoot\IdentityFirst.QuickChecks"
if (-not (Test-Path "$moduleRoot\IdentityFirst.QuickChecks.psd1")) {
    throw "Module manifest not found"
}

# Verify all module files exist
$requiredFiles = @(
    'IdentityFirst.QuickChecks.psd1',
    'IdentityFirst.QuickChecks.psm1',
    'IdentityFirst.QuickChecks.Lite.psm1',
    'IdentityFirst.QuickChecks.EntraID.psm1',
    'IdentityFirst.QuickChecks.Extended.psm1',
    'IdentityFirst.QuickChecks.Validation.psm1',
    'IdentityFirst.QuickChecks.Additional.psm1',
    'IdentityFirst.QuickChecks.Extended2.psm1',
    'IdentityFirst.QuickChecks.Compliance.psm1',
    'IdentityFirst.QuickChecks.Enterprise.psm1',
    'IdentityFirst.QuickChecks.Federation.psm1'
)

foreach ($file in $requiredFiles) {
    if (-not (Test-Path "$moduleRoot\$file")) {
        Write-Warning "Missing file: $file"
    }
}

# Import and validate module
Import-Module "$moduleRoot\IdentityFirst.QuickChecks.psd1" -Force

# Get module info
$moduleInfo = Get-Module -Name 'IdentityFirst.QuickChecks'
Write-Host "Module: $($moduleInfo.Name) v$($moduleInfo.Version)" -ForegroundColor Green
Write-Host "Exported Functions: $($moduleInfo.ExportedFunctions.Count)"

# Publish to Gallery
if (-not $WhatIf) {
    if (-not $ApiKey) {
        $ApiKey = Read-Host "Enter PowerShell Gallery API Key" -AsSecureString
        $ApiKey = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ApiKey)
        )
    }
    
    Publish-Module -Path $moduleRoot -NuGetApiKey $ApiKey -Verbose
    Write-Host "Module published to PowerShell Gallery!" -ForegroundColor Green
}
else {
    Write-Host "[WhatIf] Module would be published" -ForegroundColor Yellow
}
```

### Step 3: GitHub Actions Workflow

```yaml
# .github/workflows/publish-gallery.yml
name: Publish to PowerShell Gallery

on:
  release:
    types: [published]
  workflow_dispatch:
    inputs:
      version:
        description: 'Version number'
        required: true

jobs:
  publish:
    runs-on: windows-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Setup PowerShell
      uses: actions/powershell@v4
      with:
        shell: pwsh
        version: 5.1
    
    - name: Install dependencies
      run: |
        Install-Module -Name Az.Accounts -Scope CurrentUser -Force
        Install-Module -Name Az.Resources -Scope CurrentUser -Force
        Install-Module -Name AWS.Tools.Common -Scope CurrentUser -Force
        Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser -Force
    
    - name: Validate module
      run: |
        $ErrorActionPreference = 'Stop'
        Import-Module "./IdentityFirst.QuickChecks/IdentityFirst.QuickChecks.psd1" -Force
        $module = Get-Module -Name IdentityFirst.QuickChecks
        Write-Host "Module Version: $($module.Version)"
        Write-Host "Functions: $($module.ExportedFunctions.Count)"
    
    - name: Publish to Gallery
      if: github.event_name == 'release'
      env:
        PS_GALLERY_API_KEY: ${{ secrets.PS_GALLERY_API_KEY }}
      run: |
        Publish-Module -Path "./IdentityFirst.QuickChecks" -NuGetApiKey $env:PS_GALLERY_API_KEY -Verbose
```

---

## Option 2: GitHub Release Package

### Step 1: Create Release Script

```powershell
# scripts/Create-Release.ps1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Version = (Get-Content -Path 'VERSION.txt' -Raw).Trim(),
    
    [Parameter(Mandatory=$false)]
    [string]$OutputDir = ".\release\$Version"
)

$ErrorActionPreference = 'Stop'

Write-Host "Creating IdentityFirst QuickChecks v$Version release package..." -ForegroundColor Cyan

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Copy module files
$moduleDir = "$OutputDir\IdentityFirst.QuickChecks"
New-Item -ItemType Directory -Path $moduleDir -Force | Out-Null

$filesToCopy = @(
    'IdentityFirst.QuickChecks.psd1',
    'IdentityFirst.QuickChecks.psm1',
    'IdentityFirst.QuickChecks.Lite.psm1',
    'IdentityFirst.QuickChecks.EntraID.psm1',
    'IdentityFirst.QuickChecks.Extended.psm1',
    'IdentityFirst.QuickChecks.Validation.psm1',
    'IdentityFirst.QuickChecks.Additional.psm1',
    'IdentityFirst.QuickChecks.Extended2.psm1',
    'IdentityFirst.QuickChecks.Compliance.psm1',
    'IdentityFirst.QuickChecks.Enterprise.psm1',
    'IdentityFirst.QuickChecks.Federation.psm1'
)

foreach ($file in $filesToCopy) {
    if (Test-Path $file) {
        Copy-Item $file -Destination $moduleDir -Force
        Write-Host "  Copied: $file" -ForegroundColor Gray
    }
}

# Copy scripts
$scriptsDir = "$OutputDir\scripts"
New-Item -ItemType Directory -Path $scriptsDir -Force | Out-Null

$scriptsToCopy = @(
    'Invoke-AllIdentityQuickChecks.ps1',
    'New-QuickChecksDashboard.ps1',
    'Install-Prerequisites.ps1',
    'Run-AllQuickChecks.ps1'
)

foreach ($file in $scriptsToCopy) {
    if (Test-Path $file) {
        Copy-Item $file -Destination $scriptsDir -Force
        Write-Host "  Copied: $file" -ForegroundColor Gray
    }
}

# Copy documentation
$docsDir = "$OutputDir\docs"
New-Item -ItemType Directory -Path $docsDir -Force | Out-Null

$docsToCopy = @(
    'README.md',
    'CHANGELOG.md',
    'docs/ARCHITECTURE.md',
    'docs/DEPLOYMENT.md'
)

foreach ($file in $docsToCopy) {
    if (Test-Path $file) {
        Copy-Item $file -Destination $docsDir -Force
        Write-Host "  Copied: $file" -ForegroundColor Gray
    }
}

# Create ZIP archive
$zipPath = ".\IdentityFirst.QuickChecks-$Version.zip"
Compress-Archive -Path "$OutputDir\*" -DestinationPath $zipPath -Force

Write-Host "`nRelease package created: $zipPath" -ForegroundColor Green
Write-Host "Size: $((Get-Item $zipPath).Length / 1MB) MB" -ForegroundColor Gray

# Generate checksum
$checksum = (Get-FileHash $zipPath -Algorithm SHA256).Hash
"IdentityFirst.QuickChecks-$Version.zip`nSHA256: $checksum" | Out-File -FilePath ".\IdentityFirst.QuickChecks-$Version.sha256"

Write-Host "Checksum: $checksum" -ForegroundColor Gray
```

### Step 2: GitHub Release Action

```yaml
# .github/workflows/create-release.yml
name: Create Release

on:
  workflow_dispatch:
    inputs:
      version:
        description: 'Version number'
        required: true
      prerelease:
        description: 'Mark as prerelease'
        required: false
        default: 'false'

jobs:
  release:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Setup PowerShell
      uses: actions/powershell@v4
      with:
        shell: pwsh
        version: 5.1
    
    - name: Create release package
      run: ./scripts/Create-Release.ps1 -Version ${{ github.event.inputs.version }}
    
    - name: Create Release
      uses: softprops/action-gh-release@v2
      with:
        files: |
          IdentityFirst.QuickChecks-*.zip
          IdentityFirst.QuickChecks-*.sha256
        name: Release v${{ github.event.inputs.version }}
        body_path: CHANGELOG.md
        prerelease: ${{ github.event.inputs.prerelease }}
        generate_release_notes: true
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Step 3: Install from Release Script

```powershell
# Install-QuickChecks.ps1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Version = '1.0.0',
    
    [Parameter(Mandatory=$false)]
    [string]$InstallPath = "$env:ProgramFiles\WindowsPowerShell\Modules\IdentityFirst.QuickChecks",
    
    [Parameter(Mandatory=$false)]
    [switch]$Force
)

Write-Host "Installing IdentityFirst QuickChecks v$Version..." -ForegroundColor Cyan

$ErrorActionPreference = 'Stop'

# Download release
$zipUrl = "https://github.com/identityfirst/quickchecks/releases/download/v$Version/IdentityFirst.QuickChecks-$Version.zip"
$zipPath = "$env:TEMP\IdentityFirst.QuickChecks-$Version.zip"
$tempDir = "$env:TEMP\IdentityFirst.QuickChecks-$Version"

Write-Host "Downloading from $zipUrl..." -ForegroundColor Gray
Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing

# Verify checksum
Write-Host "Verifying checksum..." -ForegroundColor Gray
$checksumUrl = "$zipUrl.sha256"
$expectedChecksum = (Invoke-WebRequest -Uri $checksumUrl -UseBasicParsing).Content.Trim()
$actualChecksum = (Get-FileHash $zipPath -Algorithm SHA256).Hash

if ($actualChecksum -ne $expectedChecksum) {
    throw "Checksum mismatch! Expected: $expectedChecksum, Got: $actualChecksum"
}
Write-Host "Checksum verified!" -ForegroundColor Green

# Extract
Write-Host "Extracting files..." -ForegroundColor Gray
Expand-Archive -Path $zipPath -DestinationPath $tempDir -Force

# Install
if (Test-Path $InstallPath) {
    if ($Force) {
        Remove-Item -Path $InstallPath -Recurse -Force
    }
    else {
        throw "Module already exists at $InstallPath. Use -Force to reinstall."
    }
}

New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
Copy-Item -Path "$tempDir\IdentityFirst.QuickChecks\*" -Destination $InstallPath -Recurse

# Cleanup
Remove-Item -Path $zipPath -Force
Remove-Item -Path $tempDir -Recurse -Force

# Verify installation
Import-Module -Name 'IdentityFirst.QuickChecks' -Force -ErrorAction Stop
$module = Get-Module -Name 'IdentityFirst.QuickChecks'

Write-Host "`nInstallation complete!" -ForegroundColor Green
Write-Host "  Module: $($module.Name) v$($module.Version)" -ForegroundColor White
Write-Host "  Location: $InstallPath" -ForegroundColor Gray
Write-Host "  Commands: $($module.ExportedFunctions.Count) functions available" -ForegroundColor Gray
```

---

## Option 3: Git Submodule

### Step 1: Add as Submodule

```bash
# In your repository
git submodule add https://github.com/identityfirst/quickchecks.git lib/identityfirst-quickchecks
git submodule update --init --recursive
```

### Step 2: Wrapper Script

```powershell
# Invoke-QuickChecks.ps1

[CmdletBinding()]
param(
    [switch]$AllPlatforms,
    [switch]$EntraId,
    [switch]$Azure,
    [switch]$GenerateDashboard
)

$ErrorActionPreference = 'Stop'

# Determine module path
$modulePath = "$PSScriptRoot\lib\identityfirst-quickchecks\IdentityFirst.QuickChecks"

# Import module
Import-Module "$modulePath\IdentityFirst.QuickChecks.psd1" -Force

# Run checks
$params = @{}
if ($AllPlatforms) { $params['AllPlatforms'] = $true }
if ($EntraId) { $params['EntraId'] = $true }
if ($Azure) { $params['Azure'] = $true }

$result = Invoke-AllIdentityQuickChecks @params

# Generate dashboard if requested
if ($GenerateDashboard) {
    $dashboardScript = "$modulePath\New-QuickChecksDashboard.ps1"
    & $dashboardScript -JsonReport $result
}

return $result
```

### Step 3: Update Script

```bash
#!/bin/bash
# update-quickchecks.sh

cd "$(dirname "$0")"
git submodule update --remote --merge
echo "IdentityFirst QuickChecks updated!"
```

---

## Option 4: Direct Clone & Import

### Quick Install Script

```powershell
# Install-Direct.ps1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$RepoUrl = 'https://github.com/identityfirst/quickchecks.git',
    
    [Parameter(Mandatory=$false)]
    [string]$InstallDir = "$env:ProgramFiles\WindowsPowerShell\Modules\IdentityFirst.QuickChecks",
    
    [Parameter(Mandatory=$false)]
    [string]$Branch = 'main'
)

Write-Host "Cloning IdentityFirst QuickChecks..." -ForegroundColor Cyan

$tempDir = "$env:TEMP\quickchecks-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
git clone $RepoUrl $tempDir --branch $Branch --single-branch

Write-Host "Installing to $InstallDir..." -ForegroundColor Cyan
if (Test-Path $InstallDir) {
    Remove-Item $InstallDir -Recurse -Force
}
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item "$tempDir\*" -Destination $InstallDir -Recurse

# Cleanup
Remove-Item $tempDir -Recurse -Force

# Import and verify
Import-Module 'IdentityFirst.QuickChecks' -Force -ErrorAction Stop
Get-Module -Name 'IdentityFirst.QuickChecks' | Format-List Name, Version, Path

Write-Host "Installation complete!" -ForegroundColor Green
```

### One-Liner Install

```powershell
# PowerShell one-liner
git clone https://github.com/identityfirst/quickchecks.git "$env:ProgramFiles\WindowsPowerShell\Modules\IdentityFirst.QuickChecks"; Import-Module 'IdentityFirst.QuickChecks'; Get-Module IdentityFirst.QuickChecks
```

---

## Option 5: Chocolatey Package

### Package Definition

```xml
<!-- identityfirst-quickchecks.nuspec -->
<?xml version="1.0" encoding="utf-8"?>
<package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd">
  <metadata>
    <id>identityfirst-quickchecks</id>
    <version>1.0.0</version>
    <title>IdentityFirst QuickChecks</title>
    <authors>IdentityFirst Ltd</authors>
    <projectUrl>https://github.com/identityfirst/quickchecks</projectUrl>
    <licenseUrl>https://raw.githubusercontent.com/identityfirst/quickchecks/main/LICENSE</licenseUrl>
    <requireLicenseAcceptance>false</requireLicenseAcceptance>
    <description>
      Comprehensive identity security assessment platform with 106+ checks for
      Entra ID, Azure, AWS, GCP, Active Directory, Okta, and hybrid environments.
    </description>
    <tags>identity security azure aws gcp entra compliance assessment</tags>
    <dependencies>
      <dependency id="powershell-core" version="7.0.0" />
      <dependency id="az.module" version="5.0.0" />
      <dependency id="aws.tools.common" version="4.0.0" />
    </dependencies>
  </metadata>
  <files>
    <file src="tools\**\*" target="tools" />
  </files>
</package>
```

### Install Script (chocolateyInstall.ps1)

```powershell
$ErrorActionPreference = 'Stop'

$packageName = 'identityfirst-quickchecks'
$toolsDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Install module
$modulePath = "$env:ProgramFiles\WindowsPowerShell\Modules\$packageName"
New-Item -ItemType Directory -Path $modulePath -Force -ErrorAction SilentlyContinue | Out-Null

Copy-Item "$toolsDir\identityfirst-quickchecks\*" -Destination $modulePath -Recurse

# Verify
Import-Module -Name $packageName -Force
Write-Host "$packageName installed successfully!" -ForegroundColor Green
```

### Chocolatey Commands

```bash
# Install
choco install identityfirst-quickchecks

# Upgrade
choco upgrade identityfirst-quickchecks

# Uninstall
choco uninstall identityfirst-quickchecks
```

---

## Installation Scripts

### Cross-Platform Install Script

```powershell
#!/usr/bin/env pwsh
# install-identityfirst.ps1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('Gallery', 'GitHub', 'Chocolatey')]
    [string]$Method = 'GitHub',
    
    [Parameter(Mandatory=$false)]
    [string]$Version = '1.0.0'
)

$ErrorActionPreference = 'Stop'

function Write-Header {
    param([string]$Text)
    Write-Host "`n$('=' * 60)" -ForegroundColor Cyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host "$('=' * 60)`n" -ForegroundColor Cyan
}

Write-Header 'IdentityFirst QuickChecks Installation'

# Detect PowerShell version
$psVersion = $PSVersionTable.PSVersion
Write-Host "PowerShell Version: $($psVersion.ToString())"
if ($psVersion.Major -lt 5) {
    Write-Warning "PowerShell 5.1 or higher recommended"
}

# Install dependencies
Write-Host "Installing dependencies..." -ForegroundColor Cyan
$dependencies = @(
    @{ Name = 'Az.Accounts'; Source = 'PowerShellGallery' }
    @{ Name = 'Microsoft.Graph.Authentication'; Source = 'PowerShellGallery' }
)

foreach ($dep in $dependencies) {
    $module = Get-Module -ListAvailable -Name $dep.Name -ErrorAction SilentlyContinue
    if (-not $module) {
        Write-Host "  Installing $($dep.Name)..." -ForegroundColor Gray
        Install-Module -Name $dep.Name -Scope CurrentUser -Force -AllowPrerelease
    }
    else {
        Write-Host "  $($dep.Name) already installed" -ForegroundColor Gray
    }
}

# Install based on method
switch ($Method) {
    'Gallery' {
        Write-Host "Installing from PowerShell Gallery..." -ForegroundColor Cyan
        Install-Module -Name 'IdentityFirst.QuickChecks' -Scope CurrentUser -Force
        Import-Module -Name 'IdentityFirst.QuickChecks' -Force
    }
    
    'GitHub' {
        Write-Host "Installing from GitHub..." -ForegroundColor Cyan
        $releaseUrl = "https://api.github.com/repos/identityfirst/quickchecks/releases/latest"
        $releaseInfo = Invoke-RestMethod -Uri $releaseUrl
        $zipUrl = $releaseInfo.assets | Where-Object { $_.name -match 'zip' } | Select-Object -First 1
        
        $zipPath = "$env:TEMP\IdentityFirst.QuickChecks.zip"
        Invoke-WebRequest -Uri $zipUrl.browser_download_url -OutFile $zipPath
        
        $installPath = "$env:ProgramFiles\WindowsPowerShell\Modules\IdentityFirst.QuickChecks"
        Expand-Archive -Path $zipPath -DestinationPath $installPath -Force
        
        Import-Module -Name 'IdentityFirst.QuickChecks' -Force
    }
    
    'Chocolatey' {
        Write-Host "Using Chocolatey..." -ForegroundColor Cyan
        if (Get-Command choco -ErrorAction SilentlyContinue) {
            choco install identityfirst-quickchecks -y
        }
        else {
            throw 'Chocolatey not installed. Visit https://chocolatey.org/'
        }
    }
}

# Verify installation
Write-Host "`nVerifying installation..." -ForegroundColor Cyan
$module = Get-Module -Name 'IdentityFirst.QuickChecks'
if ($module) {
    Write-Host "✓ Module installed: $($module.Name) v$($module.Version)" -ForegroundColor Green
    Write-Host "✓ Location: $($module.Path)" -ForegroundColor Gray
    Write-Host "✓ Functions: $($module.ExportedFunctions.Count) exported" -ForegroundColor Gray
    
    Write-Host "`nAvailable commands:" -ForegroundColor Cyan
    $module.ExportedFunctions.Keys | Select-Object -First 10 | ForEach-Object {
        Write-Host "  - $_" -ForegroundColor Gray
    }
    
    Write-Host "`nUsage examples:" -ForegroundColor Cyan
    Write-Host "  Invoke-AllIdentityQuickChecks -AllPlatforms" -ForegroundColor Gray
    Write-Host "  Invoke-AllIdentityQuickChecks -EntraId" -ForegroundColor Gray
    Write-Host "  New-QuickChecksDashboard -JsonReport report.json" -ForegroundColor Gray
}
else {
    Write-Error "Installation failed!"
}

Write-Host "`nInstallation complete!" -ForegroundColor Green
```

---

## CI/CD Pipeline Integration

### Azure DevOps Pipeline

```yaml
# azure-pipelines.yml
trigger:
- main
- release/*

pool:
  vmImage: 'windows-latest'

variables:
  moduleName: 'IdentityFirst.QuickChecks'
  buildDir: '$(Build.ArtifactStagingDirectory)'
  
stages:
- stage: Build
  jobs:
  - job: BuildJob
    steps:
    - checkout: self
      submodule: true
    
    - task: UsePowerShell@5
      displayName: 'Setup PowerShell'
      inputs:
        targetType: 'inline'
        script: '$PSVersionTable.PSVersion'
    
    - task: PowerShell@5
      displayName: 'Validate Module'
      inputs:
        targetType: 'filePath'
        filePath: './scripts/Test-Module.ps1'
    
    - task: PublishPipelineArtifact@1
      displayName: 'Publish Artifacts'
      inputs:
        targetPath: '$(buildDir)'
        artifact: 'quickchecks'

- stage: Test
  dependsOn: Build
  jobs:
  - job: TestJob
    steps:
    - download: current
      artifact: quickchecks
    
    - task: PowerShell@5
      displayName: 'Run QuickChecks'
      inputs:
        targetType: 'inline'
        script: |
          Import-Module '$(Pipeline.Workspace)/quickchecks/IdentityFirst.QuickChecks.psd1'
          Invoke-AllIdentityQuickChecks -AllPlatforms -OutputDir '$(Build.ArtifactStagingDirectory)/results'
    
    - task: PublishPipelineArtifact@1
      displayName: 'Publish Results'
      inputs:
        targetPath: '$(Build.ArtifactStagingDirectory)/results'
        artifact: 'results'

- stage: Release
  dependsOn: Test
  condition: and(succeeded(), startsWith(variables['Build.SourceBranch'], 'refs/heads/release/'))
  jobs:
  - job: ReleaseJob
    steps:
    - download: current
      artifact: quickchecks
    
    - task: UsePowerShell@5
      displayName: 'Create Release'
      inputs:
        targetType: 'filePath'
        filePath: './scripts/Create-Release.ps1'
    
    - task: GitHubRelease@1
      displayName: 'Publish to GitHub'
      inputs:
        gitHubConnection: 'github-connection'
        repositoryName: 'identityfirst/quickchecks'
        action: 'create'
        target: '$(Build.SourceVersion)'
        tagSource: 'userSpecifiedTag'
        tag: 'v$(Build.BuildNumber)'
        title: 'Release v$(Build.BuildNumber)'
        releaseNotesSource: 'filePath'
        releaseNotesFile: 'CHANGELOG.md'
        assets: '$(Build.ArtifactStagingDirectory)/*.zip'
```

### GitHub Actions Workflow

```yaml
# .github/workflows/ci.yml
name: CI/CD Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  validate:
    runs-on: windows-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: Setup PowerShell
      uses: actions/powershell@v4
      with:
        shell: pwsh
        version: 5.1
    
    - name: Install dependencies
      run: |
        Install-Module Az.Accounts -Scope CurrentUser -Force
        Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
        Install-Module AWS.Tools.Common -Scope CurrentUser -Force
    
    - name: Validate module
      run: |
        Import-Module './IdentityFirst.QuickChecks/IdentityFirst.QuickChecks.psd1' -Force
        $module = Get-Module IdentityFirst.QuickChecks
        Write-Host "Module: $($module.Name) v$($module.Version)"
        Write-Host "Functions: $($module.ExportedFunctions.Count)"
    
    - name: Run tests
      run: |
        ./scripts/Test-Module.ps1
    
    - name: Upload artifacts
      uses: actions/upload-artifact@v4
      with:
        name: quickchecks
        path: IdentityFirst.QuickChecks/

  release:
    needs: validate
    if: startsWith(github.ref, 'refs/tags/v')
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: Download artifacts
      uses: actions/download-artifact@v4
      with:
        name: quickchecks
        path: IdentityFirst.QuickChecks/
    
    - name: Create release package
      run: ./scripts/Create-Release.ps1 -Version ${{ github.ref_name }}
    
    - name: Create Release
      uses: softprops/action-gh-release@v2
      with:
        files: IdentityFirst.QuickChecks-*.zip
        generate_release_notes: true
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

---

## Containerized Deployment

### Docker Image

```dockerfile
# Dockerfile
FROM mcr.microsoft.com/powershell:5.1-alpine-3.14

# Labels
LABEL maintainer="IdentityFirst Ltd <support@identityfirst.io>"
LABEL description="IdentityFirst QuickChecks - Identity Security Assessment Platform"
LABEL version="1.0.0"

# Install dependencies
RUN pwsh -Command {
    Install-Module Az.Accounts -Scope AllUsers -Force -AllowPrerelease
    Install-Module Az.Resources -Scope AllUsers -Force
    Install-Module Microsoft.Graph.Authentication -Scope AllUsers -Force
    Install-Module AWS.Tools.Common -Scope AllUsers -Force
}

# Copy module files
COPY IdentityFirst.QuickChecks /opt/Microsoft/WindowsPowerShell/Modules/IdentityFirst.QuickChecks/

# Create working directory
WORKDIR /quickchecks

# Copy scripts
COPY scripts/*.ps1 /quickchecks/

# Set entrypoint
ENTRYPOINT ["pwsh", "/quickchecks/run.ps1"]
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  identityfirst-quickchecks:
    build: .
    container_name: identityfirst-quickchecks
    environment:
      - AZURE_TENANT_ID=${AZURE_TENANT_ID}
      - AZURE_CLIENT_ID=${AZURE_CLIENT_ID}
      - AZURE_CLIENT_SECRET=${AZURE_CLIENT_SECRET}
      - AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
      - AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
    volumes:
      - ./output:/quickchecks/output
      - ./config:/quickchecks/config
    command: >
      pwsh -Command {
        Invoke-AllIdentityQuickChecks
          -AllPlatforms
          -OutputDir /quickchecks/output
          -TenantId $env:AZURE_TENANT_ID
      }

  identityfirst-scheduler:
    build: .
    container_name: identityfirst-scheduler
    environment:
      - AZURE_TENANT_ID=${AZURE_TENANT_ID}
    volumes:
      - ./output:/quickchecks/output
      - ./schedules:/quickchecks/schedules
    entrypoint: ["pwsh", "/quickchecks/scheduler.ps1"]
    command: ["--schedule", "0 2 * * *"]  # Run at 2 AM daily
```

### Kubernetes Deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: identityfirst-quickchecks
  namespace: security
spec:
  replicas: 1
  selector:
    matchLabels:
      app: identityfirst-quickchecks
  template:
    metadata:
      labels:
        app: identityfirst-quickchecks
    spec:
      serviceAccountName: identityfirst-sa
      containers:
      - name: quickchecks
        image: identityfirst/quickchecks:latest
        env:
        - name: AZURE_TENANT_ID
          valueFrom:
            secretKeyRef:
              name: azure-credentials
              key: tenant-id
        - name: AZURE_CLIENT_ID
          valueFrom:
            secretKeyRef:
              name: azure-credentials
              key: client-id
        - name: AZURE_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: azure-credentials
              key: client-secret
        volumeMounts:
        - name: results
          mountPath: /quickchecks/results
      volumes:
      - name: results
        persistentVolumeClaim:
          claimName: identityfirst-results
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: quickchecks-config
  namespace: security
data:
  SCHEDULE: "0 2 * * 0"  # Weekly on Sunday at 2 AM
  OUTPUT_FORMAT: "json"
```

---

## Enterprise Distribution

### Group Policy Installation

```powershell
# scripts/EnterpriseInstall.ps1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$SourcePath = '\\server\share\quickchecks',
    
    [Parameter(Mandatory=$false)]
    [string]$InstallPath = '\\domain\sysvol\$(ADDomain)\Policies\{GUID}\User\WindowsPowerShell\Modules\IdentityFirst.QuickChecks',
    
    [Parameter(Mandatory=$false)]
    [switch]$MachineWide
)

$ErrorActionPreference = 'Stop'

Write-Host "Enterprise Deployment of IdentityFirst QuickChecks" -ForegroundColor Cyan

# Get domain info
$domain = Get-ADDomain
$domainName = $domain.DNSRoot
Write-Host "Target Domain: $domainName" -ForegroundColor Gray

# Distribute module
$moduleDest = "\\$domainName\_SYSVOL\$domainName\Policies\"

# Create scheduled task for installation
$taskAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-ExecutionPolicy Bypass -File $SourcePath\scripts\Install-Locally.ps1"
$taskTrigger = New-ScheduledTaskTrigger -AtLogOn
$taskSettings = New-ScheduledTaskSettingsSet -RunOnlyIfNetworkAvailable -StartWhenAvailable

Register-ScheduledTask `
    -TaskName 'Install-IdentityFirstQuickChecks' `
    -Action $taskAction `
    -Trigger $taskTrigger `
    -Settings $taskSettings `
    -User 'NT AUTHORITY\Authenticated Users' `
    -RunLevel 'LeastPrivilege' | Out-Null

Write-Host "Scheduled task created for user logon installation" -ForegroundColor Green

# Or use Intune
Write-Host "`nFor Intune deployment:" -ForegroundColor Cyan
Write-Host "  1. Package script: scripts/Install-Locally.ps1" -ForegroundColor Gray
Write-Host "  2. Upload to Intune as 'PowerShell script'" -ForegroundColor Gray
Write-Host "  3. Configure detection script" -ForegroundColor Gray
```

### Configuration Management

```powershell
# scripts/Install-Locally.ps1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$SourcePath = '\\server\share\quickchecks'
)

# Configure module paths
$modulePath = "$env:ProgramFiles\WindowsPowerShell\Modules\IdentityFirst.QuickChecks"
$configPath = "$modulePath\config\QuickChecks.config.psd1"

# Create config from enterprise settings
$enterpriseConfig = @{
    DefaultOutputDir = "$env:ProgramData\IdentityFirst\QuickChecks\Results"
    DefaultPlatform = 'All'
    TelemetryEnabled = $false
    LogLevel = 'Warning'
    
    Azure = @{
        DefaultSubscription = ''
        TenantId = ''
    }
    
    AWS = @{
        DefaultRegion = 'us-east-1'
        ProfileName = 'default'
    }
    
    Reporting = @{
        GenerateJson = $true
        GenerateHtml = $true
        GenerateCsv = $false
    }
}

# Save enterprise config
$enterpriseConfig | Export-Psd1 -Path $configPath

# Create shortcuts
$shortcutPath = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\IdentityFirst QuickChecks.lnk"
$targetPath = "$PSHOME\powershell.exe"
$arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$modulePath\scripts\Invoke-AllQuickChecks.ps1`""

$wsh = New-Object -ComObject WScript.Shell
$shortcut = $wsh.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $targetPath
$shortcut.Arguments = $arguments
$shortcut.WorkingDirectory = $modulePath
$shortcut.Save()

Write-Host "Enterprise configuration complete!" -ForegroundColor Green
```

---

## Verification Checklist

After deployment, verify:

- [ ] Module imports successfully: `Import-Module IdentityFirst.QuickChecks`
- [ ] Version displays: `Get-Module IdentityFirst.QuickChecks | Select-Object Version`
- [ ] Functions exported: `(Get-Module).ExportedFunctions.Count`
- [ ] Help available: `Get-Help Invoke-AllIdentityQuickChecks`
- [ ] Prerequisite check: `Test-Prerequisites`
- [ ] Sample run: `Invoke-AllIdentityQuickChecks -AllPlatforms -WhatIf`

---

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| Module not found | Ensure `$env:PSModulePath` includes module location |
| DLL loading errors | Install .NET Framework 4.8+ |
| Graph API errors | Verify `Microsoft.Graph` module version |
| AWS module errors | Install AWS Tools for PowerShell |
| Permission denied | Run as Administrator for machine-wide install |
| Git timeout | Increase git config: `http.postBuffer 524288000` |

---

## Support

- **Documentation**: [docs/README.md](docs/README.md)
- **Architecture**: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- **Issues**: GitHub Issues
- **Releases**: [GitHub Releases](https://github.com/identityfirst/quickchecks/releases)
- **PowerShell Gallery**: [IdentityFirst.QuickChecks](https://www.powershellgallery.com/packages/IdentityFirst.QuickChecks)
