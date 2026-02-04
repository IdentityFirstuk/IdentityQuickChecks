# Distribution Guide

This guide covers how to package, version, and distribute IdentityFirst QuickChecks.

## Overview

| Distribution Method | Pros | Cons | Best For |
|--------------------|------|------|----------|
| ZIP Download | Simple, no hosting requirements | Manual updates | Internal distribution |
| PowerShell Gallery | Automatic updates, versioning | Requires approval | Community sharing |
| GitHub Releases | Version history, changelogs | Requires GitHub account | Open source projects |
| Internal Share | No external hosting | Access control complexity | Enterprise |

## Version Management

### Semantic Versioning

IdentityFirst QuickChecks uses [Semantic Versioning](https://semver.org):

```
MAJOR.MINOR.PATCH
- MAJOR: Breaking changes (incompatible API changes)
- MINOR: New features (backwards compatible)
- PATCH: Bug fixes (backwards compatible)
```

### Version File

Update [`VERSION.txt`](VERSION.txt) before packaging:

```
1.1.0
```

### Changelog

Maintain [`CHANGELOG.md`](CHANGELOG.md) following [Keep a Changelog](https://keepachangelog.com):

```markdown
# Changelog

## [1.1.0] - 2026-01-30

### Added
- PowerShell 7 compatibility
- Cross-platform encoding support

### Changed
- Improved error handling
- Enhanced JSON output

### Fixed
- Empty catch blocks
- DateTime null checks
```

## Packaging

### Using Package Script

```powershell
# Basic package
.\Package-QuickChecks.ps1

# With version
.\Package-QuickChecks.ps1 -Version "1.1.0"

# With digital signatures
.\Package-QuickChecks.ps1 -SignScripts

# Skip documentation
.\Package-QuickChecks.ps1 -NoDocumentation

# Custom output
.\Package-QuickChecks.ps1 -OutputPath ".\dist"
```

### Output

Creates: `IdentityFirst.QuickChecks-v{version}.zip`

Contents:
```
IdentityFirst.QuickChecks-v1.1.0/
├── Module/
│   ├── IdentityFirst.QuickChecks.psd1
│   └── IdentityFirst.QuickChecks.psm1
├── Checks/
│   ├── ActiveDirectory/
│   ├── Entra/
│   ├── AWS/
│   └── GCP/
├── Shared/
│   └── ReportFormatter.psm1
├── Run-AllQuickChecks.ps1
├── README.md
└── EULA.txt
```

## Installation

### Quick Install (Recommended)

```powershell
# Download and extract ZIP, then run:
.\Install-QuickChecks.ps1

# All users (requires admin)
.\Install-QuickChecks.ps1 -AllUsers

# Force overwrite
.\Install-QuickChecks.ps1 -Force
```

### Manual Installation

```powershell
# Current user
Copy-Item -Recurse "IdentityFirst.QuickChecks" "$env:USERPROFILE\Documents\WindowsPowerShell\Modules\"

# All users (admin required)
Copy-Item -Recurse "IdentityFirst.QuickChecks" "$env:ProgramFiles\WindowsPowerShell\Modules\"
```

### Import and Use

```powershell
# Import module
Import-Module IdentityFirst.QuickChecks

# List commands
Get-Command -Module IdentityFirst.QuickChecks

# Run checks
Invoke-BreakGlassReality
Invoke-PasswordPolicyDrift
```

## Distribution Channels

### 1. Website Download

For direct downloads from your website:

1. **Package the release**
   ```powershell
   .\Package-QuickChecks.ps1 -Version "1.1.0" -NoDocumentation
   ```

2. **Sign the package** (optional but recommended)
   ```powershell
   .\Sign-QuickChecks.ps1 -CertPath ".\cert.pfx"
   ```

3. **Upload to website**
   - Upload ZIP file
   - Upload checksum file (SHA256)
   - Upload signature file (if signed)

4. **Provide installation instructions**
   ```powershell
   # Download ZIP
   # Extract to Downloads
   # Run Install-QuickChecks.ps1
   ```

### 2. PowerShell Gallery

For direct installation from PowerShell Gallery:

1. **Prepare module manifest**
   - Update [`Module/IdentityFirst.QuickChecks.psd1`](Module/IdentityFirst.QuickChecks.psd1)
   - Set tags, description, license URI

2. **Publish to Gallery**
   ```powershell
   Publish-Module -Path ".\Module\IdentityFirst.QuickChecks" -NuGetApiKey "YOUR_API_KEY"
   ```

3. **Users install directly**
   ```powershell
   Install-Module IdentityFirst.QuickChecks
   ```

**Pros:**
- Automatic updates: `Update-Module IdentityFirst.QuickChecks`
- Version management
- No manual download needed

**Cons:**
- Requires PowerShell Gallery approval
- May not suit internal-only distributions

### 3. GitHub Releases

For open-source distribution:

1. **Create GitHub Release**
   ```bash
   git tag v1.1.0
   git push origin v1.1.0
   gh release create v1.1.0 --title "IdentityFirst QuickChecks v1.1.0" --notes "CHANGELOG.md"
   ```

2. **Upload assets**
   - ZIP package
   - SHA256 checksum

3. **Users download from Releases page**

### 4. Internal Share (Enterprise)

For enterprise deployment:

1. **Package with versioned folder**
   ```
   \\server\share\IdentityFirst\QuickChecks\v1.1.0\
   ```

2. **Use Group Policy** or **Intune** to deploy

3. **Set up update mechanism**
   - Scheduled task to check for updates
   - SCCM/Intune package deployment

## Digital Signatures

### Why Sign?

- **Trust**: Users verify the code came from you
- **Integrity**: Detects tampering
- **Security**: PowerShell execution policy

### Signing Requirements

| Certificate Type | Use Case |
|-----------------|----------|
| Code Signing (OV) | General distribution |
| Code Signing (EV) | Highest trust, fewer warnings |
| Self-signed | Testing only |

### Using the Sign Script

```powershell
# Sign with PFX file
.\Sign-QuickChecks.ps1 -CertPath ".\cert.pfx" -CertPassword (Read-Host "Password" -AsSecureString)

# Dry run (see what would be signed)
.\Sign-QuickChecks.ps1 -DryRun

# Sign specific files
.\Sign-QuickChecks.ps1 -FilePath ".\Checks\*.ps1"
```

### Verification

Users can verify signatures:

```powershell
# Check signature
Get-AuthenticodeSignature .\BreakGlassReality.ps1

# Verify all scripts
Get-ChildItem -Path ".\Checks" -Recurse -Filter "*.ps1" | Get-AuthenticodeSignature
```

## Quick Start for Distribution

### Internal Distribution (Simple)

1. Update VERSION.txt
2. Run: `.\Package-QuickChecks.ps1 -Version "1.1.0"`
3. Upload ZIP to internal share
4. Email users with instructions

### External Distribution (Professional)

1. Update VERSION.txt and CHANGELOG.md
2. Sign scripts: `.\Sign-QuickChecks.ps1 -CertPath ".\cert.pfx"`
3. Package: `.\Package-QuickChecks.ps1 -Version "1.1.0" -SignScripts`
4. Generate checksum: `Get-FileHash .\dist\*.zip -Algorithm SHA256 | Format-List`
5. Upload to website/GitHub
6. Update documentation links

### PowerShell Gallery Distribution

1. Prepare manifest with Gallery metadata
2. Test locally: `Install-Module .\Module\IdentityFirst.QuickChecks -Force`
3. Publish: `Publish-Module -Path ".\Module\IdentityFirst.QuickChecks" -NuGetApiKey "KEY"`
4. Announce release

## File Structure Reference

```
IdentityFirst.QuickChecks/
├── Module/                      # PowerShell module files
│   ├── IdentityFirst.QuickChecks.psd1
│   └── IdentityFirst.QuickChecks.psm1
├── Checks/                      # Check scripts
│   ├── ActiveDirectory/
│   ├── Entra/
│   ├── AWS/
│   └── GCP/
├── Shared/                      # Shared utilities
│   └── ReportFormatter.psm1
├── config/                      # Configuration
│   └── QuickChecks.config.psd1
├── docs/                        # Documentation
│   ├── DISTRIBUTION-GUIDE.md
│   └── ...
├── scripts/                     # Build scripts
│   ├── Package-QuickChecks.ps1
│   ├── Install-QuickChecks.ps1
│   └── Sign-QuickChecks.ps1
├── Install-Prerequisites.ps1    # Prereq installer
├── Install-QuickChecks.ps1       # Module installer
├── Package-QuickChecks.ps1       # ZIP packager
├── Run-AllQuickChecks.ps1        # Launcher
├── README.md
├── EULA.txt
├── VERSION.txt
└── CHANGELOG.md
```

## Troubleshooting

### Installation Issues

| Issue | Solution |
|-------|----------|
| "Module not found" | Run `Import-Module IdentityFirst.QuickChecks` |
| "Execution policy blocked" | Run `Set-ExecutionPolicy RemoteSigned` |
| "Access denied" | Run as administrator |
| "Version conflict" | `.\Install-QuickChecks.ps1 -Force` |

### Packaging Issues

| Issue | Solution |
|-------|----------|
| "Missing module" | Run from module root directory |
| "Signature failed" | Check certificate validity |
| "ZIP creation failed" | Verify temp directory permissions |
