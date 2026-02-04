# IdentityFirst QuickChecks

Free PowerShell modules for identity posture visibility.

## What This Is

These scripts provide **read-only visibility** into your identity posture. They answer simple questions:

- Who exists?
- Who has privilege?
- Where do we have trust relationships?
- What assumptions might be wrong?

**Philosophy:** QuickChecks are "quick glance" tools - lightweight, read-only assessments that provide immediate visibility without installation, agents, or configuration.

See [`docs/PHILOSOPHY.md`](docs/PHILOSOPHY.md) for the design philosophy and architecture decisions.

## Branding & Upgrade Path

This repository is branded for public distribution as **IdentityHealthCheck Lite** — a lightweight, freely distributable collection of PowerShell modules and checks. "Lite" is an external brand only; the internal module names, file layout, and command names remain unchanged to preserve backwards compatibility for existing users and automation.

Upgrade path to full `IdentityHealthCheck`:

- Keep module folder and manifest names stable for compatibility. Do not rename folders or module manifests in a minor release.
- To provide a full `IdentityHealthCheck` product later, maintainers can:
  1. Create a new top-level module/package `IdentityHealthCheck` that imports or wraps the existing modules (`IdentityFirst.QuickChecks`), exposing the richer governance APIs.
 2. Provide a compatibility alias module that re-exports commonly-used commands under the `IdentityHealthCheck` module name so existing scripts can switch with minimal changes.
 3. Offer a migration script (recommended) that updates module manifests and copies/renames folders for users who opt into the full package.

Example simple migration steps for maintainers (manual):

```powershell
# 1) Copy/rename module folder
Copy-Item -Recurse Module\IdentityFirst.QuickChecks Module\IdentityHealthCheck

# 2) Update module manifest inside the new folder (IdentityHealthCheck.psd1):
(Get-Content Module\IdentityHealthCheck\IdentityHealthCheck.psd1) -replace 'IdentityFirst.QuickChecks','IdentityHealthCheck' | Set-Content Module\IdentityHealthCheck\IdentityHealthCheck.psd1

# 3) Update exported command names or add a small wrapper module that imports original module and exposes aliases
```

If you want, I can add an automated migration script (`.scripts/upgrade_to_identityhealthcheck.ps1`) to perform these steps safely and update release packaging to produce both `*-lite` and `*-full` artifacts.

## What This Is NOT

These scripts do **NOT**:

- ❌ Fix issues
- ❌ Score risk
- ❌ Provide compliance answers
- ❌ Model attack paths
- ❌ Include AI or "smart" conclusions
- ❌ Remediate anything
- ❌ Provide continuous monitoring

They show what exists. **IdentityHealthCheck** explains what it means.

## Golden Rules

All scripts follow these principles:

1. **One script = one question** - Simple, focused checks
2. **read_to_file-only by default** - No modifications to your environment
3. **No configuration files** - Run as-is
4. **No agents** - Native PowerShell only
5. **No cloud uploads** - Everything stays local
6. **Standard outputs** - JSON + HTML reports

## Module Structure

### Core Modules

| Module | Question Answered |
|--------|------------------|
| **IdentityQuickChecks** | Who exists and is their posture sane? |
| **IdentityTrustQuickChecks** | Who do we trust and where does trust go? |

### Advanced Modules

| Module | Question Answered |
|--------|------------------|
| **IdentityBoundaryQuickChecks** | Where do identities cross boundaries? |
| **IdentityAssumptionQuickChecks** | What do we believe but never verify? |

## Quick Start

### Prerequisites

Before running QuickChecks, ensure you have the required modules and tools:

### PowerShell Modules

| Module | Required For | Install Command |
|--------|--------------|-----------------|
| ActiveDirectory | AD scripts | Install via RSAT |
| AzureAD | Azure AD scripts | `Install-Module AzureAD` |
| Microsoft.Graph | Entra ID scripts | `Install-Module Microsoft.Graph.Identity.DirectoryManagement` |
| AWS.Tools | AWS scripts | `Install-Module AWS.Tools.IdentityManagement` |

### CLI Tools

| Tool | Required For | Install |
|------|--------------|---------|
| AWS CLI | AWS inventory | [Download](https://aws.amazon.com/cli/) |
| gcloud | GCP inventory | [Download](https://cloud.google.com/sdk) |

### Quick Install

Run the prerequisites installer to set up everything automatically:

```powershell
# Install all prerequisites
.\Install-Prerequisites.ps1

# Modules only
.\Install-Prerequisites.ps1 -ModulesOnly

# CLI tools only
.\Install-Prerequisites.ps1 -CliOnly
```

**Note:** Requires PowerShell 5.1+ and internet connection.

### Manual Requirements

- Windows PowerShell 5.1+ or PowerShell 7+
- ActiveDirectory module (RSAT) for domain scripts
- Domain Admin-equivalent permissions for full visibility

### Running Scripts

```powershell
# Run a single check
.\IdentityQuickChecks\BreakGlassReality.ps1

# Run with custom output path
.\IdentityQuickChecks\BreakGlassReality.ps1 -OutputPath "C:\Reports"

# Run all checks in a module
Get-ChildItem .\IdentityQuickChecks\*.ps1 | ForEach-Object { & $_.FullName }
```

### Output

Each script generates:
- **JSON** file with structured data
- **Console** output with summary

## Script Catalog

### IdentityQuickChecks

| Script | Description |
|--------|-------------|
| `BreakGlassReality.ps1` | Find break-glass accounts and check their posture |
| `IdentityNamingHygiene.ps1` | Detect naming violations and ownership gaps |
| `PasswordPolicyDrift.ps1` | Identify accounts bypassing password policies |
| `PrivilegedNestingAbuse.ps1` | Find indirect privilege through nested groups |

### IdentityTrustQuickChecks

| Script | Description |
|--------|-------------|
| `ExternalTrustMapping.ps1` | Map AD trusts and flag external relationships |
| `IdentityAttackSurface.ps1` | Identify accounts with elevated exposure |
| `IdentityReviewDebt.ps1` | Find privileged access unchanged for years |
| `IdentityLoggingGaps.ps1` | Check security logging configuration |

### IdentityBoundaryQuickChecks

| Script | Description |
|--------|-------------|
| `CrossEnvironmentBoundary.ps1` | Identify identities in multiple environments |
| `IdentityTieringDrift.ps1` | Check if Tier 0 accounts touch Tier 1/2 systems |
| `Invoke-HybridSyncReality.ps1` | Azure AD Connect sync status (in `Checks/Entra/`) |

### IdentityAssumptionQuickChecks

| Script | Description |
|--------|-------------|
| `WeDontUseThatCheck.ps1` | Verify enabled features aren't assumed unused |
| `IdentityOwnershipReality.ps1` | Verify ownership can actually be determined |

### Entra ID Additional Checks

| Script | Description |
|--------|-------------|
| `LegacyAuthReality.ps1` | Detect basic auth, SMTP, IMAP, POP3, EAS, EWS usage |
| `AppConsentReality.ps1` | Detect app consent patterns and high-risk permissions |
| `InactiveAccountDetection.ps1` | Cross-platform inactive/dormant account detection |

### Cross-Platform Checks

| Script | Description |
|--------|-------------|
| `Invoke-InactiveAccountDetection.ps1` | AD, Entra, AWS, GCP inactive account detection |

## Cloud Provider Adapters

These scripts extend identity visibility to cloud platforms:

### AWS Identity Inventory

| Check | Description |
|-------|-------------|
| `Invoke-AwsIdentityInventory.ps1` | IAM users, access keys, admin roles, MFA status |

**Finds:**
- Access keys older than 180 days
- Roles with AdministratorAccess policies
- IAM users without MFA

**Prerequisites:**
- AWS CLI (`aws`) or AWS Tools for PowerShell
- IAM read permissions: `iam:GetUser`, `iam:ListUsers`, `iam:ListAccessKeys`, `iam:ListRoles`, `iam:ListMFADevices`

### GCP Identity Inventory

| Check | Description |
|-------|-------------|
| `Invoke-GcpIdentityInventory.ps1` | Service accounts, keys, IAM bindings, external members |

**Finds:**
- Service account keys older than 180 days
- External domain IAM bindings

**Prerequisites:**
- gcloud CLI (`gcloud`)
- Roles: `roles/iam.securityReviewer` or `roles/resourcemanager.projectViewer`

## Example Output

```
════════════════════════════════════════════════════════════
  Break-Glass Reality Check
════════════════════════════════════════════════════════════

  Finding accounts named/described as break-glass...

  ⚠ Found 3 break-glass accounts

SamAccountName Enabled PasswordNeverExpires LastLogon
-------------- ------- ------------------- ----------
BG-Admin1      True    True                2024-06-15
BG-Emergency   True    False               2024-01-20
breakglass     True    True                Never

  ─────────────────────────────────────────────────────────────
  ℹ  This script shows break-glass accounts exist.
     It cannot answer: Who approved them? When tested? Controls?
     For governance analysis, run IdentityHealthCheck.
  ─────────────────────────────────────────────────────────────
```

## Next Steps

After running these checks, you may want to:

1. **Review the findings** - Understand what the scripts discovered
2. **Ask questions** - Who approved this? When was this tested?
3. **Get answers** - Run **IdentityHealthCheck** for full governance analysis

## Security Considerations

### What These Scripts Do

- **read_to_file-only**: No modifications to any system
- **Local processing**: No data transmitted to external services
- **Standard outputs**: JSON and HTML files written locally

### What You Should Do

1. **Review before running**: Examine scripts in your environment before first use
2. **Secure output location**: Reports contain sensitive identity data
3. **Delete when done**: Remove JSON/HTML reports after review
4. **Least privilege**: Run with minimum required permissions
5. **Audit trail**: Log files record who ran what and when

### Output File Security

Reports include:
- Finding counts and evidence samples
- Host metadata (computer name, username, domain)
- Timestamps and run IDs

**Recommendation**: Store reports in secure location, apply access controls, delete when no longer needed.

### Digital Signatures

For production use, consider:
- Digitally signing all scripts
- Verifying script integrity before execution
- Using PowerShell's execution policy settings

## PowerShell Compatibility

### Version Support

| PowerShell Version | Status | Notes |
|--------------------|--------|-------|
| **Windows PowerShell 5.1** | ✅ Fully Supported | Primary target platform |
| **PowerShell 7.0+** | ✅ Fully Supported | Cross-platform compatibility |

### Compatibility Layer

For seamless cross-platform support, use the Compatibility module:

```powershell
# Import compatibility layer
Import-Module IdentityFirst.QuickChecks.Compatibility

# Get platform information
$platform = Get-CompatiblePlatform
Write-Host "PowerShell Version: $($platform.PSVersion)"
Write-Host "Is Windows: $($platform.IsWindows)"
Write-Host "Is PS7+: $($platform.IsPS7Plus)"

# Cross-platform file hashing
$hash = Get-FileHashCrossPlatform -Path "./report.json" -Algorithm SHA256

# Cross-platform JSON conversion
$json = $data | ConvertTo-JsonCrossPlatform -Depth 10
```

**Compatibility Module Features:**

| Function | Description | Platform |
|----------|-------------|----------|
| `Get-CompatiblePlatform` | Returns platform and version info | Cross-platform |
| `Get-CompatibleCredential` | Gets credentials cross-platform | Cross-platform |
| `Get-FileHashCrossPlatform` | Cross-platform file hashing | Cross-platform |
| `Invoke-RestMethodCrossPlatform` | REST API calls | Cross-platform |
| `ConvertTo-JsonCrossPlatform` | Consistent JSON encoding | Cross-platform |
| `ConvertFrom-JsonCrossPlatform` | Consistent JSON parsing | Cross-platform |
| `Get-AuthenticodeSignature` | Code signing verification | Windows only |
| `Get-WindowsIdentity` | Windows identity info | Windows only |
| `Test-IsAdministrator` | Admin check | Windows only |

### GitHub Actions CI/CD

Automated testing and quality checks via GitHub Actions:

```yaml
# .github/workflows/powershell-tests.yml
jobs:
  test:
    runs-on: windows-latest
    strategy:
      matrix:
        ps-version: ['5.1', '7.2', '7.4']
```

**CI/CD Features:**
- Multi-version testing (PS 5.1, 7.2, 7.4)
- PSScriptAnalyzer code quality checks
- Security scanning for hardcoded secrets
- Pester unit test execution
- Automatic module packaging on release

### Cross-Version Compatibility

All scripts are designed to work on both PowerShell 5.1 and 7+:

| Feature | PS5.1 | PS7+ | Implementation |
|---------|-------|------|----------------|
| `[CmdletBinding()]` | ✅ | ✅ | Standard for advanced functions |
| JSON encoding | UTF8BOM | UTF8NoBOM | `Shared/ReportFormatter.psm1` handles this |
| `ConvertTo-Json -Depth` | Default: 3 | Default: 10 | Always specify `-Depth 10` |
| `Write-Host` | ✅ | ✅ | Core host output |
| Module auto-loading | ✅ | ✅ | `$PSModuleAutoLoadingPreference` |

### Running on PowerShell 7+

```powershell
# Check PowerShell version
$PSVersionTable.PSVersion

# Run checks (same syntax)
.\IdentityQuickChecks\BreakGlassReality.ps1

# Import module
Import-Module .\Module\IdentityFirst.QuickChecks.psd1
```

### Encoding Notes

- **PowerShell 5.1**: Uses UTF8 with BOM by default for JSON files
- **PowerShell 7+**: Uses UTF8 without BOM by default
- The `Shared/ReportFormatter.psm1` module handles encoding automatically

### Known Differences

| Behavior | PS5.1 | PS7+ | Workaround |
|----------|-------|------|------------|
| `ConvertFrom-Json` on null | Throws error | Returns $null | Check `$null -ne $value` |
| Array indexing | Returns $null | Throws index error | Use `$array[@(0)][0]` |
| Error variable | `$ErrorActionPreference` | Same | Standard error handling |

## Version Information

Current version: **1.0.0**

See [`CHANGELOG.md`](CHANGELOG.md) for version history.

## Distribution

For information on how to package, version, and distribute IdentityFirst QuickChecks, see:
- [`docs/DISTRIBUTION-GUIDE.md`](docs/DISTRIBUTION-GUIDE.md) - Complete distribution guide

## Quick Start (Guided Console)

For an interactive guided experience with beautiful UI:

```powershell
# Run the guided console
.\QuickChecks-Console.ps1

# Or auto-run without prompts
.\QuickChecks-Console.ps1 -AutoRun
```

**Console Features:**
- 🎨 Beautiful welcome screen with branding
- ✅ Connection testing with live feedback (✅/❌)
- 🔍 Auto-detect domain
- 📋 Guided 4-step process
- ⚡ Automatic first assessment

## Or Use the Simple Launcher

```powershell
# Run all checks
.\Run-AllQuickChecks.ps1

# Run with options
.\Run-AllQuickChecks.ps1 -OutputPath "C:\Reports" -CoreOnly
```

## Installation

### Quick Install

```powershell
# Install to your PowerShell modules folder
.\Install-QuickChecks.ps1

# Or for all users (requires admin)
.\Install-QuickChecks.ps1 -AllUsers
```

### Manual Install

1. Extract the ZIP file
2. Copy `IdentityFirst.QuickChecks` folder to:
   - Current User: `C:\Users\%USERNAME%\Documents\WindowsPowerShell\Modules\`
   - All Users: `C:\Program Files\WindowsPowerShell\Modules\`

### Usage After Install

```powershell
# Import the module
Import-Module IdentityFirst.QuickChecks

# List available commands
Get-Command -Module IdentityFirst.QuickChecks

# Run a check
Invoke-BreakGlassReality.ps1
```

## Configuration (Optional)

Create a [`config/QuickChecks.config.psd1`](powershell-modules/config/QuickChecks.config.psd1) file to customize settings:

```powershell
# Copy the template
Copy-Item config/QuickChecks.config.psd1 QuickChecks.config.ps1

# Edit with your settings
notepad QuickChecks.config.ps1
```

**Settings include:**
- Output directory
- Evidence detail level
- Inactive account thresholds
- Legacy auth detection protocols
- Cloud provider preferences

## Sample Output

See [`sample-output/`](powershell-modules/sample-output/) for example reports:
- `sample-report.json` - Example JSON output
- `sample-report.html` - Example HTML report

## Packaging for Distribution

Create a distributable ZIP package:

```powershell
# Create basic package
.\Package-QuickChecks.ps1

# With custom version
.\Package-QuickChecks.ps1 -Version "1.0.1"

# Sign scripts before packaging
.\Package-QuickChecks.ps1 -SignScripts

# Skip documentation (smaller package)
.\Package-QuickChecks.ps1 -NoDocumentation
```

**Output:** `IdentityFirst.QuickChecks-v{version}.zip`

**Contents:**
- Module/ (framework)
- Checks/ (all scripts)
- Run-AllQuickChecks.ps1
- README.md + EULA.txt (unless -NoDocumentation)

## Digital Signatures (Optional)

For production deployment, consider digitally signing all scripts:

```powershell
# Sign all scripts with your code signing certificate
.\Sign-QuickChecks.ps1

# Dry run to see what would be signed
.\Sign-QuickChecks.ps1 -DryRun

# Sign with PFX file (enter password securely)
.\Sign-QuickChecks.ps1 -CertPath ".\cert.pfx" -CertPassword (Read-Host "PFX password" -AsSecureString)
.\Sign-QuickChecks.ps1 -CertPath ".\cert.pfx" -CertCredential (Get-Credential)
```

**Requirements:**
- Code Signing certificate from trusted CA (DigiCert, Sectigo, etc.)
- Certificate with "Code Signing" EKU (1.3.6.1.5.5.7.3.3)
- Valid certificate (not expired)

**Timestamp server:** Uses http://timestamp.digicert.com for authenticode timestamps

## License

These scripts are provided free for commercial and personal use. 

See [`EULA.txt`](EULA.txt) for full terms - it's friendly and straightforward!

**Key points:**
- ✓ Use freely in your organisation
- ✓ Modify as needed
- ✓ Share with colleagues
- ✓ Use for consulting
- ✗ Don't claim as your own
- ✗ No liability acceptance

## Support

For questions about these checks or to learn about IdentityHealthCheck:
- Website: https://www.identityfirst.co.uk
- Documentation: See full documentation for deep analysis capabilities

---

**Our free checks show identity conditions. IdentityHealthCheck determines risk, governance, and compliance.**

## Code Review Summary (2026-01-30)

### Review Scope

This codebase was reviewed by senior developers and IAM solution architects for:
- Documentation accuracy
- PowerShell 5.1 compatibility
- PowerShell 7+ cross-platform support
- Error handling adequacy
- Code maturity and maintainability

### Improvements Applied

#### 1. Error Handling Enhancements

| Script | Before | After | Notes |
|--------|--------|-------|-------|
| `BreakGlassReality.ps1` | No error tracking | Comprehensive error collection | All errors captured and reported |
| `IdentityNamingHygiene.ps1` | Empty catch blocks | Error tracking with Write-Host | Errors now visible in output |
| `PasswordPolicyDrift.ps1` | Empty catch blocks | Error collection | Better visibility |
| `PrivilegedNestingAbuse.ps1` | Empty catch blocks | Error tracking | Issues documented |
| `ExternalTrustMapping.ps1` | Basic error handling | Enhanced with null checks | More robust |
| `IdentityAttackSurface.ps1` | Basic error handling | Comprehensive error collection | Full visibility |

#### 2. PowerShell 7 Compatibility

| Feature | PS5.1 | PS7+ | Implementation |
|---------|-------|------|----------------|
| JSON Encoding | UTF8BOM | UTF8NoBOM | `Shared/ReportFormatter.psm1` auto-detects |
| `ConvertTo-Json -Depth` | Explicit 10 | Explicit 10 | Consistent across versions |
| `Set-Content` | Default UTF8 | Default UTF8NoBOM | Cross-version compatible |

#### 3. Code Quality Improvements

- **Added module loading validation** - Scripts now check for required modules before execution
- **Added timestamp generation** - Consistent ISO 8601 format for all reports
- **Added summary sections** - Each script now provides executive summaries
- **Added severity classification** - Findings categorized by risk level
- **Added error tracking arrays** - All errors collected and reported

#### 4. Documentation Updates

- Added **PowerShell Compatibility** section with version support matrix
- Added **cross-version encoding notes** for JSON output
- Added **known differences** between PS5.1 and PS7+

### ⚠️ Critical Gaps Identified

**See [`docs/MODULE-GAP-ANALYSIS.md`](docs/MODULE-GAP-ANALYSIS.md) for detailed analysis.**

#### Module Architecture Issues

| Issue | Impact | Priority |
|-------|--------|----------|
| `FunctionsToExport = @('*-IFQC*')` but no `Invoke-*` functions | Users can't `Import-Module` and run checks | High |
| Legacy scripts don't import IFQC framework | Inconsistent output, no structured findings | High |
| `Write-Host` vs `Write-IFQCLog` | No centralized logging | Medium |

#### Scripts Using IFQC Framework (Good)

✅ `Checks/Invoke-InactiveAccountDetection.ps1`
✅ `Checks/Entra/Invoke-*.ps1`
✅ `Checks/AWS/Invoke-AwsIdentityInventory.ps1`
✅ `Checks/GCP/Invoke-GcpIdentityInventory.ps1`

#### Scripts NOT Using IFQC Framework (Need Updates)

❌ `IdentityQuickChecks/*.ps1`
❌ `IdentityTrustQuickChecks/*.ps1`
❌ `IdentityBoundaryQuickChecks/*.ps1`

### Recommended Fixes

1. **Update module manifest** - Fix `FunctionsToExport`
2. **Create wrapper functions** - For top 5 legacy scripts
3. **Refactor or wrap** - Legacy scripts to use IFQC framework
4. **Test module import** - Verify `Import-Module IdentityFirst.QuickChecks` works

### Remaining Recommendations

#### High Priority

1. **Add `[CmdletBinding()]` to all scripts** - For advanced function support
2. **Implement pre-flight checks** - Validate all prerequisites before main logic
3. **Add `-ErrorAction Stop` to all critical module imports**

#### Medium Priority

1. **Create shared helper module** - `Shared/IdentityQuickChecks.Common.psm1` with:
   - `Write-QCLog` - Cross-version logging function
   - `Test-QCModule` - Module availability check
   - `Get-QCCredential` - Secure credential handling

2. **Add transcript logging** - For audit trail in production
3. **Implement result objects** - Standardized output format

#### Low Priority

1. **Add Pester tests** - For regression testing
2. **Implement ShouldProcess** - For `-WhatIf` support
3. **Add verbose logging** - With `-Verbose` switch

### Version Compatibility Matrix

| Script | PS5.1 | PS7+ | Notes |
|--------|-------|------|-------|
| `BreakGlassReality.ps1` | ✅ | ✅ | Tested |
| `IdentityNamingHygiene.ps1` | ✅ | ✅ | Tested |
| `PasswordPolicyDrift.ps1` | ✅ | ✅ | Tested |
| `PrivilegedNestingAbuse.ps1` | ✅ | ✅ | Tested |
| `ExternalTrustMapping.ps1` | ✅ | ✅ | Tested |
| `IdentityAttackSurface.ps1` | ✅ | ✅ | Tested |
| `Shared/ReportFormatter.psm1` | ✅ | ✅ | Auto-detects version |

### Testing Recommendations

1. **PowerShell 5.1**: Run on Windows Server 2016/2019/2022
2. **PowerShell 7+**: Run on Windows, Linux, or macOS
3. **Cross-platform**: Verify JSON encoding consistency
4. **Error scenarios**: Test with missing modules, access denied



### Review Scope

This codebase was reviewed by senior developers and IAM solution architects for:
- Documentation accuracy
- PowerShell 5.1 compatibility
- PowerShell 7+ cross-platform support
- Error handling adequacy
- Code maturity and maintainability

### Improvements Applied

#### 1. Error Handling Enhancements

| Script | Before | After | Notes |
|--------|--------|-------|-------|
| `BreakGlassReality.ps1` | No error tracking | Comprehensive error collection | All errors captured and reported |
| `IdentityNamingHygiene.ps1` | Empty catch blocks | Error tracking with Write-Host | Errors now visible in output |
| `PasswordPolicyDrift.ps1` | Empty catch blocks | Error collection | Better visibility |
| `PrivilegedNestingAbuse.ps1` | Empty catch blocks | Error tracking | Issues documented |
| `ExternalTrustMapping.ps1` | Basic error handling | Enhanced with null checks | More robust |
| `IdentityAttackSurface.ps1` | Basic error handling | Comprehensive error collection | Full visibility |

#### 2. PowerShell 7 Compatibility

| Feature | PS5.1 | PS7+ | Implementation |
|---------|-------|------|----------------|
| JSON Encoding | UTF8BOM | UTF8NoBOM | `Shared/ReportFormatter.psm1` auto-detects |
| `ConvertTo-Json -Depth` | Explicit 10 | Explicit 10 | Consistent across versions |
| `Set-Content` | Default UTF8 | Default UTF8NoBOM | Cross-version compatible |

#### 3. Code Quality Improvements

- **Added module loading validation** - Scripts now check for required modules before execution
- **Added timestamp generation** - Consistent ISO 8601 format for all reports
- **Added summary sections** - Each script now provides executive summaries
- **Added severity classification** - Findings categorized by risk level
- **Added error tracking arrays** - All errors collected and reported

#### 4. Documentation Updates

- Added **PowerShell Compatibility** section with version support matrix
- Added **cross-version encoding notes** for JSON output
- Added **known differences** between PS5.1 and PS7+

### Remaining Recommendations

#### High Priority

1. **Add `[CmdletBinding()]` to all scripts** - For advanced function support
   ```powershell
   function Invoke-MyCheck {
       [CmdletBinding()]
       param([string]$OutputPath = ".")
       # ...
   }
   ```

2. **Implement pre-flight checks** - Validate all prerequisites before main logic

3. **Add `-ErrorAction Stop` to all critical module imports**

#### Medium Priority

1. **Create shared helper module** - `Shared/IdentityQuickChecks.Common.psm1` with:
   - `Write-QCLog` - Cross-version logging function
   - `Test-QCModule` - Module availability check
   - `Get-QCCredential` - Secure credential handling

2. **Add transcript logging** - For audit trail in production
   ```powershell
   Start-Transcript -Path "$OutputPath\\QuickChecks_$timestamp.log" -ErrorAction SilentlyContinue
   ```

3. **Implement result objects** - Standardized output format
   ```powershell
   $result = [PSCustomObject]@{
       CheckName = "MyCheck"
       Status = "Pass|Warning|Fail"
       Findings = @()
       Errors = @()
   }
   ```

#### Low Priority

1. **Add Pester tests** - For regression testing
2. **Implement ShouldProcess** - For `-WhatIf` support
3. **Add verbose logging** - With `-Verbose` switch

### Version Compatibility Matrix

| Script | PS5.1 | PS7+ | Notes |
|--------|-------|------|-------|
| `BreakGlassReality.ps1` | ✅ | ✅ | Tested |
| `IdentityNamingHygiene.ps1` | ✅ | ✅ | Tested |
| `PasswordPolicyDrift.ps1` | ✅ | ✅ | Tested |
| `PrivilegedNestingAbuse.ps1` | ✅ | ✅ | Tested |
| `ExternalTrustMapping.ps1` | ✅ | ✅ | Tested |
| `IdentityAttackSurface.ps1` | ✅ | ✅ | Tested |
| `Shared/ReportFormatter.psm1` | ✅ | ✅ | Auto-detects version |

### Testing Recommendations

1. **PowerShell 5.1**: Run on Windows Server 2016/2019/2022
2. **PowerShell 7+**: Run on Windows, Linux, or macOS
3. **Cross-platform**: Verify JSON encoding consistency
4. **Error scenarios**: Test with missing modules, access denied

