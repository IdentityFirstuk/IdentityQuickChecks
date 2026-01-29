# IdentityFirst QuickChecks

Free PowerShell modules for identity posture visibility.

## What This Is

These scripts provide **read-only visibility** into your identity posture. They answer simple questions:

- Who exists?
- Who has privilege?
- Where do we have trust relationships?
- What assumptions might be wrong?

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
| `HybridSyncReality.ps1` | Azure AD Connect sync status and attribute flow visibility |

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

## Version Information

Current version: **1.0.0**

See [`CHANGELOG.md`](CHANGELOG.md) for version history.

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

# Sign with PFX file
.\Sign-QuickChecks.ps1 -CertPath ".\cert.pfx" -CertPassword (ConvertTo-SecureString "password" -AsPlainText -Force)
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
