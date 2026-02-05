# IdentityFirst QuickChecks

Free PowerShell modules for identity posture visibility.

## What This Is

These scripts provide **read-only visibility** into your identity posture:

- Who exists?
- Who has privilege?
- Where do we have trust relationships?
- What assumptions might be wrong?

**Philosophy:** QuickChecks are "quick glance" tools - lightweight, read-only assessments.

## Quick Start

```powershell
# Import the module
Import-Module IdentityFirst.QuickChecks

# Run a check
Invoke-BreakGlassReality -OutputPath ".\Reports"

# Get help
Get-QCHelp -Examples

# Run interactive wizard
Start-QCWizard
```

## Available Checks (29 Total)

### Core Identity
- BreakGlassReality - Find break-glass accounts
- IdentityNamingHygiene - Naming violations
- PasswordPolicyDrift - Password policy bypasses
- PrivilegedNestingAbuse - Nested privilege detection

### AD Security (13)
- Invoke-AdCsAssessment - AD CS vulnerabilities (ESC1-ESC8)
- Invoke-KerberosReality - Kerberos delegation analysis
- Invoke-LapsReality - LAPS deployment status
- Invoke-SidHistoryDetection - SID History security
- Invoke-DcsyncRights - DCSync permission detection
- Invoke-AdminSdHolderAssessment - AdminSDHolder protection
- Invoke-OuGpInheritanceBlocked - Blocked GP inheritance
- Invoke-AdEmptyGroups - Empty security groups
- Invoke-PrivilegedGroupMembership - Privileged group counts
- Invoke-MemberServerHealth - Member server password health
- Invoke-TrustRelationshipAnalysis - Trust security
- Invoke-CertificateTemplateInventory - Certificate templates
- Invoke-UserAccountHealth - User account security

### Hybrid Identity
- Invoke-AzureAdConnectAssessment - AAD Connect health
- Invoke-DelegationAnalysis - AD delegation patterns

### Entra ID
- Invoke-LegacyAuthReality - Legacy authentication detection
- Invoke-AppConsentReality - App consent patterns
- Invoke-GuestCreep - Guest account proliferation
- Invoke-MfaCoverageGap - MFA coverage analysis
- Invoke-HybridSyncReality - Hybrid sync status
- Invoke-EntraEnhancedIdentity - Enhanced Entra assessment

### Cloud Inventory
- Invoke-AwsIdentityInventory - AWS IAM assessment
- Invoke-GcpIdentityInventory - GCP IAM assessment

### Cross-Platform
- Invoke-InactiveAccountDetection - Multi-platform inactive accounts

## Prerequisites

| Module | Required For | Install |
|--------|--------------|---------|
| ActiveDirectory | AD scripts | RSAT |
| Microsoft.Graph | Entra ID | `Install-Module Microsoft.Graph` |
| AWS.Tools | AWS scripts | `Install-Module AWS.Tools.IdentityManagement` |

## PowerShell Support

| Version | Status |
|---------|--------|
| Windows PowerShell 5.1 | ✅ Fully Supported |
| PowerShell 7.0+ | ✅ Fully Supported |

## Data Module (Benchmarks & History)

### Benchmarks
Compare your results against industry standards:

```powershell
# Get benchmark
$benchmark = Get-Benchmark -Category 'Entra' -CheckName 'GlobalAdminsMFA'

# Quick compliance test
Test-BenchmarkCompliance -ActualValue 85 -Category 'Entra' -CheckName 'GlobalAdminsMFA'

# List categories
Get-BenchmarkCategories
```

### Historical Tracking
Track compliance over time:

```powershell
# Save a scan (auto-opens/closes database)
Save-QCScan -ScanId (New-Guid).Guid -ScanType 'QuickChecks' -Results $results

# Get history
Get-QCScanHistory -Limit 10

# View trends
Get-QCScoreTrend -Limit 12
```

## Support

- Website: https://www.identityfirst.co.uk
- Get-Help: `Get-QCHelp -Topic Overview`
- Troubleshooting: `Get-QCHelp -Topic Troubleshooting`

---

**Our free checks show identity conditions. IdentityHealthCheck determines risk, governance, and compliance.**
