# IdentityFirst QuickChecks Changelog

All notable changes to the QuickChecks module are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-01-29

### Added

#### Core Framework
- `IdentityFirst.QuickChecks.psm1` - Shared framework with:
  - Context initialization
  - Safe execution wrappers
  - Structured finding schema
  - JSON/HTML report generation
  - Security hardening (file ACLs, HTML encoding)

#### Active Directory Modules (12 scripts)
- `Invoke-BreakGlassReality.ps1` - Find and assess break-glass accounts
- `Invoke-IdentityNamingHygiene.ps1` - Detect naming violations
- `Invoke-PasswordPolicyDrift.ps1` - Identify accounts bypassing password policies
- `Invoke-PrivilegedNestingAbuse.ps1` - Find indirect privilege through nested groups
- `Invoke-ExternalTrustMapping.ps1` - Map AD trusts and external relationships
- `Invoke-IdentityAttackSurface.ps1` - Identify accounts with elevated exposure
- `Invoke-IdentityReviewDebt.ps1` - Find privileged access unchanged for years
- `Invoke-IdentityLoggingGaps.ps1` - Check security logging configuration
- `Invoke-CrossEnvironmentBoundary.ps1` - Identify identities in multiple environments
- `Invoke-IdentityTieringDrift.ps1` - Check Tier 0 account violations
- `Invoke-WeDontUseThatCheck.ps1` - Verify feature assumptions
- `Invoke-IdentityOwnershipReality.ps1` - Verify ownership can be determined

#### Entra ID Modules (10 scripts)
- `Invoke-GuestCreep.ps1` - Detect guest user proliferation
- `Invoke-MfaCoverageGap.ps1` - Identify users without MFA
- `Invoke-SystemMismatch.ps1` - Find on-prem/cloud attribute mismatches
- `Invoke-ExternalTrustMapping.ps1` - Map external trust relationships
- `Invoke-IdentityAttackSurface.ps1` - Identify exposed privileged accounts
- `Invoke-IdentityReviewDebt.ps1` - Find stale privileged access
- `Invoke-IdentityLoggingGaps.ps1` - Check Entra ID audit logging
- `Invoke-HybridSyncReality.ps1` - Azure AD Connect sync status (NEW)
- `Invoke-LegacyAuthReality.ps1` - Legacy auth detection (NEW)
- `Invoke-AppConsentReality.ps1` - App consent patterns (NEW)

#### Entra ID Enhanced
- `Invoke-EntraEnhancedIdentity.ps1` - PIM roles + Conditional Access policies

#### Cloud Adapters
- `Invoke-AwsIdentityInventory.ps1` - AWS IAM users, access keys, admin roles, MFA
- `Invoke-GcpIdentityInventory.ps1` - GCP service accounts, keys, IAM bindings

#### Cross-Platform
- `Invoke-InactiveAccountDetection.ps1` - Inactive account detection across AD, Entra, AWS, GCP (NEW)

#### Tools
- `Run-AllQuickChecks.ps1` - Master launcher with module discovery
- `Sign-QuickChecks.ps1` - Digital signing for production deployment (NEW)
- `Package-QuickChecks.ps1` - ZIP packaging for distribution (NEW)

#### Documentation
- `README.md` - Complete documentation with examples
- `EULA.txt` - Friendly end-user license agreement (NEW)
- `CHANGELOG.md` - Version history (NEW)
- `VERSION.txt` - Version file (NEW)

### Changed
- All scripts use consistent IFQC finding schema
- HTML reports include IdentityHealthCheck upgrade CTA
- Output files have restrictive ACLs (owner only)
- Evidence sampling respects DetailLevel parameter

### Security
- HTML output properly encoded (prevents XSS)
- Log files created with appropriate permissions
- No external data transmission (all local processing)

### Removed
- Nothing - initial release

---

## About IdentityFirst QuickChecks

Free PowerShell modules for identity posture visibility. read_to_file-only tools that show what exists without modifying anything.

**Author:** mark.ahearne@identityfirst.net  
**Owner:** IdentityFirst Ltd  
**Website:** https://www.identityfirst.net
