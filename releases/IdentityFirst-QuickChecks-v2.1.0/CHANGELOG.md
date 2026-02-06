# Changelog

All notable changes to IdentityFirst QuickChecks are documented here.

## [2.0.0] - 2026-02-06

### Added
- 32+ identity security QuickChecks across 4 modules
- Confidence scoring system (High/Medium/Low) for all findings
- Evidence quality indicators (Direct/Indirect/Inferred)
- Standardized finding object structure with severity levels
- 79 Pester tests for comprehensive test coverage
- Code signing for all 177 scripts
- Obfuscation for production distribution
- PSSA compliance with 0 critical/errors

### Changed
- Consolidated QuickCheck modules:
  - IdentityQuickChecks (17 checks - AD, Entra ID, AWS, GCP)
  - IdentityAssumptionQuickChecks (6 core checks)
  - IdentityBoundaryQuickChecks (4 boundary checks)
  - IdentityTrustQuickChecks (5 trust checks)

### Security
- Zero hardcoded credentials
- Secure credential handling with PSCredential
- Input validation on all parameters
- SecureString for sensitive data

### Documentation
- Complete README-Free.md user guide
- EULA.txt license agreement
- CODE-REVIEW-SUMMARY.md technical findings
- Security-Hardening-Report.md
- PSSA-Quality-Report.md

## [1.0.0] - 2025-12-01

### Added
- Initial QuickChecks release
- Basic Active Directory checks
- Entra ID integration

---

## QuickCheck Inventory

### IdentityQuickChecks
- Invoke-AdEmptyGroups
- Invoke-AdminCount
- Invoke-AdminSdHolderAssessment
- Invoke-CertificateTemplateInventory
- Invoke-DcsyncRights
- Invoke-DelegatedPermissions
- Invoke-DnsAdminMembers
- Invoke-EnterpriseAdminMembers
- Invoke-EntraAppRegistration
- Invoke-EntraConditionalAccess
- Invoke-EntraRoleAssignments
- Invoke-EntraServicePrincipals
- Invoke-EnterpriseAdminMembers
- Invoke-SchemaAdminMembers
- Invoke-SidHistoryDetection
- Invoke-TrustRelationshipAnalysis
- Invoke-UserAccountHealth

### IdentityAssumptionQuickChecks
- Invoke-BreakGlassReality
- Invoke-GuestCreep
- Invoke-HybridSyncReality
- Invoke-InactiveAccountDetection
- Invoke-LegacyAuthReality
- Invoke-MfaCoverageGap

### IdentityBoundaryQuickChecks
- Invoke-AwsIdentityInventory
- Invoke-EntraEnhancedIdentity
- Invoke-GcpIdentityInventory
- Invoke-PasswordPolicyDrift

### IdentityTrustQuickChecks
- Invoke-AzureAdConnectAssessment
- Invoke-CrossEnvironmentBoundary
- Invoke-DelegationAnalysis
- Invoke-ExternalTrustMapping
- Invoke-PrivilegedNestingAbuse

---

© 2026 IdentityFirst Ltd.
