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
@{
    RootModule        = 'IdentityFirst.QuickChecks.psm1'
    ModuleVersion     = '1.2.0'
    GUID              = 'd4f6a1c4-7c55-4a52-9f36-9a3f7c8f6a01'
    Author            = 'IdentityFirst Ltd'
    CompanyName       = 'IdentityFirst Ltd'
    Copyright         = '(c) IdentityFirst Ltd. Free for commercial and personal use.'
    PowerShellVersion = '5.1'

    RequiredModules   = @(
        @{ ModuleName = 'Microsoft.Graph'; ModuleVersion = '2.0.0'; GUID = '14dc7db2-b5b3-4a1a-980c-9062c56843a6' }
    )

    FunctionsToExport = @(
        # Core Identity QuickChecks
        'Invoke-BreakGlassReality',
        'Invoke-IdentityNamingHygiene',
        'Invoke-PasswordPolicyDrift',
        'Invoke-PrivilegedNestingAbuse',

        # AD Security QuickChecks
        'Invoke-AdCsAssessment',
        'Invoke-KerberosReality',
        'Invoke-LapsReality',
        'Invoke-SidHistoryDetection',
        'Invoke-DcsyncRights',
        'Invoke-AdminSdHolderAssessment',
        'Invoke-OuGpInheritanceBlocked',
        'Invoke-AdEmptyGroups',
        'Invoke-PrivilegedGroupMembership',
        'Invoke-MemberServerHealth',
        'Invoke-TrustRelationshipAnalysis',
        'Invoke-CertificateTemplateInventory',
        'Invoke-UserAccountHealth',

        # Trust QuickChecks
        'Invoke-ExternalTrustMapping',
        'Invoke-IdentityAttackSurface',

        # Boundary QuickChecks
        'Invoke-CrossEnvironmentBoundary',
        'Invoke-IdentityTieringDrift',

        # EntraID QuickChecks
        'Invoke-LegacyAuthReality',
        'Invoke-AppConsentReality',
        'Invoke-GuestCreep',
        'Invoke-MfaCoverageGap',
        'Invoke-HybridSyncReality',
        'Invoke-EntraEnhancedIdentity',

        # Cloud Inventory QuickChecks
        'Invoke-AwsIdentityInventory',
        'Invoke-GcpIdentityInventory',

        # Cross-Platform QuickChecks
        'Invoke-InactiveAccountDetection',

        # Validation Framework
        'Invoke-QuickChecksValidation',

        # Azure AD Connect QuickChecks
        'Invoke-AzureAdConnectAssessment',

        # Delegation Analysis QuickChecks
        'Invoke-DelegationAnalysis',

        # Okta QuickChecks
        'Invoke-OktaUserCheck',
        'Invoke-OktaMfaCheck',
        'Invoke-OktaAdminCheck',
        'Invoke-OktaAppCheck',
        'Invoke-OktaPolicyCheck',
        'Invoke-OktaIntegrationCheck',
        'Invoke-OktaApiTokenCheck',
        'Invoke-OktaGuestCheck',
        'Invoke-AllOktaQuickChecks',

        # Risk Scoring Engine
        'Invoke-QuickChecksRiskScore',
        'Get-RiskTrend',
        'Save-RiskHistory',

        # SIEM Integrations
        'Invoke-SplunkIntegration',
        'New-SplunkSearchQuery',
        'Invoke-SentinelIntegration',
        'New-SentinelAnalyticsRule',
        'Invoke-QRadarIntegration',
        'New-LEEFMessage',
        'New-CEFMessage'
    )

    CmdletsToExport   = @()
    VariablesToExport = @(
        'DefaultThresholds',
        'FindingCategories',
        'SeverityLevels'
    )
    AliasesToExport   = @()

    NestedModules     = @(
        'Shared\IdentityFirst.Data.psm1',
        'Shared\IdentityFirst.Help.psm1',
        'Shared\ReportFormatter.psm1',
        'Shared\Invoke-QuickChecksApi.ps1',
        'Shared\Invoke-QuickChecksRiskScore.ps1',
        'Shared\Invoke-SplunkIntegration.ps1',
        'Shared\Invoke-SentinelIntegration.ps1',
        'Shared\Invoke-QRadarIntegration.ps1'
    )

    ExternalModuleDependencies = @(
        'Microsoft.Graph',
        'Az.Accounts',
        'ActiveDirectory',
        'AWS.Tools.IdentityManagement'
    )

    PrivateData       = @{
        PSData = @{
            Tags         = @('Identity', 'ActiveDirectory', 'EntraID', 'Azure', 'AWS', 'GCP', 'Okta', 'Security', 'Compliance', 'MFA', 'Governance', 'SIEM')
            ProjectUri   = 'https://github.com/IdentityFirstuk/IdentityFirst-Free'
            LicenseUri   = 'https://github.com/IdentityFirstuk/IdentityFirst-Free/blob/main/EULA.txt'
            IconUri      = 'https://www.identityfirst.co.uk/favicon.ico'
            ReleaseNotes = @'
## IdentityFirst QuickChecks v1.2.0

### New Features
- **Okta QuickChecks**: 8 new security checks for Okta organizations
  - OKTA-USER-001: Inactive users detection
  - OKTA-MFA-001: MFA factor status verification
  - OKTA-ADMIN-001: Admin role assignments
  - OKTA-APP-001: Application assignments
  - OKTA-POLICY-001: Security policy gaps
  - OKTA-INTEG-001: Inactive integrations
  - OKTA-API-001: API token management
  - OKTA-GUEST-001: Guest account hygiene

- **Risk Scoring Engine**: Organizational risk score calculation
  - Aggregates finding severity × count
  - Historical trending support
  - 0-100 score with CRITICAL/HIGH/MEDIUM/LOW/MINIMAL levels

- **SIEM Integrations**:
  - Splunk HEC integration (Invoke-SplunkIntegration)
  - Azure Sentinel/Log Analytics (Invoke-SentinelIntegration)
  - IBM QRadar Syslog (Invoke-QRadarIntegration)

- **CI/CD Pipelines**:
  - GitHub Actions workflow (.github/workflows/quickchecks.yml)
  - Azure DevOps pipeline (azure-pipelines.yml)

### Improvements
- Enhanced error handling across all modules
- Added historical trend analysis for risk scoring
- New Splunk SPL query generator

### Compatibility
- Windows PowerShell 5.1: Fully supported
- PowerShell 7.0+: Fully supported (cross-platform)

### Quick Start
```powershell
# Import the module
Import-Module IdentityFirst.QuickChecks

# Run Okta QuickChecks
Invoke-AllOktaQuickChecks -OrgUrl "https://dev.okta.com" -ApiToken "xxx"

# Calculate risk score
$results = Invoke-AllIdentityQuickChecks
Invoke-QuickChecksRiskScore -Findings $results -IncludeTrending

# Send to Splunk
Invoke-SplunkIntegration -Findings $results -HecEndpoint "https://splunk:8088" -HecToken "xxx"
```
'
            Prerequisites = @'
## Prerequisites

### PowerShell
- Windows PowerShell 5.1 (minimum)
- PowerShell 7.0+ (recommended, cross-platform)

### Windows Modules (for Windows PowerShell)
- ActiveDirectory module (RSAT)
- Microsoft.Graph module
- Az.Accounts module

### Cross-Platform Modules
- Microsoft.Graph (PowerShell 7+)
- AWS Tools for PowerShell (optional)
- gcloud CLI (optional, for GCP)
'
        }
    }

    HelpInfoURI = 'https://raw.githubusercontent.com/IdentityFirstuk/IdentityFirst-Free/main/docs/Help/'
}
