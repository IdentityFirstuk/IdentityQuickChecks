@{
    RootModule        = 'IdentityFirst.QuickChecks.psm1'
    ModuleVersion     = '1.1.0'
    GUID              = 'd4f6a1c4-7c55-4a52-9f36-9a3f7c8f6a01'
    Author            = 'IdentityFirst Ltd'
    CompanyName       = 'IdentityFirst Ltd'
    Copyright         = '(c) IdentityFirst Ltd. Free for commercial and personal use.'
    PowerShellVersion = '5.1'

    # Required modules for cloud provider connectivity
    RequiredModules   = @(
        @{ ModuleName = 'Microsoft.Graph'; ModuleVersion = '2.0.0'; GUID = '14dc7db2-b5b3-4a1a-980c-9062c56843a6' }
    )

    # Functions to export - wrapper functions defined in psm1
    FunctionsToExport = @(
        # Core Identity Checks
        'Invoke-BreakGlassReality',
        'Invoke-IdentityNamingHygiene',
        'Invoke-PasswordPolicyDrift',
        'Invoke-PrivilegedNestingAbuse',

        # Trust Checks
        'Invoke-ExternalTrustMapping',
        'Invoke-IdentityAttackSurface',
        'Invoke-IdentityReviewDebt',
        'Invoke-IdentityLoggingGaps',

        # Assumption Checks
        'Invoke-WeDontUseThatCheck',
        'Invoke-IdentityOwnershipReality',

        # Boundary Checks
        'Invoke-CrossEnvironmentBoundary',
        'Invoke-IdentityTieringDrift',

        # EntraID Checks
        'Invoke-LegacyAuthReality',
        'Invoke-AppConsentReality',
        'Invoke-GuestCreep',
        'Invoke-MfaCoverageGap',
        'Invoke-HybridSyncReality',

        # Cloud Inventory
        'Invoke-AwsIdentityInventory',
        'Invoke-GcpIdentityInventory',

        # Cross-Platform
        'Invoke-InactiveAccountDetection',

        # Validation Framework
        'Invoke-QuickChecksValidation',

        # Enhanced EntraID
        'Invoke-EntraEnhancedIdentity'
    )

    CmdletsToExport   = @()
    VariablesToExport = @(
        'DefaultThresholds',
        'FindingCategories',
        'SeverityLevels'
    )
    AliasesToExport   = @()

    # Nested modules - supporting modules
    NestedModules     = @(
        'IdentityFirst.QuickChecks.Compatibility'
    )

    # External dependencies - loaded dynamically
    ExternalModuleDependencies = @(
        'Microsoft.Graph',
        'Az.Accounts',
        'ActiveDirectory',
        'AWS.Tools.IdentityManagement'
    )

    PrivateData       = @{
        PSData = @{
            Tags         = @('Identity', 'ActiveDirectory', 'EntraID', 'Azure', 'AWS', 'GCP', 'Security', 'Compliance', 'MFA', 'Governance')
            ProjectUri   = 'https://github.com/IdentityFirstuk/IdentityFirst-Free'
            LicenseUri   = 'https://github.com/IdentityFirstuk/IdentityFirst-Free/blob/main/EULA.txt'
            IconUri      = 'https://www.identityfirst.co.uk/favicon.ico'
            ReleaseNotes = @'
## IdentityFirst QuickChecks v1.1.0

### New Features
- PowerShell 7 compatibility layer for cross-platform support
- GitHub Actions CI/CD pipeline for automated testing
- Pester unit tests for core and EntraID functionality
- Compatibility module with cross-platform helper functions

### Improvements
- Fixed encoding issues affecting PowerShell 5.1 compatibility
- Enhanced error handling across all modules
- Added configurable thresholds for findings
- Added finding helper functions (New-Finding, Add-FindingObject, etc.)

### Bug Fixes
- Resolved parse errors in Validation module
- Fixed Unicode character encoding issues

### Compatibility
- Windows PowerShell 5.1: Fully supported
- PowerShell 7.0+: Fully supported (cross-platform)

### Quick Start
```powershell
# Import the module
Import-Module IdentityFirst.QuickChecks

# Run a check
Invoke-BreakGlassReality -OutputPath ".\Reports"

# Get all available commands
Get-Command -Module IdentityFirst.QuickChecks
```

### Commands Added
- Invoke-QuickChecksValidation - Validation and trust framework
- Invoke-EntraEnhancedIdentity - Enhanced EntraID identity checks
'@
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
'@
        }
    }

    # HelpInfo URI for Update-Help support
    HelpInfoURI = 'https://raw.githubusercontent.com/IdentityFirstuk/IdentityFirst-Free/main/docs/Help/'
}
