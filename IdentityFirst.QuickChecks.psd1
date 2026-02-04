# ============================================================================
# IdentityFirst QuickChecks - Main Module Manifest
# ============================================================================
# PowerShell 5.1 Compatible
# Multi-platform identity security assessment (106+ checks)
# ============================================================================

@{
    ModuleVersion = '1.0.0'
    GUID = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author = 'IdentityFirst Ltd'
    CompanyName = 'IdentityFirst Ltd'
    Copyright = '2026 IdentityFirst Ltd. All rights reserved.'
    Description = 'Comprehensive identity security assessment platform with 106+ checks across Entra ID, Azure, AWS, GCP, Active Directory, and Okta.'
    
    PowerShellVersion = '5.1'
    PowerShellHostName = 'ConsoleHost'
    PowerShellHostVersion = '5.1'
    
    RequiredModules = @(
        @{ ModuleName = 'Az.Accounts'; ModuleVersion = '2.0.0'; }
        @{ ModuleName = 'Az.Resources'; ModuleVersion = '6.0.0'; }
        @{ ModuleName = 'AWS.Tools.Common'; ModuleVersion = '4.0.0'; }
        @{ ModuleName = 'Microsoft.Graph.Authentication'; ModuleVersion = '1.0'; }
    )
    
    # Nested modules - all the check modules
    NestedModules = @(
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
    
    # Functions to export (wrappers)
    FunctionsToExport = @(
        'Invoke-AllIdentityQuickChecks',
        'Invoke-QuickChecksHealth',
        'New-QuickChecksDashboard',
        'Test-QuickChecksPrerequisites'
    )
    
    # Cmdlets to export
    CmdletsToExport = @()
    
    # Variables to export
    VariablesToExport = @()
    
    # Aliases to export
    AliasesToExport = @()
    
    # Private data
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
                'Okta',
                'Compliance',
                'Assessment',
                'MFA',
                'IAM',
                'PIM',
                'ConditionalAccess'
            )
            ProjectURI = 'https://github.com/IdentityFirstuk/IdentityQuickChecks'
            LicenseURI = 'https://github.com/IdentityFirstuk/IdentityQuickChecks/blob/main/LICENSE'
            IconURI = 'https://raw.githubusercontent.com/IdentityFirstuk/IdentityQuickChecks/main/docs/icon.png'
            ReleaseNotes = @'
## Version 1.0.0

### Features
- 106+ security checks across 9 modules
- Multi-platform support: Entra ID, Azure, AWS, GCP, AD, Okta
- Interactive HTML dashboard with real-time gauges
- Code signing and verification for secure distribution
- CI/CD pipeline integration ready

### Modules
- Core (8 checks): Azure RBAC, PBAC, ABAC
- Entra ID (16 checks): MFA, PIM, Guest, CA
- Extended (13 checks): AWS, GCP, AD Security
- Validation (10 checks): Security, Trust, Config
- Additional (12 checks): Defender, GuardDuty, SCC
- Extended2 (15 checks): AUs, OAuth, VPC
- Compliance (12 checks): Certificates, AAD Connect
- Enterprise (11 checks): AD CS, PAW, Email, K8s
- Federation (9 checks): Okta, ADFS, Backup, APIM
'@
            RequireLicenseAcceptance = $false
            ExternalModuleDependencies = @(
                'Az.Accounts',
                'Az.Resources',
                'AWS.Tools.Common',
                'Microsoft.Graph.Authentication'
            )
        }
    }
    
    # HelpInfo URI
    HelpInfoURI = 'https://github.com/IdentityFirstuk/IdentityQuickChecks/wiki'
}
