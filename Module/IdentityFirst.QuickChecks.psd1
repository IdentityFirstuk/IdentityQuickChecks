@{
    RootModule        = 'IdentityFirst.QuickChecks.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'd4f6a1c4-7c55-4a52-9f36-9a3f7c8f6a01'
    Author            = 'IdentityFirst Ltd'
    CompanyName       = 'IdentityFirst Ltd'
    Copyright         = '(c) IdentityFirst Ltd. Free for commercial and personal use.'
    PowerShellVersion = '5.1'
    
    # Required modules (empty - standalone scripts load their own)
    RequiredModules   = @()
    
    # Functions to export - wrapper functions defined in psm1
    FunctionsToExport = @(
        'Invoke-BreakGlassReality',
        'Invoke-IdentityNamingHygiene',
        'Invoke-PasswordPolicyDrift',
        'Invoke-PrivilegedNestingAbuse',
        'Invoke-ExternalTrustMapping',
        'Invoke-IdentityAttackSurface',
        'Invoke-IdentityReviewDebt',
        'Invoke-IdentityLoggingGaps',
        'Invoke-WeDontUseThatCheck',
        'Invoke-IdentityOwnershipReality',
        'Invoke-CrossEnvironmentBoundary',
        'Invoke-IdentityTieringDrift'
    )
    
    CmdletsToExport   = @()
    VariablesToExport = '*'
    AliasesToExport   = @()
    
    # Nested modules - the actual scripts
    NestedModules     = @()
    
    PrivateData       = @{
        PSData = @{
            Tags         = @('Identity', 'ActiveDirectory', 'EntraID', 'Security', 'Compliance')
            ProjectUri   = 'https://www.identityfirst.co.uk'
            LicenseUri   = 'https://www.identityfirst.co.uk/licensing'
            ReleaseNotes = @'
## IdentityFirst QuickChecks v1.0.0

Free PowerShell modules for identity posture visibility.

### Features
- Read-only Active Directory and Entra ID checks
- Structured findings with severity levels
- JSON + HTML report output
- Shared framework for consistent results

### Quick Start
```powershell
Import-Module IdentityFirst.QuickChecks
Invoke-BreakGlassReality -OutputPath ".\Reports"
```

### Commands
- Invoke-BreakGlassReality - Break-glass account detection
- Invoke-IdentityNamingHygiene - Naming convention checks
- Invoke-PasswordPolicyDrift - Password policy violations
- Invoke-PrivilegedNestingAbuse - Nested group analysis
- Invoke-ExternalTrustMapping - Trust relationship mapping
- Invoke-IdentityAttackSurface - Attack surface analysis
- Invoke-IdentityReviewDebt - Review debt detection
- Invoke-IdentityLoggingGaps - Logging configuration
- Invoke-WeDontUseThatCheck - Assumption verification
- Invoke-IdentityOwnershipReality - Ownership verification
- Invoke-CrossEnvironmentBoundary - Cross-boundary identities
- Invoke-IdentityTieringDrift - Tiering violations
'@
        }
    }
}
