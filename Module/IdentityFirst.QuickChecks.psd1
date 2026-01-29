@{
    RootModule        = 'IdentityFirst.QuickChecks.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'd4f6a1c4-7c55-4a52-9f36-9a3f7c8f6a01'
    Author            = 'IdentityFirst Ltd'
    CompanyName       = 'IdentityFirst Ltd'
    Copyright         = '(c) IdentityFirst Ltd. Free for commercial and personal use.'
    PowerShellVersion = '5.1'
    RequiredModules   = @()
    FunctionsToExport = @('*-IFQC*')
    CmdletsToExport   = @()
    VariablesToExport = '*'
    AliasesToExport   = @()
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

### Modules
- IdentityQuickCheck: Comprehensive identity posture snapshot
- LifecycleDrift: Joiner/mover/leaver hygiene
- PrivilegedReality: Privilege inventory and hygiene
- ServiceAccountExposure: Service account risk signals
- GuestCreep: External guest lifecycle
- MfaCoverageGap: MFA registration gaps
- SystemMismatch: AD vs Entra drift
- AuditReadinessReality: Audit evidence gaps
'@
        }
    }
}
