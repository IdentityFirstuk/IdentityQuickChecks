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
    # Module information
    ModuleVersion = '1.0.0'
    GUID = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author = 'IdentityFirst Security Team'
    CompanyName = 'IdentityFirst Ltd'
    Copyright = '(c) 2026 IdentityFirst Ltd. All rights reserved.'
    Description = 'Identity Security QuickChecks - Data Module for benchmarks, historical tracking, and compliance scoring'
    
    # PowerShell version requirements
    PowerShellVersion = '5.1'
    
    # Nested modules to load
    NestedModules = @(
        'Shared\IdentityFirst.Data.psm1'
    )
    
    # Functions to export
    FunctionsToExport = @(
        # Benchmark Functions
        'Get-Benchmark',
        'Compare-ToBenchmark',
        'Get-ComplianceScore',
        'Get-BenchmarkCategories',
        
        # Database/History Functions
        'Start-QCDataSession',
        'Stop-QCDataSession',
        'Save-ScanResult',
        'Get-ScanHistory',
        'Get-CheckTrend',
        'Get-ComplianceTrend',
        'Compare-ToPreviousScan',
        'Export-ScanHistory'
    )
    
    # Variables to export
    VariablesToExport = @()
    
    # Aliases to export
    AliasesToExport = @()
    
    # Required modules
    RequiredModules = @()
    
    # External module dependencies
    ModuleDependencies = @()
    
    # Release notes
    ReleaseNotes = @'
# Data Module v1.0.0
- Added comprehensive industry benchmark data
- Added SQLite-based historical tracking
- Added trend analysis and comparison features
- Added compliance scoring system
- Cross-compatible with PowerShell 5.1 and 7.x
'@
    
    # Private data
    PrivateData = @{
        # Support information
        SupportInfo = 'https://identityfirst.security/support'
        LicenseUri = 'https://identityfirst.security/license'
        ProjectUri = 'https://identityfirst.security/quickchecks'
        
        # Tags for PowerShell Gallery
        Tags = @('Identity', 'Security', 'QuickChecks', 'Compliance', 'Benchmarks', 'AzureAD', 'ActiveDirectory', 'AWS', 'GCP')
        
        # Categories
        Categories = @('Compliance', 'Identity Management', 'Monitoring')
        
        # Icon URI
        IconUri = 'https://identityfirst.security/images/logo.png'
        
        # Additional metadata
        PSData = @{
            # Prerelease string
            Prerelease = ''
            
            # Require license acceptance
            RequireLicenseAcceptance = $false
            
            # External module dependencies
            ExternalModuleDependencies = @()
        }
    }
}
