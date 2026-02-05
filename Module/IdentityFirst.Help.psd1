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
    ModuleVersion = '1.0.0'
    GUID = 'b2c3d4e5-f678-9012-bcde-f12345678901'
    Author = 'IdentityFirst Security Team'
    CompanyName = 'IdentityFirst Ltd'
    Copyright = '(c) 2026 IdentityFirst Ltd. All rights reserved.'
    Description = 'IdentityFirst QuickChecks - Help and Documentation Module'
    
    PowerShellVersion = '5.1'
    
    NestedModules = @(
        'Shared\IdentityFirst.Help.psm1'
    )
    
    FunctionsToExport = @(
        'Get-QCHelp',
        'Start-QCWizard'
    )
    
    VariablesToExport = @()
    AliasesToExport = @()
    
    RequiredModules = @()
    ModuleDependencies = @()
    
    PrivateData = @{
        SupportInfo = 'https://identityfirst.security/support'
        ProjectUri = 'https://identityfirst.security/quickchecks'
        
        Tags = @('Identity', 'Security', 'QuickChecks', 'Help', 'Documentation')
        Categories = @('Documentation')
        
        PSData = @{
            Prerelease = ''
            RequireLicenseAcceptance = $false
        }
    }
}
