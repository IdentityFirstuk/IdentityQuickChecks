# ============================================================================
# IdentityFirst QuickChecks - Main Module
# ============================================================================
# PowerShell 5.1 Compatible
# Wrapper module that loads all check modules
# ============================================================================

#requires -Version 5.1

# Get the directory where this script is located
$scriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Path
$modulePath = Split-Path -Parent -Path $scriptPath

# List of nested modules to load
$NestedModules = @(
    'IdentityFirst.QuickChecks.Lite.psm1'
    'IdentityFirst.QuickChecks.EntraID.psm1'
    'IdentityFirst.QuickChecks.Extended.psm1'
    'IdentityFirst.QuickChecks.Validation.psm1'
    'IdentityFirst.QuickChecks.Additional.psm1'
    'IdentityFirst.QuickChecks.Extended2.psm1'
    'IdentityFirst.QuickChecks.Compliance.psm1'
    'IdentityFirst.QuickChecks.Enterprise.psm1'
    'IdentityFirst.QuickChecks.Federation.psm1'
)

# Load nested modules
foreach ($nestedModule in $NestedModules) {
    $nestedModulePath = Join-Path -Path $modulePath -ChildPath $nestedModule
    if (Test-Path -Path $nestedModulePath) {
        try {
            . $nestedModulePath
        }
        catch {
            Write-Warning "Failed to load $nestedModule`: $($_.Exception.Message)"
        }
    }
}

# Export module members - wrapper functions
function Invoke-AllIdentityQuickChecks {
    <#
    .SYNOPSIS
        Runs all IdentityFirst QuickChecks across configured platforms
    
    .DESCRIPTION
        This is a wrapper function that invokes the main QuickChecks runner.
        For full functionality, use Invoke-AllIdentityQuickChecks.ps1 script.
    
    .PARAMETER AllPlatforms
        Run checks on all platforms
    
    .PARAMETER EntraId
        Run Entra ID checks only
    
    .PARAMETER Azure
        Run Azure checks only
    
    .PARAMETER GenerateDashboard
        Generate HTML dashboard
    
    .EXAMPLE
        Invoke-AllIdentityQuickChecks -AllPlatforms
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [switch]$AllPlatforms,
        
        [Parameter(Mandatory=$false)]
        [switch]$EntraId,
        
        [Parameter(Mandatory=$false)]
        [switch]$Azure,
        
        [Parameter(Mandatory=$false)]
        [switch]$GenerateDashboard
    )
    
    $runnerScript = Join-Path $modulePath 'Invoke-AllIdentityQuickChecks.ps1'
    if (Test-Path $runnerScript) {
        & $runnerScript @PSBoundParameters
    }
    else {
        Write-Error "Runner script not found: $runnerScript"
    }
}

function Invoke-QuickChecksHealth {
    <#
    .SYNOPSIS
        Gets the health status of QuickChecks module
    
    .DESCRIPTION
        Returns information about loaded modules and available checks
    #>
    
    [CmdletBinding()]
    param()
    
    $loadedModules = Get-Module -Name 'IdentityFirst.QuickChecks*' | Select-Object Name, Version
    
    $availableFunctions = @()
    $loadedModules | ForEach-Object {
        $mod = Get-Module $_.Name
        $availableFunctions += $mod.ExportedFunctions.Keys
    }
    
    return @{
        LoadedModules = $loadedModules
        TotalChecks = ($availableFunctions | Where-Object { $_ -match '^Invoke-.*Check$' }).Count
        AvailableChecks = $availableFunctions | Where-Object { $_ -match '^Invoke-.*Check$' } | Sort-Object
        ModulePath = $modulePath
    }
}

function New-QuickChecksDashboard {
    <#
    .SYNOPSIS
        Generates HTML dashboard from QuickChecks JSON report
    
    .DESCRIPTION
        Creates an interactive HTML dashboard with charts and findings
    
    .PARAMETER JsonReport
        Path to JSON report file
    
    .PARAMETER OutputDir
        Output directory for dashboard
    
    .EXAMPLE
        New-QuickChecksDashboard -JsonReport report.json
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$JsonReport,
        
        [Parameter(Mandatory=$false)]
        [string]$OutputDir = ".\Dashboard-Output",
        
        [Parameter(Mandatory=$false)]
        [string]$Title = "IdentityFirst QuickChecks Dashboard",
        
        [Parameter(Mandatory=$false)]
        [switch]$OpenBrowser
    )
    
    $dashboardScript = Join-Path $modulePath 'New-QuickChecksDashboard.ps1'
    if (Test-Path $dashboardScript) {
        & $dashboardScript -JsonReport $JsonReport -OutputDir $OutputDir -Title $Title -OpenBrowser:$OpenBrowser
    }
    else {
        Write-Error "Dashboard script not found: $dashboardScript"
    }
}

function Test-QuickChecksPrerequisites {
    <#
    .SYNOPSIS
        Tests QuickChecks prerequisites
    
    .DESCRIPTION
        Checks for required modules and connectivity
    #>
    
    [CmdletBinding()]
    param()
    
    $results = @{
        PowerShellVersion = $PSVersionTable.PSVersion
        ModulesAvailable = @{}
        Errors = @()
    }
    
    # Check required modules
    $requiredModules = @('Az.Accounts', 'Microsoft.Graph.Authentication', 'AWS.Tools.Common')
    foreach ($mod in $requiredModules) {
        $available = Get-Module -ListAvailable -Name $mod -ErrorAction SilentlyContinue
        $results.ModulesAvailable[$mod] = $null -ne $available
    }
    
    # Check AD module (Windows only)
    if ($IsWindows -or (-not $PSBoundParameters.ContainsKey('IsWindows'))) {
        $adAvailable = Get-Module -ListAvailable -Name 'ActiveDirectory' -ErrorAction SilentlyContinue
        $results.ModulesAvailable['ActiveDirectory'] = $null -ne $adAvailable
    }
    
    return $results
}

# Export wrapper functions
Export-ModuleMember -Function @(
    'Invoke-AllIdentityQuickChecks'
    'Invoke-QuickChecksHealth'
    'New-QuickChecksDashboard'
    'Test-QuickChecksPrerequisites'
)
