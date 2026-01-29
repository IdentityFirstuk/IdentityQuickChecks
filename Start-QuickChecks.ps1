# ============================================================================
# IdentityFirst QuickChecks - Unified Launcher
# ============================================================================
# Version: 1.0.0
# Date: 2026-01-29
# Description: Simple entry point for all IdentityFirst QuickChecks
# Usage: 
#   .\Start-QuickChecks.ps1                    # Run all checks
#   .\Start-QuickChecks.ps1 -Console           # Interactive console
#   .\Start-QuickChecks.ps1 -Check EntraID     # Run specific check
#   .\Start-QuickChecks.ps1 -Install           # Install to system
# ============================================================================

[CmdletBinding(DefaultParameterSetName = "Run")]
param(
    # Run all checks (default)
    [Parameter(ParameterSetName = "Run")]
    [switch]$Run,
    
    # Interactive console mode
    [Parameter(ParameterSetName = "Console")]
    [switch]$Console,
    
    # Run specific check
    [Parameter(ParameterSetName = "Check")]
    [ValidateSet(
        "ActiveDirectory", "EntraID", "AWS", "GCP", 
        "All", "GuestCreep", "MfaCoverage", "BreakGlass",
        "NamingHygiene", "PasswordPolicy", "PrivilegedNesting",
        "LegacyAuth", "AppConsent", "HybridSync", "Inactive"
    )]
    [string]$Check,
    
    # Install to system
    [Parameter(ParameterSetName = "Install")]
    [switch]$Install,
    
    # Show help
    [Parameter(ParameterSetName = "Help")]
    [switch]$Help,
    
    # Output format
    [Parameter(ParameterSetName = "Run")]
    [ValidateSet("Console", "JSON", "HTML", "CSV")]
    [string]$Output = "Console",
    
    # Output directory
    [Parameter(ParameterSetName = "Run")]
    [string]$OutputDir = "$PSScriptRoot\Output",
    
    # Skip code signing (for testing)
    [Parameter(ParameterSetName = "Run")]
    [switch]$NoSign
)

# ============================================================================
# Configuration
# ============================================================================

$script:Version = "1.0.0"
$script:ReleaseDate = "2026-01-29"
$script:Author = "mark.ahearne@identityfirst.net"
$script:Organization = "IdentityFirst Ltd"
$script:Location = "Northumberland, GB"

# Module paths
$script:SecurityModule = "$PSScriptRoot\Security\IdentityFirst.Security.psm1"
$script:ChecksFolder = "$PSScriptRoot\Checks"
$script:ConfigFile = "$PSScriptRoot\config\QuickChecks.config.psd1"

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Logo {
    @"

    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║     ██╗███╗   ███╗ █████╗  ██████╗ ███████╗                     ║
    ║     ██║████╗ ████║██╔══██╗██╔════╝ ██╔════╝                     ║
    ║     ██║██╔████╔██║███████║██║  ███╗█████╗                       ║
    ║     ██║██║╚██╔╝██║██╔══██║██║   ██║██╔══╝                       ║
    ║     ██║██║ ╚═╝ ██║██║  ██║╚██████╔╝███████╗                     ║
    ║     ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝                     ║
    ║                                                                  ║
    ║                    ██████╗ ██████╗ ██████╗                      ║
    ║                   ██╔════╝██╔═══██╗██╔══██╗                     ║
    ║                   ██║     ██║   ██║██████╔╝                     ║
    ║                   ██║     ██║   ██║██╔══██╗                     ║
    ║                   ╚██████╗╚██████╔╝██║  ██║                     ║
    ║                    ╚═════╝ ╚═════╝ ╚═╝  ╚═╝                     ║
    ║                                                                  ║
    ║          Identity Quick Checks - Security Assessment Tools       ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝

"@
}

function Write-Banner {
    param([string]$Message)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host " $Message" -ForegroundColor White
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([string]$Message)
    Write-Host "[+] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[X] $Message" -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host "[i] $Message" -ForegroundColor Cyan
}

# ============================================================================
# Core Functions
# ============================================================================

function Initialize-Environment {
    <#
    .SYNOPSIS
        Initializes the QuickChecks environment.
    .DESCRIPTION
        Loads modules, validates paths, and prepares the environment.
    #>
    Write-Info "Initializing IdentityFirst QuickChecks v$script:Version..."
    
    # Load security module
    if (Test-Path $script:SecurityModule) {
        try {
            Import-Module -Name $script:SecurityModule -ErrorAction Stop
            Write-Step "Security module loaded"
        }
        catch {
            Write-Warning "Could not load security module: $($_.Exception.Message)"
        }
    }
    
    # Validate checks folder
    if (-not (Test-Path $script:ChecksFolder)) {
        Write-Error "Checks folder not found: $script:ChecksFolder"
        return $false
    }
    
    # Load configuration
    if (Test-Path $script:ConfigFile) {
        try {
            $script:Config = Import-PowerShellDataFile -Path $script:ConfigFile
            Write-Step "Configuration loaded"
        }
        catch {
            Write-Warning "Could not load configuration: $($_.Exception.Message)"
            $script:Config = @{}
        }
    }
    
    # Create output directory
    if (-not (Test-Path $OutputDir)) {
        New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
    }
    
    Write-Step "Environment ready"
    return $true
}

function Get-AvailableChecks {
    <#
    .SYNOPSIS
        Returns list of available identity checks.
    #>
    $checks = @()
    
    # Get all PS1 files in Checks folder (recursive)
    Get-ChildItem -Path $script:ChecksFolder -Recurse -Filter "*.ps1" | ForEach-Object {
        $checks += $_.BaseName.Replace("Invoke-", "").Replace("Reality", "").Replace("Check", "")
    }
    
    return $checks | Sort-Object -Unique
}

function Invoke-Check {
    <#
    .SYNOPSIS
        Runs a specific identity check.
    #>
    param([string]$CheckName)
    
    $scriptName = "Invoke-$CheckName"
    if ($CheckName -match "^(Entra|ActiveDirectory|AWS|GCP)$") {
        $scriptName = "Invoke-$($CheckName)IdentityInventory"
    }
    
    # Find the script
    $scriptPath = Get-ChildItem -Path $script:ChecksFolder -Recurse -Filter "$scriptName.ps1" | Select-Object -First 1
    
    if (-not $scriptPath) {
        Write-Error "Check not found: $CheckName"
        return $null
    }
    
    Write-Info "Running: $CheckName"
    
    try {
        $result = & $scriptPath.FullName -ErrorAction Stop
        return $result
    }
    catch {
        Write-Error "Check failed: $($_.Exception.Message)"
        return $null
    }
}

function Invoke-AllChecks {
    <#
    .SYNOPSIS
        Runs all available identity checks.
    #>
    Write-Banner "Running All Identity Checks"
    
    $results = @{
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        Checks = @()
        Summary = @{
            Total = 0
            Passed = 0
            Failed = 0
            Warnings = 0
        }
    }
    
    $checkCategories = @(
        @{ Name = "Active Directory"; Checks = @("BreakGlassReality", "IdentityNamingHygiene", "PasswordPolicyDrift", "PrivilegedNestingAbuse") }
        @{ Name = "Entra ID"; Checks = @("GuestCreep", "MfaCoverageGap", "LegacyAuthReality", "AppConsentReality", "HybridSyncReality") }
        @{ Name = "Cloud"; Checks = @("AwsIdentityInventory", "GcpIdentityInventory") }
        @{ Name = "Cross-Platform"; Checks = @("InactiveAccountDetection") }
    )
    
    foreach ($category in $checkCategories) {
        Write-Host ""
        Write-Host "  $($category.Name)" -ForegroundColor Cyan
        Write-Host ("-" * 40) -ForegroundColor Gray
        
        foreach ($check in $category.Checks) {
            $checkName = $check.Replace("Reality", "").Replace("Gap", "")
            $result = Invoke-Check -CheckName $check
            
            if ($result) {
                $results.Checks += $result
                $results.Summary.Total++
                
                if ($result.Status -eq "Pass") {
                    $results.Summary.Passed++
                    Write-Host "    [✓] $checkName" -ForegroundColor Green
                }
                elseif ($result.Status -eq "Warning") {
                    $results.Summary.Warnings++
                    Write-Host "    [!] $checkName" -ForegroundColor Yellow
                }
                else {
                    $results.Summary.Failed++
                    Write-Host "    [X] $checkName" -ForegroundColor Red
                }
            }
        }
    }
    
    # Output summary
    Write-Host ""
    Write-Banner "Summary"
    Write-Host "  Total Checks:  $($results.Summary.Total)" -ForegroundColor White
    Write-Host "  Passed:        $($results.Summary.Passed)" -ForegroundColor Green
    Write-Host "  Warnings:      $($results.Summary.Warnings)" -ForegroundColor Yellow
    Write-Host "  Failed:        $($results.Summary.Failed)" -ForegroundColor Red
    
    return $results
}

function Start-ConsoleMode {
    <#
    .SYNOPSIS
        Starts the interactive console mode.
    #>
    Clear-Host
    Write-Logo
    Write-Banner "Interactive Console"
    
    Write-Host "Welcome to IdentityFirst QuickChecks!" -ForegroundColor White
    Write-Host ""
    Write-Host "Available commands:" -ForegroundColor Cyan
    Write-Host "  list    - Show available checks"
    Write-Host "  run     - Run all checks"
    Write-Host "  check   - Run specific check (follow prompts)"
    Write-Host "  export  - Export results"
    Write-Host "  help    - Show help"
    Write-Host "  exit    - Quit"
    Write-Host ""
    
    while ($true) {
        $choice = Read-Host "IdentityFirst" -ForegroundColor Green
        
        switch ($choice.ToLower()) {
            "list" {
                Write-Host ""
                Write-Host "Available Checks:" -ForegroundColor Cyan
                Get-AvailableChecks | ForEach-Object { Write-Host "  - $_" -ForegroundColor White }
            }
            "run" {
                Invoke-AllChecks
            }
            "check" {
                Write-Host ""
                $checkName = Read-Host "Enter check name" -ForegroundColor Yellow
                Invoke-Check -CheckName $checkName
            }
            "export" {
                Write-Host ""
                Write-Host "Export formats: JSON, HTML, CSV" -ForegroundColor Cyan
                $format = Read-Host "Format"
                Invoke-AllChecks | Export-Results -Format $format -Path $OutputDir
            }
            "help" {
                Write-Host ""
                Write-Host "Commands:" -ForegroundColor Cyan
                Write-Host "  list    - Show available checks"
                Write-Host "  run     - Run all checks"
                Write-Host "  check   - Run specific check"
                Write-Host "  export  - Export results"
                Write-Host "  help    - Show this help"
                Write-Host "  exit    - Quit"
            }
            "exit" { break }
            default {
                Write-Warning "Unknown command. Type 'help' for available commands."
            }
        }
    }
}

function Install-ToSystem {
    <#
    .SYNOPSIS
        Installs QuickChecks to the system.
    #>
    Write-Banner "Installing IdentityFirst QuickChecks"
    
    $installPath = "$env:ProgramFiles\IdentityFirst\QuickChecks"
    Write-Info "Installing to: $installPath"
    
    try {
        # Create directory
        New-Item -Path $installPath -ItemType Directory -Force | Out-Null
        
        # Copy files (excluding output and temp)
        $exclude = @("Output", "*.log", "*.pfx", "*.cer")
        Copy-Item -Path "$PSScriptRoot\*" -Destination $installPath -Exclude $exclude -Recurse -Force
        
        # Create shortcut
        $shortcutPath = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\IdentityFirst\QuickChecks.lnk"
        $ws = New-Object -ComObject WScript.Shell
        $shortcut = $ws.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = "$installPath\Start-QuickChecks.ps1"
        $shortcut.WorkingDirectory = $installPath
        $shortcut.Save()
        
        Write-Step "Installed successfully"
        Write-Info "Run: $installPath\Start-QuickChecks.ps1"
    }
    catch {
        Write-Error "Installation failed: $($_.Exception.Message)"
    }
}

function Show-Help {
    <#
    .SYNOPSIS
        Shows usage help.
    #>
    Write-Logo
    @"

IdentityFirst QuickChecks - Security Assessment Tools
Version $script:ReleaseDate

USAGE:
    .\Start-QuickChecks.ps1 [OPTIONS]

OPTIONS:
    -Run          Run all identity checks (default)
    -Console      Start interactive console mode
    -Check <name> Run a specific check
    -Install      Install to system
    -Help         Show this help message
    -Output <fmt> Output format: Console, JSON, HTML, CSV (default: Console)
    -OutputDir <path> Directory for output files (default: .\Output)
    -NoSign       Skip code signing (for testing)

EXAMPLES:
    .\Start-QuickChecks.ps1                          # Run all checks
    .\Start-QuickChecks.ps1 -Console                 # Interactive mode
    .\Start-QuickChecks.ps1 -Check EntraID           # Run Entra ID check
    .\Start-QuickChecks.ps1 -Output JSON             # JSON output
    .\Start-QuickChecks.ps1 -Install                 # Install system-wide

AVAILABLE CHECKS:
    Active Directory:
        BreakGlassReality, IdentityNamingHygiene, PasswordPolicyDrift, 
        PrivilegedNestingAbuse
    
    Entra ID:
        GuestCreep, MfaCoverageGap, LegacyAuthReality, 
        AppConsentReality, HybridSyncReality
    
    Cloud:
        AwsIdentityInventory, GcpIdentityInventory
    
    Cross-Platform:
        InactiveAccountDetection

SUPPORT:
    Author:     $script:Author
    Organization: $script:Organization
    Repository: https://github.com/IdentityFirstuk/IdentityFirst-Free

"@
}

function Export-Results {
    <#
    .SYNOPSIS
        Exports check results to file.
    #>
    param(
        [Parameter(Mandatory = $true)]
        $Results,
        
        [Parameter(Mandatory = $true)]
        [string]$Format,
        
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $filename = "IdentityQuickChecks-$timestamp"
    
    switch ($Format.ToUpper()) {
        "JSON" {
            $file = "$Path\$filename.json"
            $Results | ConvertTo-Json -Depth 10 | Set-Content -Path $file -Encoding UTF8
            Write-Step "Exported: $file"
        }
        "HTML" {
            $file = "$Path\$filename.html"
            # Simple HTML export
            $html = "<html><body><h1>IdentityFirst QuickChecks Report</h1>"
            $html += "<p>Generated: $($Results.Timestamp)</p>"
            $html += "<table border='1'><tr><th>Check</th><th>Status</th></tr>"
            foreach ($check in $Results.Checks) {
                $html += "<tr><td>$($check.Name)</td><td>$($check.Status)</td></tr>"
            }
            $html += "</table></body></html>"
            $html | Set-Content -Path $file -Encoding UTF8
            Write-Step "Exported: $file"
        }
        "CSV" {
            $file = "$Path\$filename.csv"
            $Results.Checks | Export-Csv -Path $file -NoTypeInformation
            Write-Step "Exported: $file"
        }
    }
}

# ============================================================================
# Main Execution
# ============================================================================

# Display logo
Write-Logo
Write-Host " IdentityFirst QuickChecks v$script:Version" -ForegroundColor Cyan
Write-Host " $($script:ReleaseDate)" -ForegroundColor Gray
Write-Host ""

# Process parameters
switch ($PSCmdlet.ParameterSetName) {
    "Help" {
        Show-Help
    }
    "Console" {
        Initialize-Environment | Out-Null
        Start-ConsoleMode
    }
    "Install" {
        Initialize-Environment | Out-Null
        Install-ToSystem
    }
    "Check" {
        if (-not (Initialize-Environment)) { exit 1 }
        Invoke-Check -CheckName $Check
    }
    "Run" {
        if (-not (Initialize-Environment)) { exit 1 }
        $results = Invoke-AllChecks
        
        if ($Output -ne "Console") {
            Export-Results -Results $results -Format $Output -Path $OutputDir
        }
    }
    default {
        # No parameters - show help
        Show-Help
    }
}
