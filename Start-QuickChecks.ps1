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
    Write-Output ""
    Write-Output (("=" * 70))
    Write-Output (" $Message")
    Write-Output (("=" * 70))
    Write-Output ""
}

function Write-Step {
    param([string]$Message)
    Write-Output "[+] $Message"
}

# Use named helpers to avoid overwriting built-in cmdlets
function IFQCWriteWarning {
    param([string]$Message)
    Write-Output "[!] $Message"
}

function IFQCWriteError {
    param([string]$Message)
    Write-Output "[X] $Message"
}

function Write-Info {
    param([string]$Message)
    Write-Output "[i] $Message"
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
        Write-Output ""
        Write-Output "  $($category.Name)"
        Write-Output (("-" * 40))

        foreach ($check in $category.Checks) {
            $checkName = $check.Replace("Reality", "").Replace("Gap", "")
            $result = Invoke-Check -CheckName $check

            if ($result) {
                $results.Checks += $result
                $results.Summary.Total++

                if ($result.Status -eq "Pass") {
                    $results.Summary.Passed++
                    Write-Step "    [✓] $checkName"
                }
                elseif ($result.Status -eq "Warning") {
                    $results.Summary.Warnings++
                    IFQCWriteWarning "    [!] $checkName"
                }
                else {
                    $results.Summary.Failed++
                    IFQCWriteError "    [X] $checkName"
                }
            }
        }
    }

    # Output summary
    Write-Output ""
    Write-Banner "Summary"
    Write-Output "  Total Checks:  $($results.Summary.Total)"
    Write-Output "  Passed:        $($results.Summary.Passed)"
    Write-Output "  Warnings:      $($results.Summary.Warnings)"
    Write-Output "  Failed:        $($results.Summary.Failed)"

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

    Write-Output "Welcome to IdentityFirst QuickChecks!"
    Write-Output ""
    Write-Output "Available commands:"
    Write-Output "  list    - Show available checks"
    Write-Output "  run     - Run all checks"
    Write-Output "  check   - Run specific check (follow prompts)"
    Write-Output "  export  - Export results"
    Write-Output "  help    - Show help"
    Write-Output "  exit    - Quit"
    Write-Output ""

    while ($true) {
        $choice = Read-Host "IdentityFirst" -ForegroundColor Green

        switch ($choice.ToLower()) {
            "list" {
                Write-Output ""
                Write-Output "Available Checks:"
                Get-AvailableChecks | ForEach-Object { Write-Output "  - $_" }
            }
            "run" {
                Invoke-AllChecks
            }
            "check" {
                Write-Output ""
                $checkName = Read-Host "Enter check name"
                Invoke-Check -CheckName $checkName
            }
            "export" {
                Write-Output ""
                Write-Output "Export formats: JSON, HTML, CSV"
                $format = Read-Host "Format"
                Invoke-AllChecks | Export-Results -Format $format -Path $OutputDir
            }
            "help" {
                Write-Output ""
                Write-Output "Commands:"
                Write-Output "  list    - Show available checks"
                Write-Output "  run     - Run all checks"
                Write-Output "  check   - Run specific check"
                Write-Output "  export  - Export results"
                Write-Output "  help    - Show this help"
                Write-Output "  exit    - Quit"
            }
            "exit" { break }
            default {
                IFQCWriteWarning "Unknown command. Type 'help' for available commands."
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
Write-Info "IdentityFirst QuickChecks v$script:Version"
Write-Info "$($script:ReleaseDate)"
Write-Info ""

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

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAfoTPbG3vbNAim
# shXNt+yyhDXWU3YA0Tlx2iP/zbGxLaCCFlIwggMUMIIB/KADAgECAhBDR0HvMFNE
# lkJ70azsYRwnMA0GCSqGSIb3DQEBCwUAMCIxIDAeBgNVBAMMF0lkZW50aXR5Rmly
# c3QgQ29kZSBTaWduMB4XDTI2MDIwNDE2NDE0OFoXDTI3MDIwNDE3MDE0OFowIjEg
# MB4GA1UEAwwXSWRlbnRpdHlGaXJzdCBDb2RlIFNpZ24wggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQDWJrlUCUN9yoS4qyJUFIIrjVVnfoFqTXwze3ijNE5q
# wUAAiypU86tc6ct9/wQ9Q9qOn6gjKU3vDhq8XojyQhi/q0ffxG1pP8bHfCQtrMFc
# kTOKLZRgQO73caKFxunCuRdAGxdDxy94NNjwITySkaaLFb3gULH1wbfmu5l2v9ga
# CgpRJGoofRbYbjBS5B7TTNVXlyxl5I3toq9cYRwauWq0Fqj2h6gZ/8izDVU6nMGX
# k+ZfsQwTsVSxfiiWHozhjU7Rt8ckxfVt1YLyPamewESLxw4ijFgHYZUrxNtbm2DP
# QUUG4ekzdDQlBLBzjdIJh8hIz+gcqvyXIQpoFjF2xyoFAgMBAAGjRjBEMA4GA1Ud
# DwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQU0LvUry7V
# 3WlfTmidD6yCOpbcmSQwDQYJKoZIhvcNAQELBQADggEBAAWDzEqYgCCQHZwHCMlU
# ob2Jkqcbk6GYylmfTwW9EQ7iJjyKHFJlbUGuDJxClDwDteBCVpxhfbi0fJjkib8r
# b4Fbk9Rex5rJxEMidBYbnASWnLuJD7dsHbwf6N4SM/LsYhiEtllGb0UsKET6PyuO
# f1sYdDY+UcTssCzDAElCrlVIl4Z4/JBlXOhInMD7AnP6Xx2r4hCAVEWhHtJ+ahY/
# bFAJ7v+EsTET2Pa34kiymxJ7yYRNSxwxyb1umUx/Q6pui0lYjyNXt8AAg4A0ybyj
# ABLNYct6zilczJ6JqPCBJLL0ZbCDpg8SkmAn3G3Y+bSztlOIUo4eXpjXV1DE7oB/
# kuAwggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUA
# MGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsT
# EHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQg
# Um9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqcl
# LskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YF
# PFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceIt
# DBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZX
# V59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1
# ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2Tox
# RJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdp
# ekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF
# 30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9
# t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQ
# UOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXk
# aS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud
# DgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEt
# UYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsG
# AQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0
# dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RD
# QS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAw
# DQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72arKGHLOyF
# XqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFIDyE7QKt76
# LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8L
# punyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2
# CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si
# /xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQwgga0MIIEnKADAgEC
# AhANx6xXBf8hmS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcw
# MDAwMDBaFw0zODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1l
# U3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZ
# loMsVO1DahGPNRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM
# 2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj
# 7GH8BLuxBG5AvftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQ
# Sku2Ws3IfDReb6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZ
# lDwFt+cVFBURJg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+
# 8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRx
# ykvq6gbylsXQskBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yG
# OP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqI
# MRvUBDx6z1ev+7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm
# 1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBj
# UwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729T
# SunkBnx6yuKQVvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4c
# D08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUF
# BwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEG
# CCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAX
# MAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaA
# HP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQ
# M2qEJPe36zwbSI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt
# 6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7
# bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmS
# Nq1UH410ANVko43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69
# M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnF
# RsjsYg39OlV8cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmM
# Thi0vw9vODRzW6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oa
# Qf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx
# 9yHbxtl5TPau1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3
# /BAPvIXKUjPSxyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN
# 8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQg
# VGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAw
# MDAwMFoXDTM2MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBU
# aW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx
# +wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvN
# Zh6wW2R6kSu9RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlL
# nh00Cll8pjrUcCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmn
# cOOMA3CoB/iUSROUINDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5KqCvpSduSwhw
# UmotuQhcg9tw2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL
# 4Q1OpbybpMe46YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdoRORVbPR1VVnD
# uSeHVZlc4seAO+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCy
# FG1roSrgHjSHlq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7rlRyTlaCCfw7a
# SUROwnu7zER6EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K096V1hE0yZIXe+gi
# AwW00aHzrDchIc2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGj
# ggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39/dfzkXFjGVBD
# z2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8E
# BAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGF
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUH
# MAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRH
# NFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBW
# MFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVk
# RzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkw
# FzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3x
# HCcEua5gQezRCESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh
# 8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim8/9yJmZS
# e2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUqW4daIqToXFE/
# JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMnxYOX8VBRKe1u
# NnzQVTeLni2nHkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq
# 8/gVutDojBIFeRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AWcIQfVjnzrvwi
# CZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJgddJ35XTxfUlQ
# +8Hggt8l2Yv7roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1
# R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVccAvlKV9jEnstr
# niLvUxxVZE/rptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8atufk+EMF/cWu
# iC7POGT75qaL6vdCvHlshtjdNXOCIUjsarfNZzGCBRIwggUOAgEBMDYwIjEgMB4G
# A1UEAwwXSWRlbnRpdHlGaXJzdCBDb2RlIFNpZ24CEENHQe8wU0SWQnvRrOxhHCcw
# DQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkq
# hkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGC
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgovTw1N5cV6a6RGffowoLowlpnVJqGzq8g+bp
# DOCEfyQwDQYJKoZIhvcNAQEBBQAEggEAEV4ovwWbzm6uCzqHsNAURs8jXGBdE5ho
# ejBROzajKu+EHo92+zPWxuhJTnNowxoJ4AyrIdFl2XCo5iDyBdE/DFfm68oocf3R
# IASKCW9RpQVmXwABc/eddIhITdULCfDzMg9ey6xRWIvD49Ym1j2IhC6ibyizTr94
# s1JYgF9Dikpus4huWLGeLaatpxwN12uJ84Xnx3hyWHtRArBKOn+3Fh4/gg2LSln7
# v9vdgVGOVWEKn1UeDComNOPIeWIV2imM97UrfnDu6nJ1HsThIYwbsmt3GpZ3Cf8J
# PKTTPzq9nAk3ndsYdDhaXHmiYMKLfGBlYPzvQkCjl7V+RE+NBe/2+6GCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjAyMDQxNjUyMTFaMC8GCSqGSIb3DQEJBDEiBCBe
# L/7QCkbwBXh82vLuj5EVUcCwLEi1fjafXBHqy6OyajANBgkqhkiG9w0BAQEFAASC
# AgCjhNhrC6tnzko3kPQv2VT4K6hiX7pj6r0rzJeicYPsNyaoKGC9buareuYCR43m
# skpjv1R7z1Eb8YYIIOP9DcgN56kPi3fGYVuIHXWK36sc+1mgCPJctqkOQX8F3n+B
# yGR/1B3RoRPqQaoqm7S5nqaeNBYJyD4Wq7HkfFbnIKRYqDAxpKgX1utfl8GauZ/l
# 1PEUqUN+pg/QDGxgimz4PvZMGXSouDZcZmE1ACXjZES23m0MGiyWFXp97rB2IegY
# IQrpQZ6uoB88HEG7AhpkagHZwfDFBhqDx7uT+Kgo+4NETTASf7kgT1BvZCcyocJF
# iMc0pJ1Hy+qwSoWEdgnkYnkDuiB4G+n2e2RMbp4Jw6WCRgBns8cwqBEPeBSH2p1R
# gdXCuPLQK5z3/3EQxp+R9IelUM6W/eSVP7dyzywTA9K8SsrZNBSzIyvLGl4yHvlu
# ERku54POiYfQnla7nDH1lVYseIStgUPqhRhE6SG1UeQ8X+zc5Q/WRD8uq5u7YtUN
# o5jc85xtAc0rxOvhabEgFbDmmATc0Wj8IZY13dUxIPgjb02xj1mAtL75Swj8eq3A
# D7lQhSIzk4H8g0QkQHNGqZmJrkv+9LA6fH/4XEuf652mthqM53kTvnkxkC4Prws7
# g07PMl75Uga+fW1nzw9qcCWbsEj+Tc9TjDVAZpOaaaMMFw==
# SIG # End signature block
