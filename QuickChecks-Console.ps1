<#
.SYNOPSIS
    IdentityFirst QuickChecks - Guided Console Experience

.DESCRIPTION
    Interactive console experience for running QuickChecks with:
    - Beautiful welcome screen
    - Connection testing with live feedback
    - Auto-detect domain
    - Guided 4-step process
    - Automatic first assessment

.NOTES
    Author: mark.ahearne@identityfirst.net | Owner: IdentityFirst Ltd
    Requirements: PowerShell 5.1+
#>

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$AutoRun,

    [Parameter()]
    [switch]$Help
)

if ($Help) {
    Write-Output @"
IdentityFirst QuickChecks - Guided Console
===========================================

Interactive console for running identity posture checks.

USAGE:
  .\\QuickChecks-Console.ps1           # Interactive guided experience
  .\\QuickChecks-Console.ps1 -AutoRun  # Run without prompts

FEATURES:
  ✓ Welcome screen with branding
  ✓ Connection testing with live feedback
  ✓ Auto-detect domain
  ✓ Guided 4-step process
  ✓ Automatic first assessment

"@
    exit 0
}

# ============================================================================
# Configuration
# ============================================================================

$script:version = "1.0.0"
$script:modulePath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script:results = @{}
$script:step1Results = @{}
$script:step2Results = @{}
$script:step3Results = @{}

# Colors
$colors = @{
    Primary    = "Cyan"
    Secondary  = "White"
    Success    = "Green"
    Error      = "Red"
    Warning    = "Yellow"
    Info       = "Gray"
    Muted      = "DarkGray"
}

# ============================================================================
# Helper Functions
# ============================================================================

function Write-IFQC {
    param(
        [Parameter(Mandatory=$true)] [string]$Message,
        [ValidateSet('Info','Warning','Error','Success','Debug')] [string]$Level = 'Info',
        [switch]$NoConsole,
        [switch]$AsObject
    )

    $timestamp = (Get-Date).ToString('o')
    $obj = [pscustomobject]@{
        Timestamp = $timestamp
        Level     = $Level
        Message   = $Message
    }

    # Emit machine-readable object first so callers can capture structured output
    Write-Output $obj

    if (-not $NoConsole) {
        $colorMap = @{ Info='Gray'; Warning='Yellow'; Error='Red'; Success='Green'; Debug='DarkGray' }
        $color = $colorMap[$Level]
        try {
            $oldColor = $null
            try { $oldColor = $host.UI.RawUI.ForegroundColor } catch { }
            try { $host.UI.RawUI.ForegroundColor = [System.ConsoleColor]::$color } catch { }
            Write-Output $Message
            if ($oldColor -ne $null) { try { $host.UI.RawUI.ForegroundColor = $oldColor } catch { } }
        } catch {
            Write-Output $Message
        }
    }
}

function Write-Header {
    param([string]$Title)
    Write-IFQC -Message "" -Level Info
    Write-IFQC -Message ("═" * 60) -Level Info
    Write-IFQC -Message ("  " + $Title) -Level Info
    Write-IFQC -Message ("═" * 60) -Level Info
    Write-IFQC -Message "" -Level Info
}

function Write-SubHeader {
    param([string]$Title)
    Write-IFQC -Message "" -Level Info
    Write-IFQC -Message ("  " + $Title) -Level Info
    Write-IFQC -Message "" -Level Info
}

function Write-Status {
    param(
        [string]$Message,
        [string]$Status,
        [switch]$NoNewline
    )
    $statusIcon = if ($Status -eq "OK") { "✓" } elseif ($Status -eq "FAIL") { "✗" } elseif ($Status -eq "SKIP") { "⊘" } else { "○" }
    $level = if ($Status -eq "OK") { 'Success' } elseif ($Status -eq "FAIL") { 'Error' } elseif ($Status -eq "SKIP") { 'Info' } else { 'Info' }

    Write-IFQC -Message ("  " + $statusIcon + " " + $Message) -Level $level
}

function Write-ProgressBar {
    param(
        [int]$Percent,
        [string]$Text
    )
    $width = 40
    $filled = [int]($width * $Percent / 100)
    $empty = $width - $filled
    $bar = ("█" * $filled) + ("░" * $empty)
    Write-IFQC -Message ("  [" + $bar + "] " + $Percent + "% " + $Text) -Level Info
}

function Test-Connection {
    param(
        [string]$Name,
        [scriptblock]$Test,
        [string]$SuccessMessage,
        [string]$FailMessage
    )

    Write-IFQC -Message "  Testing $Name..." -Level Info
    Start-Sleep -Milliseconds 500

    try {
        $result = & $Test
        if ($result) {
            Write-IFQC -Message " ✅" -Level Success
            Write-Status -Message $SuccessMessage -Status "OK"
            return $true
        } else {
            Write-IFQC -Message " ❌" -Level Error
            Write-Status -Message $FailMessage -Status "FAIL"
            return $false
        }
    } catch {
        Write-IFQC -Message " ❌" -Level Error
        Write-Status -Message "$($_.Exception.Message)" -Status "FAIL"
        return $false
    }
}

function Import-ModuleSafe {
    param([string]$Name)
    try {
        if (-not (Get-Module -Name $Name -ErrorAction SilentlyContinue)) {
            Import-Module $Name -ErrorAction Stop
        }
        return $true
    } catch {
        return $false
    }
}

function Get-AutoDetectedDomain {
    $envDomain = $env:USERDOMAIN
    if ($envDomain) { return $envDomain }

    try {
        $compSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($compSystem) { return $compSystem.Domain }
    } catch { }

    return $null
}

# ============================================================================
# Step 1: Welcome & Environment Check
# ============================================================================

function Step1-Welcome {
    Write-Output ""
    Write-Output "IdentityFirst QuickChecks"
    Write-Output "Identity Posture Assessment Tool"
    Write-Output ""
    Write-Output "  Version $script:version"
    Write-Output "  IdentityFirst Ltd"
    Write-Output "  https://www.identityfirst.net"
    Write-Output ""

    Write-SubHeader -Title " STEP 1: ENVIRONMENT CHECK "

    # Auto-detect domain
    $detectedDomain = Get-AutoDetectedDomain
    if ($detectedDomain) {
        Write-Status -Message "Auto-detected domain: $detectedDomain" -Status "OK"
        $script:step1Results.domain = $detectedDomain
    } else {
        Write-Status -Message "Could not auto-detect domain" -Status "SKIP"
        $script:step1Results.domain = $null
    }

    # Test PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    $isPs5 = $psVersion.Major -ge 5
    Write-Status -Message "PowerShell version: $psVersion" -Status $(if ($isPs5) { "OK" } else { "FAIL" })
    $script:step1Results.psVersion = $psVersion

    # Test AD module
    $hasAdModule = (Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue) -ne $null
    Write-Status -Message "ActiveDirectory module: $(if ($hasAdModule) { 'Installed' } else { 'Not installed' })" -Status $(if ($hasAdModule) { "OK" } else { "SKIP" })
    $script:step1Results.hasAdModule = $hasAdModule

    # Test AzureAD module
    $hasAzureAdModule = (Get-Module -ListAvailable -Name AzureAD -ErrorAction SilentlyContinue) -ne $null
    Write-Status -Message "AzureAD module: $(if ($hasAzureAdModule) { 'Installed' } else { 'Not installed' })" -Status $(if ($hasAzureAdModule) { "OK" } else { "SKIP" })
    $script:step1Results.hasAzureAdModule = $hasAzureAdModule

    # Test Graph module
    $hasGraphModule = (Get-Module -ListAvailable -Name Microsoft.Graph.Identity.DirectoryManagement -ErrorAction SilentlyContinue) -ne $null
    Write-Status -Message "Microsoft.Graph module: $(if ($hasGraphModule) { 'Installed' } else { 'Not installed' })" -Status $(if ($hasGraphModule) { "OK" } else { "SKIP" })
    $script:step1Results.hasGraphModule = $hasGraphModule

    # Test AWS CLI
    $hasAwsCli = (Get-Command "aws" -ErrorAction SilentlyContinue) -ne $null
    Write-Status -Message "AWS CLI: $(if ($hasAwsCli) { 'Available' } else { 'Not found' })" -Status $(if ($hasAwsCli) { "OK" } else { "SKIP" })
    $script:step1Results.hasAwsCli = $hasAwsCli

    # Test gcloud
    $hasGcloud = (Get-Command "gcloud" -ErrorAction SilentlyContinue) -ne $null
    Write-Status -Message "gcloud CLI: $(if ($hasGcloud) { 'Available' } else { 'Not found' })" -Status $(if ($hasGcloud) { "OK" } else { "SKIP" })
    $script:step1Results.hasGcloud = $hasGcloud

    # Check for QuickChecks module
    $hasIfqcModule = Test-Path (Join-Path $script:modulePath "Module\IdentityFirst.QuickChecks.psm1")
    Write-Status -Message "QuickChecks module: $(if ($hasIfqcModule) { 'Found' } else { 'Not found' })" -Status $(if ($hasIfqcModule) { "OK" } else { "FAIL" })
    $script:step1Results.hasIfqcModule = $hasIfqcModule

    if (-not $hasIfqcModule) {
        Write-IFQC -Message "" -Level Warning
        Write-IFQC -Message "  ⚠ QuickChecks module not found. Please ensure scripts are extracted." -Level Warning
        return $false
    }

    return $true
}

# ============================================================================
# Step 2: Connection Testing
# ============================================================================

function Step2-Connections {
    Write-SubHeader -Title " STEP 2: CONNECTION TESTING "

    # Import QuickChecks module
    Write-IFQC -Message "  Loading QuickChecks framework..." -Level Info
    try {
        Import-Module (Join-Path $script:modulePath "Module\IdentityFirst.QuickChecks.psm1") -Force -ErrorAction Stop
        Write-IFQC -Message "  ✓ Framework loaded" -Level Success
    } catch {
        Write-IFQC -Message "  ✗ Failed to load framework: $($_.Exception.Message)" -Level Error
        return $false
    }

    # Test AD connection
    if ($script:step1Results.hasAdModule) {
        $script:step2Results.adConnected = Test-Connection `
            -Name "Active Directory" `
            -Test { try { Get-ADDomain -ErrorAction Stop | Out-Null; return $true } catch { return $false } } `
            -SuccessMessage "Connected to Active Directory" `
            -FailMessage "Could not connect to Active Directory"
    } else {
        Write-Status -Message "Active Directory: Module not available" -Status "SKIP"
        $script:step2Results.adConnected = $null
    }

    # Test Azure AD connection
    if ($script:step1Results.hasAzureAdModule) {
        $script:step2Results.azureConnected = Test-Connection `
            -Name "Azure AD" `
            -Test { try { Connect-MsolService -ErrorAction Stop | Out-Null; return $true } catch { return $false } } `
            -SuccessMessage "Connected to Azure AD" `
            -FailMessage "Could not connect to Azure AD"
    } else {
        Write-Status -Message "Azure AD: Module not available" -Status "SKIP"
        $script:step2Results.azureConnected = $null
    }

    # Test Graph connection
    if ($script:step1Results.hasGraphModule) {
        $script:step2Results.graphConnected = Test-Connection `
            -Name "Microsoft Graph" `
            -Test {
                try {
                    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
                    Connect-MgGraph -Scopes "Directory.Read.All" -ErrorAction Stop | Out-Null
                    return $true
                } catch { return $false }
            } `
            -SuccessMessage "Connected to Microsoft Graph" `
            -FailMessage "Could not connect to Microsoft Graph"
    } else {
        Write-Status -Message "Microsoft Graph: Module not available" -Status "SKIP"
        $script:step2Results.graphConnected = $null
    }

    # Test AWS connection
    if ($script:step1Results.hasAwsCli) {
        $script:step2Results.awsConnected = Test-Connection `
            -Name "AWS IAM" `
            -Test { try { aws sts get-caller-identity --output json 2>$null | Out-Null; return $true } catch { return $false } } `
            -SuccessMessage "Connected to AWS" `
            -FailMessage "Could not connect to AWS"
    } else {
        Write-Status -Message "AWS: CLI not available" -Status "SKIP"
        $script:step2Results.awsConnected = $null
    }

    # Test GCP connection
    if ($script:step1Results.hasGcloud) {
        $script:step2Results.gcpConnected = Test-Connection `
            -Name "GCP IAM" `
            -Test { try { gcloud projects list --format=json 2>$null | Out-Null; return $true } catch { return $false } } `
            -SuccessMessage "Connected to GCP" `
            -FailMessage "Could not connect to GCP"
    } else {
        Write-Status -Message "GCP: CLI not available" -Status "SKIP"
        $script:step2Results.gcpConnected = $null
    }

    # Disconnect Graph if connected
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }

    return $true
}

# ============================================================================
# Step 3: Guided Assessment Selection
# ============================================================================

function Step3-Selection {
    Write-SubHeader -Title " STEP 3: SELECT ASSESSMENT "

    Write-IFQC -Message "  Available assessments:" -Level Info
    Write-IFQC -Message "" -Level Info

    $assessments = @(
        @{ Id = "AD-BREAKGLASS"; Name = "Break-Glass Accounts"; Desc = "Find and assess break-glass accounts"; Platform = "AD" }
        @{ Id = "AD-NAMING"; Name = "Naming Hygiene"; Desc = "Detect naming violations and ownership gaps"; Platform = "AD" }
        @{ Id = "ENTRA-MFA"; Name = "MFA Coverage"; Desc = "Identify users without MFA enabled"; Platform = "Entra" }
        @{ Id = "ENTRA-GUESTS"; Name = "Guest Users"; Desc = "Detect guest user proliferation"; Platform = "Entra" }
        @{ Id = "CLOUD-INACTIVE"; Name = "Inactive Accounts"; Desc = "Cross-platform inactive account detection"; Platform = "Cross" }
        @{ Id = "HYBRID-SYNC"; Name = "Hybrid Sync Status"; Desc = "Azure AD Connect sync status"; Platform = "Hybrid" }
        @{ Id = "LEGACY-AUTH"; Name = "Legacy Authentication"; Desc = "Detect basic auth usage"; Platform = "Entra" }
        @{ Id = "APP-CONSENT"; Name = "App Consent Patterns"; Desc = "Detect app permissions granted"; Platform = "Entra" }
        @{ Id = "QUICK-FULL"; Name = "Quick Full Assessment"; Desc = "Run core AD + Entra checks"; Platform = "All" }
    )

    for ($i = 0; $i -lt $assessments.Count; $i++) {
        $a = $assessments[$i]
        $platformIcon = switch ($a.Platform) {
            "AD" { "🖥️" }
            "Entra" { "☁️" }
            "Cross" { "🔄" }
            "Hybrid" { "🔗" }
            "All" { "✨" }
            default { "📋" }
        }
            Write-IFQC -Message (("  [" + ($i + 1) + "] " + $platformIcon + " " + $a.Name)) -Level Info
            Write-IFQC -Message ("       " + $a.Desc) -Level Info
    }

    Write-IFQC -Message "" -Level Info
    Write-IFQC -Message "  [A] Run ALL assessments" -Level Warning
    Write-IFQC -Message "  [R] Run recommended (Break-Glass + MFA + Guests)" -Level Info
    Write-IFQC -Message "" -Level Info

    if ($AutoRun) {
        # Auto-select recommended
        $script:selectedAssessment = "QUICK-FULL"
        Write-IFQC -Message "  → Auto-running Quick Full Assessment" -Level Warning
        return
    }

    $selection = Read-Host "  Select assessment (1-9, A, or R)"

    switch ($selection.ToUpper()) {
        "A" { $script:selectedAssessment = "ALL" }
        "R" { $script:selectedAssessment = "RECOMMENDED" }
        default {
            $idx = [int]$selection - 1
            if ($idx -ge 0 -and $idx -lt $assessments.Count) {
                $script:selectedAssessment = $assessments[$idx].Id
            } else {
                $script:selectedAssessment = "QUICK-FULL"
            }
        }
    }

    Write-IFQC -Message "" -Level Info
    Write-IFQC -Message ("  Selected: " + $script:selectedAssessment) -Level Success
}

# ============================================================================
# Step 4: Run Assessment
# ============================================================================

function Step4-RunAssessment {
    Write-SubHeader -Title " STEP 4: RUNNING ASSESSMENT "

    $outputDir = Join-Path $script:modulePath "IFQC-Output"
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }

        Write-IFQC -Message ("  Output directory: " + $outputDir) -Level Info
        Write-IFQC -Message "" -Level Info

    # Map assessment selection to script paths
    $scriptPath = $null
    $assessmentName = ""

    switch ($script:selectedAssessment) {
        "AD-BREAKGLASS" {
            $scriptPath = Join-Path $script:modulePath "Checks\ActiveDirectory\Invoke-BreakGlassReality.ps1"
            $assessmentName = "Break-Glass Accounts"
        }
        "AD-NAMING" {
            $scriptPath = Join-Path $script:modulePath "Checks\ActiveDirectory\Invoke-IdentityNamingHygiene.ps1"
            $assessmentName = "Naming Hygiene"
        }
        "ENTRA-MFA" {
            $scriptPath = Join-Path $script:modulePath "Checks\Entra\Invoke-MfaCoverageGap.ps1"
            $assessmentName = "MFA Coverage"
        }
        "ENTRA-GUESTS" {
            $scriptPath = Join-Path $script:modulePath "Checks\Entra\Invoke-GuestCreep.ps1"
            $assessmentName = "Guest Users"
        }
        "CLOUD-INACTIVE" {
            $scriptPath = Join-Path $script:modulePath "Checks\Invoke-InactiveAccountDetection.ps1"
            $assessmentName = "Inactive Accounts"
        }
        "HYBRID-SYNC" {
            $scriptPath = Join-Path $script:modulePath "Checks\Entra\Invoke-HybridSyncReality.ps1"
            $assessmentName = "Hybrid Sync Status"
        }
        "LEGACY-AUTH" {
            $scriptPath = Join-Path $script:modulePath "Checks\Entra\Invoke-LegacyAuthReality.ps1"
            $assessmentName = "Legacy Authentication"
        }
        "APP-CONSENT" {
            $scriptPath = Join-Path $script:modulePath "Checks\Entra\Invoke-AppConsentReality.ps1"
            $assessmentName = "App Consent Patterns"
        }
        "QUICK-FULL" {
            $scriptPath = Join-Path $script:modulePath "Run-AllQuickChecks.ps1"
            $assessmentName = "Quick Full Assessment"
        }
        "ALL" {
            $scriptPath = Join-Path $script:modulePath "Run-AllQuickChecks.ps1"
            $assessmentName = "Full Assessment"
        }
        "RECOMMENDED" {
            # Run multiple recommended scripts
            $recommended = @(
                @{ Path = Join-Path $script:modulePath "Checks\ActiveDirectory\Invoke-BreakGlassReality.ps1"; Name = "Break-Glass" },
                @{ Path = Join-Path $script:modulePath "Checks\Entra\Invoke-MfaCoverageGap.ps1"; Name = "MFA Coverage" },
                @{ Path = Join-Path $script:modulePath "Checks\Entra\Invoke-GuestCreep.ps1"; Name = "Guest Users" }
            )

            foreach ($item in $recommended) {
                if (Test-Path $item.Path) {
                    Write-IFQC -Message ("  Running " + $($item.Name) + "...") -Level Info
                    Write-ProgressBar -Percent 0 -Text $item.Name
                    try {
                        & $item.Path -OutputDirectory $outputDir | Out-Null
                        Write-ProgressBar -Percent 100 -Text "Complete"
                    } catch {
                        Write-IFQC -Message ("  ✗ Error: $($_.Exception.Message)") -Level Error
                    }
                }
            }

            Write-IFQC -Message "" -Level Info
            Write-IFQC -Message "  ✅ Recommended assessments complete!" -Level Success
            return
        }
    }

    # Run single assessment
    if ($scriptPath -and (Test-Path $scriptPath)) {
            Write-IFQC -Message ("  Running: " + $assessmentName) -Level Warning
            Write-IFQC -Message "" -Level Info

        # Progress animation
        for ($i = 0; $i -le 100; $i += 10) {
            Write-ProgressBar -Percent $i -Text "Scanning..."
            Start-Sleep -Milliseconds 200
        }

        try {
            & $scriptPath -OutputDirectory $outputDir | Out-Null
            Write-ProgressBar -Percent 100 -Text "Complete"
                Write-IFQC -Message "" -Level Info
                Write-IFQC -Message "  ✅ Assessment complete!" -Level Success
        } catch {
                Write-IFQC -Message ("  ✗ Error: $($_.Exception.Message)") -Level Error
        }
    } else {
            Write-IFQC -Message ("  ✗ Assessment script not found: " + $scriptPath) -Level Error
    }
}

# ============================================================================
# Summary
# ============================================================================

function Show-Summary {
    Write-SubHeader -Title " ASSESSMENT COMPLETE "
    Write-IFQC -Message "  Results saved to: IFQC-Output\" -Level Info
    Write-IFQC -Message "" -Level Info
    Write-IFQC -Message "  Next steps:" -Level Info
    Write-IFQC -Message "  1. Review the generated reports" -Level Info
    Write-IFQC -Message "  2. Identify findings to investigate" -Level Info
    Write-IFQC -Message "  3. Consider IdentityHealthCheck for deeper analysis" -Level Info
    Write-IFQC -Message "" -Level Info
    Write-IFQC -Message "  IdentityHealthCheck provides:" -Level Info
    Write-IFQC -Message "  • Risk scoring and prioritisation" -Level Info
    Write-IFQC -Message "  • Ownership correlation" -Level Info
    Write-IFQC -Message "  • Compliance mapping" -Level Info
    Write-IFQC -Message "  • Continuous monitoring" -Level Info
    Write-IFQC -Message "" -Level Info
    Write-IFQC -Message "  👉 https://www.identityfirst.net" -Level Info
    Write-IFQC -Message "" -Level Info
}

# ============================================================================
# Main
# ============================================================================

function Main {
    Clear-Host

    # Step 1: Welcome
    if (-not (Step1-Welcome)) {
        Write-IFQC -Message "" -Level Warning
        Write-IFQC -Message "  ⚠ Please ensure QuickChecks is properly installed." -Level Warning
        exit 1
    }

    # Step 2: Connections
    if (-not (Step2-Connections)) {
        Write-IFQC -Message "" -Level Warning
        Write-IFQC -Message "  ⚠ Some connections failed. Continuing with available platforms..." -Level Warning
    }

    # Step 3: Selection
    Step3-Selection

    # Step 4: Run Assessment
    Step4-RunAssessment

    # Summary
    Show-Summary
}

# Run
Main

# SIG # Begin signature block
# MIIJyAYJKoZIhvcNAQcCoIIJuTCCCbUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDwRslFJL8CHTp4
# 6DMLoefFKekeak+U3G1XSJJHZg03zaCCBdYwggXSMIIDuqADAgECAhAxVnqog0nQ
# oULr1YncnW59MA0GCSqGSIb3DQEBCwUAMIGAMQswCQYDVQQGEwJHQjEXMBUGA1UE
# CAwOTm9ydGh1bWJlcmxhbmQxFzAVBgNVBAcMDk5vcnRodW1iZXJsYW5kMRowGAYD
# VQQKDBFJZGVudGl0eUZpcnN0IEx0ZDEjMCEGA1UEAwwaSWRlbnRpdHlGaXJzdCBD
# b2RlIFNpZ25pbmcwHhcNMjYwMTI5MjExMDU3WhcNMzEwMTI5MjEyMDU2WjCBgDEL
# MAkGA1UEBhMCR0IxFzAVBgNVBAgMDk5vcnRodW1iZXJsYW5kMRcwFQYDVQQHDA5O
# b3J0aHVtYmVybGFuZDEaMBgGA1UECgwRSWRlbnRpdHlGaXJzdCBMdGQxIzAhBgNV
# BAMMGklkZW50aXR5Rmlyc3QgQ29kZSBTaWduaW5nMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAtrU2HprgcHe9mxlmt5X72OsSk7cXDyUhoOAcLE9f4lS2
# rOx7VbZSMSi0r4lt8a/S5m/JIWCdYO+GrWZCgS2S73H3KNDszR5HDPbMhv+leoWA
# qLT7C0awpjcTnvWIDxnHyHHane/TNl3ehY9Jek5qrbiNgJDatV6SEYVFlK8Nk9kE
# 3TiveVvRKokNT2xY4/h1rohFCHnF+g7dCn06xAZwoGnFVlmPop3jItAlZdUQz3zR
# /xSNW01sQXgW6/TYd2VzXXuQihMQ3ikjoNGX1L8SlcV4ih2J+r2kSHjhkZ8c+wJE
# v2iiUHqpwmch31UwQOb4qklGKg1A+SAUGdf0cTTc6ApSFsqrol1euObreoy0zdAA
# k47NELuGhKA4N0Dk9Ar616JGFt/03s1waukNisnH/sk9PmPGUo9QtKH1IQpBtwWw
# uKel0w3MmgTwi2vBwfyh2/oTDkTfic7AT3+wh6O/9mFxxu2Fsq6VSlYRpSTSpgxF
# c/YsVlQZaueZs6WB6/HzftGzv1Mmz7is8DNnnhkADTEMj+NDo4wq+lUCE7XNDnnH
# KBN8MkDh4IljXVSkP/xwt4wLLd9g7oAOW91SDA2wJniyjSUy9c+auW3lbA8ybSfL
# TrQgZiSoepcCjW2otZIXrmDnJ7BtqmmiRff4CCacdJXxqNWdFnv6y7Yy6DQmECEC
# AwEAAaNGMEQwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0G
# A1UdDgQWBBQBfqZy0Xp6lbG6lqI+cAlT7ardlTANBgkqhkiG9w0BAQsFAAOCAgEA
# IwBi/lJTGag5ac5qkMcnyholdDD6H0OaBSFtux1vPIDqNd35IOGYBsquL0BZKh8O
# AHiuaKbo2Ykevpn5nzbXDBVHIW+gN1yu5fWCXSezCPN/NgVgdH6CQ6vIuKNq4BVm
# E8AEhm7dy4pm4WPLqEzWT2fwJhnJ8JYBnPbuUVE8F8acyqG8l3QMcGICG26NWgGs
# A28YvlkzZsny+HAzLvmJn/IhlfWte1kGu0h0G7/KQG6hei5afsn0HxWHKqxI9JsG
# EF3SsMVQW3YJtDzAiRkNtII5k0PyywjrgzIGViVNOrKMT9dKlsTev6Ca/xQX13xM
# 0prtnvxiTXGtT031EBGXAUhOzvx2Hp1WFnZTEIJyX1J2qI+DQsPb9Y1jWcdGBwv3
# /m1nAHE7FpPGsSv+UIP3QQFD/j6nLl5zUoWxqAZMcV4K4t4WkPQjPAXzomoRaqc6
# toXHlXhKHKZ0kfAIcPCFlMwY/Rho82GiATIxHXjB/911VRcpv+xBoPCZkXDnsr9k
# /aRuPNt9DDSrnocJIoTtqIdel/GJmD0D75Lg4voUX9J/1iBuUzta2hoBA8fSVPS5
# 6plrur3Sn5QQG2kJt9I4z5LS3UZSfT+29+xJz7WSyp8+LwU7jaNUuWr3lpUnY2nS
# pohDlw2BFFNGT6/DZ0loRJrUMt58UmfdUX8FPB7uNuIxggNIMIIDRAIBATCBlTCB
# gDELMAkGA1UEBhMCR0IxFzAVBgNVBAgMDk5vcnRodW1iZXJsYW5kMRcwFQYDVQQH
# DA5Ob3J0aHVtYmVybGFuZDEaMBgGA1UECgwRSWRlbnRpdHlGaXJzdCBMdGQxIzAh
# BgNVBAMMGklkZW50aXR5Rmlyc3QgQ29kZSBTaWduaW5nAhAxVnqog0nQoULr1Ync
# nW59MA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAw
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEINDB3le42yv0Upf9+uMglzjWH/YnrbmE
# SXgfhEhbHyLOMA0GCSqGSIb3DQEBAQUABIICAHLgz/XevRAY08b8yAV/MQQs8eUu
# GdqB/9dQlkzaiiPmy37OJEJityUJVsevOPnq04EdZnhdjt4qMykt3VQ7e9qOpoU9
# NYf1PUPUDaa28YJm7tOp3vD8t1YcGQNGXjk6FA7M69Yfo2tYGfrhxQpgYkfWugQk
# 1msI0AgesJCTiULap+beGvaXZHwTOrTSyUqlkFEJavowcSXvIV8Rj0geqTo2KOBw
# uIrrKBnkCblQys1/aTiM5/+KdLBUrQevq79BmFj5sQtkzFTMo0Jb8z7KlZMpTXKl
# viblTParlPmTO5HDso2385t5ZIhMnw+6H/acDCq2SPFlBHXjgCOnnc+PhDgcp5Je
# HsGwxnwyQgXfVWsjJwl/bvh1yI+/35Ho2hyHkW5uxNDmuwuutOh1DNFOKFl1o8rL
# f44W3hfVQFHf5T6t86KV8iMxEhRXdjOfD9mYHwAcZwr8gYpuoZJ+h1F2rAgU7LEe
# RDKxvGlAO42CTipi4zyI1mivVvY6fzDrthB9Wyy/RDJTPluTAogKHn1Ptn7y5hM2
# DubU9F4VfmoFakZZTAKg+topNltGYu9tC0JkhsWVxy6fHQyAl1LtWHesu1pcepey
# a2KDqvp72YvdW+JrQPg6N9wO6/9eP8kecW0EqpOFRq307yQUmSooEpBtmjbcyLpU
# Bvyur0H9ysJPM15P
# SIG # End signature block

