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
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAegjqleNvWTsYD
# OHBw2K/3mS+nGiIOCM+UsIjpiHTQ1KCCFlIwggMUMIIB/KADAgECAhBDR0HvMFNE
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgBdnsl90cMgOqJeksqccgnEz0uVXdrAynAOe1
# 1xRwGBgwDQYJKoZIhvcNAQEBBQAEggEAJQUY0CmWCh7QUhIAIXP/hWbJCfIymufA
# WhMSnW1MHrsb3WpzBsCQ8Xxx5Qj3CtdQ6xYgei6x+QxXLU+/FV4mRcizBtokr9z0
# mmLNt9Cj6GZJWQPXw1UlcwPLxutWZKULZqZhFNyWnKHFytmJ/h+dytL/tO6UJR2y
# OcuYuVB7oTEBSK2tS46Buz+DK0ByE/Aug/Q018bDkuQIJHg9vUP0qnH0K1iO0OYh
# j3i+E4uaJJBlc+RO2YlCnPhhp/p/829A3IZn/CcDb/EN814NteQLQK3sxloue0oJ
# gcz1U7dbxRxt93zBtL4sDb5YwHHfH4KulOZwHATGf003pd96WYI6yaGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjAyMDQxNjUyMDlaMC8GCSqGSIb3DQEJBDEiBCCJ
# 61zOHlyMOV5FfE6JNFQst8CmoU39CXHivBIJtJHcyjANBgkqhkiG9w0BAQEFAASC
# AgAz2XZspZcDMIU72fiMPZZGL4DmWB7TSaZQI4LeItmfCEsiybB/Y9Hy5Q3wIO6i
# gMwW/Z3jtCcYgREn4G6s5fiK6IZtg9gLccPv8/LXV1eVtSEooff6Vs4S/DfKeBVo
# veu1DL4hPbsCvWpZVSynSEWh02DPoaZQaEHs7jwOUrP2MC0sQOUXm+6bVmr1+3Nk
# fM5RBh2nhgUWGcmWXRxNa4h66Q1T2/FfFwzSzo5D726uxK/P0BkGw518znS8k2U6
# /Y/uJsAw1FHZ7CSzTYuIhVg3ZLsvIfT56OcS6MJu0pLfNZOQYYsEc/XdwRTdwEar
# DDrVCp6anMNIUjfQFaug05yavzDnzr67klQp2wUGZkHH/dREdCLVzQTGJ8uMq8iV
# zgVPtdQT1/7Z74CesHa1CJwpeF5f5cdVfJfrtOnvA7ax+gG7zxUY3X66AVerhmU4
# NqYr010uAq7fobS6lTfrRfFEzUnvoI+atyWNqLlWwuiGWvAi+uFJE/eCYho86j9q
# dfBoU83fkf1cV99MZQlCSsDvCRZyT018+AMGGGfP2LnMVpe6ua3RxEhYFcpkQrLM
# Ec+5pBPwYqjjNctGrTyDrTCPypeFpbBS628k1/nXovx1f5hyH04NOMHfZlcf5wmj
# oqVJlpFaiiSaOMuD4oMlyc2LSE9Zn3uKi0nq8Yrc+sqBPw==
# SIG # End signature block
