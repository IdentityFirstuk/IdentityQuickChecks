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
    Write-Host @"
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

function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host ("═" * 60) -ForegroundColor $colors.Primary
    Write-Host ("  " + $Title) -ForegroundColor $colors.Primary
    Write-Host ("═" * 60) -ForegroundColor $colors.Primary
    Write-Host ""
}

function Write-SubHeader {
    param([string]$Title)
    Write-Host ""
    Write-Host ("  " + $Title) -ForegroundColor $colors.Secondary -BackgroundColor $colors.Primary
    Write-Host ""
}

function Write-Status {
    param(
        [string]$Message,
        [string]$Status,
        [switch]$NoNewline
    )
    $statusIcon = if ($Status -eq "OK") { "✓" } elseif ($Status -eq "FAIL") { "✗" } elseif ($Status -eq "SKIP") { "⊘" } else { "○" }
    $statusColor = if ($Status -eq "OK") { $colors.Success } elseif ($Status -eq "FAIL") { $colors.Error } elseif ($Status -eq "SKIP") { $colors.Muted } else { $colors.Info }
    
    Write-Host ("  " + $statusIcon + " ") -ForegroundColor $statusColor -NoNewline:$NoNewline
    Write-Host $Message -ForegroundColor $colors.Info -NoNewline:$NoNewline
    if (-not $NoNewline) { Write-Host "" }
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
    Write-Host ("  [" + $bar + "] " + $Percent + "% " + $Text) -ForegroundColor $colors.Info
}

function Test-Connection {
    param(
        [string]$Name,
        [scriptblock]$Test,
        [string]$SuccessMessage,
        [string]$FailMessage
    )
    
    Write-Host "  Testing $Name..." -ForegroundColor $colors.Muted -NoNewline
    Start-Sleep -Milliseconds 500
    
    try {
        $result = & $Test
        if ($result) {
            Write-Host " ✅" -ForegroundColor $colors.Success
            Write-Status -Message $SuccessMessage -Status "OK"
            return $true
        } else {
            Write-Host " ❌" -ForegroundColor $colors.Error
            Write-Status -Message $FailMessage -Status "FAIL"
            return $false
        }
    } catch {
        Write-Host " ❌" -ForegroundColor $colors.Error
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
    Write-Host ""
    Write-Host ("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓") -ForegroundColor $colors.Primary
    Write-Host ("▓▓                                                ▓▓") -ForegroundColor $colors.Primary
    Write-Host ("▓▓    I D E N T I T Y   F I R S T   Q U I C K C H E C K S") -ForegroundColor $colors.Secondary -BackgroundColor $colors.Primary
    Write-Host ("▓▓                                                ▓▓") -ForegroundColor $colors.Primary
    Write-Host ("▓▓              Identity Posture Assessment Tool              ▓▓") -ForegroundColor $colors.Info
    Write-Host ("▓▓                                                ▓▓") -ForegroundColor $colors.Primary
    Write-Host ("▓▓         Free Tools for Identity Visibility & Governance        ▓▓") -ForegroundColor $colors.Muted
    Write-Host ("▓▓                                                ▓▓") -ForegroundColor $colors.Primary
    Write-Host ("▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓") -ForegroundColor $colors.Primary
    Write-Host ""
    Write-Host "  Version $script:version" -ForegroundColor $colors.Muted
    Write-Host "  IdentityFirst Ltd" -ForegroundColor $colors.Muted
    Write-Host "  https://www.identityfirst.net" -ForegroundColor $colors.Muted
    Write-Host ""
    
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
        Write-Host ""
        Write-Host "  ⚠ QuickChecks module not found. Please ensure scripts are extracted." -ForegroundColor $colors.Warning
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
    Write-Host "  Loading QuickChecks framework..." -ForegroundColor $colors.Muted
    try {
        Import-Module (Join-Path $script:modulePath "Module\IdentityFirst.QuickChecks.psm1") -Force -ErrorAction Stop
        Write-Host "  ✓ Framework loaded" -ForegroundColor $colors.Success
    } catch {
        Write-Host "  ✗ Failed to load framework: $($_.Exception.Message)" -ForegroundColor $colors.Error
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
    
    Write-Host "  Available assessments:" -ForegroundColor $colors.Info
    Write-Host ""
    
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
        Write-Host ("  [" + ($i + 1) + "] " + $platformIcon + " " + $a.Name) -ForegroundColor $colors.Secondary
        Write-Host "       " + $a.Desc -ForegroundColor $colors.Muted
    }
    
    Write-Host ""
    Write-Host "  [A] Run ALL assessments" -ForegroundColor $colors.Warning
    Write-Host "  [R] Run recommended (Break-Glass + MFA + Guests)" -ForegroundColor $colors.Info
    Write-Host ""
    
    if ($AutoRun) {
        # Auto-select recommended
        $script:selectedAssessment = "QUICK-FULL"
        Write-Host "  → Auto-running Quick Full Assessment" -ForegroundColor $colors.Warning
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
    
    Write-Host ""
    Write-Host "  Selected: $script:selectedAssessment" -ForegroundColor $colors.Success
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
    
    Write-Host "  Output directory: $outputDir" -ForegroundColor $colors.Muted
    Write-Host ""
    
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
                    Write-Host "  Running $($item.Name)..." -ForegroundColor $colors.Info
                    Write-ProgressBar -Percent 0 -Text $item.Name
                    try {
                        & $item.Path -OutputDirectory $outputDir | Out-Null
                        Write-ProgressBar -Percent 100 -Text "Complete"
                    } catch {
                        Write-Host "  ✗ Error: $($_.Exception.Message)" -ForegroundColor $colors.Error
                    }
                }
            }
            
            Write-Host ""
            Write-Host "  ✅ Recommended assessments complete!" -ForegroundColor $colors.Success
            return
        }
    }
    
    # Run single assessment
    if ($scriptPath -and (Test-Path $scriptPath)) {
        Write-Host "  Running: $assessmentName" -ForegroundColor $colors.Warning
        Write-Host ""
        
        # Progress animation
        for ($i = 0; $i -le 100; $i += 10) {
            Write-ProgressBar -Percent $i -Text "Scanning..."
            Start-Sleep -Milliseconds 200
        }
        
        try {
            & $scriptPath -OutputDirectory $outputDir | Out-Null
            Write-ProgressBar -Percent 100 -Text "Complete"
            Write-Host ""
            Write-Host "  ✅ Assessment complete!" -ForegroundColor $colors.Success
        } catch {
            Write-Host "  ✗ Error: $($_.Exception.Message)" -ForegroundColor $colors.Error
        }
    } else {
        Write-Host "  ✗ Assessment script not found: $scriptPath" -ForegroundColor $colors.Error
    }
}

# ============================================================================
# Summary
# ============================================================================

function Show-Summary {
    Write-SubHeader -Title " ASSESSMENT COMPLETE "
    
    Write-Host "  Results saved to: IFQC-Output\" -ForegroundColor $colors.Info
    Write-Host ""
    Write-Host "  Next steps:" -ForegroundColor $colors.Info
    Write-Host "  1. Review the generated reports" -ForegroundColor $colors.Muted
    Write-Host "  2. Identify findings to investigate" -ForegroundColor $colors.Muted
    Write-Host "  3. Consider IdentityHealthCheck for deeper analysis" -ForegroundColor $colors.Muted
    Write-Host ""
    
    Write-Host "  IdentityHealthCheck provides:" -ForegroundColor $colors.Info
    Write-Host "  • Risk scoring and prioritisation" -ForegroundColor $colors.Muted
    Write-Host "  • Ownership correlation" -ForegroundColor $colors.Muted
    Write-Host "  • Compliance mapping" -ForegroundColor $colors.Muted
    Write-Host "  • Continuous monitoring" -ForegroundColor $colors.Muted
    Write-Host ""
    
    Write-Host "  👉 https://www.identityfirst.net" -ForegroundColor $colors.Primary
    Write-Host ""
}

# ============================================================================
# Main
# ============================================================================

function Main {
    Clear-Host
    
    # Step 1: Welcome
    if (-not (Step1-Welcome)) {
        Write-Host ""
        Write-Host "  ⚠ Please ensure QuickChecks is properly installed." -ForegroundColor $colors.Warning
        exit 1
    }
    
    # Step 2: Connections
    if (-not (Step2-Connections)) {
        Write-Host ""
        Write-Host "  ⚠ Some connections failed. Continuing with available platforms..." -ForegroundColor $colors.Warning
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
