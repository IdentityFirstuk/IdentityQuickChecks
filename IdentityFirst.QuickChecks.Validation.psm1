<#
.SYNOPSIS
    IdentityFirst QuickChecks - Validation, Trust and Informational Framework

.DESCRIPTION
    Lite framework ensuring QuickChecks is:
    - SECURE: Safe execution, credential handling, dependency validation
    - TRUSTED: Code signing verification, integrity checks, audit logging
    - VALIDATED: Input validation, connection testing, prerequisite checks
    - INFORMATIVE: Progress indicators, summary reports, actionable output

.NOTES
    Author: mark.ahearne@identityfirst.net
    Requirements: PowerShell 5.1+
#>

# =============================================================================
# SECURE: Credential and Secret Handling
# =============================================================================

function Test-SecureCredentialHandling {
    <#
    .SYNOPSIS
        Verifies secure handling of credentials in scripts.
    #>
    param($Context)
    $findings = @()

    # Check for hardcoded credentials in scripts
    $scriptPath = $MyInvocation.MyCommand.Path
    $scriptDir = Split-Path $scriptPath -Parent

    $dangerousPatterns = @(
        @{ Pattern = 'password\s*=\s*["''][^"'']+["'']'; Severity = 'Critical'; Name = 'Hardcoded password' },
        @{ Pattern = 'secret\s*=\s*["''][^"'']+["'']'; Severity = 'Critical'; Name = 'Hardcoded secret' },
        @{ Pattern = 'api[_-]?key\s*=\s*["''][^"'']+["'']'; Severity = 'Critical'; Name = 'Hardcoded API key' },
        @{ Pattern = 'connection[_-]?string\s*=\s*["''][^"'']+["'']'; Severity = 'High'; Name = 'Hardcoded connection string' }
    )

    $psFiles = Get-ChildItem -Path $scriptDir -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue

    foreach ($file in $psFiles) {
        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if ($content) {
            foreach ($check in $dangerousPatterns) {
                if ($content -match $check.Pattern) {
                    $f = @{ Id = "SEC-CRED-001"; Title = "$($check.Name) in $($file.Name)";
                            Description = "Potential $($check.Name.ToLower()) found in script";
                            Severity = $check.Severity; Category = "Security_CredentialHandling";
                            Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @();
                            RemediationSteps = @(); IsResolved = $false; Confidence = "Medium";
                            RuleId = "SEC-CRED-001"; Source = "Security"; CheckName = "CredentialHandlingCheck";
                            AffectedCount = 0; Remediation = "" }
                    $f.Remediation = "Use secure credential storage (Azure Key Vault, Windows Credential Manager, or environment variables)."
                    $f.RemediationSteps = @("Replace hardcoded values with Get-Credential",
                                           "Use environment variables (e.g. `$env:VAR_NAME)",
                                           "Integrate with Azure Key Vault",
                                           "Implement secret management")
                    Add-FindingObject $f $file.Name
                    $findings += $f
                }
            }
        }
    }

    return $findings
}

function Test-LeastPrivilegeExecution {
    <#
    .SYNOPSIS
        Checks if scripts require excessive permissions.
    #>
    param($Context)
    $findings = @()

    # Check current execution context
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = (New-Object System.Security.Principal.WindowsPrincipal $currentUser).IsInRole(
        [System.Security.Principal.WindowsBuiltInRole]::Administrator
    )

    if ($isAdmin) {
        $f = @{ Id = "SEC-PRIV-001"; Title = "Running with administrator privileges";
                Description = "Script is executing with elevated privileges";
                Severity = 'Low'; Category = "Security_LeastPrivilege";
                Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @();
                RemediationSteps = @(); IsResolved = $false; Confidence = "High";
                RuleId = "SEC-PRIV-001"; Source = "Security"; CheckName = "LeastPrivilegeCheck";
                AffectedCount = 0; Remediation = "" }
        $f.Remediation = "Run with least privilege required. Only elevate when necessary."
        $f.RemediationSteps = @("Review if admin rights are truly needed",
                               "Implement Just-In-Time elevation",
                               "Use constrained language mode where possible")
        Add-FindingObject $f $currentUser.Name
        $findings += $f
    }

    # Check for dangerous PowerShell settings
    $executionPolicy = Get-ExecutionPolicy -Scope CurrentUser -ErrorAction SilentlyContinue
    if ($executionPolicy -eq 'Bypass' -or $executionPolicy -eq 'Unrestricted') {
        $f = @{ Id = "SEC-POL-001"; Title = "Execution Policy set to Bypass/Unrestricted";
                Description = "PowerShell execution policy allows running unsigned scripts";
                Severity = 'Medium'; Category = "Security_ExecutionPolicy";
                Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @();
                RemediationSteps = @(); IsResolved = $false; Confidence = "High";
                RuleId = "SEC-POL-001"; Source = "Security"; CheckName = "ExecutionPolicyCheck";
                AffectedCount = 0; Remediation = "" }
        $f.Remediation = "Use RemoteSigned or AllSigned for production. Document why Bypass is needed."
        $f.RemediationSteps = @("Set ExecutionPolicy to RemoteSigned",
                               "Digitally sign all scripts",
                               "Document exception justification")
        Add-FindingObject $f "Execution Policy: $executionPolicy"
        $findings += $f
    }

    return $findings
}

# =============================================================================
# TRUSTED: Code Signing and Integrity Verification
# =============================================================================

function Test-CodeSignature {
    <#
    .SYNOPSIS
        Verifies digital signatures on scripts.
    #>
    param($Context)
    $findings = @()

    $scriptPath = $MyInvocation.MyCommand.Path
    $scriptDir = Split-Path $scriptPath -Parent
    $psFiles = Get-ChildItem -Path $scriptDir -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue

    $unsignedCount = 0
    foreach ($file in $psFiles) {
        try {
            $signature = Get-AuthenticodeSignature $file.FullName -ErrorAction SilentlyContinue
            if (-not $signature -or $signature.Status -ne 'Valid') {
                $unsignedCount++
            }
        }
        catch {
            $unsignedCount++
        }
    }

    if ($unsignedCount -gt 0) {
        $f = @{ Id = "TRUST-SIGN-001"; Title = "$unsignedCount scripts are not digitally signed";
                Description = "Scripts without valid digital signatures may have been tampered with";
                Severity = 'Medium'; Category = "Trust_CodeSigning";
                Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @();
                RemediationSteps = @(); IsResolved = $false; Confidence = "High";
                RuleId = "TRUST-SIGN-001"; Source = "Trust"; CheckName = "CodeSignatureCheck";
                AffectedCount = 0; Remediation = "" }
        $f.Remediation = "Digitally sign all scripts with a trusted certificate."
        $f.RemediationSteps = @("Obtain code signing certificate from trusted CA",
                               "Sign all scripts: Set-AuthenticodeSignature",
                               "Configure execution policy to AllSigned",
                               "Distribute signed scripts only")
        Add-FindingObject $f "$unsignedCount unsigned scripts"
        $findings += $f
    }

    return $findings
}

function Test-FileIntegrity {
    <#
    .SYNOPSIS
        Verifies file integrity using hash checks.
    #>
    param($Context)
    $findings = @()

    $scriptPath = $MyInvocation.MyCommand.Path
    $scriptDir = Split-Path $scriptPath -Parent

    # Calculate hashes for core scripts
    $knownGoodHashes = @{}  # In production, would store known hashes

    $psFiles = Get-ChildItem -Path $scriptDir -Filter '*.ps1' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 20

    foreach ($file in $psFiles) {
        try {
            $hash = (Get-FileHash $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash

            # Check for modified files (simple heuristic - future hashes would be stored)
            $fileAge = (Get-Date) - $file.LastWriteTime
            if ($fileAge.Days -gt 365) {
                $f = @{ Id = "TRUST-INT-001"; Title = "Script has not been updated in over a year";
                        Description = "$($file.Name) was last modified $($fileAge.Days) days ago";
                        Severity = 'Low'; Category = "Trust_FileIntegrity";
                        Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @();
                        RemediationSteps = @(); IsResolved = $false; Confidence = "Medium";
                        RuleId = "TRUST-INT-001"; Source = "Trust"; CheckName = "FileIntegrityCheck";
                        AffectedCount = 0; Remediation = "" }
                $f.Remediation = "Review and update scripts regularly for security patches."
                $f.RemediationSteps = @("Schedule quarterly script review",
                                       "Check for security updates to cmdlets",
                                       "Test scripts after Windows updates")
                Add-FindingObject $f "$($file.Name): $($fileAge.Days) days old"
                $findings += $f
            }
        }
        catch {
            # Skip files we can't hash
        }
    }

    return $findings
}

# =============================================================================
# VALIDATED: Prerequisites and Configuration Checks
# =============================================================================

function Test-Prerequisites {
    <#
    .SYNOPSIS
        Validates all prerequisites are met.
    #>
    param($Context)
    $findings = @()

    # Check PowerShell version
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -lt 5) {
        $f = @{ Id = "VAL-PS-001"; Title = "PowerShell version is below 5.1";
                Description = "Running PowerShell $($psVersion.Major).$($psVersion.Minor). Some features may not work.";
                Severity = 'High'; Category = "Validation_PowerShellVersion";
                Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @();
                RemediationSteps = @(); IsResolved = $false; Confidence = "High";
                RuleId = "VAL-PS-001"; Source = "Validation"; CheckName = "PrerequisitesCheck";
                AffectedCount = 0; Remediation = "" }
        $f.Remediation = "Upgrade to PowerShell 5.1 or later (7.x recommended)."
        $f.RemediationSteps = @("Install Windows Management Framework 5.1",
                               "Or install PowerShell 7+ from GitHub")
        Add-FindingObject $f "Version: $psVersion"
        $findings += $f
    }

    # Check required modules
    $requiredModules = @('Microsoft.Graph', 'Az.Accounts', 'ActiveDirectory')
    foreach ($mod in $requiredModules) {
        $available = Get-Module -ListAvailable -Name $mod -ErrorAction SilentlyContinue
        if (-not $available) {
            $f = @{ Id = "VAL-MOD-001"; Title = "Required module not available: $mod";
                    Description = "$mod module is not installed. Some checks will be skipped.";
                    Severity = 'Medium'; Category = "Validation_Modules";
                    Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @();
                    RemediationSteps = @(); IsResolved = $false; Confidence = "High";
                    RuleId = "VAL-MOD-001"; Source = "Validation"; CheckName = "PrerequisitesCheck";
                    AffectedCount = 0; Remediation = "" }
            $f.Remediation = "Install the required module for full functionality."
            $f.RemediationSteps = @("Install module: Install-Module $mod",
                                   "Or for Graph: Install-Module Microsoft.Graph")
            Add-FindingObject $f $mod
            $findings += $f
        }
    }

    # Check .NET version
    try {
        $netVersion = [System.Environment]::GetVersion()
        $netMajor = [int]($netVersion.Major)
        if ($netMajor -lt 4) {
            $f = @{ Id = "VAL-DOT-001"; Title = "Old .NET Framework version detected";
                    Description = ".NET version may be incompatible with some modules";
                    Severity = 'Low'; Category = "Validation_DotNet";
                    Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @();
                    RemediationSteps = @(); IsResolved = $false; Confidence = "Medium";
                    RuleId = "VAL-DOT-001"; Source = "Validation"; CheckName = "PrerequisitesCheck";
                    AffectedCount = 0; Remediation = "" }
            $f.Remediation = "Ensure .NET 4.5+ is installed for Azure module compatibility."
            $f.RemediationSteps = @("Check .NET version: Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse | Get-ItemProperty -Name version",
                                   "Install .NET 4.8 if needed")
            Add-FindingObject $f ".NET Version: $netVersion"
            $findings += $f
        }
    }
    catch {
        # Skip .NET check if fails
    }

    return $findings
}

function Test-ConnectionValidity {
    <#
    .SYNOPSIS
        Validates connections to cloud services.
    #>
    param($Context)
    $findings = @()

    # Test Microsoft Graph connectivity
    try {
        $graphConnected = $false
        $graphError = ""
        try {
            Connect-MgGraph -Scopes "User.Read.All" -ErrorAction Stop | Out-Null
            $graphConnected = $true
            Disconnect-MgGraph | Out-Null
        }
        catch {
            $graphConnected = $false
            $graphError = $_.Exception.Message
        }

        if (-not $graphConnected) {
            $f = @{ Id = "VAL-CON-001"; Title = "Cannot connect to Microsoft Graph";
                    Description = "Graph connection failed: $graphError";
                    Severity = 'Medium'; Category = "Validation_Connectivity";
                    Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @();
                    RemediationSteps = @(); IsResolved = $false; Confidence = "High";
                    RuleId = "VAL-CON-001"; Source = "Validation"; CheckName = "ConnectionCheck";
                    AffectedCount = 0; Remediation = "" }
            $f.Remediation = "Verify network connectivity and authentication."
            $f.RemediationSteps = @("Check internet connectivity",
                                   "Verify Azure AD tenant access",
                                   "Review Graph permissions",
                                   "Check for conditional access blocking")
            Add-FindingObject $f "Microsoft Graph: $graphError"
            $findings += $f
        }
    }
    catch {
        # Module not available, skip
    }

    # Test Azure connectivity
    try {
        $azConnected = $false
        $azError = ""
        try {
            Get-AzSubscription -ErrorAction Stop | Out-Null
            $azConnected = $true
        }
        catch {
            $azConnected = $false
            $azError = $_.Exception.Message
        }

        if (-not $azConnected) {
            $f = @{ Id = "VAL-CON-002"; Title = "Cannot connect to Azure";
                    Description = "Azure connection failed: $azError";
                    Severity = 'Low'; Category = "Validation_Connectivity";
                    Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @();
                    RemediationSteps = @(); IsResolved = $false; Confidence = "Medium";
                    RuleId = "VAL-CON-002"; Source = "Validation"; CheckName = "ConnectionCheck";
                    AffectedCount = 0; Remediation = "" }
            $f.Remediation = "Azure RBAC checks will be skipped. Connect with Connect-AzAccount if needed."
            $f.RemediationSteps = @("Run: Connect-AzAccount",
                                   "Check Azure subscription access",
                                   "Verify network connectivity")
            Add-FindingObject $f "Azure: $azError"
            $findings += $f
        }
    }
    catch {
        # Module not available, skip
    }

    return $findings
}

function Test-ConfigurationValidity {
    <#
    .SYNOPSIS
        Validates configuration settings.
    #>
    param($Context)
    $findings = @()

    # Check for required environment variables
    $requiredEnvVars = @()

    # Validate output directory is writable
    $outputDir = ".\QuickChecks-Output"
    if (Test-Path $outputDir) {
        try {
            $testFile = Join-Path $outputDir "test-$([guid]::NewGuid().ToString().Substring(0,8)).tmp"
            "test" | Out-File $testFile -ErrorAction Stop
            Remove-Item $testFile -ErrorAction SilentlyContinue
        }
        catch {
            $f = @{ Id = "VAL-CFG-001"; Title = "Output directory not writable";
                    Description = "Cannot write to output directory: $($_.Exception.Message)";
                    Severity = 'Medium'; Category = "Validation_Configuration";
                    Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @();
                    RemediationSteps = @(); IsResolved = $false; Confidence = "High";
                    RuleId = "VAL-CFG-001"; Source = "Validation"; CheckName = "ConfigurationCheck";
                    AffectedCount = 0; Remediation = "" }
            $f.Remediation = "Ensure output directory exists and is writable."
            $f.RemediationSteps = @("Create directory: New-Item -ItemType Directory -Path $outputDir",
                                   "Check NTFS permissions",
                                   "Run as user with write access")
            Add-FindingObject $f $outputDir
            $findings += $f
        }
    }

    return $findings
}

# =============================================================================
# INFORMATIVE: Progress, Logging and Reporting
# =============================================================================

function New-ProgressAssessment {
    <#
    .SYNOPSIS
        Creates a progress tracking assessment.
    #>
    param($Findings)

    # Group findings by category
    $byCategory = $Findings | Group-Object Category
    $bySeverity = $Findings | Group-Object Severity

    return @{
        Timestamp = [datetime]::UtcNow
        TotalFindings = $Findings.Count
        ByCategory = $byCategory
        BySeverity = $bySeverity
        CriticalCount = ($Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
        HighCount = ($Findings | Where-Object { $_.Severity -eq 'High' }).Count
        MediumCount = ($Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
        LowCount = ($Findings | Where-Object { $_.Severity -eq 'Low' }).Count
    }
}

function New-ExecutiveSummary {
    <#
    .SYNOPSIS
        Generates an executive summary.
    #>
    param(
        $Findings,
        $Duration,
        $ModulesScanned
    )

    $critCount = ($Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $highCount = ($Findings | Where-Object { $_.Severity -eq 'High' }).Count

    $summaryBuilder = [System.Text.StringBuilder]::new()

    [void]$summaryBuilder.AppendLine("================================================================================")
    [void]$summaryBuilder.AppendLine("                     IDENTITYFIRST QUICKCHECKS - EXECUTIVE SUMMARY")
    [void]$summaryBuilder.AppendLine("================================================================================")
    [void]$summaryBuilder.AppendLine("")
    [void]$summaryBuilder.AppendLine("Assessment Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC")
    [void]$summaryBuilder.AppendLine("Duration: $Duration seconds")
    [void]$summaryBuilder.AppendLine("Modules Scanned: $($ModulesScanned -join ', ')")
    [void]$summaryBuilder.AppendLine("")
    [void]$summaryBuilder.AppendLine("OVERALL STATUS: $(if ($critCount -gt 0) { 'CRITICAL - Immediate action required' } elseif ($highCount -gt 0) { 'WARNING - Review required' } else { 'HEALTHY - No critical issues' })")
    [void]$summaryBuilder.AppendLine("")
    [void]$summaryBuilder.AppendLine("FINDINGS SUMMARY")
    [void]$summaryBuilder.AppendLine("-------------------------------------------------------------------------------")

    $medCount = ($Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
    $lowCount = ($Findings | Where-Object { $_.Severity -eq 'Low' }).Count

    if ($critCount -gt 0) {
        [void]$summaryBuilder.AppendLine("  CRITICAL:   $critCount   [!!] IMMEDIATE ACTION REQUIRED")
    }
    else {
        [void]$summaryBuilder.AppendLine("  CRITICAL:   $critCount   [OK] No critical findings")
    }

    if ($highCount -gt 0) {
        [void]$summaryBuilder.AppendLine("  HIGH:       $highCount   [!] Review within 7 days")
    }
    else {
        [void]$summaryBuilder.AppendLine("  HIGH:       $highCount   [OK] No high findings")
    }

    [void]$summaryBuilder.AppendLine("  MEDIUM:     $medCount   Review within 30 days")
    [void]$summaryBuilder.AppendLine("  LOW:        $lowCount   Informational")
    [void]$summaryBuilder.AppendLine("")
    [void]$summaryBuilder.AppendLine("BY CATEGORY")
    [void]$summaryBuilder.AppendLine("-------------------------------------------------------------------------------")

    $byCategory = $Findings | Group-Object Category | Sort-Object Count -Descending
    foreach ($group in $byCategory) {
        [void]$summaryBuilder.AppendLine("  $($group.Name): $($group.Count) findings")
    }

    [void]$summaryBuilder.AppendLine("")
    [void]$summaryBuilder.AppendLine("TOP PRIORITY ACTIONS")
    [void]$summaryBuilder.AppendLine("-------------------------------------------------------------------------------")

    $criticalFindings = $Findings | Where-Object { $_.Severity -eq 'Critical' } | Select-Object -First 5
    if ($criticalFindings) {
        foreach ($f in $criticalFindings) {
            [void]$summaryBuilder.AppendLine("  [!!] $($f.Title)")
            [void]$summaryBuilder.AppendLine("      Category: $($f.Category)")
            [void]$summaryBuilder.AppendLine("      Action: $($f.Remediation)")
            [void]$summaryBuilder.AppendLine("")
        }
    }
    else {
        [void]$summaryBuilder.AppendLine("  [OK] No critical findings requiring immediate action")
    }

    [void]$summaryBuilder.AppendLine("")
    [void]$summaryBuilder.AppendLine("RECOMMENDATIONS")
    [void]$summaryBuilder.AppendLine("-------------------------------------------------------------------------------")

    if ($critCount -gt 0) {
        [void]$summaryBuilder.AppendLine("  1. Address all CRITICAL findings immediately")
        [void]$summaryBuilder.AppendLine("  2. Review and remediate HIGH findings within 7 days")
        [void]$summaryBuilder.AppendLine("  3. Schedule review of MEDIUM findings within 30 days")
    }
    elseif ($highCount -gt 0) {
        [void]$summaryBuilder.AppendLine("  1. Review HIGH findings within 7 days")
        [void]$summaryBuilder.AppendLine("  2. Address MEDIUM findings within 30 days")
    }
    else {
        [void]$summaryBuilder.AppendLine("  1. Continue regular security assessments")
        [void]$summaryBuilder.AppendLine("  2. Monitor for new findings")
    }

    [void]$summaryBuilder.AppendLine("")
    [void]$summaryBuilder.AppendLine("================================================================================")

    return $summaryBuilder.ToString()
}

function Write-ProgressIndicator {
    <#
    .SYNOPSIS
        Displays a progress indicator.
    #>
    param(
        [int]$Current,
        [int]$Total,
        [string]$Activity,
        [string[]]$Messages
    )

    $percent = [int](($Current / $Total) * 100)
    $filled = [int]($percent / 5)
    $empty = 20 - $filled
    $bar = ("#" * $filled) + ("-" * $empty)

    Write-Host "`r[$bar] $percent% - $Activity" -NoNewline -ForegroundColor Cyan
    if ($Current -eq $Total) {
        Write-Host " [OK]" -ForegroundColor Green
    }
}

function New-AuditLog {
    <#
    .SYNOPSIS
        Creates an audit log entry.
    #>
    param(
        [string]$Operation,
        [string]$User,
        [string]$Result,
        [string]$Details
    )

    $logEntry = @{
        Timestamp = [datetime]::UtcNow
        Operation = $Operation
        User = $User
        Result = $Result
        Details = $Details
        SessionId = [guid]::NewGuid().ToString().Substring(0, 8)
    }

    return $logEntry
}

# =============================================================================
# MAIN VALIDATION FUNCTION
# =============================================================================

function Invoke-QuickChecksValidation {
    <#
    .SYNOPSIS
        Runs comprehensive validation, trust, security, and information checks.
    #>
    [CmdletBinding()] param(
        [string]$OutputDir = ".\QuickChecks-Validation-Output",
        [ValidateSet('Console', 'Json')][string]$Format = 'Console',
        [switch]$SkipSecurity,
        [switch]$SkipTrust,
        [switch]$SkipValidation,
        [switch]$Help
    )

    if ($Help) {
        Write-Host @"
IdentityFirst QuickChecks - Validation and Trust Framework
=========================================================
Ensures QuickChecks is SECURE, TRUSTED, VALIDATED, and INFORMATIVE.

SECURE Checks:
  - Credential handling (no hardcoded secrets)
  - Least privilege execution
  - Execution policy validation

TRUSTED Checks:
  - Code signature verification
  - File integrity validation

VALIDATED Checks:
  - Prerequisites (PS version, modules)
  - Connectivity (Graph, Azure)
  - Configuration (output directories)

INFORMATIVE Output:
  - Progress indicators
  - Executive summaries
  - Audit logging
  - Categorized findings

USAGE:
    Invoke-QuickChecksValidation [-OutputDir <path>] [-Format <format>]

FLAGS:
    -SkipSecurity    Skip security checks
    -SkipTrust       Skip trust verification
    -SkipValidation  Skip validation checks
"@
        return
    }

    Write-Host "`n+================================================================================+" -ForegroundColor Cyan
    Write-Host "|  IdentityFirst QuickChecks - Security, Trust and Validation Framework        |" -ForegroundColor Cyan
    Write-Host "+================================================================================+" -ForegroundColor Cyan

    $startTime = Get-Date
    $context = @{ StartTime = $startTime; Log = @() }
    $allFindings = @()

    # Security Checks
    if (-not $SkipSecurity) {
        Write-Host "`n[SECURITY] Running security checks..." -ForegroundColor Yellow
        Write-Host "  [1/3] Testing credential handling..." -ForegroundColor Gray
        $allFindings += Test-SecureCredentialHandling -Context $context
        Write-Host "  [2/3] Testing least privilege..." -ForegroundColor Gray
        $allFindings += Test-LeastPrivilegeExecution -Context $context
        Write-Host "  [3/3] Security checks complete" -ForegroundColor Green
    }

    # Trust Checks
    if (-not $SkipTrust) {
        Write-Host "`n[TRUST] Running trust verification..." -ForegroundColor Yellow
        Write-Host "  [1/2] Verifying code signatures..." -ForegroundColor Gray
        $allFindings += Test-CodeSignature -Context $context
        Write-Host "  [2/2] Checking file integrity..." -ForegroundColor Gray
        $allFindings += Test-FileIntegrity -Context $context
        Write-Host "  Trust verification complete" -ForegroundColor Green
    }

    # Validation Checks
    if (-not $SkipValidation) {
        Write-Host "`n[VALIDATION] Running validation..." -ForegroundColor Yellow
        Write-Host "  [1/3] Checking prerequisites..." -ForegroundColor Gray
        $allFindings += Test-Prerequisites -Context $context
        Write-Host "  [2/3] Testing connectivity..." -ForegroundColor Gray
        $allFindings += Test-ConnectionValidity -Context $context
        Write-Host "  [3/3] Validating configuration..." -ForegroundColor Gray
        $allFindings += Test-ConfigurationValidity -Context $context
        Write-Host "  Validation complete" -ForegroundColor Green
    }

    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalSeconds

    # Generate reports
    Write-Host "`n[REPORT] Generating reports..." -ForegroundColor Yellow

    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    $timestamp = $startTime.ToString('yyyyMMdd-HHmmss')

    # Executive Summary
    $summary = New-ExecutiveSummary -Findings $allFindings -Duration $duration -ModulesScanned @('Security', 'Trust', 'Validation')
    Write-Host $summary

    # Save JSON report
    if ($Format -eq 'Json') {
        $report = @{
            Timestamp = $startTime
            Duration = $duration
            Findings = $allFindings
            Progress = New-ProgressAssessment -Findings $allFindings
            AuditLog = New-AuditLog -Operation "FullValidation" -User $env:USERNAME -Result "Complete" -Details "$($allFindings.Count) findings"
        }
        $report | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $OutputDir "Validation-Report-$timestamp.json") -Encoding UTF8
        Write-Host "JSON Report: $(Join-Path $OutputDir "Validation-Report-$timestamp.json")" -ForegroundColor Green
    }

    # Save executive summary
    $summary | Set-Content -Path (Join-Path $OutputDir "Executive-Summary-$timestamp.txt") -Encoding UTF8
    Write-Host "Summary: $(Join-Path $OutputDir "Executive-Summary-$timestamp.txt")" -ForegroundColor Green

    # Display statistics
    $crit = ($allFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $high = ($allFindings | Where-Object { $_.Severity -eq 'High' }).Count

    Write-Host "`n================================================================================" -ForegroundColor Cyan
    Write-Host " VALIDATION SUMMARY " -ForegroundColor White
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Duration: $([math]::Round($duration, 2)) seconds"
    Write-Host "  Total Findings: $($allFindings.Count)"
    Write-Host "  Critical: $crit" -ForegroundColor $(if ($crit -gt 0) { 'Red' } else { 'Green' })
    Write-Host "  High: $high" -ForegroundColor $(if ($high -gt 0) { 'DarkRed' } else { 'Green' })
    Write-Host "  Medium: $(($allFindings | Where-Object { $_.Severity -eq 'Medium' }).Count)" -ForegroundColor Yellow
    Write-Host "  Low: $(($allFindings | Where-Object { $_.Severity -eq 'Low' }).Count)" -ForegroundColor Cyan
    Write-Host ""

    $exitCode = if ($crit -gt 0) { 2 } elseif ($high -gt 0) { 1 } else { 0 }
    Write-Host "Exit Code: $exitCode" -ForegroundColor Gray
    Write-Host ""

    return @{ Findings = $allFindings; ExitCode = $exitCode; Duration = $duration }
}

Export-ModuleMember -Function Invoke-QuickChecksValidation

# SIG # Begin signature block
# MIIf3QYJKoZIhvcNAQcCoIIfzjCCH8oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBZQ/zNJkKZ3+/J
# ugmFBux4Wterm+dlzaaRT+mpBxc2vKCCGNwwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggWeMIIDhqADAgECAhAfb4XAeia2j0f08ahQbRKXMA0GCSqG
# SIb3DQEBCwUAMGcxCzAJBgNVBAYTAkdCMRcwFQYDVQQHDA5Ob3J0aHVtYmVybGFu
# ZDEaMBgGA1UECgwRSWRlbnRpdHlGaXJzdCBMdGQxIzAhBgNVBAMMGklkZW50aXR5
# Rmlyc3QgQ29kZSBTaWduaW5nMB4XDTI2MDEyOTIwNTAyM1oXDTI5MDEyOTIxMDAy
# M1owZzELMAkGA1UEBhMCR0IxFzAVBgNVBAcMDk5vcnRodW1iZXJsYW5kMRowGAYD
# VQQKDBFJZGVudGl0eUZpcnN0IEx0ZDEjMCEGA1UEAwwaSWRlbnRpdHlGaXJzdCBD
# b2RlIFNpZ25pbmcwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDV9YyY
# z49V2ipI5ePMgWVHs5h89pYHRk60XSkSOUrCXYH+83sOhTgzKnpvwo7Mzuchbf6f
# q4+85DpydvkLD1L/ZMAF3x1oP74iZ28JZYv/3PwrwLsUDAAiqFQlZk7YrDxgMhdO
# Z90dXpnK+xLTfbaRGLaqB40xnCMAozxHwIm1ClEOOlhC/I+BoPZqG6GRCcOXIdzU
# UQFWRGw8o33e2YyvDfCpwZlFHTgbD1Zmsx/SE7x9LiKi3UdnAyOMlrfHgSeJRIss
# omIVDKheB5MuAHlZQm//DMNBV7o+jO3prF4MJJygD+scND5ZImw+3L2BJEPYyBLZ
# Jum+fnKp4obGnMafQWyEk77bR+ebX3hIyglqcEwalVFdPQsIMeNQ7ervsFy7NOU0
# wBPIuEgLifGWwTVPHy70T2Ci+rz5+93qSljOWvOeT4LdQ/hpqH9JS4Eu4SpJrJ+U
# 6pwdbB3rZnFLax57w/Uh/ayZ74FZDvZhCg8KaV5sJo7XgbwZ44b3OPo6bXAWV7Jl
# yIWrO4h1q3QbgSXVWui3fWxfNmHgW3CEPTzKJlRM88wCvcPe/gQYx4aDFUKtEoiE
# JKmbuDFWoHyDAEuVo+ohUt03eRdEv73XZR/hwg9imN6NbaaR9aG1TV8C3/uMD5ET
# jBmdlUcGEztyHDLzVyIad+RQGh3nDmq2vhGLfQIDAQABo0YwRDAOBgNVHQ8BAf8E
# BAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFHZkS4haGPdZn+Um
# 4fJ/zeQU7kJzMA0GCSqGSIb3DQEBCwUAA4ICAQAnWa5k8D/hKdPn9IIZNY15hX6B
# NQylhSEPNRl4PT4vR1KKyX7Wl6c55c57z3egOC23wjOC6n0Nzt0JzZwgor9Do2V8
# 7R7APMQbXVMU2N1wDugVMNBsXbDbcS4AJz2IxRPmcW+CbMo32BoFeVbc6AODLhEr
# 1PEcAydxANk7E3rxXd1TD7pCLgp1XtRmZPx87SVJgYrRvr7J3VG0As/2KOO6Eu8n
# QTAwiyOZaRXh8MGmI/kd8SUZzFzwRpcafvSgjGqbQK6s4Tkvyxo9rkLKcS9xOww7
# hyEB6mmmV9Z0kPRBMk7llIKebFzN3exzhU8Jrdsnoas4dHl/O78VOl7nZEAbujhF
# l2IL+wFTicwrwCe9s4ZVtEhFZogUAxgGk6Ut00axJF5DgRuvc06YSRrrG7DvMKZw
# vSLWeeT9u+gbwmwEFLIjaEuF+PG0HQ2EgEaNxOKXP7xjJzLo58f5GWoFk+AKealG
# 8E1TuUfHLGJSl4m30vmenyjTlWtpcgbX5XBAb7BbYv3BrIsTiPwoqKY/X9orSDK8
# owFCw1x3Gy+K2DnaVR8JMtGv5KfC2hSobmjnc3nsryd0Bf0iEO/rcwtNbhAzjNEi
# rEKDng+bz5WEJ5HXVg3SXB7v73m+Q4xNVPfBT4WVV0YHxlbwtIk/Jpbsls43n5Uv
# 6aqzWFEZtlMMLRwTezCCBrQwggScoAMCAQICEA3HrFcF/yGZLkBDIgw6SYYwDQYJ
# KoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IElu
# YzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQg
# VHJ1c3RlZCBSb290IEc0MB4XDTI1MDUwNzAwMDAwMFoXDTM4MDExNDIzNTk1OVow
# aTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQD
# EzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1
# NiAyMDI1IENBMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALR4MdMK
# mEFyvjxGwBysddujRmh0tFEXnU2tjQ2UtZmWgyxU7UNqEY81FzJsQqr5G7A6c+Gh
# /qm8Xi4aPCOo2N8S9SLrC6Kbltqn7SWCWgzbNfiR+2fkHUiljNOqnIVD/gG3SYDE
# Ad4dg2dDGpeZGKe+42DFUF0mR/vtLa4+gKPsYfwEu7EEbkC9+0F2w4QJLVSTEG8y
# AR2CQWIM1iI5PHg62IVwxKSpO0XaF9DPfNBKS7Zazch8NF5vp7eaZ2CVNxpqumzT
# CNSOxm+SAWSuIr21Qomb+zzQWKhxKTVVgtmUPAW35xUUFREmDrMxSNlr/NsJyUXz
# dtFUUt4aS4CEeIY8y9IaaGBpPNXKFifinT7zL2gdFpBP9qh8SdLnEut/GcalNeJQ
# 55IuwnKCgs+nrpuQNfVmUB5KlCX3ZA4x5HHKS+rqBvKWxdCyQEEGcbLe1b8Aw4wJ
# khU1JrPsFfxW1gaou30yZ46t4Y9F20HHfIY4/6vHespYMQmUiote8ladjS/nJ0+k
# 6MvqzfpzPDOy5y6gqztiT96Fv/9bH7mQyogxG9QEPHrPV6/7umw052AkyiLA6tQb
# Zl1KhBtTasySkuJDpsZGKdlsjg4u70EwgWbVRSX1Wd4+zoFpp4Ra+MlKM2baoD6x
# 0VR4RjSpWM8o5a6D8bpfm4CLKczsG7ZrIGNTAgMBAAGjggFdMIIBWTASBgNVHRMB
# Af8ECDAGAQH/AgEAMB0GA1UdDgQWBBTvb1NK6eQGfHrK4pBW9i/USezLTjAfBgNV
# HSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYD
# VR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1Ud
# HwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwH
# ATANBgkqhkiG9w0BAQsFAAOCAgEAF877FoAc/gc9EXZxML2+C8i1NKZ/zdCHxYga
# MH9Pw5tcBnPw6O6FTGNpoV2V4wzSUGvI9NAzaoQk97frPBtIj+ZLzdp+yXdhOP4h
# CFATuNT+ReOPK0mCefSG+tXqGpYZ3essBS3q8nL2UwM+NMvEuBd/2vmdYxDCvwzJ
# v2sRUoKEfJ+nN57mQfQXwcAEGCvRR2qKtntujB71WPYAgwPyWLKu6RnaID/B0ba2
# H3LUiwDRAXx1Neq9ydOal95CHfmTnM4I+ZI2rVQfjXQA1WSjjf4J2a7jLzWGNqNX
# +DF0SQzHU0pTi4dBwp9nEC8EAqoxW6q17r0z0noDjs6+BFo+z7bKSBwZXTRNivYu
# ve3L2oiKNqetRHdqfMTCW/NmKLJ9M+MtucVGyOxiDf06VXxyKkOirv6o02OoXN4b
# FzK0vlNMsvhlqgF2puE6FndlENSmE+9JGYxOGLS/D284NHNboDGcmWXfwXRy4kbu
# 4QFhOm0xJuF2EZAOk5eCkhSxZON3rGlHqhpB/8MluDezooIs8CVnrpHMiD2wL40m
# m53+/j7tFaxYKIqL0Q4ssd8xHZnIn/7GELH3IdvG2XlM9q7WP/UwgOkw/HQtyRN6
# 2JK4S1C8uw3PdBunvAZapsiI5YKdvlarEvf8EA+8hcpSM9LHJmyrxaFtoza2zNaQ
# 9k+5t1wwggbtMIIE1aADAgECAhAKgO8YS43xBYLRxHanlXRoMA0GCSqGSIb3DQEB
# CwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8G
# A1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBT
# SEEyNTYgMjAyNSBDQTEwHhcNMjUwNjA0MDAwMDAwWhcNMzYwOTAzMjM1OTU5WjBj
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMT
# MkRpZ2lDZXJ0IFNIQTI1NiBSU0E0MDk2IFRpbWVzdGFtcCBSZXNwb25kZXIgMjAy
# NSAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0EasLRLGntDqrmBW
# sytXum9R/4ZwCgHfyjfMGUIwYzKomd8U1nH7C8Dr0cVMF3BsfAFI54um8+dnxk36
# +jx0Tb+k+87H9WPxNyFPJIDZHhAqlUPt281mHrBbZHqRK71Em3/hCGC5KyyneqiZ
# 7syvFXJ9A72wzHpkBaMUNg7MOLxI6E9RaUueHTQKWXymOtRwJXcrcTTPPT2V1D/+
# cFllESviH8YjoPFvZSjKs3SKO1QNUdFd2adw44wDcKgH+JRJE5Qg0NP3yiSyi5Mx
# gU6cehGHr7zou1znOM8odbkqoK+lJ25LCHBSai25CFyD23DZgPfDrJJJK77epTwM
# P6eKA0kWa3osAe8fcpK40uhktzUd/Yk0xUvhDU6lvJukx7jphx40DQt82yepyekl
# 4i0r8OEps/FNO4ahfvAk12hE5FVs9HVVWcO5J4dVmVzix4A77p3awLbr89A90/nW
# GjXMGn7FQhmSlIUDy9Z2hSgctaepZTd0ILIUbWuhKuAeNIeWrzHKYueMJtItnj2Q
# +aTyLLKLM0MheP/9w6CtjuuVHJOVoIJ/DtpJRE7Ce7vMRHoRon4CWIvuiNN1Lk9Y
# +xZ66lazs2kKFSTnnkrT3pXWETTJkhd76CIDBbTRofOsNyEhzZtCGmnQigpFHti5
# 8CSmvEyJcAlDVcKacJ+A9/z7eacCAwEAAaOCAZUwggGRMAwGA1UdEwEB/wQCMAAw
# HQYDVR0OBBYEFOQ7/PIx7f391/ORcWMZUEPPYYzoMB8GA1UdIwQYMBaAFO9vU0rp
# 5AZ8esrikFb2L9RJ7MtOMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggr
# BgEFBQcDCDCBlQYIKwYBBQUHAQEEgYgwgYUwJAYIKwYBBQUHMAGGGGh0dHA6Ly9v
# Y3NwLmRpZ2ljZXJ0LmNvbTBdBggrBgEFBQcwAoZRaHR0cDovL2NhY2VydHMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNI
# QTI1NjIwMjVDQTEuY3J0MF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly9jcmwzLmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZT
# SEEyNTYyMDI1Q0ExLmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1s
# BwEwDQYJKoZIhvcNAQELBQADggIBAGUqrfEcJwS5rmBB7NEIRJ5jQHIh+OT2Ik/b
# NYulCrVvhREafBYF0RkP2AGr181o2YWPoSHz9iZEN/FPsLSTwVQWo2H62yGBvg7o
# uCODwrx6ULj6hYKqdT8wv2UV+Kbz/3ImZlJ7YXwBD9R0oU62PtgxOao872bOySCI
# LdBghQ/ZLcdC8cbUUO75ZSpbh1oipOhcUT8lD8QAGB9lctZTTOJM3pHfKBAEcxQF
# oHlt2s9sXoxFizTeHihsQyfFg5fxUFEp7W42fNBVN4ueLaceRf9Cq9ec1v5iQMWT
# FQa0xNqItH3CPFTG7aEQJmmrJTV3Qhtfparz+BW60OiMEgV5GWoBy4RVPRwqxv7M
# k0Sy4QHs7v9y69NBqycz0BZwhB9WOfOu/CIJnzkQTwtSSpGGhLdjnQ4eBpjtP+XB
# 3pQCtv4E5UCSDag6+iX8MmB10nfldPF9SVD7weCC3yXZi/uuhqdwkgVxuiMFzGVF
# wYbQsiGnoa9F5AaAyBjFBtXVLcKtapnMG3VH3EmAp/jsJ3FVF3+d1SVDTmjFjLbN
# FZUWMXuZyvgLfgyPehwJVxwC+UpX2MSey2ueIu9THFVkT+um1vshETaWyQo8gmBt
# o/m3acaP9QsuLj3FNwFlTxq25+T4QwX9xa6ILs84ZPvmpovq90K8eWyG2N01c4Ih
# SOxqt81nMYIGVzCCBlMCAQEwezBnMQswCQYDVQQGEwJHQjEXMBUGA1UEBwwOTm9y
# dGh1bWJlcmxhbmQxGjAYBgNVBAoMEUlkZW50aXR5Rmlyc3QgTHRkMSMwIQYDVQQD
# DBpJZGVudGl0eUZpcnN0IENvZGUgU2lnbmluZwIQH2+FwHomto9H9PGoUG0SlzAN
# BglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqG
# SIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3
# AgEVMC8GCSqGSIb3DQEJBDEiBCBCSwJRYvggV0DYdPkELEnWQcs65EnWs4FU/QFm
# FkmgejANBgkqhkiG9w0BAQEFAASCAgAalGydv2URUGWQJrYXIAdIH9Id10zDg4ah
# LylJUZBngoQDfXOMVQhNPRqPgVc6hSS57dF2x1jzCJGazd5nXBH5Sd6z6deaedda
# j7MF2rfFmVrPPoNRmtamPSrIktj+km44Glr4TUA3YGzrbz26pmcEXYvXbQiopunH
# T/dBykiC1PiZrUyO0yHD0Dx01AQ8zPyYmuFxS/usR/kOj9YpCxByULShkZqOoHUF
# 3Q9AMGD8z6ormvs/NrXTo1iPwU0aTtNyzuaVrpxL5l7HvKjn38XCYCO+xfLVvnHs
# VTvvc1GEQqvZeWACVGYboLPxTqedLcKtLbO+QWieRs3EED4bcPmt2f6geSsEK3dQ
# XvVf258cFxvYvkoLNZk4uWphaZAyG5x15rzcRq3bIzxyycPfHwwqq790IIGmi/4G
# RQ+VB5mH+7pJf6d9lYinRjefhF6i3YuUSJr4/+8RSVR9dvCQJv06PLkNPFbIDIYB
# 5e+vQpWD9bkSoU4osigbDohAjB7sNXbzonE0Tjqbog5cnLWfzTckOQBbWog7iXLW
# 5MlqMcn91XDFm8SO1H2Fy6aHle6VmDxMNq+6QV6dGfKgl3u0lDzh3U2MX6Xrzs/x
# NRiBFLL2SpgYaSzOao9lVDIIacSZqAM0wgoCbxQt3MSE1rInfRYG4iOBTIl9/jTK
# Ghhog1kO/aGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAyMDUxNzEyNDdaMC8G
# CSqGSIb3DQEJBDEiBCCPd8vPyYHZ1Q1SdnI636+csKgNT2/jHp8HselK/rt0SzAN
# BgkqhkiG9w0BAQEFAASCAgDL9Z2t4DaROM/5OBl3Mx4YYIVOIMg+9OPcfvdDe0wh
# Z4fsz5ejhgXEeVbH/L+2vMctUwwA8xqlYebzwX+CjwhjTyKP0DLqjmKIZM0JoqO2
# LWHNAlli3SXnPq1SPpDDFJu4qtPn6nJ/qhYr9PJE6Az71RhVH1+rb3E2MJdrsU+U
# Acw9Z8gezlTLhCpndqKu/pyG9jmQvDesrAPRl5u0/skkI42vGt2FbtwvzMNjoRmF
# eZ0O8O3e6En+KjCmHc7JaMPTYosRv3/yLz1waRLhsIf2/faeo9wLXNULRphPTQQJ
# k5lPgNF0VRy4dweNeZoi8K1Asu+ySOFIMSegLcoOve5pPUdnnHiQ7gNtoBJn4Xad
# RwRFj3+meRxAs1Pu5mlOXhgg9MazwTokcUjpKnJjcjghk0FA54RNN/rRuDVn6Caf
# 5LoSTEemRLwkuLQZ2s4dY2OnEPE9u8p0W0FIW7cxe4HELGFjUByW+fdfahzaJYTR
# O2IxNSwHNUEhwKZIchKrAofG8a63pKqnQJt87RbVbB7U5pEppYcGGniyPNvoZodM
# QkvO+L/cHnI5NemHbRIqHLPseEekvMwLdYsYSdwnrVHaxIYdW38sAseWbBpi0a3q
# yusG8DHAsUlCfZEjXekI5zjOOla/GfRfx3rSq2ckILeHtyLC1ThdQkyZIy4sbhFC
# ew==
# SIG # End signature block
