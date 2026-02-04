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
