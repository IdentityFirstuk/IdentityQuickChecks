# ============================================================================
# IdentityFirst QuickChecks - Main Runner Script
# ============================================================================
# Consolidated script to run all QuickChecks across platforms
# Generates JSON report and optional HTML dashboard
# ============================================================================

#requires -Version 5.1

[CmdletBinding()]
param(
    # Platform selection
    [Parameter(Mandatory=$false)]
    [switch]$EntraId,
    
    [Parameter(Mandatory=$false)]
    [switch]$Azure,
    
    [Parameter(Mandatory=$false)]
    [switch]$ActiveDirectory,
    
    [Parameter(Mandatory=$false)]
    [switch]$AWS,
    
    [Parameter(Mandatory=$false)]
    [switch]$GCP,
    
    [Parameter(Mandatory=$false)]
    [switch]$AllPlatforms,
    
    # Output options
    [Parameter(Mandatory=$false)]
    [string]$OutputDir = ".\QuickChecks-Results",
    
    [Parameter(Mandatory=$false)]
    [switch]$GenerateDashboard,
    
    [Parameter(Mandatory=$false)]
    [string]$DashboardTitle = "IdentityFirst QuickChecks Report",
    
    # Cloud credentials
    [Parameter(Mandatory=$false)]
    [string]$TenantId,
    
    [Parameter(Mandatory=$false)]
    [pscredential]$EntraIdCredential,
    
    [Parameter(Mandatory=$false)]
    [string]$AzureSubscriptionId,
    
    [Parameter(Mandatory=$false)]
    [string]$ADDomain,
    
    [Parameter(Mandatory=$false)]
    [string]$AWSRegion = 'us-east-1',
    
    [Parameter(Mandatory=$false)]
    [string]$GCPOrganizationId,
    
    [Parameter(Mandatory=$false)]
    [string]$GCPProjectId,
    
    # Execution options
    [Parameter(Mandatory=$false)]
    [int]$ThrottleLimit = 5,
    
    [Parameter(Mandatory=$false)]
    [switch]$SilentMode
)

# Import required modules
$ErrorActionPreference = 'Stop'

function Import-ModuleSafe {
    param([string]$Name)
    
    try {
        $null = Import-Module $Name -ErrorAction Stop
        return $true
    }
    catch {
        Write-Warning "Module $Name not available: $($_.Exception.Message)"
        return $false
    }
}

# Try to load QuickChecks modules
$modulesPath = $PSScriptRoot
if (-not $modulesPath) { $modulesPath = '.' }

$moduleFiles = @(
    'IdentityFirst.QuickChecks.Lite.psm1',
    'IdentityFirst.QuickChecks.EntraID.psm1',
    'IdentityFirst.QuickChecks.Extended.psm1',
    'IdentityFirst.QuickChecks.Validation.psm1',
    'IdentityFirst.QuickChecks.Additional.psm1'
)

foreach ($modFile in $moduleFiles) {
    $modPath = Join-Path $modulesPath $modFile
    if (Test-Path $modPath) {
        try {
            $null = Import-Module $modPath -ErrorAction Stop
            if (-not $SilentMode) {
                Write-Host "Loaded: $modFile" -ForegroundColor Green
            }
        }
        catch {
            if (-not $SilentMode) {
                Write-Warning "Failed to load module: $($_.Exception.Message)"
            }
        }
    }
}

# Import shared module for report formatting
$sharedModule = Join-Path $modulesPath 'Shared' 'ReportFormatter.psm1'
if (Test-Path $sharedModule) {
    try {
        $null = Import-Module $sharedModule -ErrorAction Stop
    }
    catch {
        # Continue without shared module
    }
}

# ============================================================================
# Main Execution
# ============================================================================

if (-not $SilentMode) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  IdentityFirst QuickChecks Runner" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    Write-Host "Execution Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
    Write-Host "PowerShell Version: $($PSVersionTable.PSVersion.ToString())`n" -ForegroundColor White
}

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Initialize results collection
$allFindings = @()
$checkResults = @()
$executionSummary = @{
    StartTime = (Get-Date)
    Platform = @()
    TotalChecks = 0
    Passed = 0
    Failed = 0
    Warnings = 0
    Errors = 0
}

# Function to process check results
function Add-CheckResult {
    param([PSCustomObject]$Result)
    
    $script:checkResults += $Result
    $script:executionSummary.TotalChecks++
    
    switch ($Result.Status) {
        'Pass' { $script:executionSummary.Passed++ }
        'Fail' { $script:executionSummary.Failed++ }
        'Warning' { $script:executionSummary.Warnings++ }
        'Error' { $script:executionSummary.Errors++ }
    }
    
    # Collect findings
    if ($Result.Findings) {
        foreach ($finding in $Result.Findings) {
            $finding | Add-Member -NotePropertyName 'CheckId' -NotePropertyValue $Result.CheckId -Force
            $finding | Add-Member -NotePropertyName 'CheckName' -NotePropertyValue $Result.CheckName -Force
            $finding | Add-Member -NotePropertyName 'Category' -NotePropertyValue $Result.Category -Force
            $script:allFindings += $finding
        }
    }
}

# ============================================================================
# Prerequisites Check
# ============================================================================

if (-not $SilentMode) {
    Write-Host "[1/6] Running Prerequisites Check..." -ForegroundColor Cyan
}

try {
    $prereqResult = Test-Prerequisites
    Add-CheckResult -Result $prereqResult
    
    if (-not $prereqResult.PrerequisitesMet -and -not $SilentMode) {
        Write-Warning "Some prerequisites are not met. Check results for details."
    }
}
catch {
    Add-CheckResult -Result @{
        CheckId = 'IDF-SYS-PREREQ'
        CheckName = 'System Prerequisites'
        Category = 'System'
        Severity = 'High'
        Status = 'Error'
        Findings = @(
            @{
                Title = 'Prerequisites check failed'
                Description = $_.Exception.Message
                Remediation = 'Ensure PowerShell 5.1 and required modules are available'
                AffectedCount = 1
                Confidence = 'Medium'
            }
        )
        Timestamp = (Get-Date -Format 'o')
    }
}

# ============================================================================
# Entra ID Checks
# ============================================================================

if ($AllPlatforms -or $EntraId) {
    if (-not $SilentMode) {
        Write-Host "[2/6] Running Entra ID Checks..." -ForegroundColor Cyan
    }
    $executionSummary.Platform += 'Entra ID'
    
    try {
        # Core Entra ID checks
        $checks = @(
            @{ Name = 'MFA Coverage'; Func = { Invoke-IFQCMfaCoverageGapCheck } }
            @{ Name = 'Guest User'; Func = { Invoke-IFQCGuestCreepCheck } }
            @{ Name = 'Legacy Auth'; Func = { Invoke-IFQCLegacyAuthRealityCheck } }
            @{ Name = 'Hybrid Sync'; Func = { Invoke-IFQCHybridSyncRealityCheck } }
            @{ Name = 'App Consent'; Func = { Invoke-IFQCAppConsentRealityCheck } }
        )
        
        foreach ($check in $checks) {
            if (-not $SilentMode) {
                Write-Host "  - $($check.Name)..." -ForegroundColor Gray
            }
            try {
                $result = & $check.Func
                Add-CheckResult -Result $result
            }
            catch {
                Add-CheckResult -Result @{
                    CheckId = "IDF-ENT-$($check.Name.ToUpper().Replace(' ', '-'))"
                    CheckName = $check.Name
                    Category = 'Entra ID'
                    Severity = 'Medium'
                    Status = 'Error'
                    Findings = @(
                        @{
                            Title = "Check failed: $($check.Name)"
                            Description = $_.Exception.Message
                            Remediation = 'Verify Microsoft Graph API access'
                            AffectedCount = 1
                            Confidence = 'Low'
                        }
                    )
                    Timestamp = (Get-Date -Format 'o')
                }
            }
        }
        
        # Additional Entra ID checks
        if (Get-Command 'Invoke-EntraIdAccessReviewCheck' -ErrorAction SilentlyContinue) {
            try {
                $result = Invoke-EntraIdAccessReviewCheck -TenantId $TenantId -Credential $EntraIdCredential
                Add-CheckResult -Result $result
            }
            catch { }
        }
        
        if (Get-Command 'Invoke-EntraIdEntitlementManagementCheck' -ErrorAction SilentlyContinue) {
            try {
                $result = Invoke-EntraIdEntitlementManagementCheck -TenantId $TenantId -Credential $EntraIdCredential
                Add-CheckResult -Result $result
            }
            catch { }
        }
    }
    catch {
        if (-not $SilentMode) {
            Write-Warning "Entra ID checks encountered errors: $($_.Exception.Message)"
        }
    }
}

# ============================================================================
# Azure Checks
# ============================================================================

if ($AllPlatforms -or $Azure) {
    if (-not $SilentMode) {
        Write-Host "[3/6] Running Azure Checks..." -ForegroundColor Cyan
    }
    $executionSummary.Platform += 'Azure'
    
    try {
        # Azure RBAC checks
        $azChecks = @(
            @{ Name = 'Wide Scope Roles'; Func = { Invoke-IFQCWideScopeRoleCheck } }
            @{ Name = 'Overprivileged Roles'; Func = { Invoke-IFQCOverprivilegedRoleCheck } }
            @{ Name = 'Classic Admins'; Func = { Invoke-IFQCClassicAdminCheck } }
            @{ Name = 'Permanent Assignments'; Func = { Invoke-IFQCPermanentRoleAssignmentCheck } }
        )
        
        foreach ($check in $azChecks) {
            if (-not $SilentMode) {
                Write-Host "  - $($check.Name)..." -ForegroundColor Gray
            }
            try {
                $result = & $check.Func
                Add-CheckResult -Result $result
            }
            catch {
                # Azure check failed, continue
            }
        }
        
        # Additional Azure checks
        if (Get-Command 'Invoke-AzureSecurityCenterCheck' -ErrorAction SilentlyContinue) {
            try {
                $result = Invoke-AzureSecurityCenterCheck -SubscriptionId $AzureSubscriptionId
                Add-CheckResult -Result $result
            }
            catch { }
        }
        
        if (Get-Command 'Invoke-AzureDefenderPlansCheck' -ErrorAction SilentlyContinue) {
            try {
                $result = Invoke-AzureDefenderPlansCheck -SubscriptionId $AzureSubscriptionId
                Add-CheckResult -Result $result
            }
            catch { }
        }
    }
    catch {
        if (-not $SilentMode) {
            Write-Warning "Azure checks encountered errors: $($_.Exception.Message)"
        }
    }
}

# ============================================================================
# Active Directory Checks
# ============================================================================

if ($AllPlatforms -or $ActiveDirectory) {
    if (-not $SilentMode) {
        Write-Host "[4/6] Running Active Directory Checks..." -ForegroundColor Cyan
    }
    $executionSummary.Platform += 'Active Directory'
    
    try {
        $adChecks = @(
            @{ Name = 'Break Glass Accounts'; Func = { Invoke-IFQCBreakGlassRealityCheck } }
            @{ Name = 'Naming Hygiene'; Func = { Invoke-IFQCIdentityNamingHygieneCheck } }
            @{ Name = 'Password Policy Drift'; Func = { Invoke-IFQCPasswordPolicyDriftCheck } }
            @{ Name = 'Privileged Nesting'; Func = { Invoke-IFQCPrivilegedNestingAbuseCheck } }
        )
        
        foreach ($check in $adChecks) {
            if (-not $SilentMode) {
                Write-Host "  - $($check.Name)..." -ForegroundColor Gray
            }
            try {
                $result = & $check.Func -Domain $ADDomain
                Add-CheckResult -Result $result
            }
            catch {
                # AD check failed, continue
            }
        }
        
        # Additional AD checks
        if (Get-Command 'Invoke-ADAccountLockoutCheck' -ErrorAction SilentlyContinue) {
            try {
                $result = Invoke-ADAccountLockoutCheck -Domain $ADDomain
                Add-CheckResult -Result $result
            }
            catch { }
        }
        
        if (Get-Command 'Invoke-ADKerberosTicketLifetimeCheck' -ErrorAction SilentlyContinue) {
            try {
                $result = Invoke-ADKerberosTicketLifetimeCheck -Domain $ADDomain
                Add-CheckResult -Result $result
            }
            catch { }
        }
    }
    catch {
        if (-not $SilentMode) {
            Write-Warning "Active Directory checks encountered errors: $($_.Exception.Message)"
        }
    }
}

# ============================================================================
# AWS Checks
# ============================================================================

if ($AllPlatforms -or $AWS) {
    if (-not $SilentMode) {
        Write-Host "[5/6] Running AWS Checks..." -ForegroundColor Cyan
    }
    $executionSummary.Platform += 'AWS'
    
    try {
        if (Get-Command 'Invoke-AwsIdentityInventory' -ErrorAction SilentlyContinue) {
            $awsInv = Invoke-AwsIdentityInventory -Region $AWSRegion
            Add-CheckResult -Result $awsInv
        }
        
        if (Get-Command 'Invoke-AwsCloudTrailCheck' -ErrorAction SilentlyContinue) {
            try {
                $result = Invoke-AwsCloudTrailCheck -Region $AWSRegion
                Add-CheckResult -Result $result
            }
            catch { }
        }
        
        if (Get-Command 'Invoke-AwsGuardDutyCheck' -ErrorAction SilentlyContinue) {
            try {
                $result = Invoke-AwsGuardDutyCheck -Region $AWSRegion
                Add-CheckResult -Result $result
            }
            catch { }
        }
    }
    catch {
        if (-not $SilentMode) {
            Write-Warning "AWS checks encountered errors: $($_.Exception.Message)"
        }
    }
}

# ============================================================================
# GCP Checks
# ============================================================================

if ($AllPlatforms -or $GCP) {
    if (-not $SilentMode) {
        Write-Host "[6/6] Running GCP Checks..." -ForegroundColor Cyan
    }
    $executionSummary.Platform += 'GCP'
    
    try {
        if (Get-Command 'Invoke-GcpIdentityInventory' -ErrorAction SilentlyContinue) {
            $gcpInv = Invoke-GcpIdentityInventory
            Add-CheckResult -Result $gcpInv
        }
        
        if (Get-Command 'Invoke-GcpSecurityCommandCenterCheck' -ErrorAction SilentlyContinue) {
            try {
                $result = Invoke-GcpSecurityCommandCenterCheck -OrganizationId $GCPOrganizationId
                Add-CheckResult -Result $result
            }
            catch { }
        }
        
        if (Get-Command 'Invoke-GcpServiceAccountKeyCheck' -ErrorAction SilentlyContinue) {
            try {
                $result = Invoke-GcpServiceAccountKeyCheck -ProjectId $GCPProjectId
                Add-CheckResult -Result $result
            }
            catch { }
        }
    }
    catch {
        if (-not $SilentMode) {
            Write-Warning "GCP checks encountered errors: $($_.Exception.Message)"
        }
    }
}

# ============================================================================
# Generate Report
# ============================================================================

$executionSummary.EndTime = (Get-Date)
$executionSummary.Duration = ($executionSummary.EndTime - $executionSummary.StartTime).TotalSeconds

# Calculate overall score
$maxScore = 100
$deductions = 0

foreach ($finding in $allFindings) {
    switch ($finding.Severity) {
        'Critical' { $deductions += 25 }
        'High' { $deductions += 10 }
        'Medium' { $deductions += 5 }
        'Low' { $deductions += 2 }
    }
}

$overallScore = [Math]::Max(0, $maxScore - $deductions)
$healthStatus = if ($overallScore -ge 80) { 'Healthy' } elseif ($overallScore -ge 60) { 'Warning' } else { 'Critical' }

# Build final report
$report = @{
    Metadata = @{
        Tool = 'IdentityFirst QuickChecks'
        Version = '1.0.0'
        GeneratedAt = $executionSummary.EndTime.ToString('o')
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        OSPlatform = if ($IsWindows) { 'Windows' } elseif ($IsLinux) { 'Linux' } elseif ($IsMacOS) { 'macOS' } else { 'Unknown' }
    }
    Execution = $executionSummary
    OverallScore = $overallScore
    HealthStatus = $healthStatus
    Checks = $checkResults
    Findings = $allFindings
    Summary = @{
        TotalFindings = ($allFindings | Measure-Object).Count
        BySeverity = @{
            Critical = (($allFindings | Where-Object { $_.Severity -eq 'Critical' }) | Measure-Object).Count
            High = (($allFindings | Where-Object { $_.Severity -eq 'High' }) | Measure-Object).Count
            Medium = (($allFindings | Where-Object { $_.Severity -eq 'Medium' }) | Measure-Object).Count
            Low = (($allFindings | Where-Object { $_.Severity -eq 'Low' }) | Measure-Object).Count
        }
        ByCategory = ($allFindings | Group-Object Category | ForEach-Object {
            @{
                Category = $_.Name
                Count = $_.Count
            }
        })
    }
}

# Save JSON report
$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$jsonPath = Join-Path $OutputDir "QuickChecks-Report-$timestamp.json"
$report | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8

if (-not $SilentMode) {
    Write-Host "`nJSON Report: $jsonPath" -ForegroundColor Green
}

# Generate HTML dashboard if requested
if ($GenerateDashboard) {
    if (-not $SilentMode) {
        Write-Host "Generating HTML Dashboard..." -ForegroundColor Cyan
    }
    
    if (Test-Path (Join-Path $PSScriptRoot 'New-QuickChecksDashboard.ps1')) {
        $dashboardPath = & (Join-Path $PSScriptRoot 'New-QuickChecksDashboard.ps1') `
            -JsonReport $jsonPath `
            -OutputDir $OutputDir `
            -Title $DashboardTitle
        
        if (-not $SilentMode -and $dashboardPath) {
            Write-Host "Dashboard: $dashboardPath" -ForegroundColor Green
        }
    }
    else {
        Write-Warning "Dashboard generator not found. Skipping HTML output."
    }
}

# ============================================================================
# Summary Output
# ============================================================================

if (-not $SilentMode) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  QuickChecks Complete" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    
    Write-Host "`nHealth Status: $healthStatus" -ForegroundColor (if ($healthStatus -eq 'Healthy') { 'Green' } elseif ($healthStatus -eq 'Warning') { 'Yellow' } else { 'Red' })
    Write-Host "Overall Score: $overallScore / 100"
    
    Write-Host "`nCheck Summary:" -ForegroundColor White
    Write-Host "  Total Checks: $($executionSummary.TotalChecks)"
    Write-Host "  Passed:       $($executionSummary.Passed)" -ForegroundColor Green
    Write-Host "  Failed:       $($executionSummary.Failed)" -ForegroundColor Red
    Write-Host "  Warnings:     $($executionSummary.Warnings)" -ForegroundColor Yellow
    Write-Host "  Errors:       $($executionSummary.Errors)" -ForegroundColor Gray
    
    Write-Host "`nFindings Summary:" -ForegroundColor White
    Write-Host "  Critical: $($report.Summary.BySeverity.Critical)"
    Write-Host "  High:     $($report.Summary.BySeverity.High)"
    Write-Host "  Medium:   $($report.Summary.BySeverity.Medium)"
    Write-Host "  Low:      $($report.Summary.BySeverity.Low)"
    
    Write-Host "`nExecution Time: $([math]::Round($executionSummary.Duration, 2)) seconds"
}

# Return report
return $report
