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

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDvDikyy5hYaP1M
# rhuTEUGbciJUlUXPKmaCA+bEcixwV6CCFlIwggMUMIIB/KADAgECAhBDR0HvMFNE
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQg2e4jSN57aaCCojDVmdlXd9gmErpqHZ3RqCb3
# mltg0sQwDQYJKoZIhvcNAQEBBQAEggEAl8P6oJ9/jldx2aeGD/UM2GBj0v62UIE+
# 1Jct78V9w2TvHE31H6/5Rqwm6agmsTbeRIcyVfC7pYzoYkdt1ZkVfW5LvuHvGcAO
# lN42GqPebRGl9h2bvlea3H+NuHUcGWxQv6/CL4wnQsCnU6qSOmQO6EToSmw3s2Ag
# exOfGwRAZMarZOdOLf8hMN8MOAnD0/F41HAtGv0xLKFFm7m5hB/uly8kBDOktrkF
# vFFpugsd0LbXBwl+UfV6YRG+R4T9rP3T0txpkEITxWdXS9X8dsPHH+6YL7Zk0YFE
# tAkz/16GSGRWbyDBNHb38UNfw1o7T7cqNjcFOZpNqSUtnOLvl6PGhKGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjAyMDQxNjUyMDhaMC8GCSqGSIb3DQEJBDEiBCAv
# 854a6wxFx5TCh0NRj4VjNz+qX0xpM5/G76+QuNbsLDANBgkqhkiG9w0BAQEFAASC
# AgBI3K8tfuun2fUPKBjAh090mI5h7GcwZubt6/L1ThN8nGUKRhu0crWyufCdYJ1g
# zjzXXuRN63sgVHJ10P5xbFGc7xDmQ8dUkbD62bGi+PyGKyV4+t+NTuABzvbKVsrR
# m/tmmgSg7ovLjfGRh1rlNbOyNE7ezjqvu0f6h9n7pZtCJ/Xxj1nK2Dh5Tyb3BlGw
# Nz16j+hmfCwR8qS4oAvMayA/HNRViTkqwcAyb9zLtMN3cKKG4+y53aEOYc+0k19Q
# YvJM2FLaEvstG+A6hEH0DnKvY9YKF2JHYPR51qxaWT2ktgSzC36Xlra5s8ux2kNS
# RXStmiqQ0qWWgCQmeRDhSvclI8HH0+fLo+5OpF3Q+3jjQDcV+pe9ZSTq+9HevXG0
# YCfRIqIQxB5ulAxL7/rptYbgeit7HYodiskCravy7PRAnEoLpN4Y9nf9MbcVavsS
# nHju4Z9fraRxWbKurqdgrfdv0rXeUqKfZRq5bb6LjztxVH4S1s666AWMUx6HO8TL
# i8n2t3J8BO+YHzRdWEX7bE3gu+ihNKmsKeus97+6L5wNMJXxLNBMeCSCs6PwAjhk
# JqfHNggp24O9pwIgJHAGQzu4MqOYEOQPl8+RbnNvyOcBsVkrdEwRi5GYPiwjPwrP
# R0oY3zt4+gToSnsYKwYzGZUrzbXTRJCpTVsymkzRaxW4uQ==
# SIG # End signature block
