param([string]$OutputPath = ".")

$ErrorActionPreference = "Stop"

<#
.SYNOPSIS
    Detect naming violations and ownership gaps.

.DESCRIPTION
    Analyzes AD accounts for naming convention violations,
    missing descriptions, and potential ownership gaps.

.NOTES
    - Read-only: YES
    - Requires: ActiveDirectory module (RSAT)

.EXAMPLE
    .\IdentityNamingHygiene.ps1

.EXAMPLE
    Invoke-IdentityNamingHygiene -OutputPath ".\Reports"
#>

# Get module root for IFQC framework
$moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

# Try to load IFQC framework
$useFramework = $false
try {
    $frameworkPath = Join-Path $moduleRoot "Module\IdentityFirst.QuickChecks.psm1"
    if (Test-Path $frameworkPath) {
        . $frameworkPath -ErrorAction Stop | Out-Null
        $useFramework = $true
    }
}
catch {
    $useFramework = $false
}

if ($useFramework) {
    $ctx = New-IFQCContext -ToolName "IdentityNamingHygiene" -ToolVersion "1.0.0" -OutputDirectory $OutputPath
    Write-IFQCLog -Context $ctx -Level INFO -Message "Starting Identity Naming Hygiene Check"
    
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-IFQCLog -Context $ctx -Level INFO -Message "ActiveDirectory module loaded"
    }
    catch {
        Write-IFQCLog -Context $ctx -Level ERROR -Message "ActiveDirectory module not available"
        exit 1
    }
    
    try {
        $allUsers = Get-ADUser -Filter * -Properties SamAccountName, Name, Description, Created -ErrorAction Stop
        Write-IFQCLog -Context $ctx -Level INFO -Message "Found $($allUsers.Count) users"
    }
    catch {
        Write-IFQCLog -Context $ctx -Level ERROR -Message "Failed to retrieve users: $($_.Exception.Message)"
        exit 1
    }
    
    $violations = @()
    
    foreach ($user in $allUsers) {
        try {
            $userViolations = @()
            
            if ($user.SamAccountName.Length -gt 20) {
                $userViolations += "SamAccountName too long"
            }
            
            if ($user.Name -match "\s") {
                $userViolations += "Name contains whitespace"
            }
            
            if ([string]::IsNullOrWhiteSpace($user.Description)) {
                $userViolations += "Missing description"
            }
            
            if ($userViolations.Count -gt 0) {
                $finding = New-IFQCFinding -Id "NH-001" -Title "Naming Violation: $($user.SamAccountName)" -Severity "Medium" -Description "Naming convention violations detected" -Count $userViolations.Count -Evidence @($user | Select-Object SamAccountName, Name, Description) -Recommendation "Review and correct naming conventions"
                Add-IFQCFinding -Context $ctx -Finding $finding
            }
        }
        catch {
            Write-IFQCLog -Context $ctx -Level WARN -Message "Failed to analyze user $($user.SamAccountName): $($_.Exception.Message)"
        }
    }
    
    $output = Save-IFQCReport -Context $ctx
    Write-IFQCLog -Context $ctx -Level INFO -Message "Check complete. JSON: $($output.Json)"
}
else {
    # Original standalone mode
    Write-Host ""
    Write-Host "========================================================================"
    Write-Host "  Identity Naming Hygiene Check"
    Write-Host "========================================================================"
    
    $violations = @()
    $errors = @()
    $processedCount = 0
    
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Host "  ActiveDirectory module loaded" -ForegroundColor Green
    }
    catch {
        Write-Host "  ERROR: ActiveDirectory module not available" -ForegroundColor Red
        exit 1
    }
    
    try {
        $allUsers = Get-ADUser -Filter * -Properties SamAccountName, Name, Description, Created -ErrorAction Stop
        Write-Host "  Found $($allUsers.Count) user accounts to analyze" -ForegroundColor Gray
    }
    catch {
        Write-Host "  ERROR: Failed to retrieve users: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
    
    foreach ($user in $allUsers) {
        try {
            $processedCount++
            $userViolations = @()
            
            if ($user.SamAccountName.Length -gt 20) {
                $userViolations += "SamAccountName too long ($($user.SamAccountName.Length) > 20)"
            }
            
            if ($user.Name -match "\s") {
                $userViolations += "Name contains whitespace"
            }
            
            if ([string]::IsNullOrWhiteSpace($user.Description)) {
                $userViolations += "Missing description"
            }
            
            if ($userViolations.Count -gt 0) {
                $violations += New-Object PSObject -Property @{
                    SamAccountName = $user.SamAccountName
                    Name = $user.Name
                    Violations = $userViolations -join "; "
                    ViolationCount = $userViolations.Count
                }
            }
        }
        catch {
            $errors += "Failed to analyze user $($user.SamAccountName): $($_.Exception.Message)"
        }
    }
    
    Write-Host ""
    Write-Host "  Naming Hygiene Summary"
    Write-Host "  ======================"
    Write-Host "  Accounts analyzed: $processedCount"
    Write-Host "  Violations found: $($violations.Count)"
    
    if ($violations) {
        $highCount = ($violations | Where-Object { $_.ViolationCount -ge 3 }).Count
        Write-Host "  High severity: $highCount"
        
        Write-Host ""
        Write-Host "  Violations:"
        $violations | Sort-Object -Property ViolationCount -Descending | Format-Table -AutoSize
    }
    else {
        Write-Host "  No naming violations detected!" -ForegroundColor Green
    }
    
    if ($errors) {
        Write-Host ""
        Write-Host "  Errors encountered:" -ForegroundColor Yellow
        $errors | ForEach-Object { Write-Host "    - $_" -ForegroundColor Gray }
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $reportPath = Join-Path $OutputPath "IdentityNamingHygiene-$timestamp.json"
    
    $report = @{
        CheckName = "Identity Naming Hygiene"
        Timestamp = Get-Date -Format "o"
        Summary = @{
            TotalAccountsAnalyzed = $processedCount
            ViolationsFound = $violations.Count
        }
        Violations = $violations
        Errors = $errors
    }
    
    try {
        $jsonOutput = $report | ConvertTo-Json -Depth 10
        $jsonOutput | Set-Content -Path $reportPath -ErrorAction Stop
        Write-Host ""
        Write-Host "  Report saved: $reportPath" -ForegroundColor Cyan
    }
    catch {
        Write-Host ""
        Write-Host "  ERROR: Failed to save report" -ForegroundColor Red
    }
}

exit 0
