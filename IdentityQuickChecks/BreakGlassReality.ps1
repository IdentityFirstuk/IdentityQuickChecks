param(
    [string]$OutputPath = "."
)

$ErrorActionPreference = "Stop"

<#
.SYNOPSIS
    Find break-glass accounts and check their posture.

.DESCRIPTION
    Searches for accounts named or described as break-glass,
    emergency, or firecall accounts. Reports on their posture
    including password never expires, last logon, and risk factors.

.NOTES
    - Read-only: YES
    - Requires: ActiveDirectory module (RSAT)
    - Permissions: Domain Admin recommended

.EXAMPLE
    .\BreakGlassReality.ps1

.EXAMPLE
    # As module command
    Invoke-BreakGlassReality -OutputPath ".\Reports"
#>

# Get module root for IFQC framework
$moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

# Try to load IFQC framework for consistent output (optional)
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
    # Use IFQC framework
    $ctx = New-IFQCContext -ToolName "BreakGlassReality" -ToolVersion "1.0.0" -OutputDirectory $OutputPath
    
    Write-IFQCLog -Context $ctx -Level INFO -Message "Starting Break-Glass Reality Check"
    
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-IFQCLog -Context $ctx -Level INFO -Message "ActiveDirectory module loaded"
    }
    catch {
        Write-IFQCLog -Context $ctx -Level ERROR -Message "ActiveDirectory module not available"
        Write-Host "ERROR: ActiveDirectory module not available" -ForegroundColor Red
        exit 1
    }
    
    $breakGlassAccounts = @()
    $errors = @()
    
    # Search patterns for break-glass accounts
    $bgPatterns = @("*break*glass*", "*bg-*", "*breakglass*", "*emergency*", "*firewall*", "*disaster*recovery*", "*dr-*", "*escrow*", "*hold*", "*admin*break*")
    
    foreach ($pattern in $bgPatterns) {
        try {
            $found = Get-ADUser -Filter { SamAccountName -like $pattern -Or Name -like $pattern -Or Description -like $pattern } -Properties SamAccountName, Name, Description, Enabled, PasswordNeverExpires, LastLogonTimestamp, whenCreated -ErrorAction Stop
            $breakGlassAccounts += $found
        }
        catch {
            $errors += "Pattern '$pattern' failed: $($_.Exception.Message)"
        }
    }
    
    # Remove duplicates
    if ($breakGlassAccounts) {
        $breakGlassAccounts = $breakGlassAccounts | Sort-Object -Property ObjectGUID -Unique
    }
    
    Write-IFQCLog -Context $ctx -Level INFO -Message "Found $($breakGlassAccounts.Count) potential break-glass accounts"
    
    foreach ($account in $breakGlassAccounts) {
        try {
            $lastLogon = "Never"
            if ($account.LastLogonTimestamp) {
                $lastLogonDate = [DateTime]::FromFileTime($account.LastLogonTimestamp)
                $lastLogon = $lastLogonDate.ToString("yyyy-MM-dd")
            }
            
            $riskIndicators = @()
            if ($account.Enabled -eq $true) { $riskIndicators += "Account is ENABLED" }
            if ($account.PasswordNeverExpires -eq $true) { $riskIndicators += "PasswordNeverExpires=TRUE" }
            
            $finding = New-IFQCFinding -Id "BGA-001" -Title "Break-Glass Account: $($account.SamAccountName)" -Severity "High" -Description "Break-glass account detected with risk factors" -Count 1 -Evidence @($account | Select-Object SamAccountName, Name, Enabled, PasswordNeverExpires, LastLogon) -Recommendation "Review necessity and controls for this break-glass account"
            
            Add-IFQCFinding -Context $ctx -Finding $finding
        }
        catch {
            $errors += "Failed to process $($account.SamAccountName): $($_.Exception.Message)"
        }
    }
    
    if ($errors) {
        $errors | ForEach-Object { Write-IFQCLog -Context $ctx -Level WARN -Message $_ }
    }
    
    # Save report
    $output = Save-IFQCReport -Context $ctx
    
    Write-IFQCLog -Context $ctx -Level INFO -Message "Check complete. JSON: $($output.Json) HTML: $($output.Html)"
    
    Write-Host ""
    Write-Host "Break-Glass Reality Check complete. See reports in $OutputPath" -ForegroundColor Cyan
}
else {
    # Original standalone mode (for backward compatibility)
    Write-Host ""
    Write-Host "========================================================================"
    Write-Host "  Break-Glass Reality Check"
    Write-Host "========================================================================"
    
    $breakGlassAccounts = @()
    $errors = @()
    $processedCount = 0
    
    Write-Host ""
    Write-Host "  Finding accounts named/described as break-glass..." -ForegroundColor Gray
    
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Host "  ActiveDirectory module loaded" -ForegroundColor Green
    }
    catch {
        Write-Host "  ERROR: ActiveDirectory module not available" -ForegroundColor Red
        exit 1
    }
    
    $bgPatterns = @("*break*glass*", "*bg-*", "*breakglass*", "*emergency*", "*firewall*", "*disaster*recovery*", "*dr-*", "*escrow*", "*hold*", "*admin*break*")
    
    $searchResults = @()
    foreach ($pattern in $bgPatterns) {
        try {
            $found = Get-ADUser -Filter { SamAccountName -like $pattern -Or Name -like $pattern -Or Description -like $pattern } -Properties SamAccountName, Name, Description, Enabled, PasswordNeverExpires, LastLogonTimestamp, whenCreated -ErrorAction Stop
            $searchResults += $found
        }
        catch {
            $errors += "Search pattern '$pattern' failed: $($_.Exception.Message)"
        }
    }
    
    if ($searchResults) {
        $searchResults = $searchResults | Sort-Object -Property ObjectGUID -Unique
    }
    
    Write-Host ""
    Write-Host "  Analyzing $($searchResults.Count) potential break-glass accounts..." -ForegroundColor Gray
    
    foreach ($account in $searchResults) {
        try {
            $processedCount++
            
            $lastLogon = "Never"
            if ($account.LastLogonTimestamp) {
                try {
                    $lastLogonDate = [DateTime]::FromFileTime($account.LastLogonTimestamp)
                    $lastLogon = $lastLogonDate.ToString("yyyy-MM-dd")
                }
                catch {
                    $lastLogon = "Unknown"
                }
            }
            
            $pwdLastSet = "N/A"
            try {
                $pwdInfo = Get-ADUser -Identity $account.DistinguishedName -Properties pwdLastSet -ErrorAction Stop
                if ($pwdInfo.pwdLastSet -and $pwdInfo.pwdLastSet -ne 0) {
                    $pwdLastSetDate = [DateTime]::FromFileTime($pwdInfo.pwdLastSet)
                    $pwdLastSet = $pwdLastSetDate.ToString("yyyy-MM-dd")
                }
            }
            catch {
            }
            
            $riskIndicators = @()
            if ($account.Enabled -eq $true) { $riskIndicators += "Account is ENABLED" }
            if ($account.PasswordNeverExpires -eq $true) { $riskIndicators += "PasswordNeverExpires=TRUE" }
            
            $breakGlassAccounts += New-Object PSObject -Property @{
                SamAccountName = $account.SamAccountName
                Name = $account.Name
                Description = $account.Description
                Enabled = $account.Enabled
                PasswordNeverExpires = $account.PasswordNeverExpires
                LastLogon = $lastLogon
                PasswordLastSet = $pwdLastSet
                Created = $account.whenCreated
                RiskLevel = if ($riskIndicators.Count -ge 3) { "HIGH" } elseif ($riskIndicators.Count -ge 1) { "MEDIUM" } else { "LOW" }
                RiskIndicators = $riskIndicators -join "; "
            }
        }
        catch {
            $errorMsg = "Failed to process account $($account.SamAccountName): $($_.Exception.Message)"
            $errors += $errorMsg
            Write-Host "  WARNING: $errorMsg" -ForegroundColor Yellow
        }
    }
    
    Write-Host ""
    Write-Host "  Break-Glass Account Summary"
    Write-Host "  ============================"
    Write-Host "  Total accounts found: $($breakGlassAccounts.Count)" -ForegroundColor $(if ($breakGlassAccounts.Count -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  Accounts successfully processed: $processedCount"
    
    $highRisk = ($breakGlassAccounts | Where-Object { $_.RiskLevel -eq "HIGH" }).Count
    $mediumRisk = ($breakGlassAccounts | Where-Object { $_.RiskLevel -eq "MEDIUM" }).Count
    $lowRisk = ($breakGlassAccounts | Where-Object { $_.RiskLevel -eq "LOW" }).Count
    
    Write-Host "  Risk breakdown: $highRisk HIGH, $mediumRisk MEDIUM, $lowRisk LOW"
    
    if ($breakGlassAccounts) {
        Write-Host ""
        Write-Host "  Findings:"
        Write-Host "  =========="
        
        $breakGlassAccounts | Format-Table -AutoSize -Property `
            @{Name="SamAccountName"; Expression={$_.SamAccountName}; Width=20},
            @{Name="Enabled"; Expression={$_.Enabled}; Width=10},
            @{Name="PwdNeverExpires"; Expression={$_.PasswordNeverExpires}; Width=15},
            @{Name="LastLogon"; Expression={$_.LastLogon}; Width=12},
            @{Name="Risk"; Expression={$_.RiskLevel}; Width=10}
    }
    else {
        Write-Host ""
        Write-Host "  No accounts matching break-glass patterns were found." -ForegroundColor Green
    }
    
    if ($errors) {
        Write-Host ""
        Write-Host "  Errors Encountered During Execution:" -ForegroundColor Yellow
        foreach ($err in $errors) {
            Write-Host "    - $err" -ForegroundColor Gray
        }
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $reportPath = Join-Path $OutputPath "BreakGlassReality-$timestamp.json"
    
    $report = @{
        CheckName = "Break-Glass Reality Check"
        Timestamp = Get-Date -Format "o"
        Summary = @{
            TotalAccountsFound = $breakGlassAccounts.Count
            SuccessfullyProcessed = $processedCount
            HighRisk = $highRisk
            MediumRisk = $mediumRisk
            LowRisk = $lowRisk
            ErrorsEncountered = $errors.Count
        }
        Findings = $breakGlassAccounts
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
        Write-Host "  ERROR: Failed to save report to $reportPath" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────────────────────"
    Write-Host "  ℹ  This script shows break-glass accounts exist." -ForegroundColor Gray
    Write-Host "     It cannot answer: Who approved them? When tested? Controls?" -ForegroundColor Gray
    Write-Host "     For governance analysis, run IdentityHealthCheck." -ForegroundColor Gray
    Write-Host "  ─────────────────────────────────────────────────────────────"
}

exit 0
