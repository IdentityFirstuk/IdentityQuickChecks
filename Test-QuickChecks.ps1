# ============================================================================
# IdentityFirst QuickChecks - Test Suite
# ============================================================================
# Version: 1.0.0
# Date: 2026-01-29
# Description: Validates QuickChecks installation and functionality
# ============================================================================

[CmdletBinding()]
param(
    [switch]$All,
    [switch]$Syntax,
    [switch]$Security,
    [switch]$Launcher,
    [switch]$Quick
)

# ============================================================================
# Test Results
# ============================================================================

$script:TestsPassed = 0
$script:TestsFailed = 0
$script:TestsTotal = 0
$script:TestResults = @()

# ============================================================================
# Helper Functions
# ============================================================================

function Write-Test {
    param(
        [string]$Name,
        [string]$Description,
        [string]$Status,
        [string]$Message = ""
    )
    
    $script:TestsTotal++
    
    if ($Status -eq "PASS") {
        $script:TestsPassed++
        Write-Host "[PASS] " -ForegroundColor Green -NoNewline
    }
    else {
        $script:TestsFailed++
        Write-Host "[FAIL] " -ForegroundColor Red -NoNewline
    }
    
    Write-Host "$Name" -ForegroundColor White -NoNewline
    if ($Message) {
        Write-Host " - $Message" -ForegroundColor Gray
    }
    else {
        Write-Host ""
    }
    
    $script:TestResults += [PSCustomObject]@{
        Name = $Name
        Description = $Description
        Status = $Status
        Message = $Message
    }
}

function Write-Header {
    param([string]$Message)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host " $Message" -ForegroundColor White
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
}

# ============================================================================
# Syntax Tests
# ============================================================================

function Test-Syntax {
    Write-Header "Syntax Validation Tests"
    
    # Test all PS1 files
    $ps1Files = Get-ChildItem -Path "$PSScriptRoot" -Recurse -Filter "*.ps1" -ErrorAction SilentlyContinue
    
    foreach ($file in $ps1Files) {
        $name = $file.FullName.Replace("$PSScriptRoot\", "")
        
        try {
            $errors = $null
            $null = [System.Management.Automation.PSParser]::Tokenize(
                (Get-Content -Path $file.FullName -Raw),
                [ref]$errors
            )
            
            if ($errors.Count -eq 0) {
                Write-Test -Name $name -Description "Syntax check" -Status "PASS"
            }
            else {
                $errorCount = ($errors | Where-Object { $_.Severity -eq "Error" }).Count
                if ($errorCount -eq 0) {
                    Write-Test -Name $name -Description "Syntax check (warnings only)" -Status "PASS"
                }
                else {
                    Write-Test -Name $name -Description "Syntax check" -Status "FAIL" -Message "$errorCount errors"
                }
            }
        }
        catch {
            Write-Test -Name $name -Description "Syntax check" -Status "FAIL" -Message $_.Exception.Message
        }
    }
}

# ============================================================================
# Security Tests
# ============================================================================

function Test-Security {
    Write-Header "Security Module Tests"
    
    # Test 1: Module exists
    $securityModule = "$PSScriptRoot\Security\IdentityFirst.Security.psm1"
    if (Test-Path $securityModule) {
        Write-Test -Name "Security module exists" -Description "Verify security module file" -Status "PASS"
        
        # Test 2: Module loads
        try {
            Import-Module -Name $securityModule -Force -ErrorAction Stop
            Write-Test -Name "Security module loads" -Description "Import security module" -Status "PASS"
            
            # Test 3: Functions available
            $requiredFunctions = @(
                'ConvertTo-SecureStringIfNeeded',
                'Get-CredentialFromInput',
                'Test-ValidPath',
                'Write-SecureLog',
                'Get-SecureHtmlContent',
                'Set-OutputFileSecurity'
            )
            
            foreach ($func in $requiredFunctions) {
                if (Get-Command $func -ErrorAction SilentlyContinue) {
                    Write-Test -Name "Function: $func" -Description "Security function available" -Status "PASS"
                }
                else {
                    Write-Test -Name "Function: $func" -Description "Security function available" -Status "FAIL"
                }
            }
            
            # Test 4: Secure logging redaction
            $logOutput = & {
                $logMsg = Write-SecureLog -Message "API key: secret123" -Level INFO -LogFile $null 2>$null
                $logMsg
            } 2>$null
            
            if ($logOutput -match '\*\*\*REDACTED\*\*\*') {
                Write-Test -Name "Credential redaction" -Description "Sensitive data redacted in logs" -Status "PASS"
            }
            else {
                Write-Test -Name "Credential redaction" -Description "Sensitive data redacted in logs" -Status "FAIL"
            }
            
            # Test 5: HTML encoding
            $encoded = Get-SecureHtmlContent -Content "<script>alert('xss')</script>"
            if ($encoded -match '<script>') {
                Write-Test -Name "XSS protection" -Description "HTML special characters encoded" -Status "PASS"
            }
            else {
                Write-Test -Name "XSS protection" -Description "HTML special characters encoded" -Status "FAIL"
            }
            
            # Remove module
            Remove-Module -Name "IdentityFirst.Security" -ErrorAction SilentlyContinue
        }
        catch {
            Write-Test -Name "Security module loads" -Description "Import security module" -Status "FAIL" -Message $_.Exception.Message
        }
    }
    else {
        Write-Test -Name "Security module exists" -Description "Verify security module file" -Status "FAIL"
    }
}

# ============================================================================
# Launcher Tests
# ============================================================================

function Test-Launcher {
    Write-Header "Launcher Tests"
    
    # Test 1: Launcher exists
    $launcher = "$PSScriptRoot\Start-QuickChecks.ps1"
    if (Test-Path $launcher) {
        Write-Test -Name "Launcher exists" -Description "Start-QuickChecks.ps1 found" -Status "PASS"
        
        # Test 2: Launcher syntax
        try {
            $errors = $null
            $null = [System.Management.Automation.PSParser]::Tokenize(
                (Get-Content -Path $launcher -Raw),
                [ref]$errors
            )
            if ($errors.Count -eq 0) {
                Write-Test -Name "Launcher syntax" -Description "Valid PowerShell syntax" -Status "PASS"
            }
            else {
                Write-Test -Name "Launcher syntax" -Description "Valid PowerShell syntax" -Status "FAIL" -Message "$($errors.Count) issues"
            }
        }
        catch {
            Write-Test -Name "Launcher syntax" -Description "Valid PowerShell syntax" -Status "FAIL" -Message $_.Exception.Message
        }
        
        # Test 3: Help parameter
        try {
            $output = & $launcher -Help -ErrorAction SilentlyContinue 2>&1 | Out-String
            if ($output -match "USAGE:") {
                Write-Test -Name "Help parameter" -Description "Help output generated" -Status "PASS"
            }
            else {
                Write-Test -Name "Help parameter" -Description "Help output generated" -Status "FAIL"
            }
        }
        catch {
            Write-Test -Name "Help parameter" -Description "Help output generated" -Status "FAIL" -Message $_.Exception.Message
        }
    }
    else {
        Write-Test -Name "Launcher exists" -Description "Start-QuickChecks.ps1 found" -Status "FAIL"
    }
    
    # Test 4: Certificate script
    $certScript = "$PSScriptRoot\Create-SelfSignedCert.ps1"
    if (Test-Path $certScript) {
        Write-Test -Name "Certificate script exists" -Description "Create-SelfSignedCert.ps1 found" -Status "PASS"
    }
    else {
        Write-Test -Name "Certificate script exists" -Description "Create-SelfSignedCert.ps1 found" -Status "FAIL"
    }
    
    # Test 5: Sign script
    $signScript = "$PSScriptRoot\Sign-QuickChecks.ps1"
    if (Test-Path $signScript) {
        Write-Test -Name "Sign script exists" -Description "Sign-QuickChecks.ps1 found" -Status "PASS"
    }
    else {
        Write-Test -Name "Sign script exists" -Description "Sign-QuickChecks.ps1 found" -Status "FAIL"
    }
}

# ============================================================================
# Module Tests
# ============================================================================

function Test-Modules {
    Write-Header "Check Module Tests"
    
    $checkCount = 0
    
    # Test all check scripts
    $checkScripts = Get-ChildItem -Path "$PSScriptRoot\Checks" -Recurse -Filter "*.ps1" -ErrorAction SilentlyContinue
    
    foreach ($script in $checkScripts) {
        $name = $script.FullName.Replace("$PSScriptRoot\", "")
        $checkCount++
        
        # Syntax check
        try {
            $errors = $null
            $null = [System.Management.Automation.PSParser]::Tokenize(
                (Get-Content -Path $script.FullName -Raw),
                [ref]$errors
            )
            
            if ($errors.Count -eq 0) {
                Write-Test -Name $name -Description "Check script syntax" -Status "PASS"
            }
            else {
                Write-Test -Name $name -Description "Check script syntax" -Status "FAIL" -Message "$($errors.Count) issues"
            }
        }
        catch {
            Write-Test -Name $name -Description "Check script syntax" -Status "FAIL" -Message $_.Exception.Message
        }
    }
    
    Write-Host ""
    Write-Host "Total check scripts: $checkCount" -ForegroundColor Cyan
}

# ============================================================================
# Configuration Tests
# ============================================================================

function Test-Configuration {
    Write-Header "Configuration Tests"
    
    # Test config file
    $configFile = "$PSScriptRoot\config\QuickChecks.config.psd1"
    if (Test-Path $configFile) {
        try {
            $config = Import-PowerShellDataFile -Path $configFile -ErrorAction Stop
            Write-Test -Name "Config file valid" -Description "QuickChecks.config.psd1 loads" -Status "PASS"
            
            if ($config.ModuleVersion) {
                Write-Test -Name "Config version" -Description "Version: $($config.ModuleVersion)" -Status "PASS"
            }
        }
        catch {
            Write-Test -Name "Config file valid" -Description "QuickChecks.config.psd1 loads" -Status "FAIL" -Message $_.Exception.Message
        }
    }
    else {
        Write-Test -Name "Config file exists" -Description "QuickChecks.config.psd1 found" -Status "FAIL"
    }
    
    # Test security manifest
    $manifestFile = "$PSScriptRoot\Security\IdentityFirst.Security.manifest.psd1"
    if (Test-Path $manifestFile) {
        try {
            $manifest = Import-PowerShellDataFile -Path $manifestFile -ErrorAction Stop
            Write-Test -Name "Security manifest" -Description "Security manifest loads" -Status "PASS"
            
            if ($manifest.SecurityFeatures) {
                Write-Test -Name "Security features" -Description "Security features defined" -Status "PASS"
            }
        }
        catch {
            Write-Test -Name "Security manifest" -Description "Security manifest loads" -Status "FAIL" -Message $_.Exception.Message
        }
    }
}

# ============================================================================
# Summary
# ============================================================================

function Show-Summary {
    Write-Header "Test Summary"
    
    Write-Host "  Total Tests:   $script:TestsTotal" -ForegroundColor White
    Write-Host "  Passed:        $script:TestsPassed" -ForegroundColor Green
    Write-Host "  Failed:        $script:TestsFailed" -ForegroundColor $(if ($script:TestsFailed -gt 0) { "Red" } else { "White" })
    Write-Host ""
    
    $passRate = if ($script:TestsTotal -gt 0) { [math]::Round(($script:TestsPassed / $script:TestsTotal) * 100, 1) } else { 0 }
    Write-Host "  Pass Rate:     $passRate%" -ForegroundColor $(if ($passRate -ge 90) { "Green" } elseif ($passRate -ge 70) { "Yellow" } else { "Red" })
    Write-Host ""
    
    if ($script:TestsFailed -eq 0) {
        Write-Host "  ✓ All tests passed!" -ForegroundColor Green
    }
    else {
        Write-Host "  ✗ Some tests failed. Review output above." -ForegroundColor Red
    }
    
    # Export results
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $reportPath = "$PSScriptRoot\Output\test-results-$timestamp.xml"
    
    $script:TestResults | Export-Clixml -Path $reportPath -Force -ErrorAction SilentlyContinue
    Write-Host ""
    Write-Host "Results exported to: $reportPath" -ForegroundColor Gray
}

# ============================================================================
# Main Execution
# ============================================================================

Write-Logo
Write-Host " IdentityFirst QuickChecks - Test Suite" -ForegroundColor Cyan
Write-Host " $(Get-Date -Format 'yyyy-MM-dd')" -ForegroundColor Gray
Write-Host ""

# Run requested tests
if ($All -or (-not $Syntax -and -not $Security -and -not $Launcher -and -not $Quick)) {
    Test-Syntax
    Test-Security
    Test-Launcher
    Test-Modules
    Test-Configuration
}
else {
    if ($Syntax) { Test-Syntax }
    if ($Security) { Test-Security }
    if ($Launcher) { Test-Launcher }
    if ($Quick) {
        Test-Syntax
        Test-Launcher
    }
}

# Show summary
Show-Summary

# Exit with appropriate code
if ($script:TestsFailed -gt 0) {
    exit 1
}
exit 0
