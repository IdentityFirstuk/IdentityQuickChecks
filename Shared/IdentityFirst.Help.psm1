# ============================================================================
# IdentityFirst.Help.psm1
# QuickHelp and Usage Examples for IdentityFirst QuickChecks
# ============================================================================
# PowerShell 5.1 and PowerShell 7 compatible
# ============================================================================

# ============================================================================
# QUICK HELP FUNCTIONS
# ============================================================================

function Get-QCHelp {
    <#
    .SYNOPSIS
        Displays quick help information for IdentityFirst QuickChecks.
    
    .DESCRIPTION
        This function provides quick access to help topics, examples, and
        command references for IdentityFirst modules.
    
    .PARAMETER Topic
        The help topic to display. Options: Overview, GettingStarted, 
        Examples, Benchmarks, Troubleshooting, All
    
    .PARAMETER Examples
        Switch to show usage examples.
    
    .EXAMPLE
        Get-QCHelp -Topic Overview
    
    .EXAMPLE
        Get-QCHelp -Examples
    
    .NOTES
        Author: IdentityFirst Security Team
    #>
    
    [CmdletBinding(DefaultParameterSetName = 'Topic')]
    param(
        [Parameter(ParameterSetName = 'Topic')]
        [ValidateSet('Overview', 'GettingStarted', 'Examples', 'Benchmarks', 'Troubleshooting', 'All')]
        [string]$Topic = 'Overview',
        
        [Parameter(ParameterSetName = 'Examples')]
        [switch]$Examples
    )
    
    if ($Examples) {
        Show-Examples
        return
    }
    
    switch ($Topic) {
        'Overview' { Show-Overview }
        'GettingStarted' { Show-GettingStarted }
        'Examples' { Show-Examples }
        'Benchmarks' { Show-BenchmarksHelp }
        'Troubleshooting' { Show-Troubleshooting }
        'All' { 
            Show-Overview
            Show-GettingStarted
            Show-Examples
            Show-BenchmarksHelp
            Show-Troubleshooting
        }
    }
}

function Show-Overview {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "           IDENTITYFIRST QUICKCHECKS - OVERVIEW" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "IdentityFirst QuickChecks is a comprehensive identity security" -ForegroundColor White
    Write-Host "assessment tool that evaluates your organization's identity" -ForegroundColor White
    Write-Host "security posture across multiple platforms." -ForegroundColor White
    Write-Host ""
    Write-Host "PLATFORMS SUPPORTED:" -ForegroundColor Yellow
    Write-Host "  • Active Directory (on-premises)" -ForegroundColor Green
    Write-Host "  • Microsoft Entra ID (Azure AD)" -ForegroundColor Green
    Write-Host "  • AWS Identity and Access Management" -ForegroundColor Green
    Write-Host "  • Google Cloud Platform IAM" -ForegroundColor Green
    Write-Host ""
    Write-Host "QUICKCHECKS AVAILABLE: 29+" -ForegroundColor Yellow
    Write-Host "  • Identity Security Checks" -ForegroundColor White
    Write-Host "  • Active Directory Security" -ForegroundColor White
    Write-Host "  • Entra ID Security" -ForegroundColor White
    Write-Host "  • Cloud Provider Security" -ForegroundColor White
    Write-Host "  • Compliance Benchmarks" -ForegroundColor White
    Write-Host ""
    Write-Host "FEATURES:" -ForegroundColor Yellow
    Write-Host "  • Historical Trend Tracking" -ForegroundColor White
    Write-Host "  • Industry Benchmark Comparison" -ForegroundColor White
    Write-Host "  • Compliance Scoring" -ForegroundColor White
    Write-Host "  • REST API Integration" -ForegroundColor White
    Write-Host "  • Webhook Notifications" -ForegroundColor White
    Write-Host ""
}

function Show-GettingStarted {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "              GETTING STARTED" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "STEP 1: IMPORT THE MODULE" -ForegroundColor Yellow
    Write-Host "----------------------------------------" -ForegroundColor Gray
    Write-Host "  Import-Module IdentityFirst.QuickChecks" -ForegroundColor Green
    Write-Host ""
    Write-Host "STEP 2: CONNECT TO YOUR ENVIRONMENT" -ForegroundColor Yellow
    Write-Host "----------------------------------------" -ForegroundColor Gray
    Write-Host "  # For Active Directory:" -ForegroundColor White
    Write-Host "  Import-Module ActiveDirectory" -ForegroundColor Green
    Write-Host ""
    Write-Host "  # For Entra ID:" -ForegroundColor White
    Write-Host "  Connect-MgGraph -Scopes 'Organization.Read.All', 'Directory.Read.All'" -ForegroundColor Green
    Write-Host ""
    Write-Host "  # For AWS:" -ForegroundColor White
    Write-Host "  Initialize-AWSDefaultConfiguration -Region us-east-1" -ForegroundColor Green
    Write-Host ""
    Write-Host "STEP 3: RUN A QUICKCHECK" -ForegroundColor Yellow
    Write-Host "----------------------------------------" -ForegroundColor Gray
    Write-Host "  # Run a single check" -ForegroundColor White
    Write-Host "  Invoke-BreakGlassReality -OutputPath '.\Reports'" -ForegroundColor Green
    Write-Host ""
    Write-Host "  # Run all checks" -ForegroundColor White
    Write-Host "  Start-QuickChecks -OutputPath '.\Reports'" -ForegroundColor Green
    Write-Host ""
    Write-Host "STEP 4: VIEW RESULTS" -ForegroundColor Yellow
    Write-Host "----------------------------------------" -ForegroundColor Gray
    Write-Host "  Results are saved to:" -ForegroundColor White
    Write-Host "  • JSON format (detailed)" -ForegroundColor White
    Write-Host "  • HTML format (report)" -ForegroundColor White
    Write-Host "  • Console output" -ForegroundColor White
    Write-Host ""
}

function Show-Examples {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "                   USAGE EXAMPLES" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "EXAMPLE 1: Basic Single Check" -ForegroundColor Yellow
    Write-Host "----------------------------------------" -ForegroundColor Gray
    Write-Host "  # Check break-glass account security" -ForegroundColor White
    Write-Host "  Invoke-BreakGlassReality -OutputPath '.\Reports\'" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "EXAMPLE 2: Run All Checks" -ForegroundColor Yellow
    Write-Host "----------------------------------------" -ForegroundColor Gray
    Write-Host "  # Comprehensive identity security assessment" -ForegroundColor White
    Write-Host "  Start-QuickChecks -OutputPath '.\Reports\' -Format JSON,HTML" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "EXAMPLE 3: Historical Tracking" -ForegroundColor Yellow
    Write-Host "----------------------------------------" -ForegroundColor Gray
    Write-Host "  # Start database session" -ForegroundColor White
    Write-Host "  Start-QCDataSession -DbPath '.\data\QuickChecks.db'" -ForegroundColor Green
    Write-Host ""
    Write-Host "  # Run and save results" -ForegroundColor White
    Write-Host "  \$results = Invoke-BreakGlassReality" -ForegroundColor Green
    Write-Host "  Save-ScanResult -ScanId (New-Guid).Guid -ScanType 'QuickChecks' \" -ForegroundColor Green
    Write-Host "      -OverallScore 85 -CheckResults \$results" -ForegroundColor Green
    Write-Host ""
    Write-Host "  # View trends" -ForegroundColor White
    Write-Host "  Get-ComplianceTrend -Environment 'Production'" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "EXAMPLE 4: Benchmark Comparison" -ForegroundColor Yellow
    Write-Host "----------------------------------------" -ForegroundColor Gray
    Write-Host "  # Get MFA benchmark" -ForegroundColor White
    Write-Host "  \$benchmark = Get-Benchmark -Category 'Entra' -CheckName 'GlobalAdminsMFA'" -ForegroundColor Green
    Write-Host ""
    Write-Host "  # Compare your results" -ForegroundColor White
    Write-Host "  Compare-ToBenchmark -ActualValue 85 -Benchmark \$benchmark" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "EXAMPLE 5: API Integration" -ForegroundColor Yellow
    Write-Host "----------------------------------------" -ForegroundColor Gray
    Write-Host "  # Start REST API on port 8080" -ForegroundColor White
    Write-Host "  Start-QuickChecksApi -Port 8080" -ForegroundColor Green
    Write-Host ""
    Write-Host "  # Configure webhooks for notifications" -ForegroundColor White
    Write-Host "  Start-QuickChecksWebhook -WebhookUrl 'https://your-corp.com/webhook'" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "EXAMPLE 6: Compliance Reporting" -ForegroundColor Yellow
    Write-Host "----------------------------------------" -ForegroundColor Gray
    Write-Host "  # Calculate compliance score" -ForegroundColor White
    Write-Host "  \$score = Get-ComplianceScore -CheckResults \$allResults" -ForegroundColor Green
    Write-Host "  Write-Host \"Score: \$($score.OverallScore)%\" " -ForegroundColor Green
    Write-Host ""
    Write-Host "  # Export historical data" -ForegroundColor White
    Write-Host "  Export-ScanHistory -Path '.\reports\history.json' -Format Json" -ForegroundColor Green
    Write-Host ""
}

function Show-BenchmarksHelp {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "              INDUSTRY BENCHMARKS" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Available Benchmark Categories:" -ForegroundColor White
    Write-Host ""
    Write-Host "  • ActiveDirectory    - AD security benchmarks" -ForegroundColor Green
    Write-Host "  • Entra             - Microsoft Entra ID benchmarks" -ForegroundColor Green
    Write-Host "  • AWS               - AWS IAM benchmarks" -ForegroundColor Green
    Write-Host "  • GCP               - Google Cloud Platform benchmarks" -ForegroundColor Green
    Write-Host "  • General           - General security benchmarks" -ForegroundColor Green
    Write-Host "  • Compliance        - Compliance framework benchmarks" -ForegroundColor Green
    Write-Host ""
    Write-Host "Using Benchmarks:" -ForegroundColor Yellow
    Write-Host "----------------------------------------" -ForegroundColor Gray
    Write-Host "  # List all benchmarks" -ForegroundColor White
    Write-Host "  Get-BenchmarkCategories" -ForegroundColor Green
    Write-Host ""
    Write-Host "  # Get benchmarks for a category" -ForegroundColor White
    Write-Host "  Get-Benchmark -Category 'Entra'" -ForegroundColor Green
    Write-Host ""
    Write-Host "  # Get a specific benchmark" -ForegroundColor White
    Write-Host "  Get-Benchmark -Category 'Entra' -CheckName 'GlobalAdminsMFA'" -ForegroundColor Green
    Write-Host ""
    Write-Host "Benchmark Status Levels:" -ForegroundColor Yellow
    Write-Host "----------------------------------------" -ForegroundColor Gray
    Write-Host "  • Compliant          - Meets best practice" -ForegroundColor Green
    Write-Host "  • IndustryStandard   - Meets industry average" -ForegroundColor Yellow
    Write-Host "  • NeedsImprovement  - Below average, action needed" -ForegroundColor Red
    Write-Host "  • Critical          - Critical gap, immediate action" -ForegroundColor DarkRed
    Write-Host ""
}

function Show-Troubleshooting {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "              TROUBLESHOOTING" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "COMMON ISSUES:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "1. MODULE NOT LOADING" -ForegroundColor White
    Write-Host "   Error: 'Module ... not found'" -ForegroundColor Gray
    Write-Host "   Solution:" -ForegroundColor Gray
    Write-Host "   - Verify module is in \$Env:PSModulePath" -ForegroundColor Green
    Write-Host "   - Import explicitly: Import-Module \path\to\module" -ForegroundColor Green
    Write-Host ""
    Write-Host "2. CONNECTIVITY ISSUES" -ForegroundColor White
    Write-Host "   Error: Unable to connect to service" -ForegroundColor Gray
    Write-Host "   Solution:" -ForegroundColor Gray
    Write-Host "   - Check credentials and permissions" -ForegroundColor Green
    Write-Host "   - Verify network connectivity" -ForegroundColor Green
    Write-Host "   - Run: Connect-MgGraph -Scopes ..." -ForegroundColor Green
    Write-Host ""
    Write-Host "3. PERMISSION DENIED" -ForegroundColor White
    Write-Host "   Error: Access is denied" -ForegroundColor Gray
    Write-Host "   Solution:" -ForegroundColor Gray
    Write-Host "   - Run PowerShell as Administrator" -ForegroundColor Green
    Write-Host "   - Check AD permissions (Domain Admin)" -ForegroundColor Green
    Write-Host "   - Verify Graph API permissions" -ForegroundColor Green
    Write-Host ""
    Write-Host "4. ENCODING ISSUES" -ForegroundColor White
    Write-Host "   Error: Unicode characters not displaying" -ForegroundColor Gray
    Write-Host "   Solution:" -ForegroundColor Gray
    Write-Host "   - Use UTF-8 BOM encoding for PS 5.1" -ForegroundColor Green
    Write-Host "   - Check output encoding: \$OutputEncoding" -ForegroundColor Green
    Write-Host ""
    Write-Host "5. SQLITE DATABASE LOCKED" -ForegroundColor White
    Write-Host "   Error: Database is locked" -ForegroundColor Gray
    Write-Host "   Solution:" -ForegroundColor Gray
    Write-Host "   - Call Stop-QCDataSession after operations" -ForegroundColor Green
    Write-Host "   - Ensure no other processes are using the DB" -ForegroundColor Green
    Write-Host ""
    Write-Host "GETTING HELP:" -ForegroundColor Yellow
    Write-Host "----------------------------------------" -ForegroundColor Gray
    Write-Host "  • Get-Help Invoke-BreakGlassReality -Full" -ForegroundColor Green
    Write-Host "  • Get-QCHelp -Examples" -ForegroundColor Green
    Write-Host "  • GitHub: https://github.com/IdentityFirstuk/IdentityFirst-Free" -ForegroundColor Green
    Write-Host ""
}

# ============================================================================
# QUICKSTART WIZARD
# ============================================================================

function Start-QCWizard {
    <#
    .SYNOPSIS
        Interactive wizard for quick configuration and execution.
    
    .DESCRIPTION
        Guides users through setting up and running QuickChecks
        with interactive prompts.
    
    .EXAMPLE
        Start-QCWizard
    #>
    
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "          IDENTITYFIRST QUICKCHECKS WIZARD" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    # Step 1: Environment Selection
    Write-Host "STEP 1: Select Target Environment(s)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [1] Active Directory Only" -ForegroundColor Green
    Write-Host "  [2] Entra ID Only" -ForegroundColor Green
    Write-Host "  [3] AWS Only" -ForegroundColor Green
    Write-Host "  [4] All Platforms" -ForegroundColor Green
    Write-Host ""
    
    $envChoice = Read-Host "Enter your choice (1-4)"
    Write-Host ""
    
    $platforms = @()
    switch ($envChoice) {
        '1' { $platforms = @('AD') }
        '2' { $platforms = @('Entra') }
        '3' { $platforms = @('AWS') }
        '4' { $platforms = @('AD', 'Entra', 'AWS', 'GCP') }
        default { 
            Write-Host "Invalid choice, defaulting to All Platforms" -ForegroundColor Yellow
            $platforms = @('AD', 'Entra', 'AWS', 'GCP')
        }
    }
    
    # Step 2: Output Selection
    Write-Host "STEP 2: Select Output Format(s)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  [1] Console Only" -ForegroundColor Green
    Write-Host "  [2] JSON Only" -ForegroundColor Green
    Write-Host "  [3] HTML Report" -ForegroundColor Green
    Write-Host "  [4] All Formats" -ForegroundColor Green
    Write-Host ""
    
    $outputChoice = Read-Host "Enter your choice (1-4)"
    Write-Host ""
    
    $formats = @()
    switch ($outputChoice) {
        '1' { $formats = @('Console') }
        '2' { $formats = @('JSON') }
        '3' { $formats = @('HTML') }
        '4' { $formats = @('Console', 'JSON', 'HTML') }
        default { 
            $formats = @('Console', 'JSON', 'HTML')
        }
    }
    
    # Step 3: Output Path
    Write-Host "STEP 3: Output Directory" -ForegroundColor Yellow
    Write-Host ""
    $outputPath = Read-Host "Enter output path (press Enter for '.\Reports')"
    if ([string]::IsNullOrEmpty($outputPath)) {
        $outputPath = '.\Reports'
    }
    Write-Host ""
    
    # Step 4: Historical Tracking
    Write-Host "STEP 4: Historical Tracking" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Enable SQLite database for tracking scan history?" -ForegroundColor White
    Write-Host "  [Y] Yes (recommended)" -ForegroundColor Green
    Write-Host "  [N] No" -ForegroundColor Gray
    Write-Host ""
    
    $trackChoice = Read-Host "Enter choice (Y/N)"
    $enableTracking = $trackChoice -eq 'Y' -or $trackChoice -eq 'y'
    Write-Host ""
    
    # Execute
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "                    EXECUTING" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    if ($enableTracking) {
        Start-QCDataSession
    }
    
    $params = @{
        'OutputPath' = $outputPath
        'Format' = $formats
    }
    
    try {
        Start-QuickChecks @params
        Write-Host ""
        Write-Host "QuickChecks completed successfully!" -ForegroundColor Green
    }
    catch {
        Write-Host ""
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    if ($enableTracking) {
        Stop-QCDataSession
    }
}

# ============================================================================
# EXPORT FUNCTIONS
# ============================================================================

Export-ModuleMember -Function @(
    'Get-QCHelp',
    'Start-QCWizard'
) -ErrorAction SilentlyContinue

# ============================================================================
# END OF MODULE
# ============================================================================
