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

# SIG # Begin signature block
# MIIf3QYJKoZIhvcNAQcCoIIfzjCCH8oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCBnRVGjecJ8fVr
# ZgU1TG8tEqcovuknVltc3GYZHI5ziaCCGNwwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# AgEVMC8GCSqGSIb3DQEJBDEiBCCw39RaRRS0LfMC5f6bTQB49bvSfu9RMK+PLVW1
# M0aZrTANBgkqhkiG9w0BAQEFAASCAgDRnx16BL2xihZf1SFSNHaJRO1opp0uxhh3
# ESzmzlxFebRPRiro24qeNyxl9cEV/0rd1P73LtPQpO0pU3g783dD/dYTe793aswE
# sj2ujDwGHnBdXthN/jvLXQOHUcbnYCL2ogcUWPF72M6eO3XQ3xeWYA/ti2IzFLTS
# myoWK0gJjIx5Gt5+uf38d0FbgAwPOl/K58cOSolyk87RqHCYEMTox3pcJBJ/Zt+8
# UopzwRCulHXhuL9wQgHFOQIrB5hjBnT7O9r8HkAhntKe5TC6wOZlC7/O3HBGNZPC
# +uB+oZ0V/6vJbKH5oKSWJjiKJhoBCWRm5vl0Iy8ABXUdcxVG7ky8Aob+9SUY+EzW
# nv9RFo870NbFmCWNc/S31CxWh1MLnxuz1qZiIU4XmN4/Q2LrA1MhTzprA8LxcReY
# fI/fD3TNHJZPxq5OIF5ZilyHDoaKBu7u+L6HNobCzXJHzTGhDyuu+iHWaAK1fv1X
# SIwqy3hn1yudehlUch6tnYKhi7tdsnRygManMFJdhzD+mr8+WYj/xfpTQymfGsK5
# 0IcwE7IggPMxSKGwnAXgJ8yPgBm5giOAyiRLBo3EJes8afg0VpsT8eG+piLKUaiw
# nxyFJks2t0jw5vAnDWzX9/8S0tnePsJ/RPyBWVI4XZkYrL+ma7GLNIDD3/Xj6bIA
# 5Xp54MGXaKGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAyMDUxNzE0NDVaMC8G
# CSqGSIb3DQEJBDEiBCDlEqHyapF7Uh7i1bw8eWdh93ELG8B7SediLlhCnQkprjAN
# BgkqhkiG9w0BAQEFAASCAgBi1wy1CKb0nwJBE1Ztr/V2ubRK8nl7IRAcD3B6MT9T
# knj+Q8AfdDwNXKlTsV7MD+EaYt2PsxPHs+xyzw3hc5mMUJx1LYJQuvdTYGlJ/n/V
# qb41jLbB8pxYp1KJauxbOL7IpcPAKUHV+teR88Ij5hvzBsiZLPgGVDls4uIG9iCo
# oUG24QvMHi7EF3qDRkcqhVm50EtaaAN8tZp0M8xsWXOHqQcOXKecoR+OrnHv95uo
# 9pVnZHTkepR8k9woeXcrIVimShvSl5y+jwraL4vuKrCmdbW4pvl7xwSeLnuRrt24
# rBIf5jhVniws5MoEp+p+p6Eoo5TsPFM+FC2cXsmrj/K9pQlVSiPN/vUazpBA5mUE
# ei5cZJRQ5rQM/+uo+42/iECyibpQvg9dbRtBBzYAaA0LhIqagM1Y7viqxuONBlwE
# AZJN734tEqcJZRSq/TUQMvNCS7WCMojXd7xpwREmWu4a/IakapaZFK1XLlDI3xLj
# Eyj8u9Midu8cOD+5SYWYeOO9m0pAwpqvr+za6X8kruOKark+mNdbC33r9baRNhVj
# ho0cZgZIWqKX4j3xXOaSe2qKXGCRnsTR5J4eV8bS+ZMk/jLvEwr4MLdUSCBDF/GA
# bYf5tjOFIryASxUf1xC5FNYbkLhdhklz7osl8bNHwMca3LlhaNdTXm68mIsqecOR
# jg==
# SIG # End signature block
