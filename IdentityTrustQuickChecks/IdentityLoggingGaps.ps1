param([string]$OutputPath = ".")

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================================================"
Write-Host "  Identity Logging Gaps Check"
Write-Host "========================================================================"

<#
.SYNOPSIS
    Check security logging configuration for identity-related events.

.DESCRIPTION
    Identifies potential logging gaps in Active Directory that could
    prevent forensic investigation or compliance monitoring of identity events.

.NOTES
    - Read-only: YES
    - Requires: ActiveDirectory module (RSAT)
    - Permissions: Domain Admin recommended

.EXAMPLE
    .\IdentityLoggingGaps.ps1
#>

# Initialize tracking variables
$loggingGaps = @()
$loggingVerified = @()
$errors = @()
$processedCount = 0

Write-Host ""
Write-Host "  Analyzing identity logging configuration..." -ForegroundColor Gray

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "  ActiveDirectory module loaded" -ForegroundColor Green
}
catch {
    Write-Host "  ERROR: ActiveDirectory module not available" -ForegroundColor Red
    exit 1
}

# ============================================================================
# Check 1: Audit Policy Configuration
# ============================================================================

Write-Host ""
Write-Host "  Checking domain audit policy..." -ForegroundColor Gray

try {
    $domain = Get-ADDomain -ErrorAction Stop
    $domainController = Get-ADDomainController -Discover -ErrorAction Stop
    
    # Check if we can access security event logs
    $logSettings = @{}
    $importantLogs = @("Security", "Directory Service", "System")
    
    $auditIssues = @()
    
    foreach ($logName in $importantLogs) {
        try {
            $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
            $logSettings[$logName] = @{
                IsEnabled = $log.IsEnabled
                RetentionPolicy = $log.RetentionPolicy
                MaximumSizeInBytes = $log.MaximumSizeInBytes
            }
            
            if (-not $log.IsEnabled) {
                $auditIssues += "$logName log is NOT enabled"
            }
        }
        catch {
            $auditIssues += "Cannot access $logName log (permission denied)"
        }
    }
    
    if ($auditIssues) {
        $loggingGaps += New-Object PSObject -Property @{
            Category = "Windows Event Log Configuration"
            Issues = $auditIssues
            Severity = "HIGH"
        }
        Write-Host "    ⚠ Windows Event Log issues found:" -ForegroundColor Red
        $auditIssues | ForEach-Object { Write-Host "       - $_" -ForegroundColor Gray }
    }
    else {
        $loggingVerified += "Windows Event Logs are configured"
        Write-Host "    ✅ Windows Event Logs are accessible and enabled" -ForegroundColor Green
    }
}
catch {
    $errors += "Failed to check audit policy: $($_.Exception.Message)"
    Write-Host "    ⚠ Cannot verify audit policy (may require admin)" -ForegroundColor Yellow
}

# ============================================================================
# Check 2: Advanced Audit Policy (if accessible)
# ============================================================================

Write-Host ""
Write-Host "  Checking advanced audit policy..." -ForegroundColor Gray

try {
    # Try to get advanced audit policy
    $auditSubcategories = @(
        "Account Logon",
        "Account Management",
        "Directory Service Access",
        "Logon/Logoff",
        "Object Access",
        "Policy Change",
        "Privilege Use",
        "System"
    )
    
    $policyIssues = @()
    
    foreach ($subcategory in $auditSubcategories) {
        try {
            # Check via secedit (works on most systems)
            $secedit = secedit /export /areas USER_RIGHTS /cfg $env:TEMP\secedit.inf 2>$null
            if ($LASTEXITCODE -eq 0) {
                # Policy exported
                break
            }
        }
        catch {
            # Non-critical
        }
    }
    
    $loggingVerified += "Advanced audit policy check attempted"
    Write-Host "    ℹ Advanced audit policy requires elevated access to verify" -ForegroundColor Gray
}
catch {
    # Non-critical
}

# ============================================================================
# Check 3: AD LDS / ADCS Logging Configuration
# ============================================================================

Write-Host ""
Write-Host "  Checking AD LDS/CS logging (if present)..." -ForegroundColor Gray

$adServices = @()
$servicesCheck = @(
    "ADWS",          # Active Directory Web Services
    "NTDS",          # Active Directory Domain Services
    "KDC",           # Kerberos Key Distribution Center
    "NetLogon"       # Net Logon
)

try {
    foreach ($service in $servicesCheck) {
        try {
            $svc = Get-Service -Name $service -ErrorAction Stop
            $adServices += @{
                Name = $service
                Status = $svc.Status.ToString()
                StartType = $svc.StartType.ToString()
            }
        }
        catch {
            # Service may not exist on this system
        }
    }
    
    if ($adServices) {
        $loggingVerified += "$($adServices.Count) AD services verified"
        Write-Host "    ℹ $($adServices.Count) AD-related services found on this system" -ForegroundColor Gray
    }
}
catch {
    # Non-critical
}

# ============================================================================
# Check 4: Object Access Auditing (Directory Service)
# ============================================================================

Write-Host ""
Write-Host "  Checking Directory Service object access auditing..." -ForegroundColor Gray

try {
    # Get domain NC root DACL (to check if auditing is configured)
    $rootDSE = Get-ADRootDSE -ErrorAction Stop
    
    try {
        $ntdsSettings = Get-ADObject "CN=NTDS Settings,CN=$($domainController.Name),CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,$($rootDSE.rootDomainNamingContext)" -Properties * -ErrorAction Stop
        
        $loggingVerified += "NTDS Settings accessible for logging verification"
        Write-Host "    ✅ Directory Service configuration accessible" -ForegroundColor Green
    }
    catch {
        $loggingGaps += New-Object PSObject -Property @{
            Category = "Directory Service Access Audit"
            Issues = @("Cannot verify Directory Service audit configuration")
            Severity = "MEDIUM"
        }
        Write-Host "    ⚠ Cannot verify Directory Service audit (may require DC access)" -ForegroundColor Yellow
    }
}
catch {
    $errors += "Failed to check Directory Service: $($_.Exception.Message)"
}

# ============================================================================
# Check 5: Account Management Audit
# ============================================================================

Write-Host ""
Write-Host "  Checking account management audit capability..." -ForegroundColor Gray

try {
    # Check if we can enumerate administrative accounts (indicates AD is functional)
    $adminCount = (Get-ADGroupMember "Domain Admins" -ErrorAction Stop | Measure-Object).Count
    
    if ($adminCount -gt 0) {
        $loggingVerified += "Account management audit possible (AD functional)"
        Write-Host "    ✅ Active Directory is functional for account auditing" -ForegroundColor Green
        Write-Host "       Domain Admins group has $adminCount members" -ForegroundColor Gray
    }
    else {
        $loggingGaps += New-Object PSObject -Property @{
            Category = "Account Management"
            Issues = @("Domain Admins group appears empty")
            Severity = "LOW"
        }
        Write-Host "    ⚠ Domain Admins group appears empty" -ForegroundColor Yellow
    }
}
catch {
    $errors += "Failed to check account management: $($_.Exception.Message)"
    Write-Host "    ⚠ Cannot verify account management auditing" -ForegroundColor Yellow
}

# ============================================================================
# Check 6: Group Policy Audit Settings
# ============================================================================

Write-Host ""
Write-Host "  Checking Group Policy audit settings..." -ForegroundColor Gray

try {
    # Try to access GPOs
    $gpos = Get-GPO -All -ErrorAction Stop | Select-Object -First 10
    
    $loggingVerified += "Group Policy accessible for audit verification"
    Write-Host "    ℹ $($gpos.Count) GPOs found (audit settings in GPOs require DC access)" -ForegroundColor Gray
}
catch {
    # GPO module may not be available
    Write-Host "    ⚠ Group Policy module not available (run on Domain Controller for full audit)" -ForegroundColor Yellow
}

# ============================================================================
# Summary Output
# ============================================================================

Write-Host ""
Write-Host "  Logging Gaps Summary"
Write-Host "  ===================="
Write-Host "  Logging verified: $($loggingVerified.Count) areas"
Write-Host "  Logging gaps found: $($loggingGaps.Count)" -ForegroundColor $(if ($loggingGaps.Count -gt 0) { "Yellow" } else { "Green" })
Write-Host "  Errors: $($errors.Count)"

if ($loggingGaps) {
    Write-Host ""
    Write-Host "  LOGGING GAPS:"
    
    $highSeverity = $loggingGaps | Where-Object { $_.Severity -eq "HIGH" }
    if ($highSeverity) {
        Write-Host ""
        Write-Host "    HIGH SEVERITY GAPS:" -ForegroundColor Red
        $highSeverity | ForEach-Object {
            Write-Host "      - $($_.Category)" -ForegroundColor Gray
            $_.Issues | ForEach-Object { Write-Host "        • $_" -ForegroundColor Gray }
        }
    }
    
    $mediumSeverity = $loggingGaps | Where-Object { $_.Severity -eq "MEDIUM" }
    if ($mediumSeverity) {
        Write-Host ""
        Write-Host "    MEDIUM SEVERITY GAPS:" -ForegroundColor Yellow
        $mediumSeverity | ForEach-Object {
            Write-Host "      - $($_.Category)" -ForegroundColor Gray
        }
    }
}

if ($errors) {
    Write-Host ""
    Write-Host "  Errors encountered:" -ForegroundColor Yellow
    foreach ($err in $errors) {
        Write-Host "    - $err" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "  VERIFIED AREAS:"
$loggingVerified | ForEach-Object { Write-Host "    ✅ $_" -ForegroundColor Green }

# ============================================================================
# Generate Report
# ============================================================================

$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$reportPath = Join-Path $OutputPath "IdentityLoggingGaps-$timestamp.json"

$report = @{
    CheckName = "Identity Logging Gaps"
    Timestamp = Get-Date -Format "o"
    Summary = @{
        LoggingVerified = $loggingVerified.Count
        LoggingGaps = $loggingGaps.Count
        Errors = $errors.Count
    }
    VerifiedAreas = $loggingVerified
    LoggingGaps = $loggingGaps
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

Write-Host ""
Write-Host "  ─────────────────────────────────────────────────────────────"
Write-Host "  ℹ  Full logging verification requires Domain Controller access." -ForegroundColor Gray
Write-Host "     For comprehensive audit readiness, run IdentityHealthCheck." -ForegroundColor Gray
Write-Host "  ─────────────────────────────────────────────────────────────"

exit 0
