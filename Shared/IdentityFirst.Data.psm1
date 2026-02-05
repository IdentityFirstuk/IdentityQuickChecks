# ============================================================================
# IdentityFirst.Data.psm1 (Enhanced Version)
# Data Module for Identity Security QuickChecks
# ============================================================================
# Features: Auto-initialization, simplified workflows, benchmark data
# PowerShell 5.1 and PowerShell 7 compatible
# ============================================================================

# Default database path
$script:DefaultDbPath = $null
$script:DbConnection = $null
$script:BenchmarkData = @{}
$script:AutoInitialize = $true

# ============================================================================
# AUTO-INITIALIZATION
# ============================================================================

$script:DefaultDbPath = Join-Path -Path $PSScriptRoot -ChildPath '..\data\IdentityFirst.QuickChecks.db'

function Initialize-Module {
    <#
    .SYNOPSIS
        Initializes the data module automatically.
    
    .DESCRIPTION
        Called automatically when module is loaded. Sets up benchmark data
        and prepares the database connection without requiring user action.
    
    .NOTES
        Internal function called by module startup.
    #>
    
    try {
        # Initialize benchmark data
        Initialize-BenchmarkData
        
        # Create data directory if needed
        $dbDir = Split-Path -Path $script:DefaultDbPath -Parent
        if (-not (Test-Path -Path $dbDir)) {
            New-Item -Path $dbDir -ItemType Directory -Force | Out-Null
        }
        
        Write-Verbose "IdentityFirst.Data module initialized"
    }
    catch {
        Write-Warning "Failed to initialize module: $($_.Exception.Message)"
    }
}

# ============================================================================
# BENCHMARK DATA INITIALIZATION
# ============================================================================

function Initialize-BenchmarkData {
    # Active Directory Benchmarks
    $script:BenchmarkData['ActiveDirectory'] = @{}
    $script:BenchmarkData['ActiveDirectory']['PasswordPolicy'] = @{
        'MaximumPasswordAge' = @{ 'BestPractice' = 90; 'IndustryAverage' = 60; 'CriticalThreshold' = 30; 'Unit' = 'days'; 'Description' = 'Maximum password age' }
        'MinimumPasswordLength' = @{ 'BestPractice' = 14; 'IndustryAverage' = 12; 'CriticalThreshold' = 8; 'Unit' = 'characters'; 'Description' = 'Minimum password length' }
        'PasswordComplexity' = @{ 'BestPractice' = $true; 'IndustryAverage' = $true; 'CriticalThreshold' = $false; 'Unit' = 'boolean'; 'Description' = 'Password complexity required' }
        'ReversibleEncryption' = @{ 'BestPractice' = $false; 'IndustryAverage' = $false; 'CriticalThreshold' = $true; 'Unit' = 'boolean'; 'Description' = 'Store passwords using reversible encryption' }
    }
    
    $script:BenchmarkData['ActiveDirectory']['PrivilegedAccounts'] = @{
        'EmergencyAccessAccounts' = @{ 'BestPractice' = 2; 'IndustryAverage' = 4; 'CriticalThreshold' = 10; 'Unit' = 'accounts'; 'Description' = 'Break-glass accounts' }
        'StalePrivilegedAccounts' = @{ 'BestPractice' = 0; 'IndustryAverage' = 5; 'CriticalThreshold' = 15; 'Unit' = 'accounts'; 'Description' = 'Stale privileged accounts' }
    }
    
    $script:BenchmarkData['ActiveDirectory']['Kerberos'] = @{
        'DelegationConfigured' = @{ 'BestPractice' = $false; 'IndustryAverage' = $true; 'CriticalThreshold' = $true; 'Unit' = 'boolean'; 'Description' = 'Unconstrained delegation' }
        'KerberoastableAccounts' = @{ 'BestPractice' = 0; 'IndustryAverage' = 5; 'CriticalThreshold' = 20; 'Unit' = 'accounts'; 'Description' = 'Kerberoastable accounts' }
    }
    
    $script:BenchmarkData['ActiveDirectory']['LAPS'] = @{
        'LAPSEnabledComputers' = @{ 'BestPractice' = 100; 'IndustryAverage' = 85; 'CriticalThreshold' = 50; 'Unit' = 'percent'; 'Description' = 'LAPS enabled computers' }
    }
    
    $script:BenchmarkData['ActiveDirectory']['Replication'] = @{
        'DcsyncRights' = @{ 'BestPractice' = 3; 'IndustryAverage' = 8; 'CriticalThreshold' = 15; 'Unit' = 'accounts'; 'Description' = 'Accounts with DCSync rights' }
    }
    
    # Entra ID Benchmarks
    $script:BenchmarkData['Entra'] = @{}
    $script:BenchmarkData['Entra']['MultiFactorAuthentication'] = @{
        'GlobalAdminsMFA' = @{ 'BestPractice' = 100; 'IndustryAverage' = 95; 'CriticalThreshold' = 80; 'Unit' = 'percent'; 'Description' = 'Global Admins with MFA' }
        'AllUsersMFA' = @{ 'BestPractice' = 100; 'IndustryAverage' = 80; 'CriticalThreshold' = 50; 'Unit' = 'percent'; 'Description' = 'All users with MFA' }
        'PhishingResistantMFA' = @{ 'BestPractice' = $true; 'IndustryAverage' = $false; 'CriticalThreshold' = $false; 'Unit' = 'boolean'; 'Description' = 'Phishing-resistant MFA' }
    }
    
    $script:BenchmarkData['Entra']['GuestAccess'] = @{
        'GuestAccounts' = @{ 'BestPractice' = 0; 'IndustryAverage' = 15; 'CriticalThreshold' = 50; 'Unit' = 'percent'; 'Description' = 'Guest account percentage' }
        'GuestInvitationsEnabled' = @{ 'BestPractice' = $false; 'IndustryAverage' = $true; 'CriticalThreshold' = $true; 'Unit' = 'boolean'; 'Description' = 'Anyone can invite guests' }
    }
    
    $script:BenchmarkData['Entra']['LegacyAuthentication'] = @{
        'BlockLegacyAuth' = @{ 'BestPractice' = $true; 'IndustryAverage' = $true; 'CriticalThreshold' = $false; 'Unit' = 'boolean'; 'Description' = 'Legacy auth blocked' }
    }
    
    $script:BenchmarkData['Entra']['PIM'] = @{
        'PIMEnabled' = @{ 'BestPractice' = $true; 'IndustryAverage' = $true; 'CriticalThreshold' = $false; 'Unit' = 'boolean'; 'Description' = 'PIM enabled' }
        'GlobalAdminPIM' = @{ 'BestPractice' = 100; 'IndustryAverage' = 80; 'CriticalThreshold' = 50; 'Unit' = 'percent'; 'Description' = 'Global Admins using PIM' }
    }
    
    # AWS Benchmarks
    $script:BenchmarkData['AWS'] = @{}
    $script:BenchmarkData['AWS']['IAM'] = @{
        'UsersWithMFA' = @{ 'BestPractice' = 100; 'IndustryAverage' = 95; 'CriticalThreshold' = 80; 'Unit' = 'percent'; 'Description' = 'IAM users with MFA' }
        'AccessKeysOlderThan90Days' = @{ 'BestPractice' = 0; 'IndustryAverage' = 20; 'CriticalThreshold' = 50; 'Unit' = 'percent'; 'Description' = 'Old access keys' }
    }
    
    $script:BenchmarkData['AWS']['RootAccount'] = @{
        'MFAEnabled' = @{ 'BestPractice' = $true; 'IndustryAverage' = $true; 'CriticalThreshold' = $false; 'Unit' = 'boolean'; 'Description' = 'Root MFA enabled' }
    }
    
    $script:BenchmarkData['AWS']['GuardDuty'] = @{
        'Enabled' = @{ 'BestPractice' = $true; 'IndustryAverage' = $true; 'CriticalThreshold' = $false; 'Unit' = 'boolean'; 'Description' = 'GuardDuty enabled' }
    }
    
    # GCP Benchmarks
    $script:BenchmarkData['GCP'] = @{}
    $script:BenchmarkData['GCP']['IAM'] = @{
        'ServiceAccountsWithKeys' = @{ 'BestPractice' = 10; 'IndustryAverage' = 25; 'CriticalThreshold' = 50; 'Unit' = 'percent'; 'Description' = 'SA with user keys' }
    }
    
    $script:BenchmarkData['GCP']['SecurityCommandCenter'] = @{
        'Enabled' = @{ 'BestPractice' = $true; 'IndustryAverage' = $true; 'CriticalThreshold' = $false; 'Unit' = 'boolean'; 'Description' = 'SCC enabled' }
    }
    
    # General Benchmarks
    $script:BenchmarkData['General'] = @{}
    $script:BenchmarkData['General']['AccessGovernance'] = @{
        'AccessReviewsConfigured' = @{ 'BestPractice' = $true; 'IndustryAverage' = $true; 'CriticalThreshold' = $false; 'Unit' = 'boolean'; 'Description' = 'Access reviews configured' }
    }
    
    $script:BenchmarkData['General']['Monitoring'] = @{
        'SIEMIntegrated' = @{ 'BestPractice' = $true; 'IndustryAverage' = $true; 'CriticalThreshold' = $false; 'Unit' = 'boolean'; 'Description' = 'SIEM integration' }
        'LogRetentionDays' = @{ 'BestPractice' = 365; 'IndustryAverage' = 180; 'CriticalThreshold' = 90; 'Unit' = 'days'; 'Description' = 'Log retention period' }
    }
    
    # Compliance Benchmarks
    $script:BenchmarkData['Compliance'] = @{}
    $script:BenchmarkData['Compliance']['NIST80053'] = @{
        'ACControls' = @{ 'BestPractice' = 95; 'IndustryAverage' = 75; 'CriticalThreshold' = 50; 'Unit' = 'percent'; 'Description' = 'AC controls implemented' }
    }
    
    $script:BenchmarkData['Compliance']['CIS'] = @{
        'CISLevel1' = @{ 'BestPractice' = 100; 'IndustryAverage' = 85; 'CriticalThreshold' = 70; 'Unit' = 'percent'; 'Description' = 'CIS Level 1 compliance' }
    }
}

# ============================================================================
# SIMPLIFIED DATABASE FUNCTIONS
# ============================================================================

function Open-QCDatabase {
    <#
    .SYNOPSIS
        Opens the database connection with auto-initialization.
    
    .DESCRIPTION
        Simplified function that automatically initializes the database
        and tables if they don't exist.
    
    .PARAMETER DbPath
        Optional path to the database file.
    
    .EXAMPLE
        Open-QCDatabase
        # Database is now ready to use
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$DbPath
    )
    
    if ([string]::IsNullOrEmpty($DbPath)) {
        $DbPath = $script:DefaultDbPath
    }
    
    try {
        $dbDir = Split-Path -Path $DbPath -Parent
        if (-not (Test-Path -Path $dbDir)) {
            New-Item -Path $dbDir -ItemType Directory -Force | Out-Null
        }
        
        $connectionString = "Data Source=$DbPath;Version=3;"
        $script:DbConnection = New-Object -TypeName 'System.Data.SQLite.SQLiteConnection' -ArgumentList $connectionString
        $script:DbConnection.Open()
        
        # Create tables
        $createScanTable = "CREATE TABLE IF NOT EXISTS Scans (ScanId TEXT PRIMARY KEY, ScanType TEXT NOT NULL, Environment TEXT, ExecutedBy TEXT, StartTime DATETIME NOT NULL, EndTime DATETIME, OverallScore REAL, TotalChecks INTEGER, PassedChecks INTEGER, FailedChecks INTEGER, Warnings INTEGER, Duration TEXT, AdditionalInfo TEXT, CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP)"
        
        $createCheckTable = "CREATE TABLE IF NOT EXISTS CheckResults (ResultId INTEGER PRIMARY KEY AUTOINCREMENT, ScanId TEXT NOT NULL, CheckName TEXT NOT NULL, Category TEXT NOT NULL, Severity TEXT, Status TEXT NOT NULL, ActualValue REAL, ExpectedValue REAL, FindingCount INTEGER, Findings TEXT, Remediation TEXT, ComplianceScore REAL, BenchmarkStatus TEXT, Duration TEXT, AdditionalData TEXT, CreatedAt DATETIME DEFAULT CURRENT_TIMESTAMP)"
        
        $null = $script:DbConnection.CreateCommand()
        $null = $script:DbCommand.CommandText = $createScanTable
        $null = $script:DbCommand.ExecuteNonQuery()
        $script:DbCommand.Dispose()
        
        $null = $script:DbConnection.CreateCommand()
        $null = $script:DbCommand.CommandText = $createCheckTable
        $null = $script:DbCommand.ExecuteNonQuery()
        $script:DbCommand.Dispose()
        
        Write-Verbose "Database opened: $DbPath"
        return $true
    }
    catch {
        Write-Error "Failed to open database: $($_.Exception.Message)"
        return $false
    }
}

function Close-QCDatabase {
    <#
    .SYNOPSIS
        Closes the database connection.
    
    .DESCRIPTION
        Properly closes the database connection to release resources.
    
    .EXAMPLE
        Close-QCDatabase
    #>
    
    if ($null -ne $script:DbConnection) {
        try {
            $script:DbConnection.Close()
            $script:DbConnection.Dispose()
            $script:DbConnection = $null
        }
        catch {
            Write-Warning "Error closing database: $($_.Exception.Message)"
        }
    }
}

# Aliases for backward compatibility
Set-Alias -Name 'Start-QCDataSession' -Value 'Open-QCDatabase' -Description 'Open database connection' -ErrorAction SilentlyContinue
Set-Alias -Name 'Stop-QCDataSession' -Value 'Close-QCDatabase' -Description 'Close database connection' -ErrorAction SilentlyContinue

# ============================================================================
# SIMPLIFIED SAVE FUNCTION
# ============================================================================

function Save-QCScan {
    <#
    .SYNOPSIS
        Simplified function to save a complete scan.
    
    .DESCRIPTION
        Combines opening the database, saving results, and optional close.
    
    .PARAMETER ScanId
        Unique identifier for the scan.
    
    .PARAMETER ScanType
        Type of scan performed.
    
    .PARAMETER Results
        Array of check result objects.
    
    .PARAMETER Environment
        Target environment.
    
    .PARAMETER KeepOpen
        Keep database connection open after saving.
    
    .EXAMPLE
        Save-QCScan -ScanId (New-Guid).Guid -ScanType 'QuickChecks' -Results $results
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScanId,
        
        [Parameter(Mandatory = $true)]
        [string]$ScanType,
        
        [Parameter(Mandatory = $false)]
        [array]$Results,
        
        [Parameter(Mandatory = $false)]
        [string]$Environment,
        
        [Parameter(Mandatory = $false)]
        [switch]$KeepOpen
    )
    
    try {
        # Auto-open if needed
        if ($null -eq $script:DbConnection) {
            $null = Open-QCDatabase
        }
        
        $startTime = Get-Date
        
        # Calculate statistics
        $totalChecks = if ($null -ne $Results) { $Results.Count } else { 0 }
        $passedChecks = if ($null -ne $Results) { ($Results | Where-Object { $_.Status -eq 'Pass' }).Count } else { 0 }
        $failedChecks = if ($null -ne $Results) { ($Results | Where-Object { $_.Status -eq 'Fail' }).Count } else { 0 }
        $warnings = if ($null -ne $Results) { ($Results | Where-Object { $_.Status -eq 'Warning' }).Count } else { 0 }
        
        # Calculate overall score
        $overallScore = 0
        if ($null -ne $Results -and $Results.Count -gt 0) {
            $totalScore = 0
            foreach ($r in $Results) {
                $totalScore += ($r.ComplianceScore -as [double])
            }
            $overallScore = $totalScore / $Results.Count
        }
        
        # Insert scan metadata
        $insertScan = "INSERT INTO Scans (ScanId, ScanType, Environment, ExecutedBy, StartTime, EndTime, OverallScore, TotalChecks, PassedChecks, FailedChecks, Warnings) VALUES (@ScanId, @ScanType, @Environment, @ExecutedBy, @StartTime, @EndTime, @OverallScore, @TotalChecks, @PassedChecks, @FailedChecks, @Warnings)"
        
        $null = $script:DbConnection.CreateCommand()
        $null = $script:DbCommand.CommandText = $insertScan
        $null = $script:DbCommand.Parameters.AddWithValue('@ScanId', $ScanId)
        $null = $script:DbCommand.Parameters.AddWithValue('@ScanType', $ScanType)
        $null = $script:DbCommand.Parameters.AddWithValue('@Environment', $Environment)
        $null = $script:DbCommand.Parameters.AddWithValue('@ExecutedBy', $Env:Username)
        $null = $script:DbCommand.Parameters.AddWithValue('@StartTime', $startTime)
        $null = $script:DbCommand.Parameters.AddWithValue('@EndTime', (Get-Date))
        $null = $script:DbCommand.Parameters.AddWithValue('@OverallScore', $overallScore)
        $null = $script:DbCommand.Parameters.AddWithValue('@TotalChecks', $totalChecks)
        $null = $script:DbCommand.Parameters.AddWithValue('@PassedChecks', $passedChecks)
        $null = $script:DbCommand.Parameters.AddWithValue('@FailedChecks', $failedChecks)
        $null = $script:DbCommand.Parameters.AddWithValue('@Warnings', $warnings)
        $null = $script:DbCommand.ExecuteNonQuery()
        $script:DbCommand.Dispose()
        
        # Insert check results
        if ($null -ne $Results -and $Results.Count -gt 0) {
            $insertCheck = "INSERT INTO CheckResults (ScanId, CheckName, Category, Severity, Status, ActualValue, ComplianceScore, BenchmarkStatus) VALUES (@ScanId, @CheckName, @Category, @Severity, @Status, @ActualValue, @ComplianceScore, @BenchmarkStatus)"
            
            foreach ($result in $Results) {
                $null = $script:DbConnection.CreateCommand()
                $null = $script:DbCommand.CommandText = $insertCheck
                $null = $script:DbCommand.Parameters.AddWithValue('@ScanId', $ScanId)
                $null = $script:DbCommand.Parameters.AddWithValue('@CheckName', $result.CheckName)
                $null = $script:DbCommand.Parameters.AddWithValue('@Category', $result.Category)
                $null = $script:DbCommand.Parameters.AddWithValue('@Severity', $result.Severity)
                $null = $script:DbCommand.Parameters.AddWithValue('@Status', $result.Status)
                $null = $script:DbCommand.Parameters.AddWithValue('@ActualValue', $result.ActualValue)
                $null = $script:DbCommand.Parameters.AddWithValue('@ComplianceScore', $result.ComplianceScore)
                $null = $script:DbCommand.Parameters.AddWithValue('@BenchmarkStatus', $result.BenchmarkStatus)
                $null = $script:DbCommand.ExecuteNonQuery()
                $script:DbCommand.Dispose()
            }
        }
        
        Write-Verbose "Scan saved: $ScanId (Score: $([math]::Round($overallScore, 1))%)"
        
        # Close if not keeping open
        if (-not $KeepOpen) {
            Close-QCDatabase
        }
        
        return $true
    }
    catch {
        Write-Error "Error saving scan: $($_.Exception.Message)"
        return $false
    }
}

# ============================================================================
# BENCHMARK FUNCTIONS
# ============================================================================

function Get-Benchmark {
    <#
    .SYNOPSIS
        Retrieves benchmark data for a specific category and check.
    
    .DESCRIPTION
        Returns industry best practices, averages, and thresholds for
        comparing QuickCheck results.
    
    .PARAMETER Category
        Benchmark category (ActiveDirectory, Entra, AWS, GCP, General, Compliance).
    
    .PARAMETER CheckName
        Specific benchmark check name.
    
    .EXAMPLE
        $benchmark = Get-Benchmark -Category 'Entra' -CheckName 'GlobalAdminsMFA'
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('ActiveDirectory', 'Entra', 'AWS', 'GCP', 'General', 'Compliance')]
        [string]$Category,
        
        [Parameter(Mandatory = $false)]
        [string]$CheckName
    )
    
    try {
        if ([string]::IsNullOrEmpty($Category)) {
            return $script:BenchmarkData
        }
        
        if ($script:BenchmarkData.ContainsKey($Category)) {
            if ([string]::IsNullOrEmpty($CheckName)) {
                return $script:BenchmarkData[$Category]
            }
            
            if ($script:BenchmarkData[$Category].ContainsKey($CheckName)) {
                return $script:BenchmarkData[$Category][$CheckName]
            }
        }
        return $null
    }
    catch {
        Write-Error "Error retrieving benchmark: $($_.Exception.Message)"
        return $null
    }
}

function Test-BenchmarkCompliance {
    <#
    .SYNOPSIS
        Quick test of compliance against a benchmark.
    
    .DESCRIPTION
        Simplified function to check if a value meets best practice.
    
    .PARAMETER ActualValue
        The actual value to check.
    
    .PARAMETER Category
        Benchmark category.
    
    .PARAMETER CheckName
        Specific benchmark check.
    
    .PARAMETER HigherIsBetter
        Whether higher values are better (default: $true).
    
    .EXAMPLE
        Test-BenchmarkCompliance -ActualValue 85 -Category 'Entra' -CheckName 'GlobalAdminsMFA'
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ActualValue,
        
        [Parameter(Mandatory = $true)]
        [string]$Category,
        
        [Parameter(Mandatory = $true)]
        [string]$CheckName,
        
        [Parameter(Mandatory = $false)]
        [bool]$HigherIsBetter = $true
    )
    
    $benchmark = Get-Benchmark -Category $Category -CheckName $CheckName
    
    if ($null -eq $benchmark) {
        return $null
    }
    
    $bestPractice = $benchmark['BestPractice']
    $status = 'Unknown'
    
    if ($HigherIsBetter) {
        if ($ActualValue -ge $bestPractice) { $status = 'Compliant' }
        elseif ($ActualValue -ge $benchmark['IndustryAverage']) { $status = 'IndustryStandard' }
        elseif ($ActualValue -ge $benchmark['CriticalThreshold']) { $status = 'NeedsImprovement' }
        else { $status = 'Critical' }
    }
    else {
        if ($ActualValue -le $bestPractice) { $status = 'Compliant' }
        elseif ($ActualValue -le $benchmark['IndustryAverage']) { $status = 'IndustryStandard' }
        elseif ($ActualValue -le $benchmark['CriticalThreshold']) { $status = 'NeedsImprovement' }
        else { $status = 'Critical' }
    }
    
    return [PSCustomObject]@{
        Status = $status
        ActualValue = $ActualValue
        TargetValue = $bestPractice
        Description = $benchmark['Description']
        Unit = $benchmark['Unit']
    }
}

function Get-BenchmarkCategories {
    <#
    .SYNOPSIS
        Lists all available benchmark categories.
    #>
    
    return $script:BenchmarkData.Keys | Sort-Object
}

# ============================================================================
# COMPLIANCE SCORING
# ============================================================================

function Get-QCComplianceScore {
    <#
    .SYNOPSIS
        Calculates overall compliance score from check results.
    
    .DESCRIPTION
        Provides a quick compliance score calculation with breakdown.
    
    .PARAMETER Results
        Array of check result objects.
    
    .EXAMPLE
        $score = Get-QCComplianceScore -Results $allResults
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [array]$Results
    )
    
    process { $allResults += $Results }
    
    end {
        if ($null -eq $allResults -or $allResults.Count -eq 0) {
            return [PSCustomObject]@{
                OverallScore = 0
                TotalChecks = 0
                Compliant = 0
                IndustryStandard = 0
                NeedsImprovement = 0
                Critical = 0
                Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            }
        }
        
        $compliant = ($allResults | Where-Object { $_.BenchmarkStatus -eq 'Compliant' }).Count
        $industryStandard = ($allResults | Where-Object { $_.BenchmarkStatus -eq 'IndustryStandard' }).Count
        $needsImprovement = ($allResults | Where-Object { $_.BenchmarkStatus -eq 'NeedsImprovement' }).Count
        $critical = ($allResults | Where-Object { $_.BenchmarkStatus -eq 'Critical' }).Count
        
        $totalScore = 0
        foreach ($r in $allResults) {
            $totalScore += ($r.ComplianceScore -as [double])
        }
        
        return [PSCustomObject]@{
            OverallScore = [math]::Round($totalScore / $allResults.Count, 2)
            TotalChecks = $allResults.Count
            Compliant = $compliant
            IndustryStandard = $industryStandard
            NeedsImprovement = $needsImprovement
            Critical = $critical
            Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        }
    }
}

# ============================================================================
# HISTORY FUNCTIONS
# ============================================================================

function Get-QCScanHistory {
    <#
    .SYNOPSIS
        Retrieves recent scan history.
    
    .DESCRIPTION
        Simple function to get recent scans from the database.
    
    .PARAMETER Limit
        Maximum number of records to return.
    
    .EXAMPLE
        Get-QCScanHistory -Limit 10
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$Limit = 10
    )
    
    try {
        if ($null -eq $script:DbConnection) {
            $null = Open-QCDatabase
        }
        
        $query = "SELECT * FROM Scans ORDER BY StartTime DESC LIMIT @Limit"
        
        $null = $script:DbConnection.CreateCommand()
        $null = $script:DbCommand.CommandText = $query
        $null = $script:DbCommand.Parameters.AddWithValue('@Limit', $Limit)
        
        $adapter = New-Object -TypeName 'System.Data.SQLite.SQLiteDataAdapter' -ArgumentList $script:DbCommand
        $dataset = New-Object -TypeName 'System.Data.DataSet'
        $null = $adapter.Fill($dataset)
        $script:DbCommand.Dispose()
        
        return $dataset.Tables[0]
    }
    catch {
        Write-Error "Error retrieving history: $($_.Exception.Message)"
        return $null
    }
}

function Get-QCScoreTrend {
    <#
    .SYNOPSIS
        Gets compliance score trend over time.
    
    .DESCRIPTION
        Returns the trend of overall compliance scores.
    
    .PARAMETER Limit
        Number of data points to return.
    
    .EXAMPLE
        $trend = Get-QCScoreTrend -Limit 12
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$Limit = 12
    )
    
    try {
        if ($null -eq $script:DbConnection) {
            $null = Open-QCDatabase
        }
        
        $query = "SELECT ScanId, OverallScore, StartTime, Environment FROM Scans ORDER BY StartTime DESC LIMIT @Limit"
        
        $null = $script:DbConnection.CreateCommand()
        $null = $script:DbCommand.CommandText = $query
        $null = $script:DbCommand.Parameters.AddWithValue('@Limit', $Limit)
        
        $adapter = New-Object -TypeName 'System.Data.SQLite.SQLiteDataAdapter' -ArgumentList $script:DbCommand
        $dataset = New-Object -TypeName 'System.Data.DataSet'
        $null = $adapter.Fill($dataset)
        $script:DbCommand.Dispose()
        
        return $dataset.Tables[0]
    }
    catch {
        Write-Error "Error retrieving trend: $($_.Exception.Message)"
        return $null
    }
}

# ============================================================================
# AUTO-INITIALIZE ON MODULE LOAD
# ============================================================================

Initialize-Module

# ============================================================================
# EXPORT FUNCTIONS
# ============================================================================

Export-ModuleMember -Function @(
    # Simplified Functions
    'Open-QCDatabase',
    'Close-QCDatabase',
    'Save-QCScan',
    
    # Benchmark Functions
    'Get-Benchmark',
    'Test-BenchmarkCompliance',
    'Get-BenchmarkCategories',
    
    # Compliance Functions
    'Get-QCComplianceScore',
    
    # History Functions
    'Get-QCScanHistory',
    'Get-QCScoreTrend'
) -Alias @(
    'Start-QCDataSession',
    'Stop-QCDataSession'
) -ErrorAction SilentlyContinue

# ============================================================================
# END OF MODULE
# ============================================================================
