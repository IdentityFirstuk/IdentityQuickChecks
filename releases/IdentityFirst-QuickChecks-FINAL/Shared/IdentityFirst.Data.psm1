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

# SIG # Begin signature block
# MIIf3QYJKoZIhvcNAQcCoIIfzjCCH8oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB9wxodeFQcFsvm
# u6lH6wTSIjrm+SkaMIhjE0ZmET2f1aCCGNwwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# AgEVMC8GCSqGSIb3DQEJBDEiBCAqdTjdU54PA58CppmR+79D0qFC7FrCdijFhSkD
# VLqrZzANBgkqhkiG9w0BAQEFAASCAgCsmgqgnXTE4AufMEXT6p7O0x7FyF7sxOGO
# wKmqYG6AXFejo8vlP4zY/qW6xL/vTLHTuBLBHHXmfdeyTG0m9DNddEDk4SILx3nf
# wb4WlzFn4JqNwMKuKz+Z4ztwS1kigMjRFbeKTEv/Sm7dQkHkTCjlLKHpbv7RxHVo
# Hi3d56OQ05mqhTbgc3M4J2DKrd0ATL9lJxRVNew5+MbxvjLSUmWCK5U9AzSye0y3
# 34dd9lTuD/QRZ9QzIFHHfBZlmuPmy1sQMTbA0u3e5DpnoOojdSfmVzErUJXjhPx5
# 8lXb4sKEJ0wUdHoKw6KSyevAxRdg/Na/LGO1qsiHMubZEYIxDPbK9B4KqjsZ86vo
# 4sqwA80eK+zJjEbTYTuS03rgfhFqhtXych1u27L/Rxr5L9zUG3Twfc7rGLPKw+Pn
# VJxScJ7puOdQPGucSvyrLF28yTNkGM6he/KwxhTcuXEIhr1l3pieDvb2e64+FAB+
# 35tdDhUDqmdQL3TJIRZs2ZaFTqO0Z6WMDR42vpD68ljfB52AV8dYB5zBjWxKa2hX
# n9oPZpOh0pfLf7jlOBsvRfvp3oaUNqBbRGM3bmFfz6Aa/d3j13kCT6SYXz2iSNRR
# litzsN9NDohnsbDNHHIunevy2380nWpkPOugcTLYiyGhgQdVzaXybPo/9B4UUm2u
# 5r7nIWGUbqGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAyMDUxNzE0NDVaMC8G
# CSqGSIb3DQEJBDEiBCCDwofkECwSl35Es4OFNc3XhNXFfwcwu88dQozmVkxZsDAN
# BgkqhkiG9w0BAQEFAASCAgBmclYAlm55QWXWuwCMXRkyw3ybpqCb0TR4pnjv44Ly
# 3Aq9N6jf7lyQCHmkXg1xB1KXLgUr7+Nyqbfmdp1VEzYKZ+0KGfszMrVEVQW0Ny8E
# jUAzsdTFFg54sy/V2/cBkhK+G1jjOB7pkkF7CaBP84UQRqL9NOH1hhHMZCz7KTeM
# 12WvDu5kzXQI1i+/n04xqlT1qOyHxYcZaq2UgD8wiZ5nRhBZA/hkSNA8mEYkf0nq
# 7TMJ1ZGvqkfyi1pHQB77M/XpWpgG8guH4gUOCPMEOx89iN3jWKvnZ2CfWuCIxoBb
# DhOrqcCfFq6l64Ow9bFJdXOmrHOLqKlgS8Vj+P69vYIGN2w1MqIoSg2pL9GygI8x
# fUICJA5/yVNpw3dpltpgPOYv3WxYwKKTZ2y25+NPa7j3Jt3CT19iIHZCfp8c8NE+
# +furrHYIR5JakSU98R38DXSzOe5wWmb79dwcT+UjwCYCcjG6dT9uPND+mVlz75sJ
# /Bn1HfH8jmdI2dIHTPTV6Vdp9bBFydT7pfqff9CrbyTtH4LT0FJTowjAk5VPG9J2
# tUYo6HmwoyxMG9S8b6GqInOR/XkZLxEpIyvBruyRJH1cG/xeddbIn5zGOb4OjqPh
# bZp+TnJwNN6LeeZXDo8uCoTpr+y6uRNS0YK5D1SR2UmdNjVbYAfJIJEx4hcBwAWn
# Ow==
# SIG # End signature block
