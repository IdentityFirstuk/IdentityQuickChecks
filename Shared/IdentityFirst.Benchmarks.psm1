# ============================================================================
# IdentityFirst.Benchmarks.psm1
# Industry Benchmark Data Module for Identity Security QuickChecks
# ============================================================================
# PowerShell 5.1 and PowerShell 7 compatible
# ============================================================================

# ============================================================================
# PRIVATE: Benchmark Data Storage
# ============================================================================

# Store benchmark data in a script-scoped variable for module persistence
$script:BenchmarkData = @{}

# Initialize Active Directory benchmarks
$script:BenchmarkData['ActiveDirectory'] = @{}
$script:BenchmarkData['ActiveDirectory']['PasswordPolicy'] = @{
    'MaximumPasswordAge' = @{ 'BestPractice' = 90; 'IndustryAverage' = 60; 'CriticalThreshold' = 30; 'Unit' = 'days'; 'Description' = 'Maximum password age before forced change' }
    'MinimumPasswordAge' = @{ 'BestPractice' = 1; 'IndustryAverage' = 0; 'CriticalThreshold' = 0; 'Unit' = 'days'; 'Description' = 'Minimum days before password can be changed' }
    'PasswordHistoryCount' = @{ 'BestPractice' = 24; 'IndustryAverage' = 12; 'CriticalThreshold' = 6; 'Unit' = 'passwords'; 'Description' = 'Number of unique passwords remembered' }
    'MinimumPasswordLength' = @{ 'BestPractice' = 14; 'IndustryAverage' = 12; 'CriticalThreshold' = 8; 'Unit' = 'characters'; 'Description' = 'Minimum password length requirement' }
    'AccountLockoutThreshold' = @{ 'BestPractice' = 10; 'IndustryAverage' = 5; 'CriticalThreshold' = 3; 'Unit' = 'attempts'; 'Description' = 'Failed login attempts before lockout' }
    'LockoutDuration' = @{ 'BestPractice' = 15; 'IndustryAverage' = 30; 'CriticalThreshold' = 60; 'Unit' = 'minutes'; 'Description' = 'Duration of account lockout' }
    'PasswordComplexity' = @{ 'BestPractice' = $true; 'IndustryAverage' = $true; 'CriticalThreshold' = $false; 'Unit' = 'boolean'; 'Description' = 'Require uppercase, lowercase, numbers, symbols' }
    'ReversibleEncryption' = @{ 'BestPractice' = $false; 'IndustryAverage' = $false; 'CriticalThreshold' = $true; 'Unit' = 'boolean'; 'Description' = 'Store passwords using reversible encryption' }
}

$script:BenchmarkData['ActiveDirectory']['PrivilegedAccounts'] = @{
    'EmergencyAccessAccounts' = @{ 'BestPractice' = 2; 'IndustryAverage' = 4; 'CriticalThreshold' = 10; 'Unit' = 'accounts'; 'Description' = 'Number of emergency break-glass accounts' }
    'DaysSinceLastPasswordChange' = @{ 'BestPractice' = 30; 'IndustryAverage' = 45; 'CriticalThreshold' = 90; 'Unit' = 'days'; 'Description' = 'Maximum days since privileged password change' }
    'PrivilegedGroupNesting' = @{ 'BestPractice' = 1; 'IndustryAverage' = 3; 'CriticalThreshold' = 5; 'Unit' = 'levels'; 'Description' = 'Maximum nesting depth for privileged groups' }
    'StalePrivilegedAccounts' = @{ 'BestPractice' = 0; 'IndustryAverage' = 5; 'CriticalThreshold' = 15; 'Unit' = 'accounts'; 'Description' = 'Privileged accounts unused for 90+ days' }
    'ServiceAccountPasswordAge' = @{ 'BestPractice' = 90; 'IndustryAverage' = 180; 'CriticalThreshold' = 365; 'Unit' = 'days'; 'Description' = 'Maximum age for service account passwords' }
}

$script:BenchmarkData['ActiveDirectory']['Kerberos'] = @{
    'DelegationConfigured' = @{ 'BestPractice' = $false; 'IndustryAverage' = $true; 'CriticalThreshold' = $true; 'Unit' = 'boolean'; 'Description' = 'Kerberos unconstrained delegation present' }
    'ConstrainedDelegation' = @{ 'BestPractice' = 'Resource-Based'; 'IndustryAverage' = 'None'; 'CriticalThreshold' = 'None'; 'Unit' = 'string'; 'Description' = 'Preferred delegation model' }
    'KerberoastableAccounts' = @{ 'BestPractice' = 0; 'IndustryAverage' = 5; 'CriticalThreshold' = 20; 'Unit' = 'accounts'; 'Description' = 'Accounts with SPNs vulnerable to Kerberoasting' }
    'ASREPRoastableAccounts' = @{ 'BestPractice' = 0; 'IndustryAverage' = 0; 'CriticalThreshold' = 5; 'Unit' = 'accounts'; 'Description' = 'Accounts with pre-auth disabled' }
    'RODCImplemented' = @{ 'BestPractice' = $true; 'IndustryAverage' = $false; 'CriticalThreshold' = $false; 'Unit' = 'boolean'; 'Description' = 'Read-Only Domain Controllers deployed' }
}

$script:BenchmarkData['ActiveDirectory']['LAPS'] = @{
    'LAPSEnabledComputers' = @{ 'BestPractice' = 100; 'IndustryAverage' = 85; 'CriticalThreshold' = 50; 'Unit' = 'percent'; 'Description' = 'Percentage of computers with LAPS enabled' }
    'LAPSExpiredPasswords' = @{ 'BestPractice' = 0; 'IndustryAverage' = 5; 'CriticalThreshold' = 15; 'Unit' = 'percent'; 'Description' = 'Computers with LAPS password age > 90 days' }
    'LocalAdminDisabled' = @{ 'BestPractice' = 0; 'IndustryAverage' = 5; 'CriticalThreshold' = 15; 'Unit' = 'percent'; 'Description' = 'Computers with local admin disabled' }
}

$script:BenchmarkData['ActiveDirectory']['Replication'] = @{
    'DcsyncRights' = @{ 'BestPractice' = 3; 'IndustryAverage' = 8; 'CriticalThreshold' = 15; 'Unit' = 'accounts'; 'Description' = 'Accounts with DCSync rights' }
    'ReplicationAllowed' = @{ 'BestPractice' = $false; 'IndustryAverage' = $false; 'CriticalThreshold' = $true; 'Unit' = 'boolean'; 'Description' = 'Non-admin accounts can trigger replication' }
}

# Initialize Entra benchmarks
$script:BenchmarkData['Entra'] = @{}
$script:BenchmarkData['Entra']['MultiFactorAuthentication'] = @{
    'GlobalAdminsMFA' = @{ 'BestPractice' = 100; 'IndustryAverage' = 95; 'CriticalThreshold' = 80; 'Unit' = 'percent'; 'Description' = 'Global Administrators with MFA enabled' }
    'AllUsersMFA' = @{ 'BestPractice' = 100; 'IndustryAverage' = 80; 'CriticalThreshold' = 50; 'Unit' = 'percent'; 'Description' = 'All users with MFA enabled' }
    'ConditionalAccessMFA' = @{ 'BestPractice' = $true; 'IndustryAverage' = $true; 'CriticalThreshold' = $false; 'Unit' = 'boolean'; 'Description' = 'Conditional Access policy enforcing MFA' }
    'PhishingResistantMFA' = @{ 'BestPractice' = $true; 'IndustryAverage' = $false; 'CriticalThreshold' = $false; 'Unit' = 'boolean'; 'Description' = 'Phishing-resistant MFA methods enforced' }
}

$script:BenchmarkData['Entra']['GuestAccess'] = @{
    'GuestAccounts' = @{ 'BestPractice' = 0; 'IndustryAverage' = 15; 'CriticalThreshold' = 50; 'Unit' = 'percent'; 'Description' = 'Percentage of guest accounts vs total' }
    'GuestInvitationsEnabled' = @{ 'BestPractice' = $false; 'IndustryAverage' = $true; 'CriticalThreshold' = $true; 'Unit' = 'boolean'; 'Description' = 'Anyone can invite guests' }
    'GuestUsersWithOwnerRights' = @{ 'BestPractice' = 0; 'IndustryAverage' = 5; 'CriticalThreshold' = 20; 'Unit' = 'percent'; 'Description' = 'Guests with directory access rights' }
}

$script:BenchmarkData['Entra']['LegacyAuthentication'] = @{
    'BlockLegacyAuth' = @{ 'BestPractice' = $true; 'IndustryAverage' = $true; 'CriticalThreshold' = $false; 'Unit' = 'boolean'; 'Description' = 'Legacy authentication blocked' }
}

$script:BenchmarkData['Entra']['HybridIdentity'] = @{
    'PasswordHashSync' = @{ 'BestPractice' = $true; 'IndustryAverage' = $true; 'CriticalThreshold' = $true; 'Unit' = 'boolean'; 'Description' = 'Password Hash Synchronization enabled' }
    'SyncErrors' = @{ 'BestPractice' = 0; 'IndustryAverage' = 2; 'CriticalThreshold' = 10; 'Unit' = 'errors'; 'Description' = 'Active directory synchronization errors' }
}

$script:BenchmarkData['Entra']['PIM'] = @{
    'PIMEnabled' = @{ 'BestPractice' = $true; 'IndustryAverage' = $true; 'CriticalThreshold' = $false; 'Unit' = 'boolean'; 'Description' = 'Privileged Identity Management enabled' }
    'GlobalAdminPIM' = @{ 'BestPractice' = 100; 'IndustryAverage' = 80; 'CriticalThreshold' = 50; 'Unit' = 'percent'; 'Description' = 'Global Admins using PIM for assignments' }
    'PermanentAssignments' = @{ 'BestPractice' = 0; 'IndustryAverage' = 30; 'CriticalThreshold' = 60; 'Unit' = 'percent'; 'Description' = 'Permanent role assignments' }
}

# Initialize AWS benchmarks
$script:BenchmarkData['AWS'] = @{}
$script:BenchmarkData['AWS']['IAM'] = @{
    'UsersWithMFA' = @{ 'BestPractice' = 100; 'IndustryAverage' = 95; 'CriticalThreshold' = 80; 'Unit' = 'percent'; 'Description' = 'IAM users with MFA enabled' }
    'UsersWithAccessKeys' = @{ 'BestPractice' = 20; 'IndustryAverage' = 40; 'CriticalThreshold' = 60; 'Unit' = 'percent'; 'Description' = 'Users with access keys' }
    'AccessKeysOlderThan90Days' = @{ 'BestPractice' = 0; 'IndustryAverage' = 20; 'CriticalThreshold' = 50; 'Unit' = 'percent'; 'Description' = 'Access keys older than 90 days' }
}

$script:BenchmarkData['AWS']['RootAccount'] = @{
    'MFAEnabled' = @{ 'BestPractice' = $true; 'IndustryAverage' = $true; 'CriticalThreshold' = $false; 'Unit' = 'boolean'; 'Description' = 'Root account MFA enabled' }
    'AccessKeysPresent' = @{ 'BestPractice' = $false; 'IndustryAverage' = $false; 'CriticalThreshold' = $true; 'Unit' = 'boolean'; 'Description' = 'Root account has access keys' }
}

$script:BenchmarkData['AWS']['GuardDuty'] = @{
    'Enabled' = @{ 'BestPractice' = $true; 'IndustryAverage' = $true; 'CriticalThreshold' = $false; 'Unit' = 'boolean'; 'Description' = 'GuardDuty enabled' }
    'FindingCount' = @{ 'BestPractice' = 0; 'IndustryAverage' = 10; 'CriticalThreshold' = 50; 'Unit' = 'findings'; 'Description' = 'Active GuardDuty findings' }
}

# Initialize GCP benchmarks
$script:BenchmarkData['GCP'] = @{}
$script:BenchmarkData['GCP']['IAM'] = @{
    'ServiceAccountsWithKeys' = @{ 'BestPractice' = 10; 'IndustryAverage' = 25; 'CriticalThreshold' = 50; 'Unit' = 'percent'; 'Description' = 'Service accounts with user-managed keys' }
    'KeysOlderThan90Days' = @{ 'BestPractice' = 0; 'IndustryAverage' = 20; 'CriticalThreshold' = 50; 'Unit' = 'percent'; 'Description' = 'Service account keys older than 90 days' }
}

$script:BenchmarkData['GCP']['SecurityCommandCenter'] = @{
    'Enabled' = @{ 'BestPractice' = $true; 'IndustryAverage' = $true; 'CriticalThreshold' = $false; 'Unit' = 'boolean'; 'Description' = 'Security Command Center enabled' }
    'ActiveFindings' = @{ 'BestPractice' = 0; 'IndustryAverage' = 10; 'CriticalThreshold' = 50; 'Unit' = 'findings'; 'Description' = 'Active security findings' }
}

# Initialize General benchmarks
$script:BenchmarkData['General'] = @{}
$script:BenchmarkData['General']['AccessGovernance'] = @{
    'AccessReviewsConfigured' = @{ 'BestPractice' = $true; 'IndustryAverage' = $true; 'CriticalThreshold' = $false; 'Unit' = 'boolean'; 'Description' = 'Periodic access reviews configured' }
    'ReviewFrequency' = @{ 'BestPractice' = 30; 'IndustryAverage' = 90; 'CriticalThreshold' = 180; 'Unit' = 'days'; 'Description' = 'Access review frequency' }
}

$script:BenchmarkData['General']['Monitoring'] = @{
    'SIEMIntegrated' = @{ 'BestPractice' = $true; 'IndustryAverage' = $true; 'CriticalThreshold' = $false; 'Unit' = 'boolean'; 'Description' = 'Identity events sent to SIEM' }
    'LogRetentionDays' = @{ 'BestPractice' = 365; 'IndustryAverage' = 180; 'CriticalThreshold' = 90; 'Unit' = 'days'; 'Description' = 'Log retention period' }
}

# Initialize Compliance benchmarks
$script:BenchmarkData['Compliance'] = @{}
$script:BenchmarkData['Compliance']['NIST80053'] = @{
    'ACControls' = @{ 'BestPractice' = 95; 'IndustryAverage' = 75; 'CriticalThreshold' = 50; 'Unit' = 'percent'; 'Description' = 'Access Control controls implemented' }
    'AUControls' = @{ 'BestPractice' = 95; 'IndustryAverage' = 75; 'CriticalThreshold' = 50; 'Unit' = 'percent'; 'Description' = 'Audit and Accountability controls' }
}

$script:BenchmarkData['Compliance']['CIS'] = @{
    'CISLevel1' = @{ 'BestPractice' = 100; 'IndustryAverage' = 85; 'CriticalThreshold' = 70; 'Unit' = 'percent'; 'Description' = 'CIS Level 1 benchmark compliance' }
}

# ============================================================================
# PUBLIC FUNCTIONS
# ============================================================================

function Get-Benchmark {
    <#
    .SYNOPSIS
        Retrieves benchmark data for a specific category and check.
    
    .DESCRIPTION
        This function returns industry benchmark data for comparing
        QuickChecks results against best practices and industry averages.
    
    .PARAMETER Category
        The benchmark category (e.g., 'ActiveDirectory', 'Entra', 'AWS', 'GCP', 'General', 'Compliance')
    
    .PARAMETER CheckName
        The specific benchmark check name (e.g., 'UsersWithMFA', 'KerberoastableAccounts')
    
    .EXAMPLE
        Get-Benchmark -Category 'Entra' -CheckName 'GlobalAdminsMFA'
    
    .NOTES
        Author: IdentityFirst Security Team
        Version: 1.0.0
        Compatible: PowerShell 5.1 and 7.x
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
        # If no category specified, return all benchmarks
        if ([string]::IsNullOrEmpty($Category)) {
            return $script:BenchmarkData
        }
        
        # If category exists but no check name, return category
        if ($script:BenchmarkData.ContainsKey($Category)) {
            if ([string]::IsNullOrEmpty($CheckName)) {
                return $script:BenchmarkData[$Category]
            }
            
            # Return specific check
            if ($script:BenchmarkData[$Category].ContainsKey($CheckName)) {
                return $script:BenchmarkData[$Category][$CheckName]
            }
            else {
                Write-Warning "Benchmark check '$CheckName' not found in category '$Category'"
                return $null
            }
        }
        else {
            Write-Warning "Benchmark category '$Category' not found"
            return $null
        }
    }
    catch {
        Write-Error "Error retrieving benchmark: $($_.Exception.Message)"
        return $null
    }
}

function Compare-ToBenchmark {
    <#
    .SYNOPSIS
        Compares an actual value to benchmark thresholds.
    
    .DESCRIPTION
        This function compares the actual check result against industry
        best practices and returns compliance status.
    
    .PARAMETER ActualValue
        The actual value from the QuickCheck result.
    
    .PARAMETER Benchmark
        The benchmark hashtable containing BestPractice, IndustryAverage, and CriticalThreshold.
    
    .PARAMETER HigherIsBetter
        Indicates if higher values are better (default: $true for most metrics).
    
    .EXAMPLE
        $benchmark = Get-Benchmark -Category 'Entra' -CheckName 'GlobalAdminsMFA'
        Compare-ToBenchmark -ActualValue 85 -Benchmark $benchmark
    
    .NOTES
        Returns a custom object with compliance status, gap analysis, and recommendations.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $ActualValue,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$Benchmark,
        
        [Parameter(Mandatory = $false)]
        [bool]$HigherIsBetter = $true
    )
    
    try {
        $bestPractice = $Benchmark['BestPractice']
        $industryAverage = $Benchmark['IndustryAverage']
        $criticalThreshold = $Benchmark['CriticalThreshold']
        $unit = $Benchmark['Unit']
        $description = $Benchmark['Description']
        
        # Determine compliance status
        $status = 'Unknown'
        $gapFromBest = 0
        $gapFromAverage = 0
        
        if ($HigherIsBetter) {
            $gapFromBest = $bestPractice - $ActualValue
            $gapFromAverage = $industryAverage - $ActualValue
            
            if ($ActualValue -ge $bestPractice) {
                $status = 'Compliant'
            }
            elseif ($ActualValue -ge $industryAverage) {
                $status = 'IndustryStandard'
            }
            elseif ($ActualValue -ge $criticalThreshold) {
                $status = 'NeedsImprovement'
            }
            else {
                $status = 'Critical'
            }
        }
        else {
            $gapFromBest = $ActualValue - $bestPractice
            $gapFromAverage = $ActualValue - $industryAverage
            
            if ($ActualValue -le $bestPractice) {
                $status = 'Compliant'
            }
            elseif ($ActualValue -le $industryAverage) {
                $status = 'IndustryStandard'
            }
            elseif ($ActualValue -le $criticalThreshold) {
                $status = 'NeedsImprovement'
            }
            else {
                $status = 'Critical'
            }
        }
        
        # Build result object
        $result = [PSCustomObject]@{
            'CheckName' = $CheckName
            'Description' = $description
            'ActualValue' = $ActualValue
            'BestPractice' = $bestPractice
            'IndustryAverage' = $industryAverage
            'CriticalThreshold' = $criticalThreshold
            'Unit' = $unit
            'Status' = $status
            'GapFromBestPractice' = $gapFromBest
            'GapFromIndustryAverage' = $gapFromAverage
            'HigherIsBetter' = $HigherIsBetter
            'ComplianceScore' = if ($HigherIsBetter) {
                [math]::Min(100, [math]::Max(0, ($ActualValue / $bestPractice) * 100))
            }
            else {
                [math]::Min(100, [math]::Max(0, ($bestPractice / $ActualValue) * 100))
            }
            'Recommendations' = Get-BenchmarkRecommendations -Status $status -Gap $gapFromBest -Unit $unit
            'Timestamp' = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        }
        
        return $result
    }
    catch {
        Write-Error "Error comparing to benchmark: $($_.Exception.Message)"
        return $null
    }
}

function Get-BenchmarkRecommendations {
    <#
    .SYNOPSIS
        Generates recommendations based on benchmark status.
    
    .DESCRIPTION
        Internal function that provides remediation recommendations.
    #>
    
    [CmdletBinding()]
    param(
        [string]$Status,
        [double]$Gap,
        [string]$Unit
    )
    
    $recommendations = @()
    
    switch ($Status) {
        'Compliant' {
            $recommendations.Add('Maintain current security posture')
            $recommendations.Add('Continue monitoring for any drift')
            $recommendations.Add('Document current configuration as baseline')
        }
        'IndustryStandard' {
            $recommendations.Add('Consider implementing additional controls to exceed industry average')
            $recommendations.Add('Review industry leaders for best practices')
            $recommendations.Add('Plan phased improvements to reach best practice level')
        }
        'NeedsImprovement' {
            $recommendations.Add('Priority remediation required within 30 days')
            $recommendations.Add('Review current configuration against best practices')
            $recommendations.Add('Implement incremental improvements')
        }
        'Critical' {
            $recommendations.Add('IMMEDIATE ACTION REQUIRED - Critical security gap')
            $recommendations.Add('Escalate to security and IT teams')
            $recommendations.Add('Consider compensating controls until full remediation')
            $recommendations.Add('Schedule follow-up assessment within 7 days')
        }
    }
    
    return $recommendations
}

function Get-ComplianceScore {
    <#
    .SYNOPSIS
        Calculates overall compliance score from QuickCheck results.
    
    .DESCRIPTION
        This function calculates an aggregate compliance score based on
        multiple QuickCheck results against their benchmarks.
    
    .PARAMETER CheckResults
        Array of QuickCheck result objects.
    
    .EXAMPLE
        $results | Get-ComplianceScore
    
    .NOTES
        Returns overall score (0-100) with category breakdown.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [array]$CheckResults
    )
    
    begin {
        $allResults = @()
        $categoryScores = @{}
    }
    
    process {
        $allResults += $CheckResults
    }
    
    end {
        try {
            if ($allResults.Count -eq 0) {
                return [PSCustomObject]@{
                    'OverallScore' = 0
                    'TotalChecks' = 0
                    'Compliant' = 0
                    'IndustryStandard' = 0
                    'NeedsImprovement' = 0
                    'Critical' = 0
                    'CategoryBreakdown' = $null
                    'Timestamp' = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                }
            }
            
            $compliant = 0
            $industryStandard = 0
            $needsImprovement = 0
            $critical = 0
            
            # Calculate per-category scores
            foreach ($result in $allResults) {
                $cat = $result.Category
                if ([string]::IsNullOrEmpty($cat)) { $cat = 'General' }
                
                if (-not $categoryScores.ContainsKey($cat)) {
                    $categoryScores[$cat] = @{
                        'Total' = 0
                        'ScoreSum' = 0
                        'Compliant' = 0
                    }
                }
                
                $categoryScores[$cat]['Total']++
                $categoryScores[$cat]['ScoreSum'] += $result.ComplianceScore
                
                switch ($result.Status) {
                    'Compliant' {
                        $compliant++
                        $categoryScores[$cat]['Compliant']++
                    }
                    'IndustryStandard' { $industryStandard++ }
                    'NeedsImprovement' { $needsImprovement++ }
                    'Critical' { $critical++ }
                }
            }
            
            # Calculate overall score (weighted average)
            $totalScore = 0
            foreach ($cat in $categoryScores.Keys) {
                $totalScore += $categoryScores[$cat]['ScoreSum']
            }
            $overallScore = [math]::Round($totalScore / $allResults.Count, 2)
            
            # Build category breakdown
            $categoryBreakdown = @()
            foreach ($cat in $categoryScores.Keys) {
                $catData = $categoryScores[$cat]
                $categoryBreakdown += [PSCustomObject]@{
                    'Category' = $cat
                    'Score' = [math]::Round($catData['ScoreSum'] / $catData['Total'], 2)
                    'Checks' = $catData['Total']
                    'Compliant' = $catData['Compliant']
                }
            }
            
            return [PSCustomObject]@{
                'OverallScore' = $overallScore
                'TotalChecks' = $allResults.Count
                'Compliant' = $compliant
                'IndustryStandard' = $industryStandard
                'NeedsImprovement' = $needsImprovement
                'Critical' = $critical
                'CategoryBreakdown' = $categoryBreakdown
                'Timestamp' = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
            }
        }
        catch {
            Write-Error "Error calculating compliance score: $($_.Exception.Message)"
            return $null
        }
    }
}

function Get-BenchmarkCategories {
    <#
    .SYNOPSIS
        Lists all available benchmark categories.
    
    .DESCRIPTION
        Returns a list of all benchmark categories available in the module.
    
    .EXAMPLE
        Get-BenchmarkCategories
    
    .NOTES
        Use Get-Benchmark without parameters to see full structure.
    #>
    
    return $script:BenchmarkData.Keys | Sort-Object
}

function Get-BenchmarkChecks {
    <#
    .SYNOPSIS
        Lists all benchmark checks for a category.
    
    .DESCRIPTION
        Returns available benchmark checks within a specific category.
    
    .PARAMETER Category
        The benchmark category name.
    
    .EXAMPLE
        Get-BenchmarkChecks -Category 'Entra'
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('ActiveDirectory', 'Entra', 'AWS', 'GCP', 'General', 'Compliance')]
        [string]$Category
    )
    
    if ($script:BenchmarkData.ContainsKey($Category)) {
        return $script:BenchmarkData[$Category].Keys | Sort-Object
    }
    else {
        Write-Warning "Category '$Category' not found"
        return $null
    }
}

function Export-BenchmarkData {
    <#
    .SYNOPSIS
        Exports benchmark data to JSON format.
    
    .DESCRIPTION
        Exports all benchmark data to a JSON file for external analysis.
    
    .PARAMETER Path
        Output file path for the JSON export.
    
    .EXAMPLE
        Export-BenchmarkData -Path '.\benchmarks.json'
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )
    
    try {
        $script:BenchmarkData | ConvertTo-Json -Depth 10 | Set-Content -Path $Path -Encoding UTF8
        Write-Host "Benchmark data exported to: $Path" -ForegroundColor Green
    }
    catch {
        Write-Error "Error exporting benchmark data: $($_.Exception.Message)"
    }
}

# ============================================================================
# Export Public Functions
# ============================================================================

# Export functions for module use
Export-ModuleMember -Function @(
    'Get-Benchmark',
    'Compare-ToBenchmark',
    'Get-ComplianceScore',
    'Get-BenchmarkCategories',
    'Get-BenchmarkChecks',
    'Export-BenchmarkData'
) -ErrorAction SilentlyContinue

# ============================================================================
# END OF MODULE
# ============================================================================
