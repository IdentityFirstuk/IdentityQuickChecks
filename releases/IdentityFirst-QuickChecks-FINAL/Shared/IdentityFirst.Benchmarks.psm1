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

# SIG # Begin signature block
# MIIf3QYJKoZIhvcNAQcCoIIfzjCCH8oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAXF6xmzirf/T01
# IFVHnTkdoZffcD8E/V9r9gvcAoTqLaCCGNwwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# AgEVMC8GCSqGSIb3DQEJBDEiBCC3FDOTlHlAspRYsIYRolQiHvlqQqa7GodgG/Xy
# oa/nRzANBgkqhkiG9w0BAQEFAASCAgA1tZK/cT4JHOnQautF8GcwpGshjauyeTF/
# 86cdp1cXfyrMgNxQv8L7BGMRdkJ3hUyXXhJ3hf0hQkAO2GOX9W0jX5Dmcvqq6JiG
# sq6kiBbIRx6eoOuxcuV5yDYw6TeGJarsILVm5vduTjWGeMo/GjhfNavX1Akck3wU
# 2PEyx+/9RMVFSLoHjO5YouBL1hDlbOA5IuHe1lxYbm9HFlwiY2zkBngMrB4Ojag8
# ja+EALNKwlXhayZaDiCIDUZo8i+V64HbghEDSrggyJMUDNQz5KVnpa6LGqjfwOlc
# WBlFuf09dIdhuRjjbINLz4U+cBq8tXXQveeSzs72xVsvR3Lpu9kNzpV+9KPzqXwI
# lvUj1Y8qvRl/fvcNbVVhAyhPBJ/ViNh8KGtAwumHTPAef0627ZoVoSnDxMRG7MN7
# JxLX3cUYH+u3LNfY9u6SKneDRr8kDXf+NVBbKfPoNzeTLVXTfhAkS+XV3I0aZjMv
# QxP+1dC3gnqHEE2LnPns6E4v+QSJQuCTYoEnrann2izRNj08bcEyEyC7U7AFAmMv
# c0zPvwOcP4ZG7n+JV7TwiX5IXarScUYTJrownb0TYdqimRmWKkuKkXOowRPEKgoR
# nHjGYHeajmghCt2mv8BHP6KfC+b7U7PGF0FdwjUyMbqOJaEUJLdsfcH5ui3Hhlwg
# /fD2cFWJFqGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAyMDUxNzE0NDVaMC8G
# CSqGSIb3DQEJBDEiBCBIoQcCPGRZttP+4mkQYOSLxNLV+1iAW5jj+foG6BHYyTAN
# BgkqhkiG9w0BAQEFAASCAgBbuztCSIF1N1njCgY0gzGWYUXqML/vGOs3DqBVjsEE
# 2/D1OCce5ekOYxwHtE+m5RmWYgW05hX9ykW6tzVvHTLA+kE3q6mFFBiVuVS1qjSs
# l5QyexvTfClEkgCEyYs5+tP5yaIpzHueY8XZtEq9NTrtfLTmrjoDdQ9aGL4Dc0b2
# M8ch5x0CgRrEhGLF4sd1FtAfr/+swzrlR0NsBSC/Hedm+KBapVHDG0ztRNL9KG1w
# Yoz1rU3YPogCJk+R41/0SQbPu5uozCESZwie1vjQk0WZlVr32GnLUvryZfuloAv4
# VU/6mHZulYgynq10EegMZWhiUP3IRqKWDxf6C6wHW5W6H3ubO3bDXW2qB5UeTW7K
# +bDA55xAwrqoATBwhCyjdvGr8laQFvmKqd8YCDE8YgAHFXROLRRF06o8rnEE6F0x
# xnb39K1IcP8ppiTN1Gme69Z7PM+15x8GZPRm/Vs4WddiZ6nz8UmcailGDcHe52Xd
# SWhLGicJ4RtGk5tdUTaI30xHB5Aojp90sALEJsboVL0zf1sLIeXzjdiAD1YRYj8y
# E53c1JxHbMMFEMHNSn+BKOwa4i1ocJ2Q4gZjM4sZDufP/VkJRQWcivXH9fTuLcCF
# h2pQ38rC7IcGzxzX3ctGwSD8wry6lktX59BjgoS1VG+VLwZHPwHVNW12cpk5n087
# 4A==
# SIG # End signature block
