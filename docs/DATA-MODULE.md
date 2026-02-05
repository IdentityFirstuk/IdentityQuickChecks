# IdentityFirst Data Module

## Overview

The IdentityFirst Data Module provides comprehensive capabilities for:
- **Industry Benchmarks**: Pre-configured industry best practices and averages
- **Historical Tracking**: SQLite-based persistence for scan results
- **Trend Analysis**: Compare results over time
- **Compliance Scoring**: Calculate compliance scores against benchmarks

## Installation

The Data Module is included with IdentityFirst.QuickChecks. Import with:

```powershell
Import-Module IdentityFirst.QuickChecks
```

## Benchmark Data

### Categories Supported

| Category | Description |
|----------|-------------|
| `ActiveDirectory` | AD security benchmarks (passwords, Kerberos, LAPS, etc.) |
| `Entra` | Microsoft Entra ID benchmarks (MFA, Guest Access, PIM, etc.) |
| `AWS` | AWS IAM benchmarks (MFA, GuardDuty, CloudTrail, etc.) |
| `GCP` | GCP IAM benchmarks (Service Accounts, SCC, etc.) |
| `General` | General security benchmarks (Access Governance, Monitoring) |
| `Compliance` | Compliance framework benchmarks (NIST 800-53, CIS, etc.) |

### Using Benchmarks

```powershell
# Get all benchmarks
$benchmarks = Get-Benchmark

# Get benchmarks for a specific category
$adBenchmarks = Get-Benchmark -Category 'ActiveDirectory'

# Get a specific benchmark
$mfaBenchmark = Get-Benchmark -Category 'Entra' -CheckName 'GlobalAdminsMFA'
```

### Benchmark Structure

Each benchmark contains:
- **BestPractice**: Target value (100% compliance)
- **IndustryAverage**: Typical organization performance
- **CriticalThreshold**: Minimum acceptable level
- **Unit**: Unit of measurement (percent, boolean, days, etc.)
- **Description**: Brief explanation

## Comparison to Benchmarks

```powershell
# Get a benchmark
$benchmark = Get-Benchmark -Category 'Entra' -CheckName 'GlobalAdminsMFA'

# Compare actual value
$result = Compare-ToBenchmark -ActualValue 85 -Benchmark $benchmark

# Result properties:
# - Status: 'Compliant', 'IndustryStandard', 'NeedsImprovement', or 'Critical'
# - ComplianceScore: 0-100 score
# - GapFromBestPractice: Difference from best practice
```

## Compliance Scoring

```powershell
# Calculate overall compliance from check results
$compliance = Get-ComplianceScore -CheckResults $allResults

# Returns:
# - OverallScore: Weighted average score (0-100)
# - TotalChecks: Number of checks evaluated
# - Compliant, IndustryStandard, NeedsImprovement, Critical: Counts
# - CategoryBreakdown: Per-category scores
```

## Historical Tracking

### Database Setup

```powershell
# Start a database session
Start-QCDataSession -DbPath '.\data\QuickChecks.db'

# ... perform operations ...

# Always close the session
Stop-QCDataSession
```

### Saving Scan Results

```powershell
# After running QuickChecks, save results
$scanId = (New-Guid).Guid

Save-ScanResult -ScanId $scanId `
    -ScanType 'IdentityQuickChecks' `
    -Environment 'Production' `
    -OverallScore 85.5 `
    -TotalChecks 29 `
    -PassedChecks 25 `
    -FailedChecks 4 `
    -CheckResults $checkResults `
    -Duration '00:05:32'
```

### Retrieving History

```powershell
# Get recent scans
$scans = Get-ScanHistory -ScanType 'IdentityQuickChecks' -Limit 10

# Filter by environment
$prodScans = Get-ScanHistory -Environment 'Production' -Limit 10
```

## Trend Analysis

### Check-Specific Trends

```powershell
# Get trend for a specific check
$trend = Get-CheckTrend -CheckName 'GlobalAdminsMFA' -Category 'Entra' -Limit 12

# Returns weekly trend data with:
# - AvgScore: Average compliance score
# - MinScore, MaxScore: Range
# - AvgFindings: Average findings count
# - ScanCount: Number of scans in period
```

### Overall Compliance Trend

```powershell
# Get overall compliance trend
$trend = Get-ComplianceTrend -Environment 'Production' -Limit 26

# Returns weekly/monthly trend with:
# - AvgScore: Average overall score
# - PassRate: Percentage of passing checks
# - PeriodStart, PeriodEnd: Time period
```

### Comparing Scans

```powershell
# Compare current scan to previous
$comparison = Compare-ToPreviousScan -CurrentScanId $currentScanId

# Returns:
# - CurrentScan: Current scan metadata
# - PreviousScan: Previous scan metadata  
# - Comparison: Per-check comparison
# - ScoreChange: Difference in overall score
```

### Exporting Data

```powershell
# Export to JSON
Export-ScanHistory -Path '.\reports\history.json' -Format 'Json' -Limit 100

# Export to CSV
Export-ScanHistory -Path '.\reports\history.csv' -Format 'Csv' -Limit 100
```

## Example: Complete Workflow

```powershell
# 1. Start database session
Start-QCDataSession -DbPath '.\data\IdentityFirst.db'

# 2. Run QuickChecks
$results = Invoke-BreakGlassReality -OutputPath '.\Reports'

# 3. Save results
$scanId = (New-Guid).Guid
Save-ScanResult -ScanId $scanId `
    -ScanType 'IdentityQuickChecks' `
    -Environment 'Production' `
    -OverallScore 87.5 `
    -TotalChecks 1 `
    -PassedChecks 1 `
    -CheckResults $results

# 4. Check trends
$trend = Get-CheckTrend -CheckName 'BreakGlassAccounts' -Category 'Identity'

# 5. Close session
Stop-QCDataSession

# 6. Generate compliance report
$compliance = Get-ComplianceScore -CheckResults $results
Write-Host "Compliance Score: $($compliance.OverallScore)%"
```

## Database Schema

### Scans Table
- `ScanId`: Unique scan identifier
- `ScanType`: Type of scan performed
- `Environment`: Target environment
- `ExecutedBy`: User/system that ran scan
- `StartTime`, `EndTime`: Scan timestamps
- `OverallScore`: Compliance score (0-100)
- `TotalChecks`, `PassedChecks`, `FailedChecks`, `Warnings`: Statistics

### CheckResults Table
- `ScanId`: Foreign key to Scans
- `CheckName`: Name of the check
- `Category`: Check category
- `Status`: Pass/Fail/Warning
- `ActualValue`, `ExpectedValue`: Values compared
- `ComplianceScore`: Score for this check
- `BenchmarkStatus`: Comparison to benchmark
- `Findings`: JSON array of findings

## PowerShell Compatibility

- **Windows PowerShell 5.1**: Fully supported
- **PowerShell 7.0+**: Fully supported
- **Cross-Platform**: Same functionality on all platforms

## Requirements

- PowerShell 5.1 or later
- System.Data.SQLite (included with module)

## Support

For issues or questions, visit:
- GitHub: https://github.com/IdentityFirstuk/IdentityFirst-Free
- Documentation: https://identityfirst.security/docs
