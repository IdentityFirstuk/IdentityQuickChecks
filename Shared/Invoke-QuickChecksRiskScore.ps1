# ============================================================================
# ATTRIBUTION
# ============================================================================
# Author: Mark Ahearne
# Email: mark.ahearne@identityfirst.net
# Company: IdentityFirst Ltd
#
# This script is provided by IdentityFirst Ltd for identity security assessment.
# All rights reserved.
#
# License: See EULA.txt for license terms.
# ============================================================================

function Invoke-QuickChecksRiskScore {
<#
.SYNOPSIS
    Calculates organizational risk score from QuickChecks findings.

.DESCRIPTION
    Aggregates finding severity and count to calculate a comprehensive
    risk score (0-100) with historical trending support.

.EXAMPLE
    Invoke-QuickChecksRiskScore -Findings $allCheckResults

.EXAMPLE
    Invoke-QuickChecksRiskScore -Findings $results -IncludeTrending
#>
    param(
        [Parameter(Mandatory)]
        [array]$Findings,
        
        [string]$HistoryPath = ".\QuickChecks-History",
        
        [switch]$IncludeTrending,
        
        [switch]$Detailed
    )
    
    $ErrorActionPreference = "Stop"
    
    $severityWeights = @{
        "Critical" = 100
        "High" = 75
        "Medium" = 50
        "Low" = 25
        "Informational" = 0
    }
    
    $riskLevels = @(
        @{ Level = "CRITICAL"; MinScore = 80; Color = "Red" },
        @{ Level = "HIGH"; MinScore = 60; Color = "DarkRed" },
        @{ Level = "MEDIUM"; MinScore = 40; Color = "Yellow" },
        @{ Level = "LOW"; MinScore = 20; Color = "Green" },
        @{ Level = "MINIMAL"; MinScore = 0; Color = "DarkGreen" }
    )
    
    Write-Host "[RISK-SCORE] Calculating organizational risk score..." -ForegroundColor Cyan
    
    try {
        $severityCounts = @{
            Critical = 0
            High = 0
            Medium = 0
            Low = 0
            Informational = 0
        }
        
        $checkBreakdown = @{}
        $totalFindings = 0
        $weightedScoreSum = 0
        $maxPossibleScore = 0
        
        foreach ($checkResult in $Findings) {
            $checkId = $checkResult.CheckId
            $checkFindings = @()
            
            if ($checkResult.Findings) {
                $checkFindings = $checkResult.Findings
            }
            elseif ($checkResult.IndividualResults) {
                $tempFindings = $checkResult.IndividualResults | Where-Object { $_.Findings }
                $checkFindings = $tempFindings.Findings
            }
            
            $checkBreakdown[$checkId] = @{
                Total = 0
                Critical = 0
                High = 0
                Medium = 0
                Low = 0
                Score = 0
            }
            
            foreach ($finding in $checkFindings) {
                $severity = $finding.Severity ?? $finding.RiskLevel ?? "Medium"
                if (-not $severityWeights.ContainsKey($severity)) {
                    $severity = "Medium"
                }
                
                $severityCounts[$severity]++
                $totalFindings++
                $weightedScoreSum += $severityWeights[$severity]
                $maxPossibleScore += 100
                
                $checkBreakdown[$checkId].Total++
                $checkBreakdown[$checkId].$severity++
            }
        }
        
        $baseScore = 0
        if ($maxPossibleScore -gt 0) {
            $baseScore = [math]::Round(($weightedScoreSum / $maxPossibleScore) * 100)
        }
        
        $criticalMultiplier = 1 + ($severityCounts["Critical"] * 0.1)
        $highMultiplier = 1 + ($severityCounts["High"] * 0.05)
        
        $adjustedScore = [math]::Min(100, [math]::Round($baseScore * $criticalMultiplier * $highMultiplier))
        
        $riskLevel = $null
        foreach ($level in $riskLevels) {
            if ($adjustedScore -ge $level.MinScore) {
                $riskLevel = $level
                break
            }
        }
        
        $trendData = $null
        if ($IncludeTrending -and $HistoryPath) {
            $trendData = Get-RiskTrend -HistoryPath $HistoryPath -CurrentScore $adjustedScore
        }
        
        $recommendations = @()
        
        if ($severityCounts["Critical"] -gt 0) {
            $recommendations += @{
                Priority = "CRITICAL"
                Category = "Critical Findings"
                Action = "Immediate remediation required for $($severityCounts['Critical']) critical finding(s)"
            }
        }
        
        if ($severityCounts["High"] -gt 0) {
            $recommendations += @{
                Priority = "HIGH"
                Category = "High Severity"
                Action = "Review $($severityCounts['High']) high-severity findings within 7 days"
            }
        }
        
        if ($severityCounts["Medium"] -gt 0) {
            $recommendations += @{
                Priority = "MEDIUM"
                Category = "Medium Severity"
                Action = "Plan remediation for $($severityCounts['Medium']) medium-severity findings"
            }
        }
        
        $result = @{
            Timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            Score = $adjustedScore
            BaseScore = $baseScore
            Level = $riskLevel.Level
            Color = $riskLevel.Color
            TotalFindings = $totalFindings
            SeverityBreakdown = $severityCounts
            CheckBreakdown = $checkBreakdown
            Recommendations = $recommendations
            Trend = $trendData
        }
        
        if ($HistoryPath -and (Test-Path $HistoryPath)) {
            Save-RiskHistory -HistoryPath $HistoryPath -ScoreData $result
        }
        
        Write-Host "[RISK-SCORE] Score: $adjustedScore/100" -ForegroundColor $riskLevel.Color
        Write-Host "[RISK-SCORE] Level: $($riskLevel.Level)" -ForegroundColor $riskLevel.Color
        
        return $result
    }
    catch {
        Write-Error "[RISK-SCORE] Error: $($_.Exception.Message)"
        throw
    }
}

function Get-RiskTrend {
    param(
        [string]$HistoryPath,
        [int]$CurrentScore
    )
    
    try {
        $historyFile = Join-Path $HistoryPath "risk-history.json"
        
        $history = @()
        if (Test-Path $historyFile) {
            $history = @((Get-Content -Path $historyFile -Raw | ConvertFrom-Json))
        }
        
        $history += @{
            Timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            Score = $CurrentScore
        }
        
        $history = $history | Sort-Object Timestamp | Select-Object -Last 30
        
        $trend = "STABLE"
        $change = 0
        
        if ($history.Count -ge 2) {
            $recentScores = ($history | Select-Object -Last 5).Score
            $olderScores = ($history | Select-Object -First 5).Score
            
            $recentAvg = ($recentScores | Measure-Object -Average).Average
            $olderAvg = ($olderScores | Measure-Object -Average).Average
            
            $change = [math]::Round($recentAvg - $olderAvg)
            
            if ($change -gt 5) { $trend = "WORSENING" }
            elseif ($change -lt -5) { $trend = "IMPROVING" }
        }
        
        return @{
            History = $history
            Trend = $trend
            Change = $change
        }
    }
    catch {
        return $null
    }
}

function Save-RiskHistory {
    param(
        [string]$HistoryPath,
        [hashtable]$ScoreData
    )
    
    try {
        if (-not (Test-Path $HistoryPath)) {
            New-Item -ItemType Directory -Path $HistoryPath -Force | Out-Null
        }
        
        $historyFile = Join-Path $HistoryPath "risk-history.json"
        
        $existingHistory = @()
        if (Test-Path $historyFile) {
            $existingHistory = @((Get-Content -Path $historyFile -Raw | ConvertFrom-Json))
        }
        
        $existingHistory += @{
            Timestamp = $ScoreData.Timestamp
            Score = $ScoreData.Score
            Level = $ScoreData.Level
            TotalFindings = $ScoreData.TotalFindings
        }
        
        $existingHistory = $existingHistory | Sort-Object Timestamp | Select-Object -Last 100
        $existingHistory | ConvertTo-Json | Set-Content -Path $historyFile -Encoding UTF8
    }
    catch {
        Write-Warning "[RISK-SCORE] Could not save history"
    }
}

Export-ModuleMember -Function @(
    'Invoke-QuickChecksRiskScore',
    'Get-RiskTrend',
    'Save-RiskHistory'
) -ErrorAction SilentlyContinue
