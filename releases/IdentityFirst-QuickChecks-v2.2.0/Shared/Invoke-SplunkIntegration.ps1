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

function Invoke-SplunkIntegration {
<#
.SYNOPSIS
    Sends QuickChecks findings to Splunk via HTTP Event Collector (HEC).

.DESCRIPTION
    Formats and transmits identity security findings to Splunk for
    centralized logging and analysis.

.PARAMETER Findings
    Array of finding objects from QuickChecks.

.PARAMETER HecEndpoint
    Splunk HEC endpoint URL.

.PARAMETER HecToken
    Splunk HEC authentication token.

.PARAMETER SourceType
    Splunk source type for the events.

.EXAMPLE
    Invoke-SplunkIntegration -Findings $results -HecEndpoint "https://splunk.company.com:8088/services/collector" -HecToken "xxx"
#>
    param(
        [Parameter(Mandatory)]
        [array]$Findings,
        
        [Parameter(Mandatory)]
        [string]$HecEndpoint,
        
        [Parameter(Mandatory)]
        [string]$HecToken,
        
        [string]$SourceType = "identityfirst_quickchecks",
        
        [string]$Index = "identity"
    )
    
    $ErrorActionPreference = "Stop"
    
    Write-Host "[SPLUNK] Starting Splunk integration..." -ForegroundColor Cyan
    
    try {
        $headers = @{
            "Authorization" = "Splunk $HecToken"
            "Content-Type" = "application/json"
        }
        
        $eventsSent = 0
        $errors = @()
        
        foreach ($finding in $Findings) {
            $event = @{
                time = [Math]::Floor((Get-Date -UFormat %s))
                host = $env:COMPUTERNAME
                source = $SourceType
                sourcetype = $SourceType
                index = $Index
                event = $finding
            }
            
            $jsonPayload = $event | ConvertTo-Json -Compress
            
            try {
                $response = Invoke-RestMethod -Uri $HecEndpoint -Method Post -Headers $headers -Body $jsonPayload
                
                if ($response.code -eq 0) {
                    $eventsSent++
                }
                else {
                    $errors += "Error for $($finding.CheckId): $($response.message)"
                }
            }
            catch {
                $errors += "Failed to send $($finding.CheckId): $($_.Exception.Message)"
            }
        }
        
        # Send summary event
        $summary = @{
            CheckType = "IdentityFirstQuickChecks"
            Timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
            TotalFindings = $Findings.Count
            EventsSent = $eventsSent
            Summary = @{
                Critical = ($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
                High = ($Findings | Where-Object { $_.Severity -eq "High" }).Count
                Medium = ($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
                Low = ($Findings | Where-Object { $_.Severity -eq "Low" }).Count
            }
        }
        
        $summaryEvent = @{
            time = [Math]::Floor((Get-Date -UFormat %s))
            host = $env:COMPUTERNAME
            source = $SourceType
            sourcetype = $SourceType
            index = $Index
            event = $summary
        }
        
        $summaryJson = $summaryEvent | ConvertTo-Json -Compress
        Invoke-RestMethod -Uri $HecEndpoint -Method Post -Headers $headers -Body $summaryJson | Out-Null
        
        Write-Host "[SPLUNK] Integration complete. Events sent: $eventsSent" -ForegroundColor $(if ($errors.Count -eq 0) { "Green" } else { "Yellow" })
        
        if ($errors.Count -gt 0) {
            Write-Warning "[SPLUNK] $($errors.Count) errors occurred:"
            $errors | ForEach-Object { Write-Warning "  $_" }
        }
        
        return @{
            EventsSent = $eventsSent + 1
            Errors = $errors.Count
        }
    }
    catch {
        Write-Error "[SPLUNK] Integration failed: $($_.Exception.Message)"
        throw
    }
}

function New-SplunkSearchQuery {
<#
.SYNOPSIS
    Generates Splunk SPL queries for QuickChecks findings.

.DESCRIPTION
    Creates ready-to-use Splunk search queries for investigating
    identity security findings.

.EXAMPLE
    New-SplunkSearchQuery -CheckId "OKTA-USER-001"
#>
    param(
        [string]$CheckId,
        [string]$Severity,
        [int]$LastDays = 7
    )
    
    $baseQuery = "index=identity source=""identityfirst_quickchecks"""
    
    if ($CheckId) {
        $baseQuery += " CheckId=""$CheckId"""
    }
    
    if ($Severity) {
        $baseQuery += " Severity=""$Severity"""
    }
    
    $queries = @{
        AllFindings = "$baseQuery | sort -Timestamp"
        CriticalFindings = "$baseQuery Severity=""Critical"" | table CheckId, Severity, UserId, FindingDetails | head 100"
        FindingsByCheck = "$baseQuery | stats count by CheckId | sort -count"
        RiskTrend = "$baseQuery | timechart count by Severity"
        TopUsers = "$baseQuery | stats count by UserId | sort -count | head 20"
    }
    
    return $queries
}

Export-ModuleMember -Function @(
    'Invoke-SplunkIntegration',
    'New-SplunkSearchQuery'
) -ErrorAction SilentlyContinue
