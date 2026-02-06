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

function Invoke-SentinelIntegration {
<#
.SYNOPSIS
    Sends QuickChecks findings to Azure Sentinel (Microsoft Sentinel).

.DESCRIPTION
    Formats and transmits identity security findings to Azure Sentinel
    Log Analytics workspace for centralized security monitoring.

.PARAMETER Findings
    Array of finding objects from QuickChecks.

.PARAMETER WorkspaceId
    Azure Log Analytics Workspace ID.

.PARAMETER WorkspaceKey
    Azure Log Analytics Workspace Primary or Secondary Key.

.PARAMETER CustomLogName
    Custom log table name (e.g., "IdentityFirst_QuickChecks_CL").

.EXAMPLE
    Invoke-SentinelIntegration -Findings $results -WorkspaceId "xxx" -WorkspaceKey "xxx"
#>
    param(
        [Parameter(Mandatory)]
        [array]$Findings,
        
        [Parameter(Mandatory)]
        [string]$WorkspaceId,
        
        [Parameter(Mandatory)]
        [string]$WorkspaceKey,
        
        [string]$CustomLogName = "IdentityFirst_QuickChecks_CL"
    )
    
    $ErrorActionPreference = "Stop"
    
    Write-Host "[SENTINEL] Starting Azure Sentinel integration..." -ForegroundColor Cyan
    
    try {
        $customerId = $WorkspaceId
        $sharedKey = $WorkspaceKey
        
        # Build the API signature
        $method = "POST"
        $contentType = "application/json"
        $resource = "/api/logs"
        $rfc1123date = [DateTime]::UtcNow.ToString("r")
        $body = $Findings | ConvertTo-Json -Depth 10
        
        # Calculate hash
        $xHeaders = "x-ms-date:" + $rfc1123date
        $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
        $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
        $keyBytes = [Convert]::FromBase64String($sharedKey)
        $sha256 = New-Object System.Security.Cryptography.HMACSHA256
        $sha256.Key = $keyBytes
        $calculatedHash = $sha256.ComputeHash($bytesToHash)
        $signature = [Convert]::ToBase64String($calculatedHash)
        
        $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
        
        $headers = @{
            "Authorization" = "SharedKey " + $customerId + ":" + $signature
            "Content-Type" = "application/json"
            "x-ms-date" = $rfc1123date
            "Log-Type" = $CustomLogName
        }
        
        # Send data in batches (max 1000 records per request)
        $batchSize = 1000
        $batches = @()
        for ($i = 0; $i -lt $Findings.Count; $i += $batchSize) {
            $batch = $Findings[$i..[Math]::Min($i + $batchSize - 1, $Findings.Count - 1)]
            $batches += $batch
        }
        
        $eventsSent = 0
        foreach ($batch in $batches) {
            $jsonBody = $batch | ConvertTo-Json -Depth 10
            $contentLength = $jsonBody.Length
            
            # Recalculate signature for each batch
            $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
            $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
            $sha256 = New-Object System.Security.Cryptography.HMACSHA256
            $sha256.Key = $keyBytes
            $calculatedHash = $sha256.ComputeHash($bytesToHash)
            $signature = [Convert]::ToBase64String($calculatedHash)
            
            $headers["Authorization"] = "SharedKey " + $customerId + ":" + $signature
            
            try {
                $response = Invoke-WebRequest -Uri $uri -Method $method -Headers $headers -Body $jsonBody -UseBasicParsing
                $eventsSent += $batch.Count
            }
            catch {
                Write-Error "[SENTINEL] Failed to send batch: $($_.Exception.Message)"
            }
        }
        
        Write-Host "[SENTINEL] Integration complete. Events sent: $eventsSent" -ForegroundColor Green
        
        return @{
            EventsSent = $eventsSent
            Batches = $batches.Count
        }
    }
    catch {
        Write-Error "[SENTINEL] Integration failed: $($_.Exception.Message)"
        throw
    }
}

function New-SentinelAnalyticsRule {
<#
.SYNOPSIS
    Creates Sentinel Analytics Rule for identity findings.

.DESCRIPTION
    Generates KQL-based analytics rule for detecting high-risk identity
    security patterns.

.EXAMPLE
    New-SentinelAnalyticsRule -RuleName "High Risk Identity Findings"
#>
    param(
        [string]$RuleName = "IdentityFirst High Risk Findings",
        [string]$CustomLogName = "IdentityFirst_QuickChecks_CL"
    )
    
    $kqlQuery = @"
$CustomLogName
| where Severity in ("Critical", "High")
| project TimeGenerated, CheckId, Severity, UserId, FindingDetails, RiskScore
| sort by TimeGenerated desc
"@
    
    $ruleTemplate = @{
        displayName = $RuleName
        description = "Detects high-risk identity findings from IdentityFirst QuickChecks"
        severity = "High"
        enabled = $true
        query = $kqlQuery
        queryFrequency = "1d"
        queryPeriod = "7d"
        triggerOperator = "GreaterThan"
        triggerThreshold = 0
        tactics = @("PrivilegeEscalation", "CredentialAccess")
        techniques = @("T1078", "T1110")
    }
    
    return $ruleTemplate
}

Export-ModuleMember -Function @(
    'Invoke-SentinelIntegration',
    'New-SentinelAnalyticsRule'
) -ErrorAction SilentlyContinue
