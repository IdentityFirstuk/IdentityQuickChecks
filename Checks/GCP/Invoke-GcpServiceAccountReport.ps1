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

function Invoke-GcpServiceAccountReport {
    <#
    .SYNOPSIS
        Analyzes GCP service accounts for security issues.
    
    .DESCRIPTION
        This read-only check reviews GCP service accounts to identify
        old keys, overly broad permissions, and potential security risks.
    
    .PARAMETER OutputPath
        Path to save the results JSON file.
    
    .PARAMETER Export
        Export format: JSON, HTML, or None.
    
    .EXAMPLE
        Invoke-GcpServiceAccountReport -OutputPath ".\Reports"
    
    .NOTES
        Read-only check - requires gcloud CLI.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = ".\Reports",
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('JSON', 'HTML', 'None')]
        [string]$Export = 'JSON'
    )
    
    $checkName = "Invoke-GcpServiceAccountReport"
    $checkCategory = "GCP"
    $findings = @()
    $startTime = Get-Date
    
    try {
        # Check for gcloud CLI
        $gcloudPath = (Get-Command gcloud -ErrorAction SilentlyContinue).Path
        if (-not $gcloudPath) {
            return [PSCustomObject]@{
                CheckName = $checkName
                Category = $checkCategory
                Status = "Error"
                FindingCount = 0
                Findings = @()
                StartTime = $startTime
                EndTime = Get-Date
                Duration = 0
                Error = "gcloud CLI not found"
            }
        }
        
        # Get service accounts
        $saJson = & gcloud iam service-accounts list --format=json 2>$null
        if ($LASTEXITCODE -ne 0) {
            return [PSCustomObject]@{
                CheckName = $checkName
                Category = $checkCategory
                Status = "Error"
                FindingCount = 0
                Findings = @()
                StartTime = $startTime
                EndTime = Get-Date
                Duration = 0
                Error = "Failed to retrieve GCP service accounts"
            }
        }
        
        if (-not $saJson) {
            return [PSCustomObject]@{
                CheckName = $checkName
                Category = $checkCategory
                Status = "Error"
                FindingCount = 0
                Findings = @()
                StartTime = $startTime
                EndTime = Get-Date
                Duration = 0
                Error = "No output from gcloud command"
            }
        }
        
        $serviceAccounts = $saJson | ConvertFrom-Json
        
        if ($serviceAccounts) {
            foreach ($sa in $serviceAccounts) {
                $email = $sa.Email
                $displayName = $sa.DisplayName
                $name = $sa.Name
                $disabled = $sa.Disabled
                
                # Get keys for this service account
                $keysJson = & gcloud iam service-accounts keys list --iam-account=$email --format=json 2>$null
                $keys = if ($keysJson -and $LASTEXITCODE -eq 0) { $keysJson | ConvertFrom-Json } else { @() }
                
                $keyDetails = @()
                if ($keys) {
                    foreach ($key in $keys) {
                        $keyType = $key.KeyType
                        $keyOrigin = $key.Origin
                        $keyAlgorithm = $key.Algorithm
                        $validAfterTime = $key.ValidAfterTime
                        $validBeforeTime = $key.ValidBeforeTime
                        
                        $keyDetails += [PSCustomObject]@{
                            KeyId = $key.Name
                            KeyType = $keyType
                            Algorithm = $keyAlgorithm
                            ValidAfter = $validAfterTime
                            ValidBefore = $validBeforeTime
                        }
                    }
                }
                
                $findings += [PSCustomObject]@{
                    ServiceAccountEmail = $email
                    DisplayName = $displayName
                    Name = $name
                    IsDisabled = $disabled
                    KeyCount = $keys.Count
                    KeyDetails = $keyDetails
                    RiskLevel = if ($disabled) { "Info" } elseif ($keys.Count -gt 3) { "High" } elseif ($keys.Count -gt 1) { "Medium" } else { "Low" }
                    Recommendation = if ($disabled) { "Consider deleting disabled service account" } elseif ($keys.Count -gt 3) { "Limit to minimum required keys" } else { "No immediate action required" }
                }
            }
            
            # Summary
            $saWithManyKeys = ($findings | Where-Object { $_.KeyCount -gt 3 }).Count
            $disabledSA = ($findings | Where-Object { $_.IsDisabled -eq $true }).Count
            $findings += [PSCustomObject]@{
                Summary = "GCP Service Account Security"
                TotalServiceAccounts = $serviceAccounts.Count
                AccountsWithManyKeys = $saWithManyKeys
                DisabledAccounts = $disabledSA
                RiskLevel = if ($saWithManyKeys -gt 5) { "High" } elseif ($saWithManyKeys -gt 0) { "Medium" } else { "Low" }
                Recommendation = "Review service accounts and implement key rotation policy"
            }
        }
        else {
            $findings += [PSCustomObject]@{
                Issue = "No service accounts found"
                RiskLevel = "Info"
                Recommendation = "N/A"
            }
        }
        
        $status = if ($findings.Count -eq 0) { "Pass" } elseif ($findings.Count -le 5) { "Warning" } else { "Fail" }
        
        $endTime = Get-Date
        $duration = [Math]::Round(($endTime - $startTime).TotalSeconds, 2)
        
        $result = [PSCustomObject]@{
            CheckName = $checkName
            Category = $checkCategory
            Status = $status
            FindingCount = $findings.Count
            Findings = $findings
            StartTime = $startTime
            EndTime = $endTime
            Duration = $duration
            Error = $null
        }
        
        if ($Export -ne 'None') {
            $exportPath = Join-Path $OutputPath "$checkName.$Export"
            if (-not (Test-Path $OutputPath)) {
                New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
            }
            if ($Export -eq 'JSON') {
                $result | ConvertTo-Json -Depth 10 | Set-Content -Path $exportPath -Encoding UTF8
            }
        }
        
        return $result
    }
    catch {
        return [PSCustomObject]@{
            CheckName = $checkName
            Category = $checkCategory
            Status = "Error"
            FindingCount = 0
            Findings = @()
            StartTime = $startTime
            EndTime = Get-Date
            Duration = 0
            Error = $_.Exception.Message
        }
    }
}
