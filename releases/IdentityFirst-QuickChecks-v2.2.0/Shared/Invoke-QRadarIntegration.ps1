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

function Invoke-QRadarIntegration {
<#
.SYNOPSIS
    Sends QuickChecks findings to IBM QRadar via Syslog.

.DESCRIPTION
    Formats and transmits identity security findings to QRadar using
    Syslog protocol (LEEF or CEF format).

.PARAMETER Findings
    Array of finding objects from QuickChecks.

.PARAMETER SyslogServer
    QRadar Syslog server hostname or IP.

.PARAMETER SyslogPort
    QRadar Syslog port (default: 514).

.PARAMETER Protocol
    Transport protocol (TCP or UDP).

.PARAMETER Format
    Log format (LEEF or CEF).

.EXAMPLE
    Invoke-QRadarIntegration -Findings $results -SyslogServer "qradar.company.com" -Format "LEEF"
#>
    param(
        [Parameter(Mandatory)]
        [array]$Findings,
        
        [Parameter(Mandatory)]
        [string]$SyslogServer,
        
        [int]$SyslogPort = 514,
        
        [ValidateSet("TCP", "UDP")]
        [string]$Protocol = "UDP",
        
        [ValidateSet("LEEF", "CEF")]
        [string]$Format = "LEEF"
    )
    
    $ErrorActionPreference = "Stop"
    
    Write-Host "[QRADAR] Starting QRadar integration..." -ForegroundColor Cyan
    
    try {
        $eventsSent = 0
        $errors = @()
        
        foreach ($finding in $Findings) {
            try {
                $syslogMessage = switch ($Format) {
                    "LEEF" {
                        New-LEEFMessage -Finding $finding
                    }
                    "CEF" {
                        New-CEFMessage -Finding $finding
                    }
                }
                
                Send-SyslogMessage -Server $SyslogServer -Port $SyslogPort -Message $syslogMessage -Protocol $Protocol
                $eventsSent++
            }
            catch {
                $errors += "Failed to send $($finding.CheckId): $($_.Exception.Message)"
            }
        }
        
        Write-Host "[QRADAR] Integration complete. Events sent: $eventsSent" -ForegroundColor $(if ($errors.Count -eq 0) { "Green" } else { "Yellow" })
        
        if ($errors.Count -gt 0) {
            Write-Warning "[QRADAR] $($errors.Count) errors occurred"
        }
        
        return @{
            EventsSent = $eventsSent
            Errors = $errors.Count
        }
    }
    catch {
        Write-Error "[QRADAR] Integration failed: $($_.Exception.Message)"
        throw
    }
}

function New-LEEFMessage {
<#
.SYNOPSIS
    Creates a LEEF (Log Event Extended Format) message from a finding.
#>
    param(
        [Parameter(Mandatory)]
        [hashtable]$Finding
    )
    
    $timestamp = (Get-Date -Format "yyyy-MM-dd'T'HH:mm:ss.fffK")
    
    $sevMap = @{
        "Critical" = 10
        "High" = 8
        "Medium" = 6
        "Low" = 4
        "Informational" = 0
    }
    
    $severity = $sevMap[$Finding.Severity] ?? 6
    
    $leef = "LEEF:2.0|IdentityFirst|QuickChecks|1.0|$severity|EVENT"
    $leef += "`tSeverity=$($Finding.Severity)"
    $leef += "`tCheckId=$($Finding.CheckId)"
    $leef += "`tCheckName=$($Finding.CheckName)"
    $leef += "`tTimestamp=$timestamp"
    
    if ($Finding.UserId) {
        $leef += "`tUserId=$($Finding.UserId)"
    }
    if ($Finding.FindingDetails) {
        $details = $Finding.FindingDetails -replace "`t", " " -replace "`n", " "
        $leef += "`tFindingDetails=$details"
    }
    
    return $leef
}

function New-CEFMessage {
<#
.SYNOPSIS
    Creates a CEF (Common Event Format) message from a finding.
#>
    param(
        [Parameter(Mandatory)]
        [hashtable]$Finding
    )
    
    $timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss.fffK")
    
    $sevMap = @{
        "Critical" = 10
        "High" = 7
        "Medium" = 5
        "Low" = 3
        "Informational" = 0
    }
    
    $severity = $sevMap[$Finding.Severity] ?? 5
    
    $cef = "CEF:0|IdentityFirst|QuickChecks|1.0|$severity|$($Finding.CheckName)|$($Finding.Severity)"
    $cef += " dhost=$($env:COMPUTERNAME)"
    $cef += " dtime=$timestamp"
    
    $ext = "checkId=$($Finding.CheckId)"
    $ext += " severity=$($Finding.Severity)"
    
    if ($Finding.UserId) {
        $ext += " userId=$($Finding.UserId)"
    }
    
    return "$cef $ext"
}

function Send-SyslogMessage {
<#
.SYNOPSIS
    Sends a Syslog message to a remote server.
#>
    param(
        [Parameter(Mandatory)]
        [string]$Server,
        
        [int]$Port = 514,
        
        [Parameter(Mandatory)]
        [string]$Message,
        
        [ValidateSet("TCP", "UDP")]
        [string]$Protocol = "UDP"
    )
    
    try {
        $endpoint = New-Object System.Net.IPEndPoint([System.Net.Dns]::GetHostAddresses($Server), $Port)
        $socket = New-Object System.Net.Sockets.Socket($Protocol.ToUpper(), "Datagram", "ProtocolType")
        
        $byteMessage = [System.Text.Encoding]::ASCII.GetBytes($Message)
        
        if ($Protocol -eq "TCP") {
            $socket = New-Object System.Net.Sockets.Socket($Protocol.ToUpper(), "Stream", "ProtocolType")
            $socket.Connect($endpoint)
            $socket.Send($byteMessage) | Out-Null
            $socket.Close()
        }
        else {
            $socket.SendTo($byteMessage, $endpoint) | Out-Null
            $socket.Close()
        }
    }
    catch {
        throw "Failed to send Syslog message: $($_.Exception.Message)"
    }
}

Export-ModuleMember -Function @(
    'Invoke-QRadarIntegration',
    'New-LEEFMessage',
    'New-CEFMessage',
    'Send-SyslogMessage'
) -ErrorAction SilentlyContinue
