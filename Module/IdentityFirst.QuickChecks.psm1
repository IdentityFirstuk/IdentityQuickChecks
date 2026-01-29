<#
    IdentityFirst QuickChecks Framework
    Shared utilities for structured identity posture checks
    
    Provides:
    - Context initialization
    - Safe script execution with logging
    - Structured finding creation
    - JSON/HTML report generation
#>

#Requires -Version 5.1

function New-IFQCContext {
    <#
    .SYNOPSIS
        Creates a new IFQC (IdentityFirst QuickCheck) context for a check run.
    
    .DESCRIPTION
        Initialises output directory, log file, and returns a context object
        used by all other IFQC functions.
    
    .OUTPUTS
        PSObject - Context object with ToolName, OutputDirectory, LogPath, Findings, etc.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ToolName,
        
        [Parameter()]
        [string]$ToolVersion = "1.0.0",
        
        [Parameter()]
        [string]$OutputDirectory = (Join-Path $PWD "IFQC-Output"),
        
        [Parameter()]
        [ValidateSet("Normal","Detailed")]
        [string]$DetailLevel = "Normal"
    )

    if (-not (Test-Path -LiteralPath $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    }

    $runStamp = (Get-Date).ToString("yyyyMMdd-HHmmss")
    $logPath  = Join-Path $OutputDirectory "$ToolName-$runStamp.log"

    $ctx = [PSCustomObject]@{
        ToolName        = $ToolName
        ToolVersion     = $ToolVersion
        OutputDirectory = $OutputDirectory
        RunStamp        = $runStamp
        LogPath         = $logPath
        DetailLevel     = $DetailLevel
        RunId           = [guid]::NewGuid().ToString()
        GeneratedAtUtc  = (Get-Date).ToUniversalTime().ToString("o")
        Findings        = [System.Collections.Generic.List[object]]::new()
        Notes           = [System.Collections.Generic.List[string]]::new()
        Data            = [ordered]@{}
    }

    Write-IFQCLog -Context $ctx -Level INFO -Message "Run started. Tool=$ToolName Version=$ToolVersion Output=$OutputDirectory"
    return $ctx
}

function Write-IFQCLog {
    <#
    .SYNOPSIS
        Writes a timestamped message to the IFQC log file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object]$Context,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("INFO","WARN","ERROR")]
        [string]$Level,
        
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[$ts] [$Level] $Message"
    $line | Out-File -FilePath $Context.LogPath -Append -Encoding utf8
}

function Invoke-IFQCSafe {
    <#
    .SYNOPSIS
        Executes a script block with error handling and logging.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object]$Context,
        
        [Parameter(Mandatory=$true)]
        [string]$Name,
        
        [Parameter(Mandatory=$true)]
        [scriptblock]$Block
    )
    
    try {
        Write-IFQCLog -Context $Context -Level INFO -Message "Starting: $Name"
        $result = & $Block
        Write-IFQCLog -Context $Context -Level INFO -Message "Completed: $Name"
        return $result
    }
    catch {
        Write-IFQCLog -Context $Context -Level ERROR -Message "Failed: $Name | $($_.Exception.Message)"
        return $null
    }
}

function New-IFQCFinding {
    <#
    .SYNOPSIS
        Creates a structured finding object for inclusion in reports.
    
    .DESCRIPTION
        Findings are the core output of IFQC checks. Each finding contains:
        - id: Unique identifier
        - title: Short descriptive title
        - severity: Low/Medium/High/Critical
        - description: Detailed explanation
        - count: Number of items found
        - evidence: Sample data (limited based on DetailLevel)
        - recommendation: Suggested remediation
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Id,
        
        [Parameter(Mandatory=$true)]
        [string]$Title,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("Low","Medium","High","Critical")]
        [string]$Severity,
        
        [Parameter(Mandatory=$true)]
        [string]$Description,
        
        [Parameter(Mandatory=$true)]
        [int]$Count,
        
        [Parameter()]
        [object[]]$Evidence = @(),
        
        [Parameter()]
        [string]$Recommendation = ""
    )
    
    [PSCustomObject]@{
        id             = $Id
        title          = $Title
        severity       = $Severity
        description    = $Description
        count          = $Count
        recommendation = $Recommendation
        evidence       = $Evidence
    }
}

function Add-IFQCFinding {
    <#
    .SYNOPSIS
        Adds a finding to the IFQC context.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object]$Context,
        
        [Parameter(Mandatory=$true)]
        [object]$Finding
    )
    
    $Context.Findings.Add($Finding) | Out-Null
}

function Add-IFQCNote {
    <#
    .SYNOPSIS
        Adds a note to the report (e.g., explaining limitations).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object]$Context,
        
        [Parameter(Mandatory=$true)]
        [string]$Note
    )
    
    $Context.Notes.Add($Note) | Out-Null
}

function Get-IFQCHostInfo {
    <#
    .SYNOPSIS
        Gets basic host/machine information for report metadata.
    #>
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    
    [PSCustomObject]@{
        computerName = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { "Unknown" }
        userName     = if ($env:USERNAME) { $env:USERNAME } else { "Unknown" }
        domain       = if ($env:USERDOMAIN) { $env:USERDOMAIN } else { "Unknown" }
        osCaption    = if ($os) { $os.Caption } else { "Unknown" }
        osVersion    = if ($os) { $os.Version } else { "Unknown" }
        manufacturer = if ($cs) { $cs.Manufacturer } else { "Unknown" }
        model        = if ($cs) { $cs.Model } else { "Unknown" }
        # Note: Host info included for audit purposes. Remove if not needed.
    }
}

function ConvertTo-IFQCSafeHtml {
    <#
    .SYNOPSIS
        Escapes special HTML characters for safe rendering.
    #>
    param([string]$Text)
    
    if ($null -eq $Text) { return "" }
    return ($Text -replace '&','&' -replace '<','<' -replace '>','>')
}

function Save-IFQCReport {
    <#
    .SYNOPSIS
        Generates JSON and HTML reports from the IFQC context.
    
    .DESCRIPTION
        Creates structured output files with:
        - Metadata (tool version, run info, host details)
        - Summary counts by severity
        - All findings with evidence
        - Notes about limitations
    
    .NOTES
        Security: Output files contain potentially sensitive identity data.
        Reports should be stored securely and deleted when no longer needed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [object]$Context,
        
        [Parameter()]
        [hashtable]$AdditionalMeta = @{}
    )

    # Calculate summary
    $summary = [ordered]@{
        totalFindings = $Context.Findings.Count
        critical      = ($Context.Findings | Where-Object severity -eq "Critical" | Measure-Object).Count
        high          = ($Context.Findings | Where-Object severity -eq "High"     | Measure-Object).Count
        medium        = ($Context.Findings | Where-Object severity -eq "Medium"   | Measure-Object).Count
        low           = ($Context.Findings | Where-Object severity -eq "Low"      | Measure-Object).Count
    }

    # Build metadata
    $meta = [ordered]@{
        toolName        = $Context.ToolName
        toolVersion     = $Context.ToolVersion
        runId           = $Context.RunId
        generatedAtUtc  = $Context.GeneratedAtUtc
        host            = (Get-IFQCHostInfo)
        detailLevel     = $Context.DetailLevel
    }

    foreach ($k in $AdditionalMeta.Keys) { $meta[$k] = $AdditionalMeta[$k] }

    # Build report object
    $report = [ordered]@{
        meta     = $meta
        summary  = $summary
        data     = $Context.Data
        findings = $Context.Findings
        notes    = $Context.Notes
    }

    # Paths
    $jsonPath = Join-Path $Context.OutputDirectory "$($Context.ToolName)-$($Context.RunStamp).json"
    $htmlPath = Join-Path $Context.OutputDirectory "$($Context.ToolName)-$($Context.RunStamp).html"

    # Write JSON
    ($report | ConvertTo-Json -Depth 10) | Out-File -FilePath $jsonPath -Encoding utf8

    # Apply restrictive ACLs to output files (owner only read/write)
    try {
        $acl = Get-Acl -Path $jsonPath
        $acl.SetAccessRuleProtection($true, $false)
        $acl.AddOwnerRule([System.Security.Principal.WindowsIdentity]::GetCurrent().Name, "Read,Write")
        Set-Acl -Path $jsonPath -AclObject $acl
        Set-Acl -Path $htmlPath -AclObject $acl
    } catch {
        Write-IFQCLog -Context $Context -Level WARN -Message "Could not set restrictive ACLs on output files: $($_.Exception.Message)"
    }

    # Generate HTML
    $findingsHtml = foreach ($f in $Context.Findings) {
        $sev   = ConvertTo-IFQCSafeHtml $f.severity
        $title = ConvertTo-IFQCSafeHtml $f.title
        $desc  = ConvertTo-IFQCSafeHtml $f.description
        $rec   = ConvertTo-IFQCSafeHtml $f.recommendation
        $count = [int]$f.count

        $evidenceBlock = ""
        if ($f.evidence -and $f.evidence.Count -gt 0) {
            $evJson = ($f.evidence | ConvertTo-Json -Depth 8)
            $evidenceBlock = "<details><summary>Evidence (sample)</summary><pre>$([System.Web.HttpUtility]::HtmlEncode($evJson))</pre></details>"
        }

@"
<section class='card sev-$sev'>
  <div class='row'>
    <div class='sev'>$sev</div>
    <div class='title'>$title</div>
    <div class='count'>Count: $count</div>
  </div>
  <p class='desc'>$desc</p>
  <p class='rec'><strong>Recommendation:</strong> $rec</p>
  $evidenceBlock
</section>
"@
    }

    $notesHtml = ($Context.Notes | ForEach-Object { "<li>$([System.Web.HttpUtility]::HtmlEncode($_))</li>" }) -join "`n"

    $html = @"
<!doctype html>
<html lang="en-GB">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>$($Context.ToolName)</title>
<style>
  body { font-family: Arial, Helvetica, sans-serif; margin: 24px; background: #f6f7f9; }
  .header { background: #fff; border-radius: 12px; padding: 16px 18px; box-shadow: 0 2px 10px rgba(0,0,0,.06); }
  .grid { display: grid; grid-template-columns: repeat(4, minmax(120px, 1fr)); gap: 12px; margin-top: 12px; }
  .pill { background: #fff; border-radius: 12px; padding: 12px; box-shadow: 0 2px 10px rgba(0,0,0,.06); }
  .pill .n { font-size: 22px; font-weight: 700; }
  .pill .l { font-size: 12px; opacity: .75; }
  .card { background: #fff; border-radius: 12px; padding: 14px 16px; margin: 12px 0; box-shadow: 0 2px 10px rgba(0,0,0,.06); border-left: 6px solid #999; }
  .row { display: flex; gap: 12px; align-items: baseline; flex-wrap: wrap; }
  .sev { font-weight: 700; }
  .title { font-size: 16px; font-weight: 700; flex: 1; }
  .count { font-size: 12px; opacity: .75; }
  .desc, .rec { margin: 10px 0; }
  details { margin-top: 8px; }
  pre { overflow: auto; background: #0f172a; color: #e2e8f0; padding: 10px; border-radius: 10px; font-size: 12px; }
  .sev-Critical { border-left-color: #7f1d1d; }
  .sev-High     { border-left-color: #b45309; }
  .sev-Medium   { border-left-color: #1d4ed8; }
  .sev-Low      { border-left-color: #166534; }
</style>
</head>
<body>

<div class="header">
  <h1 style="margin:0 0 6px 0;">$($Context.ToolName)</h1>
  <div style="opacity:.8; font-size: 13px;">
    Generated (UTC): $($Context.GeneratedAtUtc)<br/>
    Run ID: $($Context.RunId)
  </div>

  <div class="grid">
    <div class="pill"><div class="n">$($summary.totalFindings)</div><div class="l">Total findings</div></div>
    <div class="pill"><div class="n">$($summary.critical)</div><div class="l">Critical</div></div>
    <div class="pill"><div class="n">$($summary.high)</div><div class="l">High</div></div>
    <div class="pill"><div class="n">$($summary.medium)</div><div class="l">Medium</div></div>
  </div>

  <h3 style="margin:16px 0 6px 0;">What this does not do</h3>
  <ul style="margin:0; padding-left: 18px;">
    $notesHtml
  </ul>
</div>

<h2 style="margin-top:18px;">Findings</h2>
$($findingsHtml -join "`n")

<p style="margin-top: 18px; opacity:.8; font-size: 12px;">
  Snapshot only. Full correlation, ownership, compliance mapping and continuous control belongs in IdentityHealthCheck / IdentityFirst.
</p>

<div style="background: linear-gradient(135deg, #1a73e8 0%, #0d47a1 100%); color: white; padding: 20px; border-radius: 12px; margin-top: 30px; text-align: center;">
  <h3 style="margin: 0 0 10px 0;">Ready for Full Identity Governance?</h3>
  <p style="margin: 0 0 15px 0; opacity: 0.9;">
    These free scripts show what exists. <strong>IdentityHealthCheck</strong> explains what it means.
  </p>
  <a href="https://www.identityfirst.net" style="display: inline-block; background: white; color: #1a73e8; padding: 12px 30px; border-radius: 6px; text-decoration: none; font-weight: 600;">
    Upgrade to IdentityHealthCheck
  </a>
</div>

</body>
</html>
"@

    $html | Out-File -FilePath $htmlPath -Encoding utf8

    Write-IFQCLog -Context $Context -Level INFO -Message "Reports written. JSON=$jsonPath HTML=$htmlPath"
    
    [PSCustomObject]@{
        Json = $jsonPath
        Html = $htmlPath
        Log  = $Context.LogPath
    }
}

# Export all functions
Export-ModuleMember -Function *-IFQC*
