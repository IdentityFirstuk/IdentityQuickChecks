<#
.SYNOPSIS
  Simple read-only runner and HTML report index generator for IdentityFirst QuickChecks

.DESCRIPTION
  Invokes the IdentityHealthCheck in enforced read-only mode, collects generated HTML reports
  and builds a simple `index.html` that links to them. If no HTML reports are present it
  will list JSON artifacts instead.

.NOTES
  - This runner enforces read-only by setting `IFQC_READONLY=1` in the process environment.
  - It does not modify repository files.
#>

param(
  [string[]]$Frameworks = @('GDPR'),
  [string]$OutputDir = '.\IFQC-Reports',
  [switch]$AllowUnsigned
)

Set-StrictMode -Version Latest

function Write-Info { param($m) Write-Output ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Info'; Message=$m }) }

Write-Info "IFQC Read-Only Runner starting. Frameworks=$($Frameworks -join ',') OutputDir=$OutputDir"

# Ensure output dir exists
if (-not (Test-Path -Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

# Enforce read-only for this process
[Environment]::SetEnvironmentVariable('IFQC_READONLY','1','Process')

$engineScript = Join-Path -Path (Split-Path -Parent $MyInvocation.MyCommand.Definition) -ChildPath '..\IdentityHealthCheck.ps1'
if (-not (Test-Path $engineScript)) {
    Write-Info "Engine script not found: $engineScript"
    exit 2
}

# --- Release verification (SHA256 + optional Authenticode) ---------------------------------
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$cwd = (Get-Location).Path

# locate SHA256SUMS.txt: prefer current working dir, fallback to release root next to tools
$sumPath = Join-Path $cwd 'SHA256SUMS.txt'
if (-not (Test-Path $sumPath)) { $sumPath = Join-Path (Join-Path $scriptDir '..') 'SHA256SUMS.txt' }

if (Test-Path $sumPath) {
  Write-Info "Found checksum manifest: $sumPath — verifying before execution"
  $verifyScript = Join-Path $scriptDir 'verify_release.ps1'
  if (Test-Path $verifyScript) {
    & pwsh -NoProfile -ExecutionPolicy Bypass -File $verifyScript -ReleasePath (Split-Path $sumPath -Parent) -FailOnMismatch
    if ($LASTEXITCODE -ne 0) { Write-Info "Checksum verification failed — aborting run."; exit 3 }
  } else {
    Write-Info "verify_release.ps1 missing; skipping automated checksum verification. Proceeding with caution."
  }
} else {
  Write-Info "No SHA256SUMS.txt found; skipping checksum verification."
}

# Authenticode check: ensure scripts are signed unless explicitly allowed
if (-not $AllowUnsigned) {
  $unsigned = @()
  $releaseRoot = if (Test-Path $sumPath) { Split-Path $sumPath -Parent } else { $cwd }
  Get-ChildItem -Path $releaseRoot -Include *.ps1,*.psm1 -Recurse -File | ForEach-Object {
    try {
      $s = Get-AuthenticodeSignature -FilePath $_.FullName -ErrorAction SilentlyContinue
    } catch {
      $s = $null
    }
    if (-not $s -or $s.Status -ne 'Valid') { $unsigned += $_.FullName }
  }
  if ($unsigned.Count -gt 0) {
    Write-Info "Found $($unsigned.Count) unsigned or invalidly-signed PowerShell files."
    Write-Info "Files: $($unsigned | Select-Object -First 10 -Unique | ForEach-Object { Split-Path $_ -Leaf } )"
    Write-Info "To proceed despite unsigned files, re-run with -AllowUnsigned. Aborting."
    exit 4
  }
}
# ----------------------------------------------------------------------------------------------

# Build engine args
$argsList = @('-Frameworks', ($Frameworks -join ','), '-OutputDir', $OutputDir, '-ReadOnly')

Write-Info "Invoking IdentityHealthCheck in read-only mode..."
& pwsh -NoProfile -ExecutionPolicy Bypass -File $engineScript @argsList

Write-Info "Collecting report artifacts from $OutputDir"

$htmlFiles = Get-ChildItem -Path $OutputDir -Filter *.html -Recurse -File -ErrorAction SilentlyContinue
$jsonFiles = Get-ChildItem -Path $OutputDir -Filter *.json -Recurse -File -ErrorAction SilentlyContinue

$indexPath = Join-Path $OutputDir 'index.html'

$indexHeader = @"
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>IdentityFirst QuickChecks - Reports</title>
  <style> body{font-family:Arial,Helvetica,sans-serif;margin:20px} h1{color:#1a73e8} ul{line-height:1.6} .meta{color:#666;font-size:0.9em}</style>
</head>
<body>
  <h1>IdentityFirst QuickChecks - Reports</h1>
  <div class="meta"><p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p></div>
  <h2>Available Reports</h2>
  <ul>
"@

$indexBody = ''
if ($htmlFiles -and $htmlFiles.Count -gt 0) {
    foreach ($f in $htmlFiles | Sort-Object LastWriteTime -Descending) {
        $rel = $f.FullName.Substring((Get-Location).Path.Length).TrimStart('\','/')
        $indexBody += "    <li><a href='$($rel)'>$($f.Name)</a> — $([string]::Format('{0:yyyy-MM-dd HH:mm}', $f.LastWriteTime))</li>`n"
    }
} elseif ($jsonFiles -and $jsonFiles.Count -gt 0) {
    $indexBody += "<p>No HTML reports found. JSON artifacts are available:</p>`n    <ul>`n"
    foreach ($f in $jsonFiles | Sort-Object LastWriteTime -Descending) {
        $rel = $f.FullName.Substring((Get-Location).Path.Length).TrimStart('\','/')
        $indexBody += "      <li><a href='$($rel)'>$($f.Name)</a> — $([string]::Format('{0:yyyy-MM-dd HH:mm}', $f.LastWriteTime))</li>`n"
    }
    $indexBody += "    </ul>`n"
} else {
    $indexBody = "<p>No reports found in $OutputDir.</p>`n"
}

$indexFooter = @"
  </ul>
  <footer><p><em>Reports generated in read-only mode. To reproduce, run the engine with -ReadOnly.</em></p></footer>
</body>
</html>
"@

$indexContent = $indexHeader + $indexBody + $indexFooter
$indexContent | Out-File -FilePath $indexPath -Encoding UTF8 -Force

Write-Info "Index generated: $indexPath"
Write-Info "Runner complete. Open the index in a browser to view reports."

exit 0
