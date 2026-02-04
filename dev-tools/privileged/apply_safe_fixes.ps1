<#
.SYNOPSIS
Safe, opt-in fixer for trivial repo issues.

.DESCRIPTION
- Dry-run by default. Use `-Apply` to make changes.
- Ensures `Output/` exists, normalizes trailing whitespace, replaces trivial `Write-Host 'text'` lines
  with `Write-IFQC` (if available) or `Write-Output`, creates backups for edited files, and writes a summary.
#>

param()

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$RepoRoot = Split-Path -Parent $ScriptDir
$OutputDir = Join-Path $RepoRoot 'Output'
$SummaryPath = Join-Path $ScriptDir 'apply_safe_fixes_summary.json'

function Log { param($m) Write-Output $m }

# Enforce read-only mode for free distribution: no edits will be applied unless explicitly requested by maintainers.
$Apply = $false
Log 'NOTE: apply_safe_fixes (privileged) is capable of applying fixes. Use only under maintainer control.'

if (-not (Test-Path $OutputDir)) {
    Log "Would create: $OutputDir"
}

$files = Get-ChildItem -Path $RepoRoot -Include *.ps1,*.psm1 -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\.git\\' -and $_.FullName -notmatch '\\.bak' -and $_.FullName -notmatch '\\node_modules\\' }

$modifiedFiles = @()

foreach ($f in $files) {
    try {
        $origText = Get-Content -Raw -LiteralPath $f.FullName -ErrorAction Stop
    } catch {
        Log "Skipping (read error): $($f.FullName)"
        continue
    }

    $lines = $origText -split "`r?`n"
    $changed = $false

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $ln = $lines[$i]
        # remove trailing whitespace
        $trimmed = $ln -replace '\\s+$',''
        if ($trimmed -ne $ln) { $lines[$i] = $trimmed; $changed = $true }

        # trivial Write-Host replacements: single literal string only
        $pattern = '^[ \t]*Write-Host[ \t]+(?:''([^'']*)''|""([^""]*)"")[ \t]*$'
        # note: pattern uses doubled single-quotes inside single-quoted string and an alternation
        if ($lines[$i] -match $pattern) {
            if ($Matches[1]) { $msg = $Matches[1] } else { $msg = $Matches[2] }
            if ($null -eq $msg) { $msg = '' }
            $msg = $msg.Replace("'", "''")
            if (Get-Command Write-IFQC -ErrorAction SilentlyContinue) {
                $replacement = "Write-IFQC -Level Info -Message '$msg'"
            } else {
                $replacement = "Write-Output '$msg'"
            }
            if ($lines[$i] -ne $replacement) { $lines[$i] = $replacement; $changed = $true }
        }
    }

    if ($changed) {
        $modifiedFiles += $f.FullName
        if ($Apply) {
            # create backup
            Copy-Item -Path $f.FullName -Destination ($f.FullName + '.bak') -Force
            $lines -join "`r`n" | Out-File -FilePath $f.FullName -Encoding utf8 -Force
            Log "Updated: $($f.FullName)"
        } else {
            Log "Would update: $($f.FullName)"
        }
    }
}

 $summary = @{ Modified = $modifiedFiles; Applied = $Apply; Timestamp = (Get-Date).ToString('o') }
try { $summary | ConvertTo-Json -Depth 3 | Out-File -FilePath $SummaryPath -Encoding utf8 -Force } catch { }

Log "Summary: $($modifiedFiles.Count) files flagged. Summary written to $SummaryPath"

exit 0
