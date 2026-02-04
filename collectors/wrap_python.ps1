<#
Wrapper to run a Python collector safely and print JSON to stdout.
Usage: .\wrap_python.ps1 -CollectorPath .\my_collector.py -Env @{KEY='VAL'}
#>
param(
    [Parameter(Mandatory=$true)][string]$CollectorPath,
    [hashtable]$Env = @{}
)

if (-not (Test-Path $CollectorPath)) { Write-Error "Collector not found: $CollectorPath"; exit 2 }

# Set environment variables for the process (process-scope)
$oldEnv = @{}
foreach ($k in $Env.Keys) {
    $oldEnv[$k] = [System.Environment]::GetEnvironmentVariable($k, 'Process')
    [System.Environment]::SetEnvironmentVariable($k, [string]$Env[$k], 'Process')
}

try {
    $python = 'python'
    $out = & $python $CollectorPath 2>&1
    $outText = if ($out -is [System.Array]) { ($out -join "`n") } else { [string]$out }

    # Try parsing full output as JSON first
    try {
        $parsed = $outText | ConvertFrom-Json -ErrorAction Stop
        $parsed | ConvertTo-Json -Depth 8
    } catch {
        # Extract the last JSON-looking chunk (object or array) using regex
        $matches = [regex]::Matches($outText, '({[\s\S]*}|\[[\s\S]*\])')
        if ($matches.Count -gt 0) {
            $last = $matches[$matches.Count - 1].Value
            try { ($last | ConvertFrom-Json -ErrorAction Stop) | ConvertTo-Json -Depth 8 } catch { Write-Output '[]' }
        } else {
            Write-Output '[]'
        }
    }
} finally {
    # restore env
    foreach ($k in $oldEnv.Keys) {
        if ($oldEnv[$k] -ne $null) { [System.Environment]::SetEnvironmentVariable($k, $oldEnv[$k], 'Process') }
        else { [System.Environment]::SetEnvironmentVariable($k, $null, 'Process') }
    }
}
