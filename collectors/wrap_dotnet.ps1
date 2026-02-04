<#
Wrapper to run a .NET (C#) collector binary and print JSON to stdout.
Usage: .\wrap_dotnet.ps1 -CollectorPath .\collector.exe -Args '--tenant x'
#>
param(
    [Parameter(Mandatory=$true)][string]$CollectorPath,
    [string[]]$Args = @()
)

if (-not (Test-Path $CollectorPath)) { Write-Error "Collector not found: $CollectorPath"; exit 2 }

try {
    $out = & $CollectorPath @Args 2>&1
    try {
        $parsed = $out | ConvertFrom-Json -ErrorAction Stop
        $parsed | ConvertTo-Json -Depth 8
    } catch {
        Write-Output '[]'
    }
} catch {
    Write-Output '[]'
}
