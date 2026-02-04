try {
    $modulePath = 'd:\IdentityFirst-Ltd\web\2026web\powershell-modules\Module\IdentityFirst.QuickChecks.psm1'
    Write-Output "Importing module: $modulePath"
    Import-Module $modulePath -Force -ErrorAction Stop

    $outdir = Join-Path $PWD 'IFQC-Output'
    Write-Output "Output directory: $outdir"
    if (-not (Test-Path -LiteralPath $outdir)) { New-Item -ItemType Directory -Path $outdir -Force | Out-Null }

    Write-Output "Creating context"
    $ctx = New-IFQCContext -ToolName TestRun -OutputDirectory $outdir

    Write-Output "Writing log entry"
    Write-IFQCLog -Context $ctx -Level INFO -Message 'Hello from smoke test'

    Write-Output "Saving report"
    $out = Save-IFQCReport -Context $ctx

    Write-Output "Report paths returned:"; Write-Output $out

    Write-Output "Listing output directory contents"
    Get-ChildItem -Path $outdir | Select-Object Name,Length,LastWriteTime | Format-Table -AutoSize
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    Write-Output $_.Exception.StackTrace
    exit 1
}
