try {
    if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer)) {
        Write-Output 'PSScriptAnalyzer not found; installing...'
        Install-Module PSScriptAnalyzer -Scope CurrentUser -Force -Confirm:$false
    }

    Import-Module PSScriptAnalyzer -ErrorAction Stop

    $findings = Invoke-ScriptAnalyzer -Path . -Recurse -ErrorAction SilentlyContinue

    if ($null -eq $findings -or $findings.Count -eq 0) {
        'No findings' | Out-File -FilePath .\pssa-report.txt -Encoding utf8 -Force
    }
    else {
        $findings | Select-Object Severity,RuleName,ScriptName,Line,Message | Export-Csv -Path .\pssa-report.csv -NoTypeInformation -Force
        $findings | ForEach-Object { "[$($_.Severity)] $($_.ScriptName):$($_.Line) $($_.RuleName) - $($_.Message)" } | Out-File -FilePath .\pssa-report.txt -Encoding utf8 -Force
    }

    Write-Output 'Done'
}
catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
