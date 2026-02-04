param([string]$OutputPath = ".")

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================================================"
Write-Host "  Privileged Nesting Abuse Check"
Write-Host "========================================================================"

function Get-NestedGroupMembers {
    param([string]$GroupName)
    
    $members = @()
    $queue = New-Object System.Collections.Queue
    $queue.Enqueue($GroupName)
    $visited = @{}
    
    while ($queue.Count -gt 0) {
        $current = $queue.Dequeue()
        if ($visited.ContainsKey($current)) { continue }
        $visited[$current] = $true
        
        try {
            $grp = Get-ADGroup $current -Properties Members -ErrorAction Stop
            foreach ($m in $grp.Members) {
                $members += $m
                try {
                    $obj = Get-ADObject $m -ErrorAction Stop
                    if ($obj.objectClass -eq "group") {
                        $queue.Enqueue($m)
                    }
                }
                catch {
                }
            }
        }
        catch {
        }
    }
    
    return $members
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "  ActiveDirectory module loaded" -ForegroundColor Green
}
catch {
    Write-Host "  ERROR: ActiveDirectory module not available" -ForegroundColor Red
    exit 1
}

$privilegedGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Server Operators"
)

$nestingResults = @()
$errors = @()

foreach ($g in $privilegedGroups) {
    Write-Host ""
    Write-Host "  Checking $g..." -ForegroundColor Gray
    
    try {
        $directMembers = Get-ADGroupMember $g -ErrorAction Stop | Where-Object { $_.objectClass -eq "user" }
        $nestedGroups = Get-ADGroupMember $g -ErrorAction Stop | Where-Object { $_.objectClass -eq "group" }
        
        $allMembers = Get-NestedGroupMembers -GroupName $g
        $userSids = @()
        foreach ($m in $allMembers) {
            try {
                $obj = Get-ADObject $m -Properties objectClass -ErrorAction Stop
                if ($obj.objectClass -eq "user") {
                    $userSids += $obj.ObjectGUID
                }
            }
            catch {
            }
        }
        
        $nestingResults += New-Object PSObject -Property @{
            GroupName = $g
            DirectUsersCount = @($directMembers).Count
            DirectGroupsCount = @($nestedGroups).Count
            TotalNestedUsersCount = @($userSids).Count
            DirectUsers = ($directMembers | ForEach-Object { $_.SamAccountName }) -join ", "
            DirectGroups = ($nestedGroups | ForEach-Object { $_.SamAccountName }) -join ", "
            NestedUsers = ($userSids | ForEach-Object { $_ }) -join ", "
        }
        
        if ($nestedGroups) {
            Write-Host "     WARNING: Contains nested groups" -ForegroundColor Yellow
            $nestedGroups | ForEach-Object { Write-Host "        - $($_.SamAccountName)" -ForegroundColor Gray }
        }
    }
    catch {
        Write-Host "     WARNING: Unable to access $g" -ForegroundColor Yellow
        $errors += $_.Exception.Message
    }
}

Write-Host ""
Write-Host "  Summary:"
Write-Host "  ========="

foreach ($r in $nestingResults) {
    $flag = ""
    if ($r.DirectGroupsCount -gt 0 -or $r.TotalNestedUsersCount -gt $r.DirectUsersCount) {
        $flag = " NESTED DETECTED"
    }
    Write-Host "     $($r.GroupName): $($r.DirectUsersCount) direct, $($r.TotalNestedUsersCount) total$flag"
}

if ($errors) {
    Write-Host ""
    Write-Host "  Errors encountered:" -ForegroundColor Yellow
    $errors | ForEach-Object { Write-Host "     - $_" -ForegroundColor Gray }
}

$ts = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$rp = Join-Path $OutputPath "PrivilegedNestingAbuse-$ts.json"

$report = @{
    CheckName = "Privileged Nesting Abuse"
    Timestamp = Get-Date -Format "o"
    Results = $nestingResults
    Errors = $errors
}

try {
    $json = $report | ConvertTo-Json -Depth 10
    $json | Set-Content -Path $rp -ErrorAction Stop
    Write-Host ""
    Write-Host "  Report saved: $rp" -ForegroundColor Cyan
}
catch {
    Write-Host ""
    Write-Host "  ERROR: Failed to save report" -ForegroundColor Red
}

exit 0
