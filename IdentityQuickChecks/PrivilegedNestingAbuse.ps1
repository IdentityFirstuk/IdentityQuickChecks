<#
    Privileged Group Nesting Abuse
    Walks nested admin groups and flags indirect privilege
#>

param(
    [string]$OutputPath = "."
)

Write-Host "════════════════════════════════════════════════════════════"
Write-Host "  Privileged Group Nesting Abuse Check"
Write-Host "════════════════════════════════════════════════════════════"
Write-Host ""
Write-Host "  Analyzing nested group membership..."
Write-Host ""

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Host "  ✗ ActiveDirectory module not available" -ForegroundColor Red
    Write-Host "  ℹ Install RSAT AD tools or run on a Domain Controller" -ForegroundColor Gray
    exit 1
}

$privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
$nestedResults = @()
$allDirectMembers = @()

foreach ($group in $privilegedGroups) {
    Write-Host "  Checking: $group..."
    
    try {
        $directMembers = Get-ADGroupMember $group -ErrorAction Stop | 
            Where-Object objectClass -eq "user"
        
        foreach ($member in $directMembers) {
            $allDirectMembers += [PSCustomObject]@{
                Group = $group
                Name = $member.Name
                SamAccountName = $member.SamAccountName
                Type = "Direct"
            }
        }
        
        $nestedGroups = Get-ADGroupMember $group -Recursive -ErrorAction Stop | 
            Where-Object objectClass -eq "group"
        
        foreach ($nestedGroup in $nestedGroups) {
            $nestedMembers = Get-ADGroupMember $nestedGroup -ErrorAction Stop | 
                Where-Object objectClass -eq "user"
            
            foreach ($member in $nestedMembers) {
                $nestedResults += [PSCustomObject]@{
                    RootGroup = $group
                    NestedGroup = $nestedGroup.Name
                    MemberName = $member.Name
                    MemberSamAccountName = $member.SamAccountName
                }
            }
        }
    }
    catch {
        Write-Host "     ⚠ Unable to access $group" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "  Direct Privileged Access:"
if ($allDirectMembers) {
    Write-Host "  Found $($allDirectMembers.Count) direct members" -ForegroundColor Yellow
    $allDirectMembers | Format-Table -AutoSize
} else {
    Write-Host "  ✓ No direct privileged members found" -ForegroundColor Green
}

Write-Host ""
Write-Host "  Indirect/Nested Privileged Access (hidden blast radius):"
if ($nestedResults) {
    Write-Host "  Found $($nestedResults.Count) users with indirect privilege" -ForegroundColor Yellow
    $nestedResults | Format-Table -AutoSize
} else {
    Write-Host "  ✓ No nested privilege detected" -ForegroundColor Green
}

# Export report
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$jsonPath = Join-Path $OutputPath "PrivilegedNestingAbuse-$timestamp.json"
$report = @{
    check = "Privileged Group Nesting Abuse Check"
    timestamp = (Get-Date).ToString("o")
    summary = @{
        directMembers = ($allDirectMembers | Measure-Object).Count
        indirectMembers = ($nestedResults | Measure-Object).Count
    }
    directMembers = $allDirectMembers
    nestedMembers = $nestedResults
}
$report | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
Write-Host ""
Write-Host "  📄 Report saved: $jsonPath" -ForegroundColor Cyan

Write-Host ""
Write-Host "  ─────────────────────────────────────────────────────────────"
Write-Host "  ℹ  Nested privilege = hidden blast radius."
Write-Host "     Only correlation makes it meaningful. Run IdentityHealthCheck."
Write-Host "  ─────────────────────────────────────────────────────────────"
