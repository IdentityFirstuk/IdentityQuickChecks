param([string]$OutputPath = ".")

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================================================"
Write-Host "  Identity Attack Surface Analysis"
Write-Host "========================================================================"

# Initialize tracking variables
$highRiskAccounts = @()
$serviceAccounts = @()
$errors = @()
$processedCount = 0

Write-Host ""
Write-Host "  Analyzing identity attack surface..." -ForegroundColor Gray

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "  ActiveDirectory module loaded" -ForegroundColor Green
}
catch {
    Write-Host "  ERROR: ActiveDirectory module not available" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "  Enumerating high-risk accounts..." -ForegroundColor Gray

# Define high-risk groups to monitor
$highRiskGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Server Operators",
    "Print Operators",
    "Backup Operators",
    "Replicator",
    "Cryptographic Operators"
)

# Get all users with additional properties
try {
    $allUsers = Get-ADUser -Filter * -Properties SamAccountName, Name, Description, Enabled, PasswordNeverExpires, LastLogonTimestamp, whenCreated, pwdLastSet, memberOf -ErrorAction Stop
    Write-Host "  Found $($allUsers.Count) user accounts" -ForegroundColor Gray
}
catch {
    Write-Host "  ERROR: Failed to retrieve users: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "  Checking privileged group memberships..." -ForegroundColor Gray

$privilegedMembers = @{}
$errors = @()

foreach ($group in $highRiskGroups) {
    try {
        $members = Get-ADGroupMember -Identity $group -ErrorAction Stop
        $privilegedMembers[$group] = $members
        Write-Host "    $group : $($members.Count) members" -ForegroundColor Gray
    }
    catch {
        $errorMsg = "Failed to get members of $group : $($_.Exception.Message)"
        $errors += $errorMsg
        Write-Host "    $group : ACCESS DENIED" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "  Analyzing account posture..." -ForegroundColor Gray

# Define risk indicators
$riskIndicators = @()

foreach ($user in $allUsers) {
    try {
        $processedCount++
        $userRiskFactors = @()
        $isPrivileged = $false
        
        # Check if user is in any high-risk group
        foreach ($group in $highRiskGroups) {
            $members = $privilegedMembers[$group]
            if ($members) {
                $isMember = $members | Where-Object { $_.SamAccountName -eq $user.SamAccountName }
                if ($isMember) {
                    $isPrivileged = $true
                    $userRiskFactors += "Member of $group"
                }
            }
        }
        
        # Check for service accounts
        $isServiceAccount = $false
        $svcIndicators = @("SVC-", "svc-", "$", "Service_", "svc_")
        foreach ($indicator in $svcIndicators) {
            if ($user.SamAccountName -like "*$indicator*") {
                $isServiceAccount = $true
                break
            }
        }
        
        if ($isServiceAccount) {
            $serviceAccounts += New-Object PSObject -Property @{
                SamAccountName = $user.SamAccountName
                Name = $user.Name
                Enabled = $user.Enabled
                PasswordNeverExpires = $user.PasswordNeverExpires
                LastLogon = if ($user.LastLogonTimestamp) { [DateTime]::FromFileTime($user.LastLogonTimestamp).ToString("yyyy-MM-dd") } else { "Never" }
            }
        }
        
        # Check risk factors for all accounts
        if ($user.Enabled -eq $true) {
            $userRiskFactors += "Account ENABLED"
        }
        
        if ($user.PasswordNeverExpires -eq $true) {
            $userRiskFactors += "PasswordNeverExpires=TRUE"
        }
        
        if ($user.pwdLastSet) {
            $pwdAgeDays = (New-TimeSpan -Start ([DateTime]::FromFileTime($user.pwdLastSet)) -End (Get-Date)).Days
            if ($pwdAgeDays -gt 90) {
                $userRiskFactors += "Password $pwdAgeDays days old"
            }
        }
        
        if ($user.LastLogonTimestamp) {
            $lastLogonDays = (New-TimeSpan -Start ([DateTime]::FromFileTime($user.LastLogonTimestamp)) -End (Get-Date)).Days
            if ($lastLogonDays -gt 90) {
                $userRiskFactors += "No logon for $lastLogonDays days"
            }
        }
        
        if ($user.whenCreated) {
            $ageDays = (New-TimeSpan -Start $user.whenCreated -End (Get-Date)).Days
            if ($ageDays -le 7) {
                $userRiskFactors += "Created within 7 days"
            }
        }
        
        # Check for accounts with many group memberships (potential escalation path)
        $memberOfCount = ($user.memberOf | Measure-Object).Count
        if ($memberOfCount -gt 50) {
            $userRiskFactors += "Member of $memberOfCount groups"
        }
        
        # Determine if this is a high-risk account
        $isHighRisk = $false
        $riskScore = 0
        
        if ($isPrivileged) { $riskScore += 5 }
        if ($user.PasswordNeverExpires -eq $true) { $riskScore += 2 }
        if ($user.Enabled -eq $true -and $isPrivileged) { $riskScore += 3 }
        
        if ($riskScore -ge 5) {
            $isHighRisk = $true
            $highRiskAccounts += New-Object PSObject -Property @{
                SamAccountName = $user.SamAccountName
                Name = $user.Name
                Enabled = $user.Enabled
                PasswordNeverExpires = $user.PasswordNeverExpires
                IsPrivileged = $isPrivileged
                RiskScore = $riskScore
                RiskFactors = $userRiskFactors -join "; "
                LastLogon = if ($user.LastLogonTimestamp) { [DateTime]::FromFileTime($user.LastLogonTimestamp).ToString("yyyy-MM-dd") } else { "Never" }
            }
        }
        
    }
    catch {
        $errorMsg = "Failed to analyze user $($user.SamAccountName): $($_.Exception.Message)"
        $errors += $errorMsg
        Write-Host "  WARNING: $errorMsg" -ForegroundColor Yellow
    }
}

# Summary
Write-Host ""
Write-Host "  Attack Surface Summary"
Write-Host "  ======================"
Write-Host "  Accounts analyzed: $processedCount"
Write-Host "  High-risk accounts: $($highRiskAccounts.Count)" -ForegroundColor $(if ($highRiskAccounts.Count -gt 0) { "Red" } else { "Green" })
Write-Host "  Service accounts: $($serviceAccounts.Count)"

# Show high-risk accounts
if ($highRiskAccounts) {
    Write-Host ""
    Write-Host "  HIGH RISK ACCOUNTS - IMMEDIATE REVIEW:" -ForegroundColor Red
    
    $highRiskAccounts | Sort-Object -Property RiskScore -Descending | Format-Table -AutoSize -Property `
        @{Name="SamAccountName"; Expression={$_.SamAccountName}; Width=20},
        @{Name="Enabled"; Expression={$_.Enabled}; Width=10},
        @{Name="PwdNeverExp"; Expression={$_.PasswordNeverExpires}; Width=12},
        @{Name="Privileged"; Expression={$_.IsPrivileged}; Width=12},
        @{Name="Score"; Expression={$_.RiskScore}; Width=8},
        @{Name="LastLogon"; Expression={$_.LastLogon}; Width=12}
    
    Write-Host ""
    Write-Host "  Risk Factor Details:"
    $highRiskAccounts | Where-Object { $_.RiskScore -ge 7 } | ForEach-Object {
        Write-Host "    $($_.SamAccountName): $($_.RiskFactors)" -ForegroundColor Gray
    }
}
else {
    Write-Host ""
    Write-Host "  No high-risk accounts identified." -ForegroundColor Green
}

# Show service account summary
if ($serviceAccounts) {
    Write-Host ""
    Write-Host "  Service Accounts Summary:"
    Write-Host "  ========================"
    
    $serviceWithIssues = $serviceAccounts | Where-Object { $_.PasswordNeverExpires -eq $true }
    Write-Host "  Total service accounts: $($serviceAccounts.Count)"
    Write-Host "  With password never expires: $($serviceWithIssues.Count)" -ForegroundColor $(if ($serviceWithIssues.Count -gt 0) { "Yellow" } else { "Green" })
    
    $inactiveSvc = $serviceAccounts | Where-Object { $_.LastLogon -ne "Never" -and (New-TimeSpan -Start ([DateTime]::ParseExact($_.LastLogon, "yyyy-MM-dd", $null)) -End (Get-Date)).Days -gt 90 }
    Write-Host "  Inactive (>90 days): $($inactiveSvc.Count)" -ForegroundColor $(if ($inactiveSvc.Count -gt 0) { "Yellow" } else { "Green" })
}

# Show privileged group summary
Write-Host ""
Write-Host "  Privileged Group Membership:"
Write-Host "  ============================"
foreach ($group in $highRiskGroups) {
    $members = $privilegedMembers[$group]
    if ($members) {
        Write-Host "    $group : $($members.Count) members" -ForegroundColor Gray
    }
}

# Show errors
if ($errors) {
    Write-Host ""
    Write-Host "  Errors encountered:" -ForegroundColor Yellow
    foreach ($err in $errors) {
        Write-Host "    - $err" -ForegroundColor Gray
    }
}

# Generate report
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$reportPath = Join-Path $OutputPath "IdentityAttackSurface-$timestamp.json"

$report = @{
    CheckName = "Identity Attack Surface Analysis"
    Timestamp = Get-Date -Format "o"
    Summary = @{
        TotalAccountsAnalyzed = $processedCount
        HighRiskAccounts = $highRiskAccounts.Count
        ServiceAccounts = $serviceAccounts.Count
        Errors = $errors.Count
    }
    HighRiskAccounts = $highRiskAccounts
    ServiceAccounts = $serviceAccounts
    PrivilegedGroupMembership = $privilegedMembers
    Errors = $errors
}

try {
    $jsonOutput = $report | ConvertTo-Json -Depth 10
    $jsonOutput | Set-Content -Path $reportPath -ErrorAction Stop
    Write-Host ""
    Write-Host "  Report saved: $reportPath" -ForegroundColor Cyan
}
catch {
    Write-Host ""
    Write-Host "  ERROR: Failed to save report" -ForegroundColor Red
}

exit 0
