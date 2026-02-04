# IdentityFirst QuickChecks Philosophy

## Core Principles

IdentityFirst QuickChecks are **read-only assessment tools** designed to provide a **quick glance** into an organization's identity posture.

### Golden Rules

| Principle | Description |
|-----------|-------------|
| **Read-Only** | Scripts NEVER modify AD, Entra ID, or any system |
| **Quick** | Run in minutes, not hours |
| **Lightweight** | No agents, no services, no dependencies beyond PowerShell |
| **Local** | No data leaves the machine |
| **Structured** | JSON + HTML reports for easy consumption |

## What QuickChecks Are

✅ **Identity visibility tools** - Show what exists in the environment
✅ **Snapshot assessments** - Point-in-time assessments
✅ **Finding generators** - Produce lists of potential issues
✅ **Report writers** - Output structured data for review

## What QuickChecks Are NOT

❌ **Remediation tools** - They don't fix anything
❌ **Monitoring solutions** - No continuous assessment
❌ **Governance platforms** - They don't track or enforce policies
❌ **Compliance engines** - They don't map to compliance frameworks

## Design Philosophy

### 1. Standalone Scripts First

QuickChecks are designed to be **run directly** from the extracted ZIP:

```powershell
# Extract ZIP, then run:
.\IdentityQuickChecks\BreakGlassReality.ps1

# Or run all:
.\Run-AllQuickChecks.ps1
```

**Rationale:**
- No installation required
- No PowerShell module dependency
- Works on any PowerShell 5.1+ host
- No execution policy issues with module imports

### 2. Read-Only Queries

Every script should only perform **read operations**:

```powershell
# ✅ Good - Read-only queries
Get-ADUser -Filter *
Get-ADGroupMember
Get-AzADUser

# ❌ Bad - Write operations
Set-ADUser
Remove-ADObject
New-AzADApp
```

### 3. Self-Contained Reports

Each script generates its own reports:

```powershell
# Output structure per check:
IFQC-Output/
├── BreakGlassReality-20260130-143022.json
├── BreakGlassReality-20260130-143022.html
├── PasswordPolicyDrift-20260130-143045.json
└── PasswordPolicyDrift-20260130-143045.html
```

### 4. No External Data Transmission

All data stays local:
- No telemetry
- No usage tracking
- No cloud uploads
- Reports written to local disk only

## Script Architecture

### Recommended Structure

```powershell
<#
.SYNOPSIS
    Quick one-line description of what this check does.

.DESCRIPTION
    Longer description explaining:
    - What the check queries
    - What findings it looks for
    - What the output represents

.NOTES
    - Read-only: YES
    - Requires: ActiveDirectory module (RSAT)
    - Permissions: Domain Admin recommended

.EXAMPLE
    .\CheckName.ps1
    .\CheckName.ps1 -OutputPath "C:\Reports"
#>

param(
    [string]$OutputPath = "."
)

# 1. Initialize - Error handling, output directory
$ErrorActionPreference = "Stop"

# 2. Prerequisite check - Exit early if modules missing
try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    Write-Host "ERROR: ActiveDirectory module not available"
    exit 1
}

# 3. Perform queries - Read-only operations
$users = Get-ADUser -Filter * -Properties Name, SamAccountName

# 4. Analyze findings - Local processing
$findings = $users | Where-Object { $_.Name -match "test" }

# 5. Generate report - Write to disk
$report = @{
    CheckName = "MyCheck"
    Timestamp = Get-Date -Format "o"
    Findings = $findings
}
$report | ConvertTo-Json -Depth 10 | Out-File -Path "$OutputPath\report.json"

# 6. Display summary - Console output
Write-Host ""
Write-Host "Summary"
Write-Host "======="
Write-Host "Total users: $($users.Count)"
Write-Host "Findings: $($findings.Count)"
```

### Output Format

#### JSON Report
```json
{
  "checkName": "BreakGlassReality",
  "timestamp": "2026-01-30T14:30:22Z",
  "summary": {
    "totalAccounts": 1500,
    "breakGlassFound": 3,
    "highRisk": 2
  },
  "findings": [
    {
      "samAccountName": "BG-Admin1",
      "riskLevel": "HIGH",
      "indicators": ["PasswordNeverExpires", "Enabled"]
    }
  ]
}
```

#### Console Output
```
========================================================================
  Break-Glass Reality Check
========================================================================

  Finding accounts named/described as break-glass...

  ⚠ Found 3 break-glass accounts

SamAccountName Enabled PasswordNeverExpires LastLogon
-------------- ------- ------------------- ----------
BG-Admin1      True    True                2024-06-15
BG-Emergency   True    False               2024-01-20

========================================================================
```

## Distribution Philosophy

### ZIP Distribution (Primary)

1. **Extract ZIP** → `IdentityFirst.QuickChecks-v1.1.0\`
2. **Run scripts** → `.\IdentityQuickChecks\BreakGlassReality.ps1`
3. **Review reports** → Open JSON/HTML in IFQC-Output\

**Why ZIP?**
- No installation required
- Works offline
- No PowerShell module issues
- Easy to audit (all files visible)

### PowerShell Gallery (Optional)

For users who prefer module import:

```powershell
Install-Module IdentityFirst.QuickChecks
Invoke-BreakGlassReality
```

**This should be a convenience, not a requirement.**

## Security Guarantees

When running IdentityFirst QuickChecks, users can verify:

| Guarantee | How to Verify |
|-----------|---------------|
| No modifications | Monitor AD audit logs |
| No data exfiltration | Monitor network traffic |
| No credential collection | Review script source |
| No persistent changes | Run before/after comparison |

## Performance Guidelines

QuickChecks should be designed to complete quickly:

| Check Type | Target Time | Examples |
|------------|-------------|----------|
| Fast | < 30 seconds | User enumeration, group membership |
| Normal | 30s - 2m | Cross-platform queries, complex filters |
| Extended | 2m - 10m | Large directory scans, log analysis |

**Optimization tips:**
- Use `-Filter *` instead of `Where-Object` where possible
- Request only needed properties: `-Properties Name,SamAccountName`
- Use pagination for large datasets
- Parallelize independent queries with `-Parallel` (PS7+)

## Error Handling

QuickChecks should fail gracefully:

```powershell
# ✅ Good - Informative error, non-zero exit
try {
    Get-ADUser -Filter * -ErrorAction Stop
}
catch {
    Write-Host "ERROR: Failed to query users: $($_.Exception.Message)"
    exit 1
}

# ❌ Bad - Silent failure
Get-ADUser -Filter * -ErrorAction SilentlyContinue | Where-Object { $false }
```

## Version Compatibility

| Feature | PS5.1 | PS7+ | Notes |
|---------|-------|------|-------|
| Core scripts | ✅ | ✅ | Primary target |
| Parallel execution | ❌ | ✅ | Use `-Parallel` in PS7+ |
| Cross-platform | ❌ | ✅ | Linux/macOS for cloud checks |

## Quick Reference

### Running Checks

```powershell
# Single check
.\IdentityQuickChecks\BreakGlassReality.ps1

# All checks
.\Run-AllQuickChecks.ps1

# With custom output
.\IdentityQuickChecks\BreakGlassReality.ps1 -OutputPath "D:\Reports"
```

### Reviewing Results

```powershell
# View JSON
Get-Content .\IFQC-Output\*.json | ConvertFrom-Json

# Open HTML report
Invoke-Item .\IFQC-Output\*.html

# Find high-risk items
Select-String -Path ".\IFQC-Output\*.json" -Pattern '"severity": "HIGH"'
```

### Troubleshooting

| Issue | Solution |
|-------|----------|
| "Module not found" | Install RSAT or run `Install-Prerequisites.ps1` |
| "Access denied" | Run from account with domain query rights |
| "Execution policy blocked" | `Set-ExecutionPolicy RemoteSigned` |
| Empty results | Verify you have query permissions |
