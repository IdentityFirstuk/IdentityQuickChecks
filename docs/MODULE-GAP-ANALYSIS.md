# IdentityHealthCheck-Lite Gap Analysis

## Executive Summary

The IdentityFirst QuickChecks module has a split architecture where:
- **Modern scripts** (in `Checks/`) properly use the IFQC framework
- **Legacy scripts** (in `IdentityQuickChecks/`, `IdentityTrustQuickChecks/`, `IdentityBoundaryQuickChecks/`) use standalone scripts with `Write-Host`

## Critical Gaps

### 1. Module Export Mismatch

**Issue**: The manifest exports `*-IFQC*` functions but these don't exist as standalone commands.

**Current (Module/IdentityFirst.QuickChecks.psd1)**:
```powershell
FunctionsToExport = @('*-IFQC*')
```

**Expected**: Either export the wrapper functions or remove this line.

### 2. Missing Wrapper Functions

**Issue**: Users expect to run:
```powershell
Import-Module IdentityFirst.QuickChecks
Invoke-BreakGlassReality
```

But the module has no exported `Invoke-*` functions.

### 3. Inconsistent Report Format

**IFQC Framework Output** (from `Save-IFQCReport`):
```json
{
  "meta": { "toolName", "toolVersion", "runId", "host" },
  "summary": { "totalFindings", "critical", "high", "medium", "low" },
  "data": {},
  "findings": [{ "id", "title", "severity", "description", "count", "evidence" }],
  "notes": []
}
```

**Legacy Script Output**:
```json
{
  "CheckName": "...",
  "Timestamp": "...",
  "Summary": { ... },
  "Findings": [...]
}
```

## Recommended Fixes

### Option 1: Wrap Legacy Scripts as Module Functions

Create wrapper functions in `Module/IdentityFirst.QuickChecks.psm1`:

```powershell
function Invoke-BreakGlassReality {
    <#
    .SYNOPSIS
        Runs the Break-Glass Reality check.
    .DESCRIPTION
        Wrapper function that executes the standalone check script
        and returns results using the IFQC framework.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputPath = (Join-Path $PWD "IFQC-Output"),

        [Parameter()]
        [ValidateSet("Normal","Detailed")]
        [string]$DetailLevel = "Normal"
    )

    $ctx = New-IFQCContext -ToolName "BreakGlassReality" -ToolVersion "1.0.0" -OutputDirectory $OutputPath -DetailLevel $DetailLevel

    # Call the standalone script
    $scriptPath = Join-Path $PSScriptRoot "..\IdentityQuickChecks\BreakGlassReality.ps1"
    if (Test-Path $scriptPath) {
        try {
            . $scriptPath -OutputPath $OutputPath | ForEach-Object {
                # Convert legacy output to IFQC findings
                Add-IFQCFinding -Context $ctx -Finding @{
                    id = "BGA-001"
                    title = "Break-Glass Account Found"
                    severity = "High"
                    description = "Break-glass account detected: $($_.SamAccountName)"
                    count = 1
                    evidence = @($_)
                }
            }
        }
        catch {
            Write-IFQCLog -Context $ctx -Level ERROR -Message "Script failed: $($_.Exception.Message)"
        }
    }

    Save-IFQCReport -Context $ctx
}
```

### Option 2: Refactor Legacy Scripts to Use IFQC Framework

Update each legacy script to:
1. Import the module
2. Create context with `New-IFQCContext`
3. Use `Write-IFQCLog` instead of `Write-Host`
4. Use `New-IFQCFinding` for findings
5. Save report with `Save-IFQCReport`

### Option 3: Dual Output Support (Recommended)

Update legacy scripts to support both modes:

```powershell
param(
    [string]$OutputPath = ".",
    [switch]$UseFramework  # New switch for IFQC mode
)

if ($UseFramework) {
    $modulePath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    Import-Module (Join-Path $modulePath "Module\IdentityFirst.QuickChecks.psm1") -Force
    $ctx = New-IFQCContext -ToolName "BreakGlassReality" -OutputDirectory $OutputPath
    # ... use framework
}
else {
    # Original standalone mode
}
```

## Files Requiring Updates

### High Priority

| File | Current Issue | Fix |
|------|--------------|-----|
| `Module/IdentityFirst.QuickChecks.psd1` | Wrong export pattern | Fix FunctionsToExport |
| `IdentityQuickChecks/BreakGlassReality.ps1` | No IFQC support | Add wrapper or refactor |
| `IdentityQuickChecks/IdentityNamingHygiene.ps1` | No IFQC support | Add wrapper or refactor |
| `IdentityQuickChecks/PasswordPolicyDrift.ps1` | No IFQC support | Add wrapper or refactor |
| `IdentityQuickChecks/PrivilegedNestingAbuse.ps1` | No IFQC support | Add wrapper or refactor |

### Medium Priority

| File | Current Issue | Fix |
|------|--------------|-----|
| `IdentityTrustQuickChecks/ExternalTrustMapping.ps1` | No IFQC support | Add wrapper or refactor |
| `IdentityTrustQuickChecks/IdentityAttackSurface.ps1` | No IFQC support | Add wrapper or refactor |
| `IdentityBoundaryQuickChecks/CrossEnvironmentBoundary.ps1` | No IFQC support | Add wrapper or refactor |
| `IdentityBoundaryQuickChecks/IdentityTieringDrift.ps1` | No IFQC support | Add wrapper or refactor |

## Testing Checklist

After fixes, verify:

```powershell
# 1. Module imports without errors
Import-Module IdentityFirst.QuickChecks -Force

# 2. Commands are exported
Get-Command -Module IdentityFirst.QuickChecks | Select-Object -First 10

# 3. Invoke a check
Invoke-BreakGlassReality -OutputPath ".\test-output"

# 4. Check output format
Get-ChildItem ".\test-output\*.json" | ForEach-Object {
    $data = $_ | Get-Content | ConvertFrom-Json
    $data.meta.toolName  # Should be "BreakGlassReality"
    $data.summary.critical  # Should exist
}
```

## User Experience Goals

After fixes, users should be able to:

```powershell
# Simple usage
Import-Module IdentityFirst.QuickChecks
Invoke-BreakGlassReality

# Advanced usage
Invoke-BreakGlassReality -OutputPath "C:\Reports" -DetailLevel Detailed

# Get structured results
$result = Invoke-BreakGlassReality
$result.summary
$result.findings
```

## Next Steps

1. **Decide on approach**: Wrapper functions vs. refactoring vs. dual mode
2. **Update manifest**: Fix FunctionsToExport
3. **Create wrapper functions**: For top 5 legacy scripts
4. **Update documentation**: README with module usage examples
5. **Test thoroughly**: Verify all exports work correctly
