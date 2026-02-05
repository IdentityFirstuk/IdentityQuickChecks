# IdentityFirst QuickChecks Security Guide

## Overview
IdentityFirst QuickChecks is a **read-only** security assessment toolkit. All scripts perform information gathering only - no modifications are made to any system.

## Security Principles

### 1. Local-Only Execution
- **All data stays local** - Reports are written only to user-specified paths
- **No data exfiltration** - No telemetry, no external data collection
- **No cloud dependencies** - Works entirely offline after initial module installation

### 2. Read-Only Operations
All cmdlets used are read-only:
- `Get-*` - Retrieve information
- `Test-*` - Validate conditions
- `Search-*` - Find patterns
- No `Set-`, `Update-`, `Remove-`, or `New-*` cmdlets that modify state

### 3. Credential Handling
- **No hardcoded credentials** - Zero secrets in the codebase
- **Uses existing sessions** - Leverages user's already-authenticated sessions
- **Supports multiple auth methods**:
  - Microsoft Graph (user login)
  - Active Directory (current user context)
  - AWS CLI (existing credentials)
  - GCP CLI (existing credentials)

## Output Security

### Report Storage
Reports are written to user-specified directories:
```
.\IFQC-Output\          # Default for Entra checks
.\Output\                # Default for Start-QuickChecks
.\Reports\               # Default for standalone scripts
```

### Protecting Reports
After running checks, secure your reports:

```powershell
# Windows - Remove inherited permissions
icacls ".\IFQC-Output" /remove:g "Users"
icacls ".\IFQC-Output" /grant:r "DOMAIN\User":(OI)(CI)F

# Linux/macOS - Restrict to owner
chmod 700 .\IFQC-Output
```

### Sensitive Data in Reports
Reports may contain:
- User principal names
- Account descriptions
- Distinguished names
- Group memberships

Treat these as sensitive documents.

## Execution Safety

### Recommended Execution Policy
```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Constrained Language Mode
The toolkit detects Constrained Language Mode and warns if not available:
```powershell
if ($ExecutionContext.SessionState.LanguageMode -eq 'ConstrainedLanguage') {
    Write-Warning "Constrained Language Mode detected - some features may be limited"
}
```

### Transcript Logging
Enable PowerShell transcript for audit trail:
```powershell
Start-Transcript -Path ".\QuickChecks-$(Get-Date -Format 'yyyyMMdd').log"
.\Start-QuickChecks.ps1
Stop-Transcript
```

## Verification

### Verify Read-Only Nature
Search for modifying cmdlets in the codebase:
```powershell
Select-String -Path . -Pattern '(Set-|Update-|Remove-|New-).*-Object' -Recurse
```

### Check for Hardcoded Secrets
```powershell
# Look for potential secrets
Select-String -Path . -Pattern '(password|secret|key|token|api).*[:=]' -Recurse
```

## Compliance Notes

This toolkit aligns with:
- **Read-only principle** - No changes to target systems
- **Audit trail capability** - Transcript logging supported
- **Least privilege** - Uses existing user permissions
- **Local data handling** - No external data transmission

## Support
- Documentation: [README.md](../README.md)
- Issues: https://github.com/IdentityFirstuk/IdentityFirst-Free/issues
- Author: mark.ahearne@identityfirst.net
