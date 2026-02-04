IFQC Audit — Action Plan
=========================

Context
-------
This repository contains a set of PowerShell scripts and modules that implement the IdentityFirst QuickChecks tooling. I ran the read-only health checks and PSScriptAnalyzer during the audit and found a set of non-functional and functional issues that are safe to fix automatically, plus higher-risk items that require manual review.

High-level recommendations
------------------------
- Run the read-only audit weekly and treat Critical → High findings as the highest priority.
- Apply the low-risk automatic fixes first (trailing-whitespace, encoding, simple Write-Host replacements, ensure `Output/` exists).
- Triage and manually remediate the medium/high risk items: password parameter conversions, complex Write-Host calls, scripts that perform state changes.
- Enforce read-only runtime for report-only tooling and gate state-changing scripts behind explicit switches and docs.

Short prioritized action list
-----------------------------
1. Ensure `Output/` exists before tests write artifacts. (Easy, safe)
2. Run a repo-wide trailing-whitespace and encoding normalization to UTF-8 (no BOM). (Safe)
3. Replace trivial `Write-Host 'text'` lines with `Write-IFQC` or `Write-Output` (non-destructive, back up files). (Safe)
4. Collect PSScriptAnalyzer results and re-run checks; review remaining `PSAvoidStateChangingInReadOnlyTools` findings. (Review)
5. Convert password-typed parameters to `SecureString`/`PSCredential` or accept credentials via `Get-Credential`/secret manager. (Manual)
6. Triage and safely wrap or exempt state-changing scripts behind `-ReadOnly` switches or `ShouldProcess`. (Manual)

Files added
-----------
- `.scripts/apply_safe_fixes.ps1` — safe, opt-in fixer for encoding, trailing whitespace, trivial `Write-Host` -> `Write-IFQC` replacement, and ensures `Output/` exists. Defaults to dry-run; requires `-Apply` to make changes.
- `.scripts/generate_fix_report.ps1` — generates a short Markdown report from `pssa-report.json` and the fixer summary.

Next steps
----------
- If you approve, run the fixer with `-Apply` to perform the safe edits. Review the generated `.bak` files for any unexpected changes.
- Manually review and patch password and state-changing findings listed in the analyzer report.

Commands
--------
Run a dry-run to see what would change:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\.scripts\apply_safe_fixes.ps1
```

Run and apply fixes:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\.scripts\apply_safe_fixes.ps1 -Apply
```
