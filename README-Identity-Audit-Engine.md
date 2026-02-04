Identity Audit Engine (PowerShell)

Overview

This lightweight audit engine normalizes evidence from collectors and evaluates assertions against framework lenses (example: GDPR). It outputs JSON and a simple CSV for auditors.

Quick run

Run the engine for GDPR and write JSON + CSV:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\Identity-Audit-Engine.ps1 -Frameworks GDPR
# outputs written to IFQC-Audit-Out and audit_run.json; CSV as findings.csv
```

Files

- `Identity-Audit-Engine.ps1` — main engine, assertions, and exporters.
- `frameworks/` — JSON lenses (GDPR sample included).

Next steps

- Implement real collectors (Graph API, AD, AWS) to replace sample evidence.
- Add more framework lenses (ISO27001, NIST) and weighting rules.
- Integrate with `Shared/ReportFormatter.psm1` for PDF/HTML packs.
