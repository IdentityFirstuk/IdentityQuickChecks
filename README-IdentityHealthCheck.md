IdentityHealthCheck

Overview

`IdentityHealthCheck.ps1` is a high-level runner that calls the `Identity-Audit-Engine.ps1`, then summarizes the generated reports and produces a concise health status (Good / Warning / Critical) suitable for executive or operational review.

Usage

Run a health check for GDPR and get a one-line summary:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\IdentityHealthCheck.ps1 -Frameworks GDPR
```

Behavior

- Invokes the audit engine (collectors → assertions → framework lens).
- Reads `IFQC-Audit-Out/reports.json` and `IFQC-Audit-Out/findings.json`.
- Computes an aggregated health score and counts of high/critical findings.
- Prints a short human-friendly summary and emits a structured `Write-IFQC` object when available.

Next steps

- Integrate into CI to run on a schedule and fail when health is `Critical`.
- Add a dashboard adapter to push results to PagerDuty/Teams/Slack.
- Tune thresholds for your environment and map to ticketing workflows.
