Purpose
- Define how we test and qualify the free, read-only PowerShell tooling (precursor to IdentityHealthCheck).

Acceptance criteria (high level)
- Read-only: no script performs write/state-changing actions by default; any action requires explicit `-WhatIf`/`-Confirm` and `-Credential` flows.
- Static quality: zero Critical PSScriptAnalyzer findings; < 10 warnings for non-critical stylistic items.
- Schema compliance: all collector outputs validate against `schemas/evidence.schema.json`.
- Functional: health-check run completes and produces structured `IFQC-Audit-Out` artifacts (evidence.json, findings.json, reports.json, findings.csv).
- Test coverage: smoke tests pass; qualification suite covers small/medium/large synthetic datasets.
- Security: no plaintext secret usage; dev-only env fallbacks clearly documented and safe.
- Reproducible CI: qualification suite runs in GitHub Actions with free runners and produces artifacts.

Qualification plan (steps)
1) Define acceptance criteria (above) and pass thresholds for health scores.
2) Create synthetic datasets and simple mock connectors for Entra/AD/AWS/GCP that mirror real responses.
3) Draft `schemas/evidence.schema.json` and implement lightweight validation in the engine.
4) Harden scripts per PSA: fix Critical findings, remove destructive defaults, enforce SecureString/PSCredential in high-impact scripts.
5) Build qualification runner: runs PSScriptAnalyzer, smoke tests, ingest synthetic datasets, run engine, validate outputs, collect results.
6) Add CI job to run the runner on push + weekly schedule, uploading artifacts.
7) Produce a concise Qualification Report + Runbook under `docs/`.

Metrics & reporting
- PSScriptAnalyzer: count by Severity (must be 0 Critical, < 10 Warning allowed).
- Schema validation: % of items passing schema across dataset sizes (target 100%).
- Health score distribution: OverallScore thresholds and sample failing controls.
- Run-time: median run time on GitHub runner for small/medium/large datasets.

Artifacts produced
- `docs/QUALIFY-READONLY-TOOLING.md` (this file)
- `schemas/evidence.schema.json` (draft)
- `tools/qualification-runner.ps1` (qualification harness) — optional next step
- CI workflow reference `.github/workflows/qualification.yml` (optional next step)

Next actions I can take now
- Create the draft evidence JSON Schema (`schemas/evidence.schema.json`).
- Implement a validator hook in `Identity-Audit-Engine.ps1` and run the qualification runner against the existing sample collectors.

Approve which next action and I'll proceed.