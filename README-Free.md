# IdentityFirst QuickChecks — Free (Read-Only)

Quick start

1. Unzip the release to a folder.
2. Open PowerShell (Windows PowerShell 5.1 or PowerShell 7+ supported).
3. Run the bundled read-only app (forces `IFQC_READONLY`):

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\IFQC-App.ps1 -Frameworks GDPR
```

By default the packager produces an HTML-only release (JSON artifacts are removed). To include JSON artifacts pass `-HtmlOnly:$false` to the packager.

Or run the runner to generate an HTML report index:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\IFQC-ReadOnlyRunner.ps1 -OutputDir .\IFQC-Audit-Out
```

Read-only guarantees
- Free distribution is read-only: fixer scripts that change files are disabled or run in report-only mode.

Support and full tooling
- To get privileged fixer tooling or to contribute fixes, contact the maintainers as described in the main project documentation.
