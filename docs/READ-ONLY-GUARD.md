# Read-Only Guard

This distribution is a read-only audit bundle. It is intended for inspection and reporting only — it will not modify your environment or repository files.

Key points
- The runtime flag `IFQC_READONLY=1` or the `-ReadOnly` parameter forces all engines and runners to operate in read-only mode.
- Fixer scripts that modify repository files are disabled or run in report-only mode in this free distribution (for example `.scripts/apply_safe_fixes.ps1` and `.scripts/pssa_fix_writehost.ps1`).
- A custom PSScriptAnalyzer rule `.scripts/pssa_readonly_rule.ps1` flags state-changing verbs for maintainers.

If you need privileged fixer tooling, request access to the maintainers' toolkit; do not run any fixer scripts you do not trust.

Usage
- Run the read-only app: `pwsh -NoProfile -ExecutionPolicy Bypass -File .\\tools\\IFQC-App.ps1 -Frameworks GDPR`
- Run the read-only runner: `pwsh -NoProfile -ExecutionPolicy Bypass -File .\\tools\\IFQC-ReadOnlyRunner.ps1 -OutputDir .\\IFQC-Audit-Out`

Output
- HTML reports are produced by `Shared/ReportFormatter.psm1`. The packager can optionally remove JSON artifacts when building an HTML-only release.
 
-Free verification (no-cost)
- The packager produces a `SHA256SUMS.txt` file in the release which lists SHA256 hashes for each file. Consumers should verify these checksums after unpacking.
- Use `tools/verify_release.ps1` to verify checksums before running the release. Example:

```powershell
# verify and fail on mismatch
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\verify_release.ps1 -ReleasePath . -FailOnMismatch
```

Optional stronger verification
- If you can use Sigstore/cosign (free) in CI, sign artifacts with cosign and publish Rekor entries; add cosign verification to runners when available.

Packager defaults
- The packager now produces an HTML-only release by default (it removes JSON artifacts). To include JSON artifacts in a release, run the packager with `-HtmlOnly:$false`.

Native module prototype (Option B)
- A small .NET prototype library has been added under `dotnet/IdentityFirst.QuickChecks.Core`. It exposes a sample check method `RunSampleCheck()` and is intended to host production-critical logic as compiled code.
- Build instructions:
	- Ensure .NET SDK (6.0+) is installed.
	- From the repo root run:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\.scripts\build_dotnet.ps1
```

	- The built DLL will be under `dotnet\IdentityFirst.QuickChecks.Core\bin\Release\net6.0\IdentityFirst.QuickChecks.Core.dll`.

- Use the PowerShell wrapper `Module\NativeChecks.psm1` (function `Invoke-NativeSampleCheck`) to call the compiled check and return JSON.
- For production, compile under CI, sign the assembly (Authenticode + strong name if desired), store build artifacts in `dotnet/bin/Release` and include them in the release ZIP. The packager already includes `dotnet/` in releases.

Read-only guard

Purpose

This project ships a read-only audit runner. By default the high-level runners and collectors should not perform any state-changing operations against upstream systems.

How it works

- `Identity-Audit-Engine.ps1` supports a `-ReadOnly` switch. When set, the engine enables a runtime guard that attempts to shadow state-changing cmdlets (verbs: `New`, `Set`, `Remove`, `Update`) exported by non-core modules to prevent accidental invocations.
- `Invoke-Collectors` accepts `-ReadOnly` and enables the guard around collector execution.
- External PowerShell collectors invoked from `collectors/*.ps1` receive `-ReadOnly` on their command line when present.
- External Python collectors receive an environment variable `IFQC_READONLY=1` when the engine is run read-only; collectors should honour this by avoiding writes.

Limitations

- The guard is best-effort: it creates shadowing `Function:\` entries to block common exported cmdlets but cannot intercept every possible code path.
- The guard does not replace least-privilege credentials or static analysis. For production use, prefer granting only read scopes and run collectors under dedicated identities.

Developer guidance

- Always run the main harness with `-ReadOnly` during qualification and CI.
- Implement `-ReadOnly` handling in custom collectors (PowerShell and Python) by checking the presence of the flag or `IFQC_READONLY` env var and avoiding writes.
- Consider adding a PSScriptAnalyzer rule to flag state-changing verbs in scripts intended to be read-only.

Examples

Run the health check in read-only mode (default):

```powershell
pwsh -NoProfile -File .\IdentityHealthCheck.ps1 -Frameworks GDPR -ReadOnly
```

Run the engine directly in read-only mode:

```powershell
pwsh -NoProfile -File .\Identity-Audit-Engine.ps1 -Frameworks GDPR -ReadOnly
```

Signing process (brief)

- **Local developer signing:** Use `dev-tools/Create-SelfSignedCert.ps1` to build a development PFX for testing. Keep the PFX private; do not include it in releases.
- **Packager signing:** The packager accepts `-SignPfxPath` and `-SignPfxPassword` to Authenticode-sign scripts before zipping. Supply a securely stored PFX (CI KeyVault/HSM) when performing production releases.
- **CI recommendations:** Sign artifacts in CI using a certificate stored in a secure store (Key Vault, HSM) or use your organization’s signing service. For public provenance, add Sigstore/cosign signing of the final ZIP and publish Rekor entries.
- **Verification:** Runners should verify signatures where required; for free distribution the packager emits `SHA256SUMS.txt` and `tools/verify_release.ps1` to validate integrity prior to execution.

Using HashiCorp Vault for PFX storage (CI)

- Recommended: store your PFX as a base64-encoded value under a KV secret with a key named `pfx` (KV v1 or KV v2 supported).
- This repository includes a helper script: `dev-tools/vault/get_pfx_from_vault.ps1` which fetches the secret using `VAULT_ADDR` and `VAULT_TOKEN` and writes a temporary PFX file for CI signing.
- CI flow example (GitHub Actions or similar):

```powershell
# set env vars in CI: VAULT_ADDR, VAULT_TOKEN
pwsh -NoProfile -File .\dev-tools\vault\get_pfx_from_vault.ps1 -SecretPath secret/ci/identityfirst/pfx -OutputPath $env:RUNNER_TEMP\identityfirst.pfx
# sign via packager
pwsh -NoProfile -File .\.scripts\package_release.ps1 -SignPfxPath $env:RUNNER_TEMP\identityfirst.pfx -SignPfxPassword (ConvertTo-SecureString $env:PFX_PASSWORD -AsPlainText -Force)
# remove artifact
Remove-Item $env:RUNNER_TEMP\identityfirst.pfx -Force
```

- Alternative: use Vault Transit or a signing agent that returns signatures rather than exporting private keys. That requires more custom tooling — for Authenticode, an exported PFX is simplest for now.

