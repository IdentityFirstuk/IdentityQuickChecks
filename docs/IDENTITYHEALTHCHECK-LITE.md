IdentityHealthCheck Lite

IdentityHealthCheck Lite is the lightweight, freely distributable collection of PowerShell modules in this repository. It provides a compact set of checks, collectors and helpers for identity-related auditing and reporting.

Key points

- Project name: IdentityHealthCheck Lite
- Scope: Lightweight collection of PowerShell modules (read-only by default for end-user flows)
- Distribution: Releases include ZIP, `SHA256SUMS.txt` and optional cosign/Rekor provenance entries.

Verification

Use the repository `tools/verify_release.ps1` and `tools/verify_cosign.ps1` helpers to validate releases.

Notes for maintainers

- This naming is a lightweight brand; existing filenames and module manifests remain unchanged unless you request renames.
- If you want I can update `README.md`, `docs/RELEASE_PROCESS.md`, and `docs/INSTALLER.md` to mention the `IdentityHealthCheck Lite` name explicitly.
