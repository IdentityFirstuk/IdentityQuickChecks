## Release process (keyless signing, Rekor, packaging)

This document describes a low-cost, secure release flow that uses Sigstore (cosign + Rekor) with GitHub Actions (OIDC) to produce auditable releases.

## Branding & Upgrade Path

Releases built from this repository are branded as **IdentityHealthCheck Lite** for public distribution. To keep upgrade paths open to a fuller `IdentityHealthCheck` product:

- Keep internal module and manifest names stable across minor releases to avoid breaking existing consumers and automation.
- Produce both `*-lite` artifacts for public consumption and `*-full` artifacts for enterprise installs when you publish a fuller product.
- Include a `RELEASE_UPGRADE.md` entry in the release notes describing how to migrate (folder rename, manifest update, aliasing) so downstream integrators can opt-in.

Recommended practice: ship compatibility shims (small wrapper modules or alias exports) so scripts referencing the future `IdentityHealthCheck` module name continue to work when you introduce the full product.

1. Enable GitHub OIDC for your repository (no long-lived signing key needed):
   - In your repository Settings → Actions → General, set "Workflow permissions" to allow `Read and write permissions` for `id-token` via the job permissions or the workflow file.
   - The example workflow in `.github/workflows/sign-and-package.yml` sets `permissions: id-token: write` for keyless cosign.

2. Packaging in CI (what runs automatically):
   - CI checks out the repo, builds artifacts, and calls `.scripts/package_release.ps1 -HtmlOnly -OutputRoot releases`.
   - When running in GitHub Actions, the packager will enable cosign signing by default and upload cosign logs and `REKOR-ENTRIES-<runid>.txt` alongside the `releases/` ZIPs.

3. What is published to the website/CDN:
   - `IFQC-free-<version>.zip` (release ZIP)
   - `SHA256SUMS.txt` (checksums)
   - `REKOR-ENTRIES-<runid>.txt` (Rekor provenance evidence)
   - `cosign-*.log` (optional cosign logs)

4. How a customer verifies a release (zero-cost):
   - Download `IFQC-free-<version>.zip`, `SHA256SUMS.txt`, and `REKOR-ENTRIES-<runid>.txt` from your website.
   - Verify checksums:
     ```powershell
     pwsh -File tools\verify_release.ps1 -ReleasePath .\releases\IFQC-free-<version> -FailOnMismatch
     ```
   - Verify cosign/Rekor signature (keyless):
     ```powershell
     pwsh -File tools\verify_cosign.ps1 -ArtifactPath .\releases\IFQC-free-<version>.zip
     ```

5. Notes and recommendations:
   - Keyless cosign uses GitHub OIDC; enable `id-token: write` permission in workflows.
   - For extra assurance, keep `REKOR-ENTRIES-<runid>.txt` and publish it together with the release asset.
   - For enterprise customers, consider producing an MSI installer signed by your Authenticode certificate in a secure signing environment (HSM/KMS).

