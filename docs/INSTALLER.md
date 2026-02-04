## Installation options for website-distributed releases

Recommendations
- For enterprise deployments prefer an MSI installer produced by your release pipeline (Windows Installer). MSIs integrate with management tools (SCCM, Intune) and allow centralized updates and uninstall.
- For easy public distribution from a website, provide a signed ZIP release plus a small signed PowerShell bootstrapper (`installer/bootstrap_install.ps1`) that downloads and verifies the release prior to installing.

What we added in this repo
- `installer/bootstrap_install.ps1`: a safe installer that downloads a release ZIP, verifies `SHA256SUMS.txt`, verifies Authenticode signatures (unless `-AllowUnsigned`), and copies files to `%ProgramFiles%\IdentityFirst\IFQC` by default.
- `docs/READ-ONLY-GUARD.md`: guidance on signing, Vault usage for PFX in CI, and packager options.

Website distribution flow (recommended)
1. CI builds release ZIP and signs scripts/assemblies (Authenticode) and optionally signs the ZIP with cosign.
2. CI publishes the ZIP to your website/CDN and exposes a stable `latest` URL.
3. Customers run the bootstrapper which downloads the ZIP, validates checksums and signatures, and installs.

Bootstrapper usage example

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\installer\bootstrap_install.ps1 -ReleaseUrl "https://example.com/releases/IFQC-free-20260131.zip"
```

CI notes
- Use secure storage (Vault, Key Vault) for PFX and retrieve it in CI (see `dev-tools/vault/get_pfx_from_vault.ps1`).
- Prefer HSM/transit-based signing if you cannot allow private keys to be exported.

Security notes
- Always serve releases via HTTPS and enable HSTS on your website.
- Do not tell users to run installers from random URLs without verifying signatures or checksums.

Cosign (Sigstore) verification
- The CI can optionally publish a cosign signature and Rekor transparency log entry for the release ZIP. This provides public, auditable provenance for artifacts.
- To verify a release ZIP using cosign (keyless), run:

```powershell
# download cosign if you don't have it
Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/sigstore/cosign/releases/latest/download/cosign-windows-amd64.exe' -OutFile .\cosign.exe
./cosign.exe verify --keyless --rekor https://rekor.sigstore.dev path\to\IFQC-free-<version>.zip
```

Or use the repository helper:

```powershell
pwsh -File tools\verify_cosign.ps1 -ArtifactPath path\to\IFQC-free-<version>.zip
```

If verification succeeds, cosign prints the signer identity and Rekor entry details. If it fails, do not run the installer and contact the vendor.

## Branding & Upgrade Path (Installer considerations)

Installer and release artifacts are labeled for public distribution as **IdentityHealthCheck Lite**. To maintain a smooth upgrade path to a future `IdentityHealthCheck` product:

- Keep the bootstrapper behavior flexible: the `-ReleaseUrl` parameter should accept either `*-lite.zip` or `*-full.zip` and validate via checksums and cosign evidence.
- When issuing a `full` product, publish both the `*-lite` and `*-full` ZIPs and include a migration note in the release assets explaining the differences and upgrade steps.
- Optionally provide an `upgrade` switch in `installer/bootstrap_install.ps1` that preserves user settings and can migrate files from the Lite layout to the Full layout.
