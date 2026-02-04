# Developer Tools — IdentityFirst QuickChecks

This `dev-tools/` folder contains helper scripts intended only for maintainers and developers of the repository. Items in this folder:

- `Create-SelfSignedCert.ps1` — Developer helper to create a local code-signing certificate and export a PFX/CER pair for signing scripts during development.

Security and distribution rules:

- Do NOT include `dev-tools/` contents or any generated private keys (`*.pfx`) in production packages or customer distributions.
- Keep private keys secure — store on encrypted volumes and rotate regularly.
- The repository `.gitignore` contains entries to avoid committing PFX/CER files; verify before committing.
- Anyone using these tools should understand they are for local development and testing only.

Usage example:

```powershell
# Run to create a new certificate and export PFX (interactive password prompt)
.\dev-tools\Create-SelfSignedCert.ps1

# Re-sign scripts using an existing PFX (interactive password prompt)
.\dev-tools\Create-SelfSignedCert.ps1 -ReSignOnly
```
