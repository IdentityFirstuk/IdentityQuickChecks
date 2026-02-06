# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.0.x | ✅ Yes |
| 1.0.x | ⚠️ Limited |

## Reporting a Vulnerability

To report a security vulnerability, please contact:

**Email**: security@identityfirst.co.uk

Do NOT open public issues for security vulnerabilities.

## Security Features

### Code Signing
All scripts are digitally signed with IdentityFirst code signing certificate.
- Certificate Subject: CN=IdentityFirst Code Signing CA, O=IdentityFirst Ltd
- Verify with: `Get-AuthenticodeSignature -FilePath <script>.ps1`

### Secure Credential Handling
- Credentials passed via PSCredential objects
- SecureString used for sensitive data in memory
- No hardcoded credentials in any script

### Input Validation
- All user parameters validated with `[ValidateNotNullOrEmpty()]`
- Type checking on all inputs
- SQL/command injection prevention patterns

### Module Security
- Module manifests restrict exported functions
- Private functions not exposed to consumers
- Audit logging on sensitive operations

## Best Practices for Users

1. **Install root CA** for signature verification:
   ```powershell
   Import-Certificate -FilePath 'IdentityFirst-Root-CA.cer' -CertStoreLocation Cert:\LocalMachine\Root
   ```

2. **Verify signatures** before running:
   ```powershell
   Get-AuthenticodeSignature -FilePath .\scripts\Obfuscated\Invoke-AllIdentityQuickChecks.ps1
   ```

3. **Use least-privilege** service accounts for execution

4. **Review permissions** before running in production

5. **Store credentials** securely, never in scripts

## Audits Passed
- ✅ PSSA Security Analysis: 0 critical issues
- ✅ Hardcoded Credential Scan: 0 found
- ✅ Pester Test Suite: 79 passing

---

For questions about this security policy, contact security@identityfirst.co.uk

© 2026 IdentityFirst Ltd.
