# IFQC Fix Report
Generated: 2026-01-31T17:17:45.2759450+00:00

## Safe fixer summary
- Applied: False
- Files flagged: 32
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\.scripts\pssa_fix_writehost.ps1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\.scripts\run_psa_and_tests.ps1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Checks\AWS\Invoke-AwsIdentityInventory.ps1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Checks\Entra\Enhanced\Invoke-EntraEnhancedIdentity.ps1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Checks\Entra\Invoke-AppConsentReality.ps1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Checks\Entra\Invoke-GuestCreep.ps1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Checks\Entra\Invoke-HybridSyncReality.ps1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Checks\Entra\Invoke-LegacyAuthReality.ps1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Checks\Entra\Invoke-MfaCoverageGap.ps1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Checks\GCP\Invoke-GcpIdentityInventory.ps1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Checks\Invoke-InactiveAccountDetection.ps1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\dev-tools\Create-SelfSignedCert.ps1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\IdentityBoundaryQuickChecks\CrossEnvironmentBoundary.ps1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\IdentityBoundaryQuickChecks\IdentityTieringDrift.ps1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\IdentityQuickChecks\BreakGlassReality.ps1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\IdentityQuickChecks\IdentityNamingHygiene.ps1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\IdentityQuickChecks\PasswordPolicyDrift.ps1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\IdentityQuickChecks\PrivilegedNestingAbuse.ps1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\IdentityTrustQuickChecks\ExternalTrustMapping.ps1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Module\IdentityFirst.QuickChecks.psm1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Security\IdentityFirst.Security.psm1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Shared\ReportFormatter.psm1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Create-SelfSignedCert.ps1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Generate-CSR.ps1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Install-Prerequisites.ps1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Install-QuickChecks.ps1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Package-QuickChecks.ps1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\QuickChecks-Console.ps1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Run-AllQuickChecks.ps1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Sign-QuickChecks.ps1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Start-QuickChecks.ps1
  - D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Test-QuickChecks.ps1

## Top PSScriptAnalyzer findings (sample)
- [PSAvoidUsingWriteHost] D:\IdentityFirst-Ltd\web\2026web\powershell-modules\.scripts\run_psa_and_tests.ps1 -- File 'run_psa_and_tests.ps1' uses Write-Host. Avoid using Write-Host because it might not work in all hosts, does not work when there is no host, and (prior to PS 5.0) cannot be suppressed, captured, or redirected. Instead, use Write-Output, Write-Verbose, or Write-Information. (Line 5)
- [PSAvoidUsingWriteHost] D:\IdentityFirst-Ltd\web\2026web\powershell-modules\.scripts\run_psa_and_tests.ps1 -- File 'run_psa_and_tests.ps1' uses Write-Host. Avoid using Write-Host because it might not work in all hosts, does not work when there is no host, and (prior to PS 5.0) cannot be suppressed, captured, or redirected. Instead, use Write-Output, Write-Verbose, or Write-Information. (Line 35)
- [PSAvoidUsingWriteHost] D:\IdentityFirst-Ltd\web\2026web\powershell-modules\.scripts\run_psa_and_tests.ps1 -- File 'run_psa_and_tests.ps1' uses Write-Host. Avoid using Write-Host because it might not work in all hosts, does not work when there is no host, and (prior to PS 5.0) cannot be suppressed, captured, or redirected. Instead, use Write-Output, Write-Verbose, or Write-Information. (Line 42)
- [PSAvoidUsingWriteHost] D:\IdentityFirst-Ltd\web\2026web\powershell-modules\.scripts\run_psa_and_tests.ps1 -- File 'run_psa_and_tests.ps1' uses Write-Host. Avoid using Write-Host because it might not work in all hosts, does not work when there is no host, and (prior to PS 5.0) cannot be suppressed, captured, or redirected. Instead, use Write-Output, Write-Verbose, or Write-Information. (Line 43)
- [PSAvoidUsingWriteHost] D:\IdentityFirst-Ltd\web\2026web\powershell-modules\.scripts\run_psa_and_tests.ps1 -- File 'run_psa_and_tests.ps1' uses Write-Host. Avoid using Write-Host because it might not work in all hosts, does not work when there is no host, and (prior to PS 5.0) cannot be suppressed, captured, or redirected. Instead, use Write-Output, Write-Verbose, or Write-Information. (Line 44)
- [PSAvoidUsingWriteHost] D:\IdentityFirst-Ltd\web\2026web\powershell-modules\.scripts\run_psa_and_tests.ps1 -- File 'run_psa_and_tests.ps1' uses Write-Host. Avoid using Write-Host because it might not work in all hosts, does not work when there is no host, and (prior to PS 5.0) cannot be suppressed, captured, or redirected. Instead, use Write-Output, Write-Verbose, or Write-Information. (Line 48)
- [PSAvoidUsingWriteHost] D:\IdentityFirst-Ltd\web\2026web\powershell-modules\.scripts\run_psa_and_tests.ps1 -- File 'run_psa_and_tests.ps1' uses Write-Host. Avoid using Write-Host because it might not work in all hosts, does not work when there is no host, and (prior to PS 5.0) cannot be suppressed, captured, or redirected. Instead, use Write-Output, Write-Verbose, or Write-Information. (Line 49)
- [PSAvoidUsingWriteHost] D:\IdentityFirst-Ltd\web\2026web\powershell-modules\.scripts\run_psa_and_tests.ps1 -- File 'run_psa_and_tests.ps1' uses Write-Host. Avoid using Write-Host because it might not work in all hosts, does not work when there is no host, and (prior to PS 5.0) cannot be suppressed, captured, or redirected. Instead, use Write-Output, Write-Verbose, or Write-Information. (Line 50)
- [PSAvoidUsingWriteHost] D:\IdentityFirst-Ltd\web\2026web\powershell-modules\.scripts\run_psa_and_tests.ps1 -- File 'run_psa_and_tests.ps1' uses Write-Host. Avoid using Write-Host because it might not work in all hosts, does not work when there is no host, and (prior to PS 5.0) cannot be suppressed, captured, or redirected. Instead, use Write-Output, Write-Verbose, or Write-Information. (Line 52)
- [PSAvoidTrailingWhitespace] D:\IdentityFirst-Ltd\web\2026web\powershell-modules\.scripts\run_psa_and_tests.ps1 -- Line has trailing whitespace (Line 35)
- [PSAvoidStateChangingInReadOnlyTools] D:\IdentityFirst-Ltd\web\2026web\powershell-modules\.scripts\run_psa_and_tests.ps1 -- Invokes state-changing command 'Install-Module'. (Line 6)
- [PSAvoidTrailingWhitespace] D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Checks\AWS\Invoke-AwsIdentityInventory.ps1 -- Line has trailing whitespace (Line 24)
- [PSAvoidTrailingWhitespace] D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Checks\AWS\Invoke-AwsIdentityInventory.ps1 -- Line has trailing whitespace (Line 28)
- [PSAvoidTrailingWhitespace] D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Checks\AWS\Invoke-AwsIdentityInventory.ps1 -- Line has trailing whitespace (Line 49)
- [PSAvoidTrailingWhitespace] D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Checks\AWS\Invoke-AwsIdentityInventory.ps1 -- Line has trailing whitespace (Line 51)
- [PSAvoidTrailingWhitespace] D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Checks\AWS\Invoke-AwsIdentityInventory.ps1 -- Line has trailing whitespace (Line 56)
- [PSAvoidTrailingWhitespace] D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Checks\AWS\Invoke-AwsIdentityInventory.ps1 -- Line has trailing whitespace (Line 63)
- [PSAvoidTrailingWhitespace] D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Checks\AWS\Invoke-AwsIdentityInventory.ps1 -- Line has trailing whitespace (Line 69)
- [PSAvoidTrailingWhitespace] D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Checks\AWS\Invoke-AwsIdentityInventory.ps1 -- Line has trailing whitespace (Line 90)
- [PSAvoidTrailingWhitespace] D:\IdentityFirst-Ltd\web\2026web\powershell-modules\Checks\AWS\Invoke-AwsIdentityInventory.ps1 -- Line has trailing whitespace (Line 106)

## Next recommended manual actions
- Inspect the listed files and backups (.bak.*) for unintended edits.
- Manually convert sensitive password params to SecureString/PSCredential.
- Triage PSAvoidStateChangingInReadOnlyTools entries and add -ReadOnly guards or ShouldProcess around state-changing code.
