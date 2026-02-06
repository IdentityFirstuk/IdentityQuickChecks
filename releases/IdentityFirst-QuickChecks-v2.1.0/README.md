# IdentityFirst QuickChecks

**Free Identity Security Assessment Tools**

![Version](https://img.shields.io/badge/Version-2.1.0-blue)
![Tests](https://img.shields.io/badge/Tests-100%2B%20Passing-green)
![Security](https://img.shields.io/badge/Security-Hardened-green)

A comprehensive PowerShell module for identity security assessments across Active Directory, Entra ID, AWS, and GCP.

## ✨ What's New in v2.1.0

| Feature | Description |
|---------|-------------|
| **Conditional Access Analysis** | Analyze CA policies for MFA requirements, legacy auth blocking, and security gaps |
| **CA What-If Simulation** | Simulate access scenarios without modifying policies |
| **Certificate Expiry Monitoring** | Track expiring service principal certificates and secrets |
| **DCSync Rights Detection** | Identify accounts with DCSync extended rights |
| **MFA Status Verification** | Verify MFA enforcement across AWS IAM users |
| **Progress Indicators** | Real-time execution progress with ETA |
| **Executive Summaries** | Formatted summary reports with risk posture |

---

## Features

### 🔍 Identity QuickChecks (42+ Checks)

#### Core QuickChecks
| Category | Checks | Description |
|----------|--------|-------------|
| **Active Directory** | 18 | Privileged groups, password policies, DCSync detection, LAPS |
| **Entra ID** | 9 | Guest accounts, legacy auth, MFA coverage, CA analysis |
| **AWS** | 5 | IAM users, access keys, MFA status, permissive roles |
| **GCP** | 3 | Service accounts, IAM roles |
| **Identity Trust** | 6 | Cross-environment, trust relationships |
| **Cross-Platform** | 4 | Credential hunting, session risks, API exposure |

#### Enhanced QuickChecks (v2.1.0)

| Check ID | Function | Description | Severity |
|----------|----------|-------------|----------|
| ENT-CERT-001 | `Invoke-EntraCertificateExpiryCheck` | Monitor app registration certificates | High |
| ENT-CONDACC-001 | `Invoke-EntraConditionalAccessAnalysis` | Analyze CA policy gaps | High |
| ENT-CONDACC-002 | `Invoke-EntraCAWhatIfSimulation` | Simulate access scenarios | Medium |
| ENT-CONDACC-003 | `Invoke-EntraCAGapAnalysis` | CA framework compliance | Medium |
| AWS-MFA-001 | `Invoke-AwsIamMfaCheck` | Verify IAM user MFA status | High |
| AD-DCSYNC-001 | `Invoke-ADDcsyncRightsCheck` | Detect DCSync rights | Critical |


### 📊 Reporting

- **Confidence Scoring** - High/Medium/Low reliability indicators
- **Evidence Quality** - Direct/Indirect/Inferred classification
- **Priority Scoring** - Severity × Confidence weighted ranking
- **Actionable Remediation** - Step-by-step fix instructions

### 🔒 Security

- **Digitally Signed** - All scripts signed with code signing certificate
- **No Hardcoded Credentials** - Secure credential handling
- **Input Validation** - Sanitized inputs and path traversal protection
- **Audit Logging** - Security event tracking

## Quick Start

### Installation

```powershell
# Option 1: Install with certificate trust (recommended)
.\Install-QuickChecks.ps1 -InstallModules -TrustCertificate

# Option 2: Manual installation
# 1. Copy to ProgramData
Copy-Item -Path 'IdentityQuickChecks' -Destination "$env:ProgramData\IdentityFirst\QuickChecks\" -Recurse

# 2. Import module
Import-Module "$env:ProgramData\IdentityFirst\QuickChecks\IdentityQuickChecks"
```

### Usage

```powershell
# Import enhanced module
Import-Module .\IdentityFirst.QuickChecks.Enhanced.psm1

# Run all enhanced quick checks
Invoke-EnhancedSecurityAssessment -Verbose

# Run individual checks
Invoke-EntraCertificateExpiryCheck -WarningThreshold 60 -CriticalThreshold 30
Invoke-EntraConditionalAccessAnalysis
Invoke-EntraCAWhatIfSimulation -UserPrincipalName "user@domain.com"
Invoke-AwsIamMfaCheck
Invoke-ADDcsyncRightsCheck -Domain $env:USERDOMAIN

# Get available commands
Get-Command -Module IdentityFirst.QuickChecks.Enhanced
```

### CA What-If Simulation Example

```powershell
# Simulate access for a user
$simulation = Invoke-EntraCAWhatIfSimulation `
    -UserPrincipalName "analyst@contoso.com" `
    -TargetApplications @("Office 365", "Azure Portal") `
    -Location "External" `
    -DeviceState "Non-Compliant"

# Output shows predicted access outcomes
$simulation | Format-List
```


### Generate Report

```powershell
# Generate executive summary
$findings = Invoke-AllIdentityQuickChecks
$summary = New-QuickChecksExecutiveSummary -Findings $findings
$summary | Format-Table

# Export to JSON
Export-QuickChecksFinding -Findings $findings -OutputPath ".\identity-audit-report.json"
```

## Finding Object Structure

All findings follow a standardized format:

```json
{
    "Id": "BG-001",
    "RuleId": "SEC-EMERG-001",
    "Title": "Break-glass accounts with password never expires",
    "Description": "Break-glass emergency accounts should have strict expiration...",
    "Severity": "Critical",
    "Confidence": "High",
    "EvidenceQuality": "Direct",
    "ReliabilityScore": 100,
    "PriorityScore": 100,
    "AffectedObjects": ["BG-Admin1", "breakglass"],
    "Remediation": "Implement 90-day password rotation for break-glass accounts",
    "RemediationSteps": [
        "Review all break-glass accounts",
        "Enable password expiration policy",
        "Document rotation procedures"
    ],
    "Timestamp": "2026-02-06T15:00:00Z",
    "Source": "BreakGlassReality",
    "Category": "EmergencyAccess",
    "IsResolved": false
}
```

### Confidence Levels

| Level | Criteria | Use Case |
|-------|----------|----------|
| **High** | Direct evidence, multiple sources | Immediate action recommended |
| **Medium** | Some corroboration | Investigate further |
| **Low** | Inferred, heuristic-based | Low priority, verify manually |

### Evidence Quality

| Quality | Definition | Example |
|---------|------------|---------|
| **Direct** | Actual directory query | `Get-ADUser -Filter *` |
| **Indirect** | API response data | Microsoft Graph responses |
| **Inferred** | Calculated patterns | Risk score algorithms |

## Supported Platforms

| Platform | Status | Checks | Requirements |
|----------|--------|--------|--------------|
| **Windows PowerShell 5.1** | ✅ Full Support | All | ActiveDirectory, AzureAD modules |
| **PowerShell 7+** | ✅ Full Support | All | Az, Microsoft.Graph modules |
| **Active Directory** | ✅ 18 Checks | DCSync, SID History, LAPS | Windows Server 2016+ |
| **Entra ID** | ✅ 9 Checks | CA Analysis, Certificates, PIM | Azure AD Premium P1/P2 |
| **AWS** | ✅ 5 Checks | IAM, MFA, Access Keys | AWS Tools for PowerShell |
| **GCP** | ✅ 3 Checks | Service Accounts, IAM | Google Cloud SDK |

---

## Philosophy

> **"QuickChecks tells you what's wrong (including what would happen). Paid tools fix and monitor."**

| Capability | Free (QuickChecks) | Paid Offerings |
|------------|-------------------|----------------|
| **Discovery** | ✅ Snapshot assessment | ✅ Continuous monitoring |
| **Assessment** | ✅ One-time + What-If | ✅ Scheduled scans |
| **Simulation** | ✅ CA What-If analysis | ✅ Full policy simulation |
| **Reporting** | ✅ Export to JSON/HTML | ✅ Real-time dashboards |
| **Remediation** | ⚠️ Manual steps only | ✅ Automated workflows |
| **Alerting** | ❌ Not included | ✅ 24/7 alerting |
| **Integration** | ✅ Webhooks | ✅ ServiceNow, Jira |

---

## Project Structure

```
IdentityFirst-QuickChecks/
├── IdentityQuickChecks/          # Core AD checks
├── IdentityAssumptionQuickChecks/ # Identity assumption checks
├── IdentityBoundaryQuickChecks/  # Boundary checks
├── IdentityTrustQuickChecks/     # Trust relationship checks
├── Module/                       # PowerShell modules
├── Scripts/                     # Utility scripts
├── Tests/                       # Pester tests
├── docs/                        # Documentation
└── sample-output/              # Example reports
```

## Testing

```powershell
# Run all tests
Invoke-Pester -Path './Tests/' -Output Detailed

# Run specific test file
Invoke-Pester -Path './Tests/IdentityFirst.QuickChecks.Core.Tests.ps1'
```

## Security

### Certificate Information

- **Issuer**: IdentityFirst Ltd
- **Thumbprint**: 602A77B6D1CAC3C6AD875CBED65A8D227BF77189
- **Valid**: 5 years from issue date

### Credential Handling

All credentials are handled securely:
- `Get-SecureCredential` - Multi-source credential retrieval
- Windows Credential Manager integration
- Environment variable support
- Interactive prompts for sensitive data

## Documentation

- [Code Review Summary](docs/CODE-REVIEW-SUMMARY.md)
- [Security Hardening Report](Security-Hardening-Report.md)
- [PSSA Quality Report](PSSA-Quality-Report.md)

## License

This project is proprietary software by IdentityFirst Ltd.

## Support

For issues and feature requests:
- **Email**: info@identityfirst.net
- **Documentation**: [docs/FREE-TOOLING-COMPARISON.md](docs/FREE-TOOLING-COMPARISON.md)
- **Enhancement Plan**: [docs/ENHANCEMENT-PLAN.md](docs/ENHANCEMENT-PLAN.md)

---

**IdentityFirst Ltd** - Securing Identity Infrastructure

---

**IdentityFirst Ltd** - Securing Identity Infrastructure
