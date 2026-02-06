# IdentityFirst QuickChecks

**Free Identity Security Assessment Tools**

![Version](https://img.shields.io/badge/Version-2.0.0-blue)
![Tests](https://img.shields.io/badge/Tests-79%20Passing-green)
![Security](https://img.shields.io/badge/Security-Hardened-green)

A comprehensive PowerShell module for identity security assessments across Active Directory, Entra ID, AWS, and GCP.

## Features

### 🔍 Identity QuickChecks (35+ Checks)

| Category | Checks | Description |
|----------|--------|-------------|
| **Active Directory** | 17 | Privileged groups, password policies, account security |
| **Entra ID** | 5 | Guest accounts, legacy auth, MFA coverage |
| **AWS** | 4 | IAM users, access keys, policies |
| **GCP** | 3 | Service accounts, IAM roles |
| **Identity Trust** | 6 | Cross-environment, trust relationships |

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
# Import module
Import-Module IdentityQuickChecks

# Run all quick checks
Invoke-AllIdentityQuickChecks

# Run specific check
Invoke-BreakGlassReality
Invoke-GuestCreep
Invoke-MfaCoverageGap

# Get available commands
Get-Command -Module IdentityQuickChecks
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

| Platform | Status | Requirements |
|----------|--------|--------------|
| **Windows PowerShell 5.1** | ✅ Full Support | ActiveDirectory, AzureAD modules |
| **PowerShell 7+** | ✅ Full Support | Az, Microsoft.Graph modules |
| **Active Directory** | ✅ 17 Checks | Windows Server 2016+ |
| **Entra ID** | ✅ 5 Checks | Azure AD Premium P1/P2 |
| **AWS** | ✅ 4 Checks | AWS Tools for PowerShell |
| **GCP** | ✅ 3 Checks | Google Cloud SDK |

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

For issues and feature requests, please contact IdentityFirst support.

---

**IdentityFirst Ltd** - Securing Identity Infrastructure
