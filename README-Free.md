# IdentityFirst QuickChecks

**Free Identity Security Assessment Tools**

| | |
|---|---|
| Version | 2.2.0 |
| QuickChecks | 53+ |
| Platforms | AD, Entra ID, AWS, GCP, Okta |
| Tests | 79 Passing |
| PSSA | 0 Critical |

---

## Why QuickChecks?

**What makes IdentityFirst QuickChecks unique:**

| Capability | QuickChecks | PingCastle | BloodHound | M365DSC |
|------------|-------------|------------|------------|----------|
| **AD Assessment** | ✅ | ✅ | ✅ | ❌ |
| **Entra ID** | ✅ | ❌ | ❌ | ✅ |
| **AWS IAM** | ✅ | ❌ | ❌ | ❌ |
| **GCP IAM** | ✅ | ❌ | ❌ | ❌ |
| **Okta** | ✅ | ❌ | ❌ | ❌ |
| **No Agent Required** | ✅ | ✅ | ❌ | ✅ |
| **REST API** | ✅ | ❌ | ❌ | ❌ |
| **Webhooks** | ✅ | ❌ | ❌ | ❌ |
| **PowerShell 5.1** | ✅ | ✅ | ❌ | ✅ |
| **CI/CD Ready** | ✅ | ❌ | ❌ | ❌ |
| **SIEM Export** | ✅ | ❌ | ❌ | ❌ |

**Key Differentiators:**
1. **Multi-Platform** - Only free tool covering AD + Entra + AWS + GCP + Okta
2. **No Agents** - Instant results, no deployment
3. **Automation Ready** - API, webhooks, CI/CD pipelines
4. **Consultant Friendly** - Quick assessments, actionable output

**Use Cases:**
- Quick security posture review
- Multi-cloud identity assessment
- Pre-audit evidence collection
- Integration with SIEM/MDR


## Quick Start

```powershell
# Install
.\Install-QuickChecks.ps1 -InstallModules -TrustCertificate

# Run all checks
Invoke-AllIdentityQuickChecks -OutputPath .\Reports

# Quick assessment
Invoke-EnhancedSecurityAssessment -Verbose
```

## What's Included

### QuickChecks (53+)

| Platform | Checks | Examples |
|----------|--------|----------|
| Active Directory | 18 | DCSync, SID History, LAPS, AdminSDHolder |
| Entra ID | 9 | CA Analysis, Certificate Expiry, MFA |
| AWS | 5 | IAM Users, MFA Status, Access Keys |
| GCP | 3 | Service Accounts, IAM Roles |
| Okta | 8 | Inactive Users, MFA, Admin Roles |
| Identity Trust | 6 | Cross-environment, Trusts |
| Cross-Platform | 4 | Credential Hunting, API Exposure |

### New in v2.2

- **Okta QuickChecks** - 8 security checks for Okta orgs
- **Risk Scoring** - Calculate 0-100 organizational risk score
- **CI/CD** - GitHub Actions + Azure DevOps pipelines
- **SIEM** - Splunk, Sentinel, QRadar integration

## QuickCheck Examples

```powershell
# Okta
Invoke-OktaInactiveUsers
Invoke-OktaMfaStatus
Invoke-OktaAdminRoles

# Risk Score
$findings = Invoke-AllIdentityQuickChecks
$risk = Invoke-QuickChecksRiskScore -Findings $findings

# CA What-If
Invoke-EntraCAWhatIfSimulation -User "user@domain.com"

# AWS MFA
Invoke-AwsIamMfaCheck

# DCSync
Invoke-ADDcsyncRightsCheck -Domain $env:USERDOMAIN
```

## CI/CD Integration

### GitHub Actions
```yaml
name: Identity QuickChecks
on: [schedule]
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run QuickChecks
        run: pwsh -File Invoke-AllIdentityQuickChecks.ps1
```

### Azure DevOps
```yaml
steps:
- pwsh: |
    Install-Module IdentityFirst.QuickChecks -Force
    Invoke-AllIdentityQuickChecks
```

## SIEM Integration

```powershell
# Splunk
Send-ToSplunk -Finding $finding -SplunkUrl $url -HecToken $token

# Sentinel
Send-ToSentinel -Findings $findings -WorkspaceId $wsId

# QRadar
Send-ToQRadar -Finding $finding -SyslogServer $server
```

## Finding Structure

```json
{
    "Id": "BG-001",
    "Title": "Finding title",
    "Severity": "Critical",
    "Confidence": "High",
    "Remediation": "Fix steps...",
    "AffectedObjects": []
}
```

## Requirements

| Platform | Requirements |
|----------|--------------|
| PowerShell | 5.1 or 7+ |
| AD | Windows Server 2016+ |
| Entra ID | Azure AD Premium P1/P2 |
| AWS | AWS Tools for PowerShell |
| GCP | Google Cloud SDK |
| Okta | Okta SDK |

## Free vs Paid

| | Free (This) | Paid |
|--|---|---|
| Discovery | ✅ Snapshot | ✅ Continuous |
| Assessment | ✅ + What-If | ✅ Scheduled |
| CI/CD | ✅ | ✅ |
| SIEM Export | ✅ | ✅ |
| Remediation | Manual | Automated |
| Alerting | ❌ | 24/7 |
| Support | Community | Dedicated |

## Files

```
IdentityFirst-QuickChecks/
├── IdentityQuickChecks/
├── OktaQuickChecks/
├── Module/
├── Shared/
├── scripts/Obfuscated/
├── .github/
├── README.md
├── EULA.txt
└── IdentityFirst-Root-CA.cer
```

## Support

**Email:** info@identityfirst.net

---

**IdentityFirst Ltd** - Securing Identity Infrastructure
