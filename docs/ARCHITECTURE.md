# IdentityFirst QuickChecks - Architecture Documentation

## Executive Summary

IdentityFirst QuickChecks is a comprehensive PowerShell-based identity security assessment platform with **106+ security checks** across **9 module files**. It provides organizations with actionable insights into their identity security posture across Microsoft Entra ID, Azure, AWS, GCP, Active Directory, Okta, and hybrid identity implementations.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Module Breakdown](#module-breakdown)
3. [Check Taxonomy](#check-taxonomy)
4. [Data Flow](#data-flow)
5. [Reporting Structure](#reporting-structure)
6. [Integration Points](#integration-points)
7. [Platform Coverage Matrix](#platform-coverage-matrix)
8. [Security Domains](#security-domains)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         IdentityFirst QuickChecks                            │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                        Entry Points                                  │    │
│  │  • Invoke-AllIdentityQuickChecks.ps1 (Main Runner)                  │    │
│  │  • Run-AllQuickChecks.ps1 (Legacy Runner)                           │    │
│  │  • New-QuickChecksDashboard.ps1 (HTML Dashboard)                    │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                         │
│                                    ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                     Module Loader                                    │    │
│  │  • PowerShell 5.1 Compatible                                        │    │
│  │  • Import-Module Pattern                                           │    │
│  │  • Error Handling Wrapper                                          │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                         │
│                    ┌────────────────┼────────────────┐                      │
│                    ▼                ▼                ▼                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐                │
│  │  Core    │  │ Entra ID  │  │ Extended │  │Validation│                │
│  │  (8)     │  │  (16)    │  │  (13)    │  │  (10)    │                │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘                │
│                    ┌────────────────┼────────────────┐                      │
│                    ▼                ▼                ▼                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐                │
│  │Additional│  │Extended2 │  │Compliance│  │Enterprise│  Federation    │
│  │  (12)   │  │  (15)    │  │  (12)    │  │  (11)    │    (9)         │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
│                                    │                                         │
│                                    ▼                                         │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                     Report Generator                                 │    │
│  │  • JSON Output                                                     │    │
│  │  • HTML Dashboard                                                  │    │
│  │  • Console Summary                                                  │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Module Breakdown

### 1. IdentityFirst.QuickChecks.Lite.psm1 (8 checks)
**Focus**: Azure RBAC, PBAC, ABAC Security

| Check ID | Category | Severity | Description |
|----------|----------|----------|-------------|
| IDF-AZ-RBAC-001 | Azure RBAC | High | Wide Scope Role Assignments |
| IDF-AZ-RBAC-002 | Azure RBAC | High | Overprivileged Role Assignments |
| IDF-AZ-RBAC-003 | Azure RBAC | Medium | Classic Administrator Detection |
| IDF-AZ-RBAC-004 | Azure RBAC | Medium | Permanent Role Assignments |
| IDF-AZ-POL-001 | Azure Policy | Medium | Policy Exemption Review |
| IDF-AZ-POL-002 | Azure Policy | Medium | Policy Effect Analysis |
| IDF-AZ-ABAC-001 | Azure ABAC | High | Conditional Access Grant All |
| IDF-AZ-ABAC-002 | Azure ABAC | Medium | Legacy Auth Blocking Analysis |

### 2. IdentityFirst.QuickChecks.EntraID.psm1 (16 checks)
**Focus**: Microsoft Entra ID Security

| Check ID | Category | Severity | Description |
|----------|----------|----------|-------------|
| IDF-ENT-MFA-001 | MFA | Critical | MFA Coverage Gap Detection |
| IDF-ENT-MFA-002 | MFA | High | MFA Policy Assessment |
| IDF-ENT-PIM-001 | PIM | High | Privileged Identity Management |
| IDF-ENT-GUEST-001 | Guest Users | Medium | Guest User Creep Detection |
| IDF-ENT-LEGACY-001 | Legacy Auth | High | Legacy Authentication Reality |
| IDF-ENT-HYBRID-001 | Hybrid Sync | Medium | Hybrid Identity Sync Reality |
| IDF-ENT-CONSENT-001 | App Consent | Medium | Application Consent Reality |
| IDF-ENT-PWB-001 | Password Writeback | Medium | Password Writeback Status |
| IDF-ENT-RISK-001 | Risk Policies | High | Risk-Based Policy Assessment |
| IDF-ENT-ADMIN-001 | Admin Consent | High | Administrative Consent Review |
| IDF-ENT-B2B-001 | B2B | Medium | B2B External Collaboration |
| IDF-ENT-DEV-001 | Devices | Medium | Device Compliance Assessment |
| IDF-ENT-DMARC-001 | Domain Security | High | DMARC Policy Configuration |
| IDF-ENT-APP-001 | App Registrations | Medium | Application Registration Review |
| IDF-ENT-SP-001 | Service Principals | Medium | Service Principal Assessment |
| IDF-ENT-COND-001 | Conditional Access | High | Conditional Access Comprehensive |

### 3. IdentityFirst.QuickChecks.Extended.psm1 (13 checks)
**Focus**: AWS, GCP, and AD Security

| Check ID | Category | Severity | Description |
|----------|----------|----------|-------------|
| IDF-AWS-IAM-001 | AWS IAM | High | IAM Policy Assessment |
| IDF-AWS-S3-001 | AWS S3 | Critical | Public S3 Bucket Detection |
| IDF-AWS-VPC-001 | AWS VPC | High | VPC Flow Log Configuration |
| IDF-AWS-MFA-001 | AWS IAM | Critical | Root Account MFA Verification |
| IDF-GCP-IAM-001 | GCP IAM | High | GCP IAM Policy Assessment |
| IDF-GCP-VPC-001 | GCP VPC | High | VPC Service Control Review |
| IDF-GCP-ORG-001 | GCP Org | Medium | GCP Organization Policy Check |
| IDF-GCP-SA-001 | GCP SA | High | Service Account Key Rotation |
| IDF-AD-SID-001 | AD Security | High | SID History Audit |
| IDF-AD-KCD-001 | AD Security | High | Constrained Delegation Review |
| IDF-AD-LAPS-001 | AD Security | Medium | LAPS Implementation Check |
| IDF-AD-ADMIN-001 | AD Security | High | Admin Count Attribute Review |
| IDF-AD-DNS-001 | AD Security | Medium | Duplicate SPN Detection |

### 4. IdentityFirst.QuickChecks.Validation.psm1 (10 checks)
**Focus**: Security, Trust, and Configuration Validation

| Check ID | Category | Severity | Description |
|----------|----------|----------|-------------|
| IDF-VAL-SEC-001 | Security | High | Hardcoded Secret Detection |
| IDF-VAL-SEC-002 | Security | Medium | Least Privilege Validation |
| IDF-VAL-SEC-003 | Security | High | Code Signing Verification |
| IDF-VAL-SEC-004 | Security | Medium | File Integrity Check |
| IDF-VAL-TRUST-001 | Trust | High | Cross-Environment Trust Mapping |
| IDF-VAL-TRUST-002 | Trust | Medium | Identity Attack Surface Mapping |
| IDF-VAL-CFG-001 | Configuration | Medium | Prerequisites Validation |
| IDF-VAL-CFG-002 | Configuration | High | Connectivity Validation |
| IDF-VAL-CFG-003 | Configuration | Medium | Configuration Drift Detection |
| IDF-VAL-IDM-001 | Identity Model | Medium | Tiering Model Assessment |

### 5. IdentityFirst.QuickChecks.Additional.psm1 (12 checks)
**Focus**: Additional Cloud Security Checks

| Check ID | Category | Severity | Description |
|----------|----------|----------|-------------|
| IDF-SYS-PREREQ-001 | System | Medium | Prerequisites Validation |
| IDF-ENT-AR-001 | Entra ID | Medium | Access Review Configuration |
| IDF-ENT-EM-001 | Entra ID | Medium | Entitlement Management Check |
| IDF-ENT-CA-003 | Entra ID | High | Named Locations Review |
| IDF-AZ-SC-001 | Azure | Medium | Security Center Configuration |
| IDF-AZ-DF-001 | Azure | Medium | Defender Plan Coverage |
| IDF-AD-LK-001 | AD | Medium | Account Lockout Policy |
| IDF-AD-KR-001 | AD | Medium | Kerberos Ticket Lifetime |
| IDF-AWS-CT-001 | AWS | High | CloudTrail Configuration |
| IDF-AWS-GD-001 | AWS | High | GuardDuty Configuration |
| IDF-GCP-SCC-001 | GCP | High | Security Command Center |
| IDF-GCP-SAK-001 | GCP | High | Service Account Key Management |

### 6. IdentityFirst.QuickChecks.Extended2.psm1 (15 checks)
**Focus**: Advanced Platform Security

| Check ID | Category | Severity | Description |
|----------|----------|----------|-------------|
| IDF-ENT-AU-001 | Entra ID | Medium | Administrative Unit Review |
| IDF-ENT-PG-001 | Entra ID | High | OAuth Permission Grants |
| IDF-ENT-TL-001 | Entra ID | Medium | Token Lifetime Configuration |
| IDF-AZ-PE-001 | Azure | Medium | Private Endpoint Review |
| IDF-AZ-VPN-001 | Azure | Medium | VNet Peering Security |
| IDF-AZ-FW-001 | Azure | Medium | Firewall Policy Assessment |
| IDF-AD-DSPN-001 | AD | High | Duplicate SPN Detection |
| IDF-AD-AC-001 | AD | Low | Admin Count Review |
| IDF-AD-RODC-001 | AD | Medium | RODC Configuration |
| IDF-AWS-IAA-001 | AWS | High | IAM Access Analyzer |
| IDF-AWS-VPC-001 | AWS | Medium | VPC Flow Logs |
| IDF-AWS-CONFIG-001 | AWS | Medium | AWS Config Conformance |
| IDF-GCP-ORG-001 | GCP | High | Organization Policy |
| IDF-GCP-VPCSC-001 | GCP | High | VPC Service Controls |
| IDF-GCP-ARMOR-001 | GCP | Medium | Cloud Armor Security |

### 7. IdentityFirst.QuickChecks.Compliance.psm1 (12 checks)
**Focus**: Compliance and Advanced Security

| Check ID | Category | Severity | Description |
|----------|----------|----------|-------------|
| IDF-ENT-CA-GA-001 | Entra ID | Critical | CA Grant All Policies |
| IDF-ENT-B2B-001 | Entra ID | High | External Collaboration |
| IDF-ENT-CERT-001 | Entra ID | High | Certificate Expiry |
| IDF-AAD-CONN-001 | Hybrid | Medium | AAD Connect Health |
| IDF-AAD-AF-001 | Hybrid | Medium | Attribute Flow Security |
| IDF-AZ-KV-001 | Azure | High | Key Vault Expiry |
| IDF-AZ-KV-AP-001 | Azure | High | Key Vault Access Policy |
| IDF-AWS-IAM-PW-001 | AWS | Medium | IAM Password Policy |
| IDF-AWS-IAM-UC-001 | AWS | High | Unused Credentials |
| IDF-AWS-IAM-MFA-001 | AWS | Critical | MFA Enforcement |
| IDF-GCP-MON-001 | GCP | High | Organization Monitoring |
| IDF-GCP-ASSET-001 | GCP | Medium | Asset Inventory |

### 8. IdentityFirst.QuickChecks.Enterprise.psm1 (11 checks)
**Focus**: Enterprise Security

| Check ID | Category | Severity | Description |
|----------|----------|----------|-------------|
| IDF-AD-CS-001 | AD CS | High | AD CS Configuration |
| IDF-AD-CS-TPL-001 | AD CS | High | Certificate Template Security |
| IDF-PAW-001 | PAW | High | PAW Configuration |
| IDF-EOP-001 | Email | High | Exchange Online Protection |
| IDF-EOP-DMARC-001 | Email | High | Domain Authentication |
| IDF-SENT-001 | SIEM | Medium | Azure Sentinel |
| IDF-AKS-001 | Kubernetes | High | AKS Security |
| IDF-K8S-POD-001 | Kubernetes | High | Pod Security Standards |
| IDF-SQL-001 | Database | High | Azure SQL Security |
| IDF-COSMOS-001 | Database | High | Cosmos DB Security |
| IDF-ZT-001 | Zero Trust | Medium | Zero Trust Readiness |

### 9. IdentityFirst.QuickChecks.Federation.psm1 (9 checks)
**Focus**: Federation, Okta, Backup, APIM

| Check ID | Category | Severity | Description |
|----------|----------|----------|-------------|
| IDF-OKTA-ORG-001 | Okta | High | Organization Security |
| IDF-OKTA-POL-001 | Okta | Medium | Policy Configuration |
| IDF-OKTA-APP-001 | Okta | Medium | Application Security |
| IDF-ADFS-001 | ADFS | High | ADFS Configuration |
| IDF-FED-TRUST-001 | Federation | Medium | Federation Trust Review |
| IDF-AZ-BACKUP-001 | Backup | High | Azure Backup Security |
| IDF-AWS-BACKUP-001 | Backup | Medium | AWS Backup Configuration |
| IDF-AD-BACKUP-001 | Backup | High | AD Backup Configuration |
| IDF-AZ-APIM-001 | APIM | High | API Management Security |

---

## Check Taxonomy

### Severity Levels

| Severity | Color | Response Time | Description |
|----------|-------|---------------|-------------|
| **Critical** | Red | Immediate | Active exploitation risk |
| **High** | Orange | 24-48 hours | Significant vulnerability |
| **Medium** | Yellow | 1-2 weeks | Configuration weakness |
| **Low** | Blue | As needed | Best practice gap |

### Status States

| Status | Description |
|--------|-------------|
| **Pass** | Check completed, no issues found |
| **Fail** | Security issue detected |
| **Warning** | Potential issue, requires review |
| **Error** | Check could not complete |
| **Skipped** | Prerequisites not met |

### Categories

| Category | Count | Examples |
|----------|-------|----------|
| Azure | 30+ | RBAC, Policy, Key Vault, Backup |
| Entra ID | 30+ | MFA, PIM, CA, App Registration |
| AWS | 15+ | IAM, GuardDuty, CloudTrail |
| GCP | 10+ | IAM, Organization, SCC |
| Active Directory | 15+ | CS, LAPS, SID History |
| Okta | 3 | Organization, Policy, Applications |
| Federation | 2 | ADFS, Trust Relationships |
| Email | 2 | SPF/DKIM/DMARC, EOP |
| Kubernetes | 2 | AKS, Pod Security |
| Database | 2 | Azure SQL, Cosmos DB |
| Backup | 3 | Azure, AWS, AD |

---

## Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Data Flow                                      │
└─────────────────────────────────────────────────────────────────────────────┘

    ┌─────────────┐
    │   User      │
    └──────┬──────┘
           │ Invoke-AllIdentityQuickChecks.ps1
           ▼
    ┌─────────────┐
    │ Credentials │
    └──────┬──────┘
           │ Authentication
           ▼
    ┌─────────────────────────────────────────┐
    │         Module Execution                │
    │  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐    │
    │  │Core │ │Entra│ │ AWS │ │ GCP │    │
    │  └─────┘ └─────┘ └─────┘ └─────┘    │
    └─────────────────┬───────────────────────┘
                      │ Check Execution
                      ▼
    ┌─────────────────────────────────────────┐
    │          Finding Collection             │
    │  • Severity Scoring                     │
    │  • Category Grouping                   │
    │  • Remediation Suggestions             │
    └─────────────────┬───────────────────────┘
                      │ Report Generation
                      ▼
    ┌─────────────────────────────────────────┐
    │         Output Generation               │
    │  • JSON Report                         │
    │  • HTML Dashboard                      │
    │  • Console Summary                     │
    └─────────────────────────────────────────┘
```

---

## Reporting Structure

### JSON Output Schema

```json
{
  "Metadata": {
    "Tool": "IdentityFirst QuickChecks",
    "Version": "1.0.0",
    "GeneratedAt": "2026-01-30T12:00:00Z",
    "PowerShellVersion": "5.1.22621.2506"
  },
  "Execution": {
    "StartTime": "2026-01-30T12:00:00Z",
    "EndTime": "2026-01-30T12:05:00Z",
    "Duration": 300,
    "Platform": ["Entra ID", "Azure", "AWS", "GCP", "AD"],
    "TotalChecks": 106,
    "Passed": 75,
    "Failed": 15,
    "Warnings": 10,
    "Errors": 6
  },
  "OverallScore": 82,
  "HealthStatus": "Healthy",
  "Checks": [
    {
      "CheckId": "IDF-ENT-MFA-001",
      "CheckName": "MFA Coverage Gap Detection",
      "Category": "Entra ID - MFA",
      "Severity": "Critical",
      "Status": "Pass",
      "Findings": [],
      "Timestamp": "2026-01-30T12:00:00Z"
    }
  ],
  "Findings": [
    {
      "Id": "Finding-001",
      "CheckId": "IDF-ENT-CA-001",
      "Title": "Legacy Authentication Detected",
      "Description": "15 users authenticated using legacy protocols",
      "Severity": "High",
      "Category": "Entra ID - Conditional Access",
      "RuleId": "IDF-RULE-LEGACY-001",
      "Remediation": "Block legacy authentication in Conditional Access policy",
      "AffectedCount": 15,
      "Confidence": "High"
    }
  ],
  "Summary": {
    "TotalFindings": 25,
    "BySeverity": {
      "Critical": 3,
      "High": 8,
      "Medium": 10,
      "Low": 4
    },
    "ByCategory": [
      {"Category": "Entra ID", "Count": 12},
      {"Category": "Azure", "Count": 8},
      {"Category": "AWS", "Count": 5}
    ]
  }
}
```

---

## Integration Points

### Microsoft Graph API
- **Permissions Required**: `Policy.Read.All`, `Directory.Read.All`, `Application.Read.All`
- **Modules**: Entra ID, Compliance, Enterprise

### Azure Resource Manager
- **Permissions Required**: Contributor or higher on subscriptions
- **Modules**: Core, Additional, Enterprise, Federation

### AWS Tools for PowerShell
- **Permissions Required**: IAM, Security Hub, Config, GuardDuty read access
- **Modules**: Extended, Additional, Compliance, Federation

### Google Cloud SDK
- **Permissions Required**: Organization Policy Viewer, Security Command Center
- **Modules**: Extended, Additional, Compliance

### Active Directory
- **Permissions Required**: Domain Admin or equivalent
- **Modules**: Extended, Enterprise, Federation

### Okta API
- **Authentication**: API Token
- **Modules**: Federation

### Exchange Online
- **Permissions Required**: Exchange Administrator
- **Modules**: Enterprise

---

## Platform Coverage Matrix

| Security Domain | Entra ID | Azure | AWS | GCP | AD | Okta |
|-----------------|----------|-------|-----|-----|-----|------|
| Identity & Access | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| MFA/Authentication | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Conditional Access | ✅ | - | - | - | - | - |
| Privileged Access | ✅ | ✅ | ✅ | ✅ | ✅ | - |
| Role-Based Access | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Policy Management | ✅ | ✅ | ✅ | ✅ | - | ✅ |
| Secret/Certificate | ✅ | ✅ | ✅ | ✅ | ✅ | - |
| Monitoring/Logging | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Backup & Recovery | - | ✅ | ✅ | ✅ | ✅ | - |
| Network Security | - | ✅ | ✅ | ✅ | - | - |
| Kubernetes | - | ✅ | - | - | - | - |
| Database Security | - | ✅ | - | - | - | - |
| Email Security | ✅ | - | - | - | - | - |
| Federation/SSO | ✅ | - | - | - | ✅ | ✅ |

---

## Security Domains

### 1. Identity Governance
- Access Reviews (IDF-ENT-AR-001)
- Entitlement Management (IDF-ENT-EM-001)
- Administrative Units (IDF-ENT-AU-001)
- PIM Configuration (IDF-ENT-PIM-001)

### 2. Cloud Security Posture
- Azure Security Center (IDF-AZ-SC-001)
- AWS GuardDuty (IDF-AWS-GD-001)
- GCP SCC (IDF-GCP-SCC-001)
- AWS Config (IDF-AWS-CONFIG-001)

### 3. Identity Protection
- MFA Coverage (IDF-ENT-MFA-001)
- Risk Policies (IDF-ENT-RISK-001)
- Conditional Access (IDF-ENT-COND-001)
- Legacy Auth (IDF-ENT-LEGACY-001)

### 4. Infrastructure Security
- AD Certificate Services (IDF-AD-CS-001)
- ADFS Configuration (IDF-ADFS-001)
- PAW Configuration (IDF-PAW-001)
- LAPS Implementation (IDF-AD-LAPS-001)

### 5. Data Protection
- Key Vault Security (IDF-AZ-KV-001)
- Certificate Expiry (IDF-ENT-CERT-001)
- Secret Management (IDF-AZ-KV-AP-001)
- Service Account Keys (IDF-GCP-SA-001)

### 6. Compliance & Governance
- Zero Trust Readiness (IDF-ZT-001)
- Password Policies (IDF-AWS-IAM-PW-001)
- Token Lifetime (IDF-ENT-TL-001)
- Federation Trusts (IDF-FED-TRUST-001)

---

## Scoring Methodology

### Overall Score Calculation

```
Initial Score: 100

Deductions:
├── Critical Finding:     -25 points
├── High Finding:         -10 points
├── Medium Finding:        -5 points
└── Low Finding:           -2 points

Final Score = max(0, 100 - Total Deductions)

Health Status:
├── Score >= 80:  Healthy  (Green)
├── Score >= 60:  Warning  (Yellow)
└── Score <  60:  Critical (Red)
```

---

## Recommendations for Enhancement

### Phase 2 Enhancements
1. **Continuous Monitoring**: Scheduled execution with email/Slack notifications
2. **Trend Analysis**: Historical score tracking and drift detection
3. **Remediation Automation**: One-click fix scripts for common issues
4. **Custom Check Framework**: User-defined security rules
5. **Compliance Mapping**: NIST, ISO 27001, SOC 2 mapping

### Integration Opportunities
- **SIEM Integration**: Sentinel, Splunk, Log Analytics
- **Ticketing**: ServiceNow, Jira integration
- **CMDB**: ServiceNow, Azure CMDB sync
- **CI/CD**: GitHub Actions, Azure DevOps pipelines

---

## Conclusion

IdentityFirst QuickChecks provides a comprehensive, multi-platform identity security assessment framework with **106+ checks** covering the critical security domains organizations need to protect their hybrid identity infrastructure.

The modular architecture allows organizations to:
- Run comprehensive assessments across all platforms
- Focus on specific security domains
- Integrate with existing security tools
- Track security posture over time
- Prioritize remediation efforts based on risk
