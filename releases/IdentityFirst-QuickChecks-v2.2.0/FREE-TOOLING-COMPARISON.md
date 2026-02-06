# Free Identity Security Tooling Comparison

## What IdentityFirst QuickChecks Does

**IdentityFirst QuickChecks** is a free, agentless identity security assessment toolkit that provides read-only visibility into your identity posture across multiple platforms.

### Core Capabilities:

1. **Discovery & Inventory**
   - Enumerate privileged accounts across AD, Entra ID, AWS, and GCP
   - Identify break-glass accounts, service accounts, and admin accounts
   - Certificate template inventory (AD CS)
   - AWS IAM user/access key/inventory
   - GCP service account inventory

2. **Configuration Assessment**
   - Detect insecure configurations
   - Find missing security controls (MFA, LAPS)
   - Identify risky delegation settings
   - Check for dangerous Kerberos configurations
   - Validate Group Policy inheritance

3. **Privilege Analysis**
   - Identify excessive group memberships
   - Find nested privilege abuse paths
   - Detect direct/indirect administrative access
   - Analyze SID History security risks
   - Review DCSync rights distribution

4. **Trust Relationship Mapping**
   - Map internal and external trusts
   - Analyze forest/domain trust security
   - Identify cross-environment boundaries

5. **Reporting & Export**
   - JSON structured output
   - HTML report generation
   - CSV export for spreadsheets
   - REST API for automation
   - Webhook support for SIEM integration

---

## Free Identity Security Tools Landscape

### 1. Active Directory Assessment Tools

| Tool | Focus | Last Updated | Stars | License |
|------|-------|--------------|-------|----------|
| **PingCastle** | AD health/risk scoring | 2024 | 1.2K | AGPL-3.0 |
| **AD ACL Scanner** | ACL analysis | 2024 | 500+ | MIT |
| **BloodHound** | Attack path analysis | 2024 | 8K+ | Apache 2.0 |
| **Purple Knight** | AD security assessment | 2024 | 1.5K | Free (Semperis) |
| **IdentityFirst QuickChecks** | Multi-platform assessment | 2026 | N/A | EULA |
| **DSInternals** | AD data analysis | 2024 | 1K+ | MIT |
| **PowerView** | Reconnaissance | 2024 | 3K+ | BSD-3 |

### 2. Entra ID / Azure AD Tools

| Tool | Focus | Last Updated | License |
|------|-------|--------------|---------|
| **Microsoft365DSC** | Configuration management | 2024 | MIT |
| **AAD Connect Reports** | AAD Connect analysis | 2024 | MIT |
| **Entra ID Governance** | Microsoft solution | 2024 | P2 License |
| **Graph API Scripts** | Custom queries | 2024 | MIT |
| **IdentityFirst QuickChecks** | Multi-platform | 2026 | EULA |

### 3. Cloud IAM Tools

| Tool | Focus | Provider | License |
|------|-------|----------|---------|
| **AWS IAM Analyzer** | AWS permission analysis | AWS | Free Tier |
| **AWS IAM Access Analyzer** | Cross-account access | AWS | Free Tier |
| **GCP IAM Recommender** | Least privilege | GCP | Free |
| **ScoutSuite** | Multi-cloud security | AWS/Azure/GCP | GPL-2.0 |
| **Prowler** | AWS security | AWS | AGPL-3.0 |
| **IdentityFirst QuickChecks** | Multi-platform | AWS + GCP | EULA |

### 4. Attack Path Analysis

| Tool | Focus | Agent Required | License |
|------|-------|----------------|---------|
| **BloodHound** | AD attack paths | Yes (collector) | Apache 2.0 |
| **SharpHound** | AD data collection | Yes | Apache 2.0 |
| **DeathStar** | AD lateral movement | Yes | MIT |
| **IdentityFirst QuickChecks** | Config assessment | No | EULA |

---

## Detailed Free Tool Comparisons

### PingCastle vs IdentityFirst QuickChecks

**PingCastle:**
```
✅ Pros:
   - Excellent risk scoring algorithm
   - Beautiful HTML reports
   - Trust relationship visualization
   - Active development community
   - French company backing (Semperis)

❌ Cons:
   - AD only (no cloud)
   - Limited Entra ID coverage
   - No API for automation
   - AGPL license (copyleft)
   - No webhook/SIEM integration
```

**IdentityFirst QuickChecks:**
```
✅ Pros:
   - Multi-platform (AD + Entra + AWS + GCP)
   - REST API + webhooks
   - OpenAPI for Power Automate
   - PowerShell 5.1 compatible
   - No agent required
   - MIT/EULA license (friendly)

❌ Cons:
   - No visual attack paths
   - No automated risk scoring
   - Newer project (less proven)
```

### BloodHound vs IdentityFirst QuickChecks

**BloodHound:**
```
✅ Pros:
   - Industry standard for attack paths
   - Huge community
   - Visual graph database
   - Identifies privilege escalation paths
   - SharpHound collector is robust

❌ Cons:
   - Requires agent deployment
   - Neo4j database required
   - Steep learning curve
   - AD only (no cloud)
   - Complex setup
   - No real-time monitoring
```

**IdentityFirst QuickChecks:**
```
✅ Pros:
   - No agents, instant results
   - Easy PowerShell execution
   - Multi-cloud support
   - API for automation
   - Consultant-friendly

❌ Cons:
   - No attack path visualization
   - Rule-based, not graph-based
   - Less comprehensive than BloodHound
```

### Microsoft365DSC vs IdentityFirst QuickChecks

**Microsoft365DSC:**
```
✅ Pros:
   - Desired State Configuration approach
   - Drift detection over time
   - Strong M365 coverage
   - Auto-remediation possible
   - Large test suite

❌ Cons:
   - M365/Azure only (no AWS/GCP)
   - DSC learning curve
   - Configuration-focused, not assessment
   - Less intuitive than QuickChecks
```

**IdentityFirst QuickChecks:**
```
✅ Pros:
   - Simpler, quicker assessments
   - Multi-cloud coverage
   - No DSC knowledge required
   - API + webhook support
   - Consultant-friendly format

❌ Cons:
   - No drift detection
   - No auto-remediation
   - Less M365 depth than M365DSC
```

---

## Feature-by-Feature Free Tool Matrix

| Feature | QuickChecks | PingCastle | BloodHound | M365DSC | Purple Knight |
|---------|-------------|------------|------------|----------|---------------|
| **AD Assessment** | ✅ | ✅ | ✅ | ❌ | ✅ |
| **Entra ID** | ✅ | ❌ | ❌ | ✅ | ❌ |
| **AWS IAM** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **GCP IAM** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **No Agent** | ✅ | ✅ | ❌ | ✅ | ✅ |
| **REST API** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **Webhooks** | ✅ | ❌ | ❌ | ❌ | ❌ |
| **HTML Reports** | ✅ | ✅ | ❌ | ❌ | ✅ |
| **JSON Export** | ✅ | ✅ | ✅ | ✅ | ❌ |
| **PS 5.1 Compatible** | ✅ | ✅ | ❌ | ✅ | ✅ |
| **Attack Paths** | ❌ | Basic | ✅ | ❌ | ✅ |
| **Risk Scoring** | Basic | ✅ | ❌ | ❌ | ✅ |
| **Free License** | ✅ | AGPL | Apache | MIT | Free |
| **Active Dev** | ✅ | ✅ | ✅ | ✅ | ✅ |

---

## Use Case Recommendations

### When to Use IdentityFirst QuickChecks

1. **Quick Security Posture Review**
   - Need instant visibility into identity risks
   - No time for agent deployment
   - Consultant delivering quick assessment

2. **Multi-Cloud Identity Review**
   - Assess AD + Entra + AWS + GCP together
   - Unified view across platforms
   - Compare cloud IAM to AD permissions

3. **Integration with Automation**
   - Power Automate workflows
   - SIEM webhook ingestion
   - Scheduled CI/CD pipeline checks

4. **Compliance Preparation**
   - Pre-audit quick checks
   - Evidence collection
   - Configuration validation

### When to Use Other Tools

| Tool | Use Case |
|------|----------|
| **PingCastle** | Full AD risk assessment with scoring |
| **BloodHound** | Attack path analysis, red team ops |
| **M365DSC** | M365 configuration drift monitoring |
| **Purple Knight** | Enterprise AD security scoring |
| **DSInternals** | Password hash analysis, account forensics |
| **PowerView** | Deep AD reconnaissance |

---

## Combining Tools for Maximum Coverage

### Recommended Tool Stack

```
Layer 1: Quick Assessment
├── IdentityFirst QuickChecks (quick wins, multi-platform)
└── PingCastle (AD risk scoring)

Layer 2: Deep Analysis
├── BloodHound (attack paths)
└── AD ACL Scanner (permission analysis)

Layer 3: Continuous Monitoring
├── Microsoft365DSC (drift detection)
└── Cloud native tools (AWS IAM Analyzer, GCP IAM Recommender)
```

### Example Assessment Workflow

```powershell
# 1. Quick posture check with QuickChecks
.\Start-QuickChecks.ps1 -Check All -Output JSON

# 2. Deep AD analysis with PingCastle
.\PingCastle.exe --healthcheck -- scoring

# 3. Attack path analysis
.\SharpHound.exe -c All
# Import into BloodHound

# 4. M365 configuration review
Update-M365AllDSC
Test-M365DSCConfiguration

# 5. Cloud IAM review
.\Invoke-AwsIdentityInventory
.\Invoke-GcpIdentityInventory
```

---

## Strategy: Free Tooling Without Undermining Paid Offerings

Many security vendors struggle with the balance between providing free value and protecting paid offerings. Here's how to position IdentityFirst QuickChecks effectively:

### The "Awareness → Assessment → Remediation" Model

Free tools should focus on **awareness and assessment** while paid tools handle **remediation and ongoing management**:

```
┌─────────────────────────────────────────────────────────────────┐
│                    FREE TOOLING DOMAIN                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    │
│   │  AWARENESS   │ →  │ ASSESSMENT   │ →  │  FINDINGS    │    │
│   │              │    │              │    │              │    │
│   │ What's       │    │ What's      │    │ What's       │    │
│   │ connected?   │    │ wrong?      │    │ at risk?     │    │
│   └──────────────┘    └──────────────┘    └──────────────┘    │
│                                                                 │
│   QuickChecks      QuickChecks          QuickChecks            │
│   excels here      does this            provides this          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   PAID OFFERING DOMAIN                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    │
│   │  REMEDIATION  │  │ CONTINUOUS   │  │  GOVERNANCE   │    │
│   │               │  │  MONITORING   │  │               │    │
│   │ How do I     │  │  Is it still  │  │  Ongoing      │    │
│   │ fix it?      │  │  secure?      │  │  compliance?  │    │
│   └──────────────┘    └──────────────┘    └──────────────┘    │
│                                                                 │
│   This is where        This is where      This is where         │
│   paid tools          paid tools          paid tools            │
│   differentiate       differentiate       differentiate         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Key Positioning Principles

#### 1. QuickChecks Discovers → Paid Tools Remediate

**Free Tool Role:** "Here's what's wrong"
- Identifies privileged accounts without MFA
- Finds excessive group nesting
- Detects stale admin accounts
- Flags dangerous delegation

**Paid Tool Role:** "Here's how to fix and stay secure"
- Automated MFA enrollment campaigns
- Scheduled group cleanup workflows
- Automated account deprovisioning
- Policy enforcement and drift prevention

**Messaging:** "QuickChecks finds the problems. Our managed services fix them."

#### 2. QuickChecks Provides Visibility → Paid Tools Provide Action

| Capability | Free (QuickChecks) | Paid (IdentityFirst) |
|------------|---------------------|----------------------|
| **Discovery** | One-time snapshot | Continuous discovery |
| **Findings** | Static report | Dynamic dashboard |
| **Remediation** | Manual steps provided | Automated workflows |
| **Compliance** | Point-in-time check | Continuous monitoring |
| **Reporting** | Export to CSV/JSON | Custom executive reports |
| **Support** | Community forum | Dedicated support team |

#### 3. Use QuickChecks as a "Tasting Menu"

**Strategic Approach:**
1. **Give away depth in a few areas** - Show expertise in AD assessments
2. **Give away breadth** - Cover AD, Entra, AWS, GCP (competitors don't)
3. **Hold back integration** - API/webhooks for free, full orchestration for paid
4. **Hold back remediation** - Always offer "we can also fix this for you"

**Example Pitch:**
> "You can run QuickChecks for free to see your identity posture across all clouds. When you're ready to automate remediation and continuously monitor, we have enterprise packages starting at [X]."

#### 4. Position Against Competitors, Not Yourself

**Don't say:** "Our free tool is almost as good as our paid tool"

**Do say:** "Most tools only do AD. QuickChecks covers AD + Entra + AWS + GCP. Our enterprise platform adds automation and continuous monitoring."

### What QuickChecks Should NOT Do (Preserve Paid Value)

| Keep for Paid | Why Free Should NOT Include |
|---------------|---------------------------|
| Automated ticket creation | Creates stickiness |
| Remediation workflows | Demonstrates expertise |
| Scheduled scanning | Revenue opportunity |
| Custom check creation | Consulting engagement |
| SSO integration | Enterprise selling point |
| SLA-based reporting | Managed service value |
| 24/7 alerting | Monitoring revenue |

### Strategic Messaging Examples

#### For Consultants/Partners
> "QuickChecks is our gift to the security community. Use it to accelerate your assessments. When you need enterprise features for your clients, we have you covered."

#### For End Customers
> "Start with QuickChecks to understand your identity risk posture. When you're ready to automate remediation and achieve continuous compliance, our platform scales with you."

#### For Sales Team
> "QuickChecks opens doors. Use it to demonstrate our expertise. The paid conversation starts when they ask 'can you also fix these issues?'"

### Measuring Free Tool Success

**KPIs for Free Tool (QuickChecks):**
- Downloads and GitHub stars
- Newsletter signups from users
- Lead generation from website
- Competitor displacement (customers switching from PingCastle/BloodHound)
- **NOT:** Revenue directly, but pipeline generation

**KPIs for Paid Conversions:**
- Customers asking for remediation features
- Enterprises requesting enterprise features
- Managed service inquiries

---

## Conclusion

**IdentityFirst QuickChecks** is strategically designed to:

1. **Demonstrate expertise** - Show depth in identity security
2. **Lower barrier to entry** - Free, no-agent assessment
3. **Cover gaps competitors miss** - Multi-cloud (AD + Entra + AWS + GCP)
4. **Create natural upgrade path** - Awareness → Remediation → Management

**Free Tool Promise:** "We'll tell you what's wrong"
**Paid Tool Promise:** "We'll help you fix it and keep it fixed"

---

*Document Version: 1.1*
*Last Updated: 2026-02-06*
*Author: IdentityFirst Ltd*
*Contact: info@identityfirst.net*
