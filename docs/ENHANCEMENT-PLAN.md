# IdentityFirst QuickChecks Free Tooling Enhancement Plan

**Version:** 1.2  
**Date:** 2026-02-06  
**Philosophy:** "QuickChecks tells you what's wrong, paid tools fix and monitor."

---

## Executive Summary

This plan outlines enhancements to the IdentityFirst QuickChecks free tooling while maintaining clear separation from paid offerings. The focus is on improving discovery, assessment, and reporting capabilities without introducing remediation, automation, or continuous monitoring features.

**Key Constraints:**
- ✅ FREE: Better UX, more checks, better reporting
- ❌ FREE: NO remediation, automation, or paid features

---

## 1. Current State Analysis

### 1.1 QuickChecks Coverage

| Platform | Current Checks | Status |
|----------|---------------|--------|
| Active Directory | 17 | ✅ Established |
| Entra ID | 5 | ✅ Established |
| AWS IAM | 4 | ✅ Established |
| GCP IAM | 3 | ✅ Established |
| Identity Trust | 6 | ✅ Established |
| **Total** | **35+** | |

### 1.2 Quality Metrics

| Metric | Value | Target |
|--------|-------|--------|
| Pester Tests | 79 Passing | 100+ |
| PSSA Critical Errors | 0 | 0 |
| PSSA Warnings | ~100 | <20 |
| Digitally Signed | ✅ Yes | ✅ Maintain |
| Obfuscated | ✅ Yes | ✅ Maintain |

### 1.3 Finding Object Structure

All findings follow standardized format with:
- Id, Title, Description, Severity
- Evidence Quality (Direct/Indirect/Inferred)
- Confidence Scoring (High/Medium/Low)
- Priority Score (Severity × Confidence)
- Remediation Steps (manual, not automated)

---

## 2. Additional QuickChecks (Discovery/Assessment Focus)

### 2.1 New QuickChecks by Category

#### Active Directory (Add 8 new checks)

| Check ID | Name | Description | Severity |
|----------|------|-------------|----------|
| AD-DCSYNC-001 | DCSync Rights Audit | Detect accounts with DCSync permissions | Critical |
| AD-SIDHISTORY-001 | SID History Analysis | Identify SID History exploitation risks | High |
| AD-ACL-001 | Sensitive Object ACLs | Check ACLs on AdminSDHolder, Domain Controllers | High |
| AD-PROPINHERIT-001 | Broken Inheritance | Find objects with blocked inheritance | Medium |
| AD-LAPS-001 | LAPS Deployment | Verify LAPS implementation status | High |
| AD-CERT-001 | Certificate Template Security | Enumerate dangerous certificate templates | High |
| AD-KERBEROAST-001 | Kerberoasting Risk | Detect SPNs with weak encryption | Medium |
| AD-FOREIGNGROUP-001 | Foreign Group Membership | Identify accounts in foreign domain groups | Medium |

#### Entra ID (Add 12 new checks - including CA simulation)

| Check ID | Name | Description | Severity |
|----------|------|-------------|----------|
| ENT-CONDACC-001 | **Conditional Access Analysis** | Identify missing CA policies and gaps | High |
| ENT-CONDACC-002 | **CA Policy Simulation** | Simulate CA policy outcomes for users/groups | Medium |
| ENT-CONDACC-003 | **CA What-If Analysis** | Predict access changes if CA policies change | Medium |
| ENT-CONDACC-004 | **CA Policy Configuration Review** | Detect weak CA configurations | High |
| ENT-CERT-001 | **Certificate Expiry Monitoring** | Track expiring service principal certificates | High |
| ENT-CERT-002 | **Token Signing Certificate Audit** | Verify federation token signing cert validity | Critical |
| ENT-PIM-001 | PIM Role Activation Review | Review privileged role activations | Medium |
| ENT-PIM-002 | PIM Assignment Audit | Check permanent vs eligible assignments | Medium |
| ENT-APP-001 | Orphaned App Registrations | Find apps with no owners | Medium |
| ENT-PERM-001 | Excessive Delegated Permissions | Review consent patterns | Medium |
| ENT-DEVICES-001 | Device Compliance Gaps | Check device enrollment status | Medium |
| ENT-SECKEYS-001 | Service Principal Keys | Detect expiring/certified SP credentials | High |

#### AWS (Add 5 new checks)

| Check ID | Name | Description | Severity |
|----------|------|-------------|----------|
| AWS-IAM-101 | Unused IAM Policies | Find detached managed policies | Low |
| AWS-ROLE-001 | Overly Permissive Roles | Detect wildcard resource policies | High |
| AWS-KEY-001 | Access Key Age | Identify keys older than 90 days | Medium |
| AWS-MFA-001 | IAM User MFA Status | Verify MFA on all users | High |
| AWS-S3-001 | Public S3 Bucket Exposure | Check for public bucket access | High |

#### GCP (Add 5 new checks)

| Check ID | Name | Description | Severity |
|----------|------|-------------|----------|
| GCP-IAM-101 | Overly Broad IAM Roles | Detect roles with excessive permissions | High |
| GCP-SERVICE-001 | Service Account Keys | Find old service account keys | Medium |
| GCP-IAP-001 | IAP Configuration | Verify IAP security settings | Medium |
| GCP-ORGS-001 | Organization Policy Gaps | Check organization constraints | Medium |
| GCP-KMS-001 | KMS Key Rotation | Verify key rotation policies | Medium |

#### Cross-Platform (Add 4 new checks)

| Check ID | Name | Description | Severity |
|----------|------|-------------|----------|
| XPL-CRED-001 | Credential Hunting | Search for exposed credentials | Critical |
| XPL-SESSION-001 | Session Duration Risks | Identify excessive session timeouts | Medium |
| XPL-API-001 | API Key Exposure | Detect hardcoded API keys | Critical |
| XPL-PRIV-001 | Cross-Cloud Privilege Mapping | Map privileges across clouds | High |

### 2.2 Updated QuickCheck Count

| Category | Current | Adding | Total |
|----------|---------|--------|-------|
| Active Directory | 17 | 8 | 25 |
| Entra ID | 5 | 12 | 17 |
| AWS IAM | 4 | 5 | 9 |
| GCP IAM | 3 | 5 | 8 |
| Cross-Platform | 0 | 4 | 4 |
| **Total** | **29** | **34** | **63** |

---

## 3. Conditional Access Policy Simulation Features

### 3.1 CA Policy Simulation Overview

The CA Policy Simulation feature provides "what-if" analysis without modifying any policies:

```powershell
Invoke-CAPolicySimulation -UserPrincipalName "user@domain.com" `
    -Application "Office 365" `
    -Location "External" `
    -DeviceState "Non-Compliant"
```

### 3.2 CA Simulation Capabilities

| Feature | Description | Output |
|---------|-------------|--------|
| **User Access Prediction** | Predict what access a user would have under current CA policies | Access: Allowed/Blocked + Controls Required |
| **Group Impact Analysis** | Analyze CA impact for specific groups | Findings per group |
| **Application Coverage** | Check which apps are protected by CA | Coverage matrix |
| **Location Risk Assessment** | Evaluate location-based CA policies | Risk score |
| **Device Compliance Mapping** | Map device compliance requirements | Compliance gaps |

### 3.3 CA Simulation Implementation

```powershell
function Invoke-ConditionalAccessSimulation {
    <#
    .SYNOPSIS
        CA Policy Simulation - "What-If" analysis without modifying policies.
    
    .DESCRIPTION
        Simulates Conditional Access policy outcomes for specific users,
        groups, applications, or locations. Analysis only - no policy changes.
    
    .OUTPUTS
        - JSON simulation report
        - Predicted access outcomes
        - Required controls
        - Policy matches
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$UserPrincipalName,
        
        [Parameter()]
        [string[]]$GroupMembership,
        
        [Parameter()]
        [string[]]$TargetApplications,
        
        [Parameter()]
        [ValidateSet("Internal", "External", "KnownLocation", "UnknownLocation")]
        [string]$Location = "External",
        
        [Parameter()]
        [ValidateSet("Compliant", "Non-Compliant", "Unknown")]
        [string]$DeviceState = "Unknown",
        
        [Parameter()]
        [string]$OutputDirectory = (Join-Path $PWD "IFQC-Output")
    )
    
    # Implementation:
    # 1. Get all CA policies (Get-MgConditionalAccessPolicy)
    # 2. Get user/group memberships (Get-MgUser, Get-MgGroupMember)
    # 3. For each policy, evaluate:
    #    - Does policy apply to user/group?
    #    - Does policy apply to target applications?
    #    - Do conditions match (location, device state)?
    #    - What grant controls are required?
    # 4. Aggregate results to predict final access
    # 5. Identify potential issues (conflicting policies, gaps)
    
    # Example output:
    # {
    #     "SimulationId": "SIM-001",
    #     "Timestamp": "2026-02-06T12:00:00Z",
    #     "Input": {
    #         "User": "user@domain.com",
    #         "Applications": ["Office 365"],
    #         "Location": "External",
    #         "DeviceState": "Non-Compliant"
    #     },
    #     "PredictedOutcome": {
    #         "Access": "Blocked",
    #         "Reason": "Multiple policies require device compliance",
    #         "PoliciesApplied": ["CA001", "CA002"]
    #     },
    #     "ControlRequirements": [
    #         {"Control": "MFA", "RequiredBy": "CA001"},
    #         {"Control": "CompliantDevice", "RequiredBy": "CA002"}
    #     ],
    #     "Gaps": [
    #         {"Issue": "No policy covers 'Unknown' device state", "Severity": "Medium"}
    #     ]
    # }
}
```

### 3.4 CA Coverage Analysis

```powershell
function Invoke-CACoverageAnalysis {
    <#
    .SYNOPSIS
        CA Policy Coverage Analysis - Identify unprotected applications.
    
    .DESCRIPTION
        Analyzes which applications are covered by CA policies
        and identifies gaps in protection.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputDirectory = (Join-Path $PWD "IFQC-Output")
    )
    
    # Implementation:
    # 1. Get all CA policies
    # 2. Extract target applications from each policy
    # 3. Compare with all registered applications
    # 4. Identify applications with no CA coverage
    # 5. Flag high-risk unprotected applications
}
```

---

## 4. UX Improvements

### 4.1 Enhanced Progress Indicators

```powershell
Invoke-IFQCProgress -CheckId "ENT-CONDACC-001" `
    -Status Running `
    -Message "Analyzing Conditional Access policies..." `
    -CurrentStep 1 `
    -TotalSteps 5
```

### 4.2 Enhanced Reporting

- Executive summary with risk posture
- Platform comparison charts
- Compliance mapping (SOC2, ISO27001, NIST)
- CA simulation results export

### 4.3 Interactive Console Mode

```powershell
Start-QuickChecksConsole -Interactive $true
```

---

## 5. Quality Improvements

### 5.1 Enhanced Pester Test Suite

| Test Category | Current | Target | Priority |
|---------------|---------|--------|----------|
| Core Functions | 25 | 35 | High |
| Finding Object | 20 | 25 | High |
| AD Checks | 10 | 20 | Medium |
| Entra ID Checks | 8 | 25 | Medium |
| AWS Checks | 6 | 10 | Medium |
| GCP Checks | 5 | 10 | Medium |
| Reporting | 5 | 15 | Medium |

### 5.2 PSSA Compliance Improvements

| Severity | Count | Plan |
|----------|-------|------|
| Errors | 0 | Maintain |
| Warnings | ~100 | Reduce to <20 |
| Informational | ~50 | Review and address |

---

## 6. Implementation Roadmap

### Phase 1: Quality Foundation - PSSA Fixes (Weeks 1-2)

| Task | Owner | Deliverable | Priority |
|------|-------|-------------|----------|
| Replace Write-Host with Write-Output | Code | 80+ replacements | Critical |
| Fix null comparison issues | Code | Fix $null on left comparisons | High |
| Remove unused parameters | Code | Remove unused param declarations | Medium |
| Add comment-based help | Code | Help for all public functions | Medium |
| PSSA re-scan validation | Tests | Verify <20 warnings | High |

### Phase 2: Test Suite Expansion (Weeks 3-4)

| Task | Owner | Deliverable | Priority |
|------|-------|-------------|----------|
| Add 40 Pester tests | Tests | 119 total tests | High |
| Core function tests | Tests | 35 tests | High |
| Finding object tests | Tests | 25 tests | Medium |
| Entra ID check tests | Tests | 20 tests | Medium |

### Phase 3: New QuickChecks (Weeks 5-6)

| Task | Owner | Deliverable |
|------|-------|-------------|
| Implement AD-DCSYNC-001 | Core | DCSync detection |
| Implement ENT-CONDACC-001 | Core | CA policy gaps |
| Implement ENT-CERT-001 | Core | Certificate expiry |
| Implement CA Simulation | Core | What-If analysis |
| Implement AWS-MFA-001 | Core | MFA verification |

### Phase 4: CA Simulation & UX (Weeks 7-8)

| Task | Owner | Deliverable |
|------|-------|-------------|
| CA Policy Simulation | Core | ENT-CONDACC-002/003 |
| CA Coverage Analysis | Core | ENT-CONDACC-004 |
| Progress indicator module | UX | New-IFQCProgress |
| Executive summary generator | UX | New-QuickChecksExecutiveSummary |

### Phase 5: Final Polish (Weeks 9-10)

| Task | Owner | Deliverable |
|------|-------|-------------|
| Error handling improvements | Core | Structured error output |
| Final PSSA validation | Tests | <20 warnings |
| Integration testing | Tests | Full suite validation |
| Documentation | Docs | Complete docs |

---

## 7. Success Metrics

| Metric | Baseline | Target |
|--------|----------|--------|
| QuickCheck Count | 35 | 63 |
| Pester Tests | 79 | 120+ |
| PSSA Warnings | ~100 | <20 |
| Documentation Pages | 5 | 15+ |

---

## 8. Paid Feature Separation

| Feature | Free (QuickChecks) | Paid |
|---------|-------------------|------|
| **Discovery** | ✅ Snapshot | ✅ Continuous |
| **Assessment** | ✅ One-time + Simulation | ✅ Scheduled |
| **Reporting** | ✅ Export to files | ✅ Dashboard |
| **Remediation** | ❌ Manual only | ✅ Automated |
| **Monitoring** | ❌ Not included | ✅ Real-time |
| **Alerting** | ❌ Not included | ✅ 24/7 |
| **Ticketing** | ❌ Not included | ✅ ServiceNow/Jira |

**Key Point:** CA Simulation is FREE (what-if analysis). CA Enforcement is PAID (automated changes).

---

## 9. Detailed Specifications

### 9.1 ENT-CERT-001: Certificate Expiry Monitoring

```powershell
function Invoke-EntraCertificateExpiry {
    <#
    .SYNOPSIS
        Certificate Expiry Monitoring - Entra ID service principal and app registration certificates.
    
    .DESCRIPTION
        Detects expiring certificates on service principals and app registrations
        in Entra ID. Critical for preventing authentication failures.
    
    .OUTPUTS
        - JSON report
        - Findings with affected certificates and expiration dates
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [int]$WarningDays = 60,
        
        [Parameter()]
        [int]$CriticalDays = 30,
        
        [Parameter()]
        [string]$OutputDirectory = (Join-Path $PWD "IFQC-Output")
    )
    
    # Implementation:
    # 1. Connect-MgGraph -Scopes "Certificate.Read.All, Application.Read.All"
    # 2. Get-MgServicePrincipal -All -Property Id,AppId,DisplayName,KeyCredentials
    # 3. For each SP, parse KeyCredentials[].EndDateTime
    # 4. Compare with WarningDays and CriticalDays thresholds
    # 5. Generate findings with certificate details
}
```

### 9.2 ENT-CONDACC-001: Conditional Access Analysis

```powershell
function Invoke-ConditionalAccessAnalysis {
    <#
    .SYNOPSIS
        Conditional Access Policy Analysis - Identify gaps and misconfigurations.
    
    .DESCRIPTION
        Analyzes CA policies to identify:
        - Missing policies for critical applications
        - Legacy authentication still allowed
        - Weak conditions (no risk-based policies)
        - Overly permissive assignments
    #>
}
```

### 9.3 ENT-CONDACC-002: CA Policy Simulation

```powershell
function Invoke-CAPolicySimulation {
    <#
    .SYNOPSIS
        CA Policy Simulation - "What-If" analysis without modifying policies.
    
    .DESCRIPTION
        Simulates Conditional Access policy outcomes for specific users,
        groups, applications, or locations. Analysis only - no policy changes.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$UserPrincipalName,
        
        [Parameter()]
        [string[]]$GroupMembership,
        
        [Parameter()]
        [string[]]$TargetApplications,
        
        [Parameter()]
        [string]$Location = "External",
        
        [Parameter()]
        [string]$DeviceState = "Unknown",
        
        [Parameter()]
        [string]$OutputDirectory = (Join-Path $PWD "IFQC-Output")
    )
    
    # Returns prediction of what CA would do for given input
}
```

---

## 10. Conclusion

This enhancement plan maintains the core philosophy while adding:

1. **30+ new QuickChecks** including comprehensive Entra ID coverage
2. **CA Policy Simulation** - What-if analysis without policy changes
3. **Better UX** - Progress indicators, executive summaries
4. **Higher Quality** - 120+ Pester tests, <20 PSSA warnings
5. **Clear paid separation** - Simulation is free, enforcement is paid

**Philosophy:** "QuickChecks tells you what's wrong (including what would happen). Paid tools fix and monitor."

---

*Document Version: 1.2*  
*Last Updated: 2026-02-06*  
*Author: IdentityFirst Ltd*
