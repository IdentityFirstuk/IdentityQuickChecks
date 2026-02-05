# ============================================================================
# ATTRIBUTION
# ============================================================================
# Author: Mark Ahearne
# Email: mark.ahearne@identityfirst.net
# Company: IdentityFirst Ltd
#
# This script is provided by IdentityFirst Ltd for identity security assessment.
# All rights reserved.
#
# License: See EULA.txt for license terms.
# ============================================================================
<#
.SYNOPSIS
  Unified Identity Audit Engine (skeleton)
.DESCRIPTION
  Engine-first skeleton: collectors -> evidence store -> assertions -> framework lenses -> reports
  Drop-in scaffold to implement Entra/AD/AWS/GCP/Okta collectors and framework mappings.
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("GDPR","ISO27001","NIST80053","SOX","HIPAA","DORA","CISv8")]
    [string[]]$Frameworks,

    [string]$OutputDir = (Join-Path $PWD "IFQC-Audit-Out"),
    [switch]$WhatIf,
    [switch]$ReadOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Read-only enforcement state
$Global:IFQC_ReadOnlyMode = $false
$Global:IFQC_OriginalCommands = @{}

# Enable read-only mode by shadowing state-changing cmdlets from non-core modules
function Enable-IFQCReadOnlyMode {
    param(
        [string[]]$BlockedVerbs = @('New','Set','Remove','Update'),
        [string[]]$ModuleAllowList = @('Microsoft.PowerShell.Core','Microsoft.PowerShell.Management','Microsoft.PowerShell.Utility','Microsoft.PowerShell.Security')
    )

    if ($Global:IFQC_ReadOnlyMode) { return }
    $Global:IFQC_OriginalCommands = @{}

    $candidates = Get-Command -CommandType Cmdlet -ErrorAction SilentlyContinue | Where-Object {
        ($BlockedVerbs -contains $_.Verb) -and ($_.ModuleName -and ($ModuleAllowList -notcontains $_.ModuleName))
    }

    foreach ($cmd in $candidates) {
        $name = $cmd.Name
        try {
            if (-not (Test-Path "Function:\$name")) {
                $sb = [scriptblock]::Create("param([object[]]`$Args) \n    throw 'IFQC Read-Only Mode: invocation of $name is blocked.'")
                # store a marker; the original cmdlet remains available via module if we remove this function later
                $Global:IFQC_OriginalCommands[$name] = @{ Module = $cmd.ModuleName; CommandType = $cmd.CommandType }
                New-Item -Path "Function:\$name" -Value $sb -Force | Out-Null
            }
        } catch {
            # best-effort: ignore failures to shadow
        }
    }

    $Global:IFQC_ReadOnlyMode = $true
    try { Write-IFQC -Level Info -Message 'Read-only mode enabled: state-changing cmdlets are blocked.' } catch { Write-Output 'Read-only mode enabled.' }
}

# Disable read-only mode and remove shadowing functions
function Disable-IFQCReadOnlyMode {
    if (-not $Global:IFQC_ReadOnlyMode) { return }
    foreach ($name in $Global:IFQC_OriginalCommands.Keys) {
        try {
            if (Test-Path "Function:\$name") { Remove-Item -Path "Function:\$name" -ErrorAction SilentlyContinue }
        } catch { }
    }
    $Global:IFQC_OriginalCommands = @{}
    $Global:IFQC_ReadOnlyMode = $false
    try { Write-IFQC -Level Info -Message 'Read-only mode disabled.' } catch { Write-Output 'Read-only mode disabled.' }
}

function New-Dir([string]$Path) {
    if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Path $Path | Out-Null }
}

function Write-Json([object]$Obj, [string]$Path) {
    $Obj | ConvertTo-Json -Depth 12 | Out-File -FilePath $Path -Encoding utf8
}

# ---- Evidence store ----
$Evidence = [System.Collections.Generic.List[object]]::new()
$Findings = [System.Collections.Generic.List[object]]::new()

# ---- Helpers ----
function Add-Finding {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        [string]$AssertionId,
        [string]$Severity,
        [string]$Title,
        [object[]]$Entities,
        [string[]]$EvidenceRefs,
        [string]$WhyItMatters,
        [string]$Remediation
    )

    $Findings.Add([pscustomobject]@{
        assertionId  = $AssertionId
        severity     = $Severity
        title        = $Title
        entities     = $Entities
        evidenceRefs = $EvidenceRefs
        whyItMatters = $WhyItMatters
        remediation  = $Remediation
    })
}

# ---- Collectors (plug-in points) ----
function Invoke-EntraCollector {
    param(
        [System.Collections.Generic.List[object]]$Evidence,
        [switch]$ReadOnly
    )

    # Defensive: attempt to import Microsoft.Graph modules if available; otherwise emit a sample record
    try {
        if (Get-Module -ListAvailable -Name Microsoft.Graph.Users) {
            Import-Module Microsoft.Graph.Users -ErrorAction Stop
            # Example: enumerate users (this requires graph connection in real usage)
            try {
                $mgUsers = Get-MgUser -All -ErrorAction Stop
                foreach ($u in $mgUsers) {
                    $e = [pscustomobject]@{
                        type = 'entra.user'
                        id = $u.Id
                        tenantId = $null
                        displayName = $u.DisplayName
                        upn = $u.UserPrincipalName
                        accountEnabled = $u.AccountEnabled
                        lastSignIn = $null
                        signals = @{ mfaRegistered = $false; isPrivileged = $false; pimEligible = $false }
                        source = @{ collector = 'EntraID'; collectedAt = (Get-Date).ToString('o') }
                    }
                    $Evidence.Add($e)
                }
                return $Evidence
            } catch {
                # Graph available but not connected or permissioned - fall through to sample
            }
        }
    } catch {
        # ignore import errors
    }

    # Fallback: emit a sample evidence item so the engine can be tested offline
    $sample = [pscustomobject]@{
        type = 'entra.user'
        id = 'sample-entra-1'
        tenantId = 'demo'
        displayName = 'Alice Example'
        upn = 'alice@example.com'
        accountEnabled = $true
        lastSignIn = (Get-Date).AddDays(-10).ToString('o')
        signals = @{ mfaRegistered = $false; isPrivileged = $true; pimEligible = $false }
        source = @{ collector = 'EntraID'; collectedAt = (Get-Date).ToString('o'); authority = 'secondary' }
    }
    $Evidence.Add($sample)
    return $Evidence
}

function Invoke-Collectors {
    param([System.Collections.Generic.List[object]]$Evidence, [switch]$ReadOnly)
    # Add more collectors here (AD, AWS, GCP, Okta, HR)
    if ($ReadOnly) { Enable-IFQCReadOnlyMode }
    $Evidence = Invoke-EntraCollector -Evidence $Evidence -ReadOnly:$ReadOnly
    # Try on-prem Active Directory collector
    try {
        $Evidence = Invoke-ADCollector -Evidence $Evidence
    } catch {
        # non-fatal: AD collector may not be available in all environments
    }
    # Run any external collectors found in ./collectors (ps1, py)
    try {
        $Evidence = Invoke-ExternalCollectors -Evidence $Evidence -ReadOnly:$ReadOnly
    } catch {
        # non-fatal
    }
    if ($ReadOnly) { Disable-IFQCReadOnlyMode }
    return $Evidence
}

# On-prem Active Directory collector (optional)
function Invoke-ADCollector {
    param([System.Collections.Generic.List[object]]$Evidence)

    try {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) { return $Evidence }
        Import-Module ActiveDirectory -ErrorAction Stop

        # Query a subset to avoid huge results by default; in real runs, paging and filters should be used
        $adUsers = Get-ADUser -Filter * -Properties DisplayName,mail,LastLogonDate,Enabled -ErrorAction Stop
        foreach ($u in $adUsers) {
            $e = [pscustomobject]@{
                type = 'ad.user'
                id = $u.SamAccountName
                displayName = $u.DisplayName
                upn = $u.mail
                accountEnabled = $u.Enabled
                lastSignIn = if ($u.LastLogonDate) { $u.LastLogonDate.ToString('o') } else { $null }
                signals = @{ onPrem = $true }
                source = @{ collector = 'ActiveDirectory'; collectedAt = (Get-Date).ToString('o') }
            }
            $Evidence.Add($e)
        }
        return $Evidence
    } catch {
        # Non-fatal: return original evidence on error
        return $Evidence
    }
}

# Run external collector scripts (PowerShell, Python) placed in ./collectors
function Invoke-ExternalCollectors {
    param([System.Collections.Generic.List[object]]$Evidence, [switch]$ReadOnly)

    $collectorDir = Join-Path $PSScriptRoot 'collectors'
    if (-not (Test-Path $collectorDir)) { return $Evidence }

    $files = Get-ChildItem -Path $collectorDir -File -ErrorAction SilentlyContinue
    foreach ($f in $files) {
        try {
            if ($f.Extension -ieq '.ps1') {
                # Run PowerShell collector and expect JSON on stdout
                $pwArgs = @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$f.FullName)
                if ($ReadOnly) { $pwArgs += '-ReadOnly' }
                $out = & pwsh @pwArgs 2>$null
                if ($out) {
                    try {
                        $parsed = $out | ConvertFrom-Json -ErrorAction Stop
                        foreach ($item in $parsed) {
                            if (Validate-EvidenceItem -Item $item) { $Evidence.Add($item) } else { Log-CollectorInvalid -File $f -Item $item }
                        }
                    } catch {
                        # If not JSON, ignore
                    }
                }
            } elseif ($f.Extension -ieq '.py') {
                # Try running with python
                $python = 'python'
                # set env var to indicate read-only intent for external collectors
                $origReadOnly = $env:IFQC_READONLY
                if ($ReadOnly) { $env:IFQC_READONLY = '1' }
                $proc = & $python $f.FullName 2>$null
                if ($ReadOnly) { if ($origReadOnly) { $env:IFQC_READONLY = $origReadOnly } else { Remove-Item Env:\IFQC_READONLY -ErrorAction SilentlyContinue } }
                if ($proc) {
                    try {
                        $parsed = $proc | ConvertFrom-Json -ErrorAction Stop
                        foreach ($item in $parsed) { if (Validate-EvidenceItem -Item $item) { $Evidence.Add($item) } else { Log-CollectorInvalid -File $f -Item $item } }
                    } catch {}
                }
            } else {
                # unsupported collector type - ignore for now
            }
        } catch {
            # ignore collector failures
        }
    }

    return $Evidence
}

# Lightweight evidence validator: ensures required fields exist and types are sane
function Validate-EvidenceItem {
    param(
        [Parameter(Mandatory=$true)][object]$Item
    )
    try {
        if (-not $Item) { return $false }

        # Basic required fields
        if (-not ($Item.PSObject.Properties.Name -contains 'type' -and $Item.PSObject.Properties.Name -contains 'id')) { return $false }
        if (-not ([string]::IsNullOrEmpty($Item.type) -eq $false)) { return $false }
        if (-not ([string]::IsNullOrEmpty($Item.id) -eq $false)) { return $false }

        # Lightweight schema check: if schema file exists, validate required keys and basic types
        $schemaPath = Join-Path $PSScriptRoot 'schemas\evidence.schema.json'
        if (Test-Path $schemaPath) {
            try {
                if (-not (Test-EvidenceAgainstSchema -Item $Item -SchemaPath $schemaPath)) { return $false }
            } catch {
                # If schema validation fails unexpectedly, treat as invalid
                return $false
            }
        }

        # Ensure source.collector exists
        try {
            if (-not $Item.source) { $Item | Add-Member -MemberType NoteProperty -Name source -Value @{ collector = 'external' } -Force }
            if (-not $Item.upn -and $Item.displayName) { $Item.upn = $null }
        } catch { }

        return $true
    } catch { return $false }
}

# Lightweight JSON Schema validator (minimal enforcement): checks required props and basic types
function Test-EvidenceAgainstSchema {
    param(
        [Parameter(Mandatory=$true)][object]$Item,
        [Parameter(Mandatory=$true)][string]$SchemaPath
    )
    try {
        if (-not (Test-Path $SchemaPath)) { return $true }
        $schema = Get-Content $SchemaPath -Raw | ConvertFrom-Json

        # required
        if ($schema.required) {
            foreach ($req in $schema.required) {
                if (-not ($Item.PSObject.Properties.Name -contains $req)) { return $false }
            }
        }

        # basic properties type checks when present in schema.properties
        if ($schema.properties) {
            foreach ($p in $schema.properties.PSObject.Properties) {
                $propName = $p.Name
                $propSchema = $p.Value
                if (-not ($Item.PSObject.Properties.Name -contains $propName)) { continue }
                $val = $Item.$propName
                if ($propSchema.type) {
                    switch ($propSchema.type.ToString().ToLower()) {
                        'string' {
                            if ($propSchema.format -and $propSchema.format -eq 'date-time') {
                                try { [datetime]$val | Out-Null } catch { return $false }
                            } else {
                                if (-not ($val -is [string])) { return $false }
                            }
                        }
                        'boolean' { if (-not ($val -is [bool])) { return $false } }
                        'integer' { if (-not ($val -is [int] -or $val -is [long])) { return $false } }
                        'number' { if (-not ($val -is [double] -or $val -is [decimal] -or $val -is [int])) { return $false } }
                        'object' { if (-not ($val -is [System.Collections.IDictionary] -or $val -is [pscustomobject])) { return $false } }
                        'array' { if (-not ($val -is [System.Collections.IEnumerable])) { return $false } }
                    }
                }
            }
        }

        return $true
    } catch {
        return $false
    }
}

# Log invalid collector items safely
function Log-CollectorInvalid {
    param([System.IO.FileInfo]$File, [object]$Item)
    try {
        try { Write-IFQC -Level Warn -Message "Collector produced invalid evidence item" -Metadata @{ file = $File.Name; item = ($Item | ConvertTo-Json -Depth 2) } } catch { Write-Output "Collector $($File.Name) produced invalid item" }
    } catch { }
}

# ---- Assertions (framework-agnostic truths) ----
function Invoke-Assertions {
    param(
        [System.Collections.Generic.List[object]]$Evidence,
        [System.Collections.Generic.List[object]]$Findings
    )

    # Example: PrivilegedAccountsWithoutMFA
    $privNoMfa = $Evidence | Where-Object {
        if (-not ($_.PSObject.Properties.Name -contains 'type') -or $_.type -ne 'entra.user') { return $false }
        if (-not $_.signals) { return $false }
        return ($_.signals.isPrivileged -eq $true -and $_.signals.mfaRegistered -eq $false)
    }

    foreach ($u in $privNoMfa) {
        Add-Finding -Findings $Findings `
            -AssertionId 'PrivilegedAccountsWithoutMFA' `
            -Severity 'critical' `
            -Title 'Privileged user without MFA' `
            -Entities @(@{ type=$u.type; id=$u.id; upn=$u.upn }) `
            -EvidenceRefs @("$($u.type):$($u.id)") `
            -WhyItMatters 'A single credential compromise can lead to tenant-wide compromise.' `
            -Remediation 'Require MFA for privileged roles, enforce Conditional Access, remove standing admin access.'
    }

    # Example: OrphanedAccounts (no HR linkage)
    $orphans = $Evidence | Where-Object {
        if (-not ($_.PSObject.Properties.Name -contains 'type') -or $_.type -ne 'entra.user') { return $false }
        $signals = $_.signals
        $hasHr = $false
        if ($signals) {
            try {
                if ($signals -is [System.Collections.IDictionary]) { $hasHr = $signals.ContainsKey('ps_hr_link') }
                else { $hasHr = ($signals.PSObject.Properties.Name -contains 'ps_hr_link') }
            } catch { $hasHr = $false }
        }
        if (-not $hasHr) { return $true }
        return (-not ($signals.ps_hr_link))
    }
    foreach ($o in $orphans) {
        Add-Finding -Findings $Findings -AssertionId 'OrphanedAccounts' -Severity 'high' -Title 'Active account without HR linkage' -Entities @(@{ type=$o.type; id=$o.id; upn=$o.upn }) -EvidenceRefs @("$($o.type):$($o.id)") -WhyItMatters 'No joiner/leaver authority' -Remediation 'Link identity to HR source of truth and automate deprovisioning.'
    }

    return $Findings
}

# Additional reusable assertions
function Add-CommonAssertions {
    param(
        [System.Collections.Generic.List[object]]$Evidence,
        [System.Collections.Generic.List[object]]$Findings,
        [int]$StaleDays = 90
    )

    # StandingAdmins: privileged and not PIM-eligible
    $standing = $Evidence | Where-Object {
        if (-not ($_.PSObject.Properties.Name -contains 'type') -or $_.type -ne 'entra.user') { return $false }
        if (-not $_.signals) { return $false }
        return ($_.signals.isPrivileged -eq $true -and (-not $_.signals.pimEligible))
    }
    foreach ($u in $standing) {
        Add-Finding -Findings $Findings -AssertionId 'StandingAdminAccess' -Severity 'high' -Title 'Standing privileged access' -Entities @(@{ type=$u.type; id=$u.id; upn=$u.upn }) -EvidenceRefs @("$($u.type):$($u.id)") -WhyItMatters 'Permanent privileged access increases risk; prefer PIM/JIT.' -Remediation 'Enable PIM or JIT for privileged roles; remove standing assignments.'
    }

    # Stale accounts: lastSignIn older than threshold or null
    $threshold = (Get-Date).AddDays(-$StaleDays)
    $stale = $Evidence | Where-Object {
        if (-not ($_.PSObject.Properties.Name -contains 'type') -or $_.type -ne 'entra.user') { return $false }
        $dt = $null
        try { $dt = [datetime]$_.lastSignIn } catch { $dt = $null }
        return (-not $dt -or $dt -lt $threshold)
    }
    foreach ($s in $stale) {
        Add-Finding -Findings $Findings -AssertionId 'StaleAccounts' -Severity 'medium' -Title "Stale account (>$StaleDays days)" -Entities @(@{ type=$s.type; id=$s.id; upn=$s.upn }) -EvidenceRefs @("$($s.type):$($s.id)") -WhyItMatters 'Unused accounts increase attack surface.' -Remediation "Review and disable accounts with no sign-in in $StaleDays days."
    }

    # Shared accounts (naming patterns)
    $shared = $Evidence | Where-Object {
        if (-not ($_.PSObject.Properties.Name -contains 'type') -or $_.type -ne 'entra.user') { return $false }
        return ($_.displayName -match '(?i)\b(shared|service|admin)\b')
    }
    foreach ($x in $shared) {
        Add-Finding -Findings $Findings -AssertionId 'SharedAccounts' -Severity 'high' -Title 'Shared user accounts detected' -Entities @(@{ type=$x.type; id=$x.id; upn=$x.upn }) -EvidenceRefs @("$($x.type):$($x.id)") -WhyItMatters 'Shared accounts reduce accountability.' -Remediation 'Replace shared accounts with individual identities and service principals.'
    }

    return $Findings
}

# CSV export helper for auditors
function Write-AuditCsv {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        [string]$Path
    )

    $rows = foreach ($f in $Findings) {
        [pscustomobject]@{
            AssertionId = $f.assertionId
            Severity = $f.severity
            Title = $f.title
            Entities = ($f.entities | ForEach-Object { $_.upn } ) -join '; '
            EvidenceRefs = ($f.evidenceRefs -join '; ')
            Why = $f.whyItMatters
            Remediation = $f.remediation
        }
    }
    $rows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8 -Force
}

# ---- Framework lens ----
function Get-FrameworkMapping {
    param([string]$Framework)
    $path = Join-Path $PSScriptRoot "frameworks\$Framework.json"
    if (-not (Test-Path $path)) { throw "Framework mapping not found: $path" }
    return (Get-Content $path -Raw | ConvertFrom-Json)
}

function Apply-FrameworkLens {
    param(
        [object]$Mapping,
        [object[]]$Findings
    )

    $controlResults = @()
    foreach ($c in $Mapping.controls) {
        $hits = @()
        foreach ($a in $c.assertions) {
            $matched = $Findings | Where-Object { $_.assertionId -eq $a.id }
            if ($matched) { $hits += $matched }
        }
        $score = if ($hits.Count -eq 0) { 100 } else { [Math]::Max(0, 100 - ($hits.Count * 15)) }
        $controlResults += [pscustomobject]@{ controlRef = $c.controlRef; score = $score; findings = $hits }
    }

    $overall = if ($controlResults.Count -eq 0) { 100 } else { [int]([Math]::Round(($controlResults | Measure-Object -Property score -Average).Average,0)) }

    return [pscustomobject]@{ framework = $Mapping.framework; version = $Mapping.version; overallScore = $overall; controls = $controlResults }
}

# ---- Run ----
New-Dir $OutputDir
$Evidence = Invoke-Collectors -Evidence $Evidence

$Findings = Invoke-Assertions -Evidence $Evidence -Findings $Findings

# Enrich with common assertions (standing admins, stale accounts, shared accounts)
Add-CommonAssertions -Evidence $Evidence -Findings $Findings -StaleDays 90 | Out-Null

Write-Json $Evidence  (Join-Path $OutputDir "evidence.json")
Write-Json $Findings  (Join-Path $OutputDir "findings.json")

$reports = @()
foreach ($fw in $Frameworks) {
    $map = Get-FrameworkMapping -Framework $fw
    $reports += Apply-FrameworkLens -Mapping $map -Findings $Findings
}

Write-Json $reports (Join-Path $OutputDir "reports.json")
$reports | ConvertTo-Json -Depth 6

# Export CSV for auditors
try {
    $csvPath = Join-Path $OutputDir 'findings.csv'
    Write-AuditCsv -Findings $Findings -Path $csvPath
    try { Write-IFQC -Level Info -Message "Exported findings CSV" -Metadata @{ path = $csvPath } } catch { Write-Output "Exported findings CSV: $csvPath" }
} catch {
    Write-Output "Failed to export CSV: $_"
}


# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCANOKN8WT0JK4g/
# 5MNB9ASCRBXQFl9MI2XhtpgScsKVIKCCFlIwggMUMIIB/KADAgECAhBDR0HvMFNE
# lkJ70azsYRwnMA0GCSqGSIb3DQEBCwUAMCIxIDAeBgNVBAMMF0lkZW50aXR5Rmly
# c3QgQ29kZSBTaWduMB4XDTI2MDIwNDE2NDE0OFoXDTI3MDIwNDE3MDE0OFowIjEg
# MB4GA1UEAwwXSWRlbnRpdHlGaXJzdCBDb2RlIFNpZ24wggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQDWJrlUCUN9yoS4qyJUFIIrjVVnfoFqTXwze3ijNE5q
# wUAAiypU86tc6ct9/wQ9Q9qOn6gjKU3vDhq8XojyQhi/q0ffxG1pP8bHfCQtrMFc
# kTOKLZRgQO73caKFxunCuRdAGxdDxy94NNjwITySkaaLFb3gULH1wbfmu5l2v9ga
# CgpRJGoofRbYbjBS5B7TTNVXlyxl5I3toq9cYRwauWq0Fqj2h6gZ/8izDVU6nMGX
# k+ZfsQwTsVSxfiiWHozhjU7Rt8ckxfVt1YLyPamewESLxw4ijFgHYZUrxNtbm2DP
# QUUG4ekzdDQlBLBzjdIJh8hIz+gcqvyXIQpoFjF2xyoFAgMBAAGjRjBEMA4GA1Ud
# DwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQU0LvUry7V
# 3WlfTmidD6yCOpbcmSQwDQYJKoZIhvcNAQELBQADggEBAAWDzEqYgCCQHZwHCMlU
# ob2Jkqcbk6GYylmfTwW9EQ7iJjyKHFJlbUGuDJxClDwDteBCVpxhfbi0fJjkib8r
# b4Fbk9Rex5rJxEMidBYbnASWnLuJD7dsHbwf6N4SM/LsYhiEtllGb0UsKET6PyuO
# f1sYdDY+UcTssCzDAElCrlVIl4Z4/JBlXOhInMD7AnP6Xx2r4hCAVEWhHtJ+ahY/
# bFAJ7v+EsTET2Pa34kiymxJ7yYRNSxwxyb1umUx/Q6pui0lYjyNXt8AAg4A0ybyj
# ABLNYct6zilczJ6JqPCBJLL0ZbCDpg8SkmAn3G3Y+bSztlOIUo4eXpjXV1DE7oB/
# kuAwggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUA
# MGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsT
# EHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQg
# Um9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqcl
# LskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YF
# PFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceIt
# DBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZX
# V59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1
# ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2Tox
# RJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdp
# ekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF
# 30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9
# t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQ
# UOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXk
# aS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud
# DgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEt
# UYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsG
# AQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0
# dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RD
# QS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAw
# DQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72arKGHLOyF
# XqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFIDyE7QKt76
# LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8L
# punyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2
# CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si
# /xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQwgga0MIIEnKADAgEC
# AhANx6xXBf8hmS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcw
# MDAwMDBaFw0zODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1l
# U3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZ
# loMsVO1DahGPNRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM
# 2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj
# 7GH8BLuxBG5AvftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQ
# Sku2Ws3IfDReb6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZ
# lDwFt+cVFBURJg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+
# 8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRx
# ykvq6gbylsXQskBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yG
# OP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqI
# MRvUBDx6z1ev+7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm
# 1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBj
# UwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729T
# SunkBnx6yuKQVvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4c
# D08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUF
# BwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEG
# CCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAX
# MAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaA
# HP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQ
# M2qEJPe36zwbSI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt
# 6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7
# bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmS
# Nq1UH410ANVko43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69
# M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnF
# RsjsYg39OlV8cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmM
# Thi0vw9vODRzW6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oa
# Qf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx
# 9yHbxtl5TPau1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3
# /BAPvIXKUjPSxyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN
# 8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQg
# VGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAw
# MDAwMFoXDTM2MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBU
# aW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx
# +wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvN
# Zh6wW2R6kSu9RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlL
# nh00Cll8pjrUcCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmn
# cOOMA3CoB/iUSROUINDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5KqCvpSduSwhw
# UmotuQhcg9tw2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL
# 4Q1OpbybpMe46YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdoRORVbPR1VVnD
# uSeHVZlc4seAO+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCy
# FG1roSrgHjSHlq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7rlRyTlaCCfw7a
# SUROwnu7zER6EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K096V1hE0yZIXe+gi
# AwW00aHzrDchIc2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGj
# ggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39/dfzkXFjGVBD
# z2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8E
# BAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGF
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUH
# MAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRH
# NFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBW
# MFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVk
# RzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkw
# FzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3x
# HCcEua5gQezRCESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh
# 8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim8/9yJmZS
# e2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUqW4daIqToXFE/
# JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMnxYOX8VBRKe1u
# NnzQVTeLni2nHkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq
# 8/gVutDojBIFeRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AWcIQfVjnzrvwi
# CZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJgddJ35XTxfUlQ
# +8Hggt8l2Yv7roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1
# R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVccAvlKV9jEnstr
# niLvUxxVZE/rptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8atufk+EMF/cWu
# iC7POGT75qaL6vdCvHlshtjdNXOCIUjsarfNZzGCBRIwggUOAgEBMDYwIjEgMB4G
# A1UEAwwXSWRlbnRpdHlGaXJzdCBDb2RlIFNpZ24CEENHQe8wU0SWQnvRrOxhHCcw
# DQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkq
# hkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGC
# NwIBFTAvBgkqhkiG9w0BCQQxIgQg1VHtdAgIgcmHb4+MrZAZ9SbX7KJsH+apY5Ue
# ToLQL3MwDQYJKoZIhvcNAQEBBQAEggEAzIvJ5lVeddsKm2D57TOUHScuQKR3ZgzT
# tokHApQWge00n2SdHCfUFWtA/BycTy1WxA7YIEtu5zO7MxDL/fdOyTGc7BVWX4NN
# m5Sg/tdKZnSDPLxlHcmmJm/xDtUzspp4haFf8SvjdknNv9bYXyknEx6797CppK28
# MAJhxDYyhdz+nKVnnqorPpK6O4fIZRN0YLNQZkuNxDD6hJjed353WUoIKsDg2b+K
# su4f9sMimJsY7/H0T5z+2uMK2gGbOc/KnJ3AN1Wz2+U3arutaETTlBAtrzj5wpLw
# ihw/2bFKpVm8mqWgkjkVdUzZsAYZOtxMZXfZqtkXuhJZyVl3L6WmzKGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjAyMDQxNjUyMDdaMC8GCSqGSIb3DQEJBDEiBCAA
# 3BRosgfo7AaDTGAZ22VworZdfPbJqLMvgs1IyI4leTANBgkqhkiG9w0BAQEFAASC
# AgDO7m7HbWxvTqt6ZYPwqh7NKmw4AGoe8O4JG5mXDIfBF0AxaMMEWucZ/bggEk5W
# jEFz62znruKKJ0T1yEfVuAYxcOfXolcn+a2M7ghpTql1VebCFcZNK998FqDDnDuC
# V4hw4H234iKn5dDRM8k5ZsYV+cu4cZxX1o+olTxfLPor5/Whj2jAeMDAb6cIWl5l
# aVdEGJpzj20PlroIdCfXb1hRb6adIfzvlK7wPjOg6j1uWsfHnnUIh0CdRFzhQdh+
# 5fZpBekfyNsPhXbNXMVA2Q2579uyHSJM79b3nQXx2oGpjOiR8PpIcPqypoKpoRqL
# Ic5hmAjDgiTgLgGKdQM1Z4UJ9nfSI9brT5x+ax/PtGuaTyR8urERbbbnL/Q/E8dY
# L2U3nUhob/YAOpEhv2yYtMCQua1tgC/tkbLfb/p/YD8QhdzEWUgONZoE+va0uEeY
# CknvBFYdb/4rNwCSVHm6O+SYUHvOy84H0S4FEo1QPZDvZ4iDO1k1ksZkf6ytJGxD
# e7ArzxpXlMTMrdWifxqbZ/hep1C2sCek90muDRdt+61h5m5Db6O0fqjn96F5swfd
# ws87OIjZH56C0gNWbH3UWaM7snjibQg7PBqPxkdvwFr34+a8QQX10fN+pXa/wUQl
# f9IP9DjdZAIMHYV/XCIXpw8SnXUo+MUAka2jhvyiMMBMBw==
# SIG # End signature block
