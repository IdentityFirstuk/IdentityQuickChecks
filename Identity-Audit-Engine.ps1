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
# MIIf3QYJKoZIhvcNAQcCoIIfzjCCH8oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA1ynPuaxoqmVAI
# n7qWAD4+CkEMbgr2kzjCfN1q6QB40qCCGNwwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggWeMIIDhqADAgECAhAfb4XAeia2j0f08ahQbRKXMA0GCSqG
# SIb3DQEBCwUAMGcxCzAJBgNVBAYTAkdCMRcwFQYDVQQHDA5Ob3J0aHVtYmVybGFu
# ZDEaMBgGA1UECgwRSWRlbnRpdHlGaXJzdCBMdGQxIzAhBgNVBAMMGklkZW50aXR5
# Rmlyc3QgQ29kZSBTaWduaW5nMB4XDTI2MDEyOTIwNTAyM1oXDTI5MDEyOTIxMDAy
# M1owZzELMAkGA1UEBhMCR0IxFzAVBgNVBAcMDk5vcnRodW1iZXJsYW5kMRowGAYD
# VQQKDBFJZGVudGl0eUZpcnN0IEx0ZDEjMCEGA1UEAwwaSWRlbnRpdHlGaXJzdCBD
# b2RlIFNpZ25pbmcwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDV9YyY
# z49V2ipI5ePMgWVHs5h89pYHRk60XSkSOUrCXYH+83sOhTgzKnpvwo7Mzuchbf6f
# q4+85DpydvkLD1L/ZMAF3x1oP74iZ28JZYv/3PwrwLsUDAAiqFQlZk7YrDxgMhdO
# Z90dXpnK+xLTfbaRGLaqB40xnCMAozxHwIm1ClEOOlhC/I+BoPZqG6GRCcOXIdzU
# UQFWRGw8o33e2YyvDfCpwZlFHTgbD1Zmsx/SE7x9LiKi3UdnAyOMlrfHgSeJRIss
# omIVDKheB5MuAHlZQm//DMNBV7o+jO3prF4MJJygD+scND5ZImw+3L2BJEPYyBLZ
# Jum+fnKp4obGnMafQWyEk77bR+ebX3hIyglqcEwalVFdPQsIMeNQ7ervsFy7NOU0
# wBPIuEgLifGWwTVPHy70T2Ci+rz5+93qSljOWvOeT4LdQ/hpqH9JS4Eu4SpJrJ+U
# 6pwdbB3rZnFLax57w/Uh/ayZ74FZDvZhCg8KaV5sJo7XgbwZ44b3OPo6bXAWV7Jl
# yIWrO4h1q3QbgSXVWui3fWxfNmHgW3CEPTzKJlRM88wCvcPe/gQYx4aDFUKtEoiE
# JKmbuDFWoHyDAEuVo+ohUt03eRdEv73XZR/hwg9imN6NbaaR9aG1TV8C3/uMD5ET
# jBmdlUcGEztyHDLzVyIad+RQGh3nDmq2vhGLfQIDAQABo0YwRDAOBgNVHQ8BAf8E
# BAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFHZkS4haGPdZn+Um
# 4fJ/zeQU7kJzMA0GCSqGSIb3DQEBCwUAA4ICAQAnWa5k8D/hKdPn9IIZNY15hX6B
# NQylhSEPNRl4PT4vR1KKyX7Wl6c55c57z3egOC23wjOC6n0Nzt0JzZwgor9Do2V8
# 7R7APMQbXVMU2N1wDugVMNBsXbDbcS4AJz2IxRPmcW+CbMo32BoFeVbc6AODLhEr
# 1PEcAydxANk7E3rxXd1TD7pCLgp1XtRmZPx87SVJgYrRvr7J3VG0As/2KOO6Eu8n
# QTAwiyOZaRXh8MGmI/kd8SUZzFzwRpcafvSgjGqbQK6s4Tkvyxo9rkLKcS9xOww7
# hyEB6mmmV9Z0kPRBMk7llIKebFzN3exzhU8Jrdsnoas4dHl/O78VOl7nZEAbujhF
# l2IL+wFTicwrwCe9s4ZVtEhFZogUAxgGk6Ut00axJF5DgRuvc06YSRrrG7DvMKZw
# vSLWeeT9u+gbwmwEFLIjaEuF+PG0HQ2EgEaNxOKXP7xjJzLo58f5GWoFk+AKealG
# 8E1TuUfHLGJSl4m30vmenyjTlWtpcgbX5XBAb7BbYv3BrIsTiPwoqKY/X9orSDK8
# owFCw1x3Gy+K2DnaVR8JMtGv5KfC2hSobmjnc3nsryd0Bf0iEO/rcwtNbhAzjNEi
# rEKDng+bz5WEJ5HXVg3SXB7v73m+Q4xNVPfBT4WVV0YHxlbwtIk/Jpbsls43n5Uv
# 6aqzWFEZtlMMLRwTezCCBrQwggScoAMCAQICEA3HrFcF/yGZLkBDIgw6SYYwDQYJ
# KoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IElu
# YzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQg
# VHJ1c3RlZCBSb290IEc0MB4XDTI1MDUwNzAwMDAwMFoXDTM4MDExNDIzNTk1OVow
# aTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQD
# EzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1
# NiAyMDI1IENBMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALR4MdMK
# mEFyvjxGwBysddujRmh0tFEXnU2tjQ2UtZmWgyxU7UNqEY81FzJsQqr5G7A6c+Gh
# /qm8Xi4aPCOo2N8S9SLrC6Kbltqn7SWCWgzbNfiR+2fkHUiljNOqnIVD/gG3SYDE
# Ad4dg2dDGpeZGKe+42DFUF0mR/vtLa4+gKPsYfwEu7EEbkC9+0F2w4QJLVSTEG8y
# AR2CQWIM1iI5PHg62IVwxKSpO0XaF9DPfNBKS7Zazch8NF5vp7eaZ2CVNxpqumzT
# CNSOxm+SAWSuIr21Qomb+zzQWKhxKTVVgtmUPAW35xUUFREmDrMxSNlr/NsJyUXz
# dtFUUt4aS4CEeIY8y9IaaGBpPNXKFifinT7zL2gdFpBP9qh8SdLnEut/GcalNeJQ
# 55IuwnKCgs+nrpuQNfVmUB5KlCX3ZA4x5HHKS+rqBvKWxdCyQEEGcbLe1b8Aw4wJ
# khU1JrPsFfxW1gaou30yZ46t4Y9F20HHfIY4/6vHespYMQmUiote8ladjS/nJ0+k
# 6MvqzfpzPDOy5y6gqztiT96Fv/9bH7mQyogxG9QEPHrPV6/7umw052AkyiLA6tQb
# Zl1KhBtTasySkuJDpsZGKdlsjg4u70EwgWbVRSX1Wd4+zoFpp4Ra+MlKM2baoD6x
# 0VR4RjSpWM8o5a6D8bpfm4CLKczsG7ZrIGNTAgMBAAGjggFdMIIBWTASBgNVHRMB
# Af8ECDAGAQH/AgEAMB0GA1UdDgQWBBTvb1NK6eQGfHrK4pBW9i/USezLTjAfBgNV
# HSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYD
# VR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1Ud
# HwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwH
# ATANBgkqhkiG9w0BAQsFAAOCAgEAF877FoAc/gc9EXZxML2+C8i1NKZ/zdCHxYga
# MH9Pw5tcBnPw6O6FTGNpoV2V4wzSUGvI9NAzaoQk97frPBtIj+ZLzdp+yXdhOP4h
# CFATuNT+ReOPK0mCefSG+tXqGpYZ3essBS3q8nL2UwM+NMvEuBd/2vmdYxDCvwzJ
# v2sRUoKEfJ+nN57mQfQXwcAEGCvRR2qKtntujB71WPYAgwPyWLKu6RnaID/B0ba2
# H3LUiwDRAXx1Neq9ydOal95CHfmTnM4I+ZI2rVQfjXQA1WSjjf4J2a7jLzWGNqNX
# +DF0SQzHU0pTi4dBwp9nEC8EAqoxW6q17r0z0noDjs6+BFo+z7bKSBwZXTRNivYu
# ve3L2oiKNqetRHdqfMTCW/NmKLJ9M+MtucVGyOxiDf06VXxyKkOirv6o02OoXN4b
# FzK0vlNMsvhlqgF2puE6FndlENSmE+9JGYxOGLS/D284NHNboDGcmWXfwXRy4kbu
# 4QFhOm0xJuF2EZAOk5eCkhSxZON3rGlHqhpB/8MluDezooIs8CVnrpHMiD2wL40m
# m53+/j7tFaxYKIqL0Q4ssd8xHZnIn/7GELH3IdvG2XlM9q7WP/UwgOkw/HQtyRN6
# 2JK4S1C8uw3PdBunvAZapsiI5YKdvlarEvf8EA+8hcpSM9LHJmyrxaFtoza2zNaQ
# 9k+5t1wwggbtMIIE1aADAgECAhAKgO8YS43xBYLRxHanlXRoMA0GCSqGSIb3DQEB
# CwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8G
# A1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBT
# SEEyNTYgMjAyNSBDQTEwHhcNMjUwNjA0MDAwMDAwWhcNMzYwOTAzMjM1OTU5WjBj
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMT
# MkRpZ2lDZXJ0IFNIQTI1NiBSU0E0MDk2IFRpbWVzdGFtcCBSZXNwb25kZXIgMjAy
# NSAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0EasLRLGntDqrmBW
# sytXum9R/4ZwCgHfyjfMGUIwYzKomd8U1nH7C8Dr0cVMF3BsfAFI54um8+dnxk36
# +jx0Tb+k+87H9WPxNyFPJIDZHhAqlUPt281mHrBbZHqRK71Em3/hCGC5KyyneqiZ
# 7syvFXJ9A72wzHpkBaMUNg7MOLxI6E9RaUueHTQKWXymOtRwJXcrcTTPPT2V1D/+
# cFllESviH8YjoPFvZSjKs3SKO1QNUdFd2adw44wDcKgH+JRJE5Qg0NP3yiSyi5Mx
# gU6cehGHr7zou1znOM8odbkqoK+lJ25LCHBSai25CFyD23DZgPfDrJJJK77epTwM
# P6eKA0kWa3osAe8fcpK40uhktzUd/Yk0xUvhDU6lvJukx7jphx40DQt82yepyekl
# 4i0r8OEps/FNO4ahfvAk12hE5FVs9HVVWcO5J4dVmVzix4A77p3awLbr89A90/nW
# GjXMGn7FQhmSlIUDy9Z2hSgctaepZTd0ILIUbWuhKuAeNIeWrzHKYueMJtItnj2Q
# +aTyLLKLM0MheP/9w6CtjuuVHJOVoIJ/DtpJRE7Ce7vMRHoRon4CWIvuiNN1Lk9Y
# +xZ66lazs2kKFSTnnkrT3pXWETTJkhd76CIDBbTRofOsNyEhzZtCGmnQigpFHti5
# 8CSmvEyJcAlDVcKacJ+A9/z7eacCAwEAAaOCAZUwggGRMAwGA1UdEwEB/wQCMAAw
# HQYDVR0OBBYEFOQ7/PIx7f391/ORcWMZUEPPYYzoMB8GA1UdIwQYMBaAFO9vU0rp
# 5AZ8esrikFb2L9RJ7MtOMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggr
# BgEFBQcDCDCBlQYIKwYBBQUHAQEEgYgwgYUwJAYIKwYBBQUHMAGGGGh0dHA6Ly9v
# Y3NwLmRpZ2ljZXJ0LmNvbTBdBggrBgEFBQcwAoZRaHR0cDovL2NhY2VydHMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNI
# QTI1NjIwMjVDQTEuY3J0MF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly9jcmwzLmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZT
# SEEyNTYyMDI1Q0ExLmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1s
# BwEwDQYJKoZIhvcNAQELBQADggIBAGUqrfEcJwS5rmBB7NEIRJ5jQHIh+OT2Ik/b
# NYulCrVvhREafBYF0RkP2AGr181o2YWPoSHz9iZEN/FPsLSTwVQWo2H62yGBvg7o
# uCODwrx6ULj6hYKqdT8wv2UV+Kbz/3ImZlJ7YXwBD9R0oU62PtgxOao872bOySCI
# LdBghQ/ZLcdC8cbUUO75ZSpbh1oipOhcUT8lD8QAGB9lctZTTOJM3pHfKBAEcxQF
# oHlt2s9sXoxFizTeHihsQyfFg5fxUFEp7W42fNBVN4ueLaceRf9Cq9ec1v5iQMWT
# FQa0xNqItH3CPFTG7aEQJmmrJTV3Qhtfparz+BW60OiMEgV5GWoBy4RVPRwqxv7M
# k0Sy4QHs7v9y69NBqycz0BZwhB9WOfOu/CIJnzkQTwtSSpGGhLdjnQ4eBpjtP+XB
# 3pQCtv4E5UCSDag6+iX8MmB10nfldPF9SVD7weCC3yXZi/uuhqdwkgVxuiMFzGVF
# wYbQsiGnoa9F5AaAyBjFBtXVLcKtapnMG3VH3EmAp/jsJ3FVF3+d1SVDTmjFjLbN
# FZUWMXuZyvgLfgyPehwJVxwC+UpX2MSey2ueIu9THFVkT+um1vshETaWyQo8gmBt
# o/m3acaP9QsuLj3FNwFlTxq25+T4QwX9xa6ILs84ZPvmpovq90K8eWyG2N01c4Ih
# SOxqt81nMYIGVzCCBlMCAQEwezBnMQswCQYDVQQGEwJHQjEXMBUGA1UEBwwOTm9y
# dGh1bWJlcmxhbmQxGjAYBgNVBAoMEUlkZW50aXR5Rmlyc3QgTHRkMSMwIQYDVQQD
# DBpJZGVudGl0eUZpcnN0IENvZGUgU2lnbmluZwIQH2+FwHomto9H9PGoUG0SlzAN
# BglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqG
# SIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3
# AgEVMC8GCSqGSIb3DQEJBDEiBCDzUtqgE7y6ehlGCA4zhvGn55ESHWI614WOZWn5
# FGNwMDANBgkqhkiG9w0BAQEFAASCAgCMWRuoPoZ2+TOF2iGUpWn3aVZL5pgWIrCk
# uNbukgLKbgQw8BepsFXt2Mk420dm6QGcir6GAQiyl3OR+YZcbZaqVqVgsLXyZHeG
# 6ke+Wrun/JkAXNO2lTqW+lUQswrNmOl021RWltj7mckhs2ksW6SGP/u/zTRE9615
# 9nSpkpBUJFpAzzZIt2PltZr6Ptp+koIPmYHWiZLkPuMDV95ZKXnOovbVnC5h4mWG
# TVLFjDSH+n95zZ2RF0E2iM0RxCmgYgapmlsvKf1TZF8lMaMqvpYKJSzEGnwAOXnQ
# Zwu3aUAl0Cmtp+sQ/ICNcWE1LANu/auKgsv1r3DHDkaDpY+y/Pz6S7hUQMuuIhq2
# J4NWnPCVkbs2Rbtn8rAaecxq/9iDO2rh4Pca4QkMblpUo9leeoIh2aSCrsVH1HS1
# uId141ZaGsyAdtJHXbul3Sq7SJx5hSF+QjN7LD0zn5jdIzgET0US+Ss+MOmpYO4q
# 3cKpAUhC3Bm8V1ptFvmjdLOvIiLE/ngm13azIvQyvCbC7VvxZ3U+nMVOGBcx/F9h
# 7FcFDrnN7MrjdlTBtpklb+4877wAaHrwwcNWoPAho5wirg2lpu7D12te12Lb+KIj
# +bbcZWD+qmroDqq1Y1PKgLfHLoVBMVf11HJHGJoyJlKcS8zIFV6NELUExEWRQeLT
# 7ugjui3RnaGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAyMDUxNzEyNDRaMC8G
# CSqGSIb3DQEJBDEiBCAoyd2QKEPY0xYPy7/cX5hJ9kG3ip8Nw8nc/83XjiuXcjAN
# BgkqhkiG9w0BAQEFAASCAgArpM52xPWuF8/i7SbDdZW1+oiqsKsVRkEymUZPHCEi
# z6Kr2w/BT33p0mZuzyPCoUhGQqhuawXIKTsTtjcH1CWdBLZjAS13d0+gUYZ5A2Qv
# /u3blVF92WihHheTKwB3i3PHbJh7iIzhGolUdKqF32GCTu9Gcir2onU0QhtJUHMT
# JvJrAtklfrWUqD2jCWdDA3uz+0BqpUBCPTW0rUgpnGPcSd8Y4ZjkZmEviyD3K7Zq
# FSU4KLZxveTptlLxV7fcy88T8E8pDhx4JBp3sQNAh/KSukosUKMsS90J2ffQ4Kf+
# euUVWH+vA2/BuZ+EehQWVgrWlt7DNLe18ZOSpiQq/kw22gexVFp+hRARvTbi01XU
# OZnJD7ZcbsEGAMcWAjJEdEvlRZjbXYFhuHUo+XnrSQ+JcW3WapmNUX9DE2D6lGH1
# Gn9ukTgWyum6foxsOckfXMmrx3zm+FVqWaaIckrAnqnUVO5MaA3muRfh7qF5Bsoa
# ppGCTk/Boe2zwax7kPdKJ2CH7g5uMDQZaJsmJ76QVPkDS6/jh/ZBti0P+Ja7EWDr
# uMosg1ZDUD5h+d/FbTBxs3Oarx+i+Jr5bP5nTzYQRbC1FhPPEzgPcq9U0MHEzy1G
# sylsFqflwLVtRbq9/w4Zq4bDDm0ypCj+aoOMaZsA2cIAgYfT7wrIYHpMP7Cd2YJh
# +Q==
# SIG # End signature block
