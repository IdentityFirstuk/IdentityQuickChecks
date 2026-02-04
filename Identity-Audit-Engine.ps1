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

