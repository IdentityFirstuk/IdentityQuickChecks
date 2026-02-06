<#
.SYNOPSIS
    IdentityFirst QuickChecks Module
.DESCRIPTION
    PowerShell module providing wrapper functions for QuickChecks scripts.
    
    Usage:
        Import-Module IdentityFirst.QuickChecks
        Invoke-BreakGlassReality -OutputPath ".\Reports"

.NOTES
    Module Version: 1.1.0
    PowerShell: 5.1+
#>

#Requires -Version 5.1

# Get the module base path
$script:ModuleRoot = $PSScriptRoot
if (-not $script:ModuleRoot) {
    $script:ModuleRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
}

# ============================================================================
# Enums for Confidence and Evidence Quality
# ============================================================================

# Confidence levels for findings
enum FindingConfidence {
    High      = 3  # Direct evidence, multiple sources confirm
    Medium    = 2  # Some corroboration, single source with validation
    Low       = 1  # Inferred, limited evidence, heuristic-based
}

# Evidence quality indicators
enum EvidenceQuality {
    Direct    = 3  # Actual object/directory query results
    Indirect  = 2  # API responses, derivative data
    Inferred  = 1  # Calculated, heuristic-based detection
}

# Severity levels
enum FindingSeverity {
    Critical  = 5
    High     = 4
    Medium   = 3
    Low      = 2
    Informational = 1
}

# ============================================================================
# Helper Functions
# ============================================================================

function Get-ScriptPath {
    <#
    .SYNOPSIS
        Gets the full path to a QuickChecks script.
    #>
    param([string]$ScriptName)
    
    $scriptFolders = @(
        'IdentityQuickChecks',
        'IdentityTrustQuickChecks',
        'IdentityBoundaryQuickChecks',
        'IdentityAssumptionQuickChecks'
    )
    
    foreach ($folder in $scriptFolders) {
        $path = Join-Path $script:ModuleRoot $folder "$ScriptName.ps1"
        if (Test-Path $path) {
            return $path
        }
    }
    
    return $null
}

function Invoke-QCScript {
    <#
    .SYNOPSIS
        Executes a QuickChecks script and captures output.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$ScriptName,
        
        [Parameter(Mandatory=$false)]
        [string]$OutputPath = (Join-Path $PWD "IFQC-Output"),
        
        [Parameter(Mandatory=$false)]
        [switch]$Passthru
    )
    
    $scriptPath = Get-ScriptPath -ScriptName $ScriptName
    
    if (-not $scriptPath) {
        Write-Error "Script not found: $ScriptName"
        return $null
    }
    
    # Ensure output directory exists
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    # Create a script block that captures output
    $output = & $scriptPath -OutputPath $OutputPath 2>&1
    
    if ($Passthru) {
        return $output
    }
    
    return $true
}

# ============================================================================
# Core Finding Functions
# ============================================================================

function New-QuickChecksFinding {
    <#
    .SYNOPSIS
        Creates a standardized finding object with confidence and evidence quality.
    
    .DESCRIPTION
        This function creates a consistent finding object structure that includes
        all required fields for IdentityFirst QuickChecks findings including
        confidence scoring and evidence quality indicators.
    
    .PARAMETER Id
        Unique identifier for the finding (e.g., "BG-001")
    
    .PARAMETER RuleId
        Security rule reference identifier
    
    .PARAMETER Title
        Brief finding title
    
    .PARAMETER Description
        Detailed description of the finding
    
    .PARAMETER Severity
        Severity level: Critical, High, Medium, Low, Informational
    
    .PARAMETER Confidence
        Confidence level: High, Medium, Low
        - High: Direct evidence, multiple sources confirm
        - Medium: Some corroboration, single source with validation
        - Low: Inferred, limited evidence, heuristic-based
    
    .PARAMETER EvidenceQuality
        Evidence quality indicator: Direct, Indirect, Inferred
        - Direct: Actual object/directory query results
        - Indirect: API responses, derivative data
        - Inferred: Calculated, heuristic-based detection
    
    .PARAMETER AffectedObjects
        Array of affected objects (user accounts, groups, etc.)
    
    .PARAMETER Remediation
        High-level remediation guidance
    
    .PARAMETER RemediationSteps
        Array of actionable remediation steps
    
    .PARAMETER Source
        The QuickCheck that generated this finding
    
    .PARAMETER Category
        Finding category (e.g., "PrivilegeManagement", "Authentication")
    
    .PARAMETER IsResolved
        Whether the finding has been resolved
    
    .OUTPUTS
        PSCustomObject - Standardized finding object
    
    .EXAMPLE
        $finding = New-QuickChecksFinding -Id "BG-001" -Title "Break-glass accounts with password never expires" `
            -Severity "High" -Confidence "High" -EvidenceQuality "Direct" `
            -Description "Break-glass accounts should have regular password rotation." `
            -Remediation "Implement 90-day password rotation for break-glass accounts." `
            -RemediationSteps @("Step 1: Review current break-glass accounts", "Step 2: Update password policy") `
            -Source "BreakGlassReality" -Category "EmergencyAccess" `
            -AffectedObjects @("BG-Admin1", "breakglass")
    
    .NOTES
        Added in version 1.1.0 for standardized confidence and evidence quality.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Id,
        
        [Parameter(Mandatory=$false)]
        [string]$RuleId,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Title,
        
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Description,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Informational')]
        [string]$Severity,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet('High', 'Medium', 'Low')]
        [string]$Confidence,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet('Direct', 'Indirect', 'Inferred')]
        [string]$EvidenceQuality,
        
        [Parameter(Mandatory=$false)]
        [array]$AffectedObjects = @(),
        
        [Parameter(Mandatory=$false)]
        [string]$Remediation,
        
        [Parameter(Mandatory=$false)]
        [array]$RemediationSteps = @(),
        
        [Parameter(Mandatory=$false)]
        [string]$Source,
        
        [Parameter(Mandatory=$false)]
        [string]$Category,
        
        [Parameter(Mandatory=$false)]
        [bool]$IsResolved = $false
    )
    
    process {
        # Convert confidence string to enum value for calculations
        $confidenceValue = [FindingConfidence]::$Confidence
        
        # Convert evidence quality string to enum value for calculations
        $evidenceValue = [EvidenceQuality]::$EvidenceQuality
        
        # Convert severity string to enum value
        $severityValue = [FindingSeverity]::$Severity
        
        # Calculate detection reliability score (0-100)
        # Based on confidence and evidence quality
        $reliabilityScore = [int](($confidenceValue * $evidenceValue) / 9 * 100)
        
        # Calculate priority score (0-100)
        # Based on severity and confidence
        $priorityScore = [int](($severityValue * $confidenceValue) / 15 * 100)
        
        $finding = [PSCustomObject]@{
            # Core identification
            Id = $Id
            RuleId = $RuleId
            Title = $Title
            Description = $Description
            
            # Severity and confidence
            Severity = $Severity
            SeverityValue = $severityValue
            Confidence = $Confidence
            ConfidenceValue = $confidenceValue
            EvidenceQuality = $EvidenceQuality
            EvidenceQualityValue = $evidenceValue
            
            # Calculated scores
            ReliabilityScore = $reliabilityScore
            PriorityScore = $priorityScore
            
            # Affected objects and remediation
            AffectedObjects = $AffectedObjects
            Remediation = $Remediation
            RemediationSteps = $RemediationSteps
            
            # Metadata
            Timestamp = (Get-Date -AsUTC).ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")
            Source = $Source
            Category = $Category
            IsResolved = $IsResolved
            
            # Additional metadata
            Metadata = @{
                ToolName = "IdentityFirst.QuickChecks"
                ToolVersion = "1.1.0"
                SchemaVersion = "1.1"
            }
        }
        
        return $finding
    }
}

function New-QuickChecksExecutiveSummary {
    <#
    .SYNOPSIS
        Creates an executive summary with confidence-weighted scoring.
    
    .DESCRIPTION
        Generates a comprehensive executive summary from multiple findings,
        including confidence-weighted scoring, evidence quality breakdown,
        and detection reliability percentages.
    
    .PARAMETER Findings
        Array of finding objects from New-QuickChecksFinding
    
    .PARAMETER ReportTitle
        Title for the executive summary report
    
    .PARAMETER IncludeRemediation
        Include remediation recommendations in summary
    
    .OUTPUTS
        PSCustomObject - Executive summary with all scoring and breakdowns
    
    .EXAMPLE
        $summary = New-QuickChecksExecutiveSummary -Findings $allFindings `
            -ReportTitle "Identity Security Assessment" -IncludeRemediation $true
    
    .NOTES
        Added in version 1.1.0 for improved reporting clarity.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$Findings,
        
        [Parameter(Mandatory=$false)]
        [string]$ReportTitle = "Identity Security Assessment",
        
        [Parameter(Mandatory=$false)]
        [bool]$IncludeRemediation = $true
    )
    
    process {
        if (-not $Findings -or $Findings.Count -eq 0) {
            return $null
        }
        
        # Count by severity
        $severityBreakdown = @{
            Critical = ($Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
            High = ($Findings | Where-Object { $_.Severity -eq 'High' }).Count
            Medium = ($Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
            Low = ($Findings | Where-Object { $_.Severity -eq 'Low' }).Count
            Informational = ($Findings | Where-Object { $_.Severity -eq 'Informational' }).Count
        }
        
        # Count by confidence
        $confidenceBreakdown = @{
            High = ($Findings | Where-Object { $_.Confidence -eq 'High' }).Count
            Medium = ($Findings | Where-Object { $_.Confidence -eq 'Medium' }).Count
            Low = ($Findings | Where-Object { $_.Confidence -eq 'Low' }).Count
        }
        
        # Count by evidence quality
        $evidenceBreakdown = @{
            Direct = ($Findings | Where-Object { $_.EvidenceQuality -eq 'Direct' }).Count
            Indirect = ($Findings | Where-Object { $_.EvidenceQuality -eq 'Indirect' }).Count
            Inferred = ($Findings | Where-Object { $_.EvidenceQuality -eq 'Inferred' }).Count
        }
        
        # Calculate weighted scores
        $totalFindings = $Findings.Count
        
        # Overall confidence score (average of reliability scores)
        $overallConfidenceScore = [int](($Findings | Measure-Object -Property ReliabilityScore -Average).Average)
        
        # Weighted severity score (accounting for confidence)
        $weightedSeverityScore = [int](($Findings | Measure-Object -Property PriorityScore -Average).Average)
        
        # High-confidence findings percentage
        $highConfidencePct = if ($totalFindings -gt 0) {
            [int](($confidenceBreakdown.High / $totalFindings) * 100)
        } else { 0 }
        
        # Direct evidence percentage
        $directEvidencePct = if ($totalFindings -gt 0) {
            [int](($evidenceBreakdown.Direct / $totalFindings) * 100)
        } else { 0 }
        
        # Detection reliability percentages
        $reliabilityBreakdown = @{
            HighReliability = ($Findings | Where-Object { $_.ReliabilityScore -ge 80 }).Count
            MediumReliability = ($Findings | Where-Object { $_.ReliabilityScore -ge 50 -and $_.ReliabilityScore -lt 80 }).Count
            LowReliability = ($Findings | Where-Object { $_.ReliabilityScore -lt 50 }).Count
        }
        
        # High-priority findings (High or Critical with High confidence)
        $highPriorityFindings = $Findings | Where-Object {
            ($_.Severity -in @('Critical', 'High')) -and ($_.Confidence -eq 'High')
        }
        
        # Top remediation priorities
        $topRemediations = if ($IncludeRemediation) {
            $highPriorityFindings | ForEach-Object {
                [PSCustomObject]@{
                    FindingId = $_.Id
                    Title = $_.Title
                    Severity = $_.Severity
                    Confidence = $_.Confidence
                    Remediation = $_.Remediation
                }
            } | Sort-Object Severity, Confidence -Descending
        } else { @() }
        
        # Create summary object
        $summary = [PSCustomObject]@{
            # Report metadata
            ReportTitle = $ReportTitle
            GeneratedAt = (Get-Date -AsUTC).ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")
            ToolName = "IdentityFirst.QuickChecks"
            ToolVersion = "1.1.0"
            
            # Overview
            TotalFindings = $totalFindings
            ResolvedFindings = ($Findings | Where-Object { $_.IsResolved }).Count
            OpenFindings = ($Findings | Where-Object { -not $_.IsResolved }).Count
            
            # Severity breakdown
            SeverityBreakdown = $severityBreakdown
            
            # Confidence breakdown
            ConfidenceBreakdown = $confidenceBreakdown
            
            # Evidence quality breakdown
            EvidenceBreakdown = $evidenceBreakdown
            
            # Reliability breakdown
            ReliabilityBreakdown = $reliabilityBreakdown
            
            # Calculated scores
            OverallConfidenceScore = $overallConfidenceScore
            WeightedSeverityScore = $weightedSeverityScore
            HighConfidencePercentage = $highConfidencePct
            DirectEvidencePercentage = $directEvidencePct
            
            # Priority items
            HighPriorityCount = $highPriorityFindings.Count
            HighPriorityFindings = $highPriorityFindings | Select-Object -First 10
            
            # Remediation
            RemediationIncluded = $IncludeRemediation
            TopRemediations = $topRemediations
        }
        
        return $summary
    }
}

function Format-QuickChecksFinding {
    <#
    .SYNOPSIS
        Formats a finding for console output with severity colors.
    
    .DESCRIPTION
        Returns a formatted string representation of a finding
        with appropriate color coding for console display.
    
    .PARAMETER Finding
        The finding object to format
    
    .PARAMETER AsHtml
        Output as HTML formatted string
    
    .OUTPUTS
        string - Formatted finding string
    
    .EXAMPLE
        Format-QuickChecksFinding -Finding $finding -AsHtml $false
    
    .NOTES
        Added in version 1.1.0 for consistent output formatting.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Finding,
        
        [Parameter(Mandatory=$false)]
        [bool]$AsHtml = $false
    )
    
    process {
        # Map severity to colors
        $colorMap = @{
            Critical = 'Red'
            High = 'DarkRed'
            Medium = 'Yellow'
            Low = 'Green'
            Informational = 'Cyan'
        }
        
        $severityColor = $colorMap[$Finding.Severity]
        
        if ($AsHtml) {
            $output = @"
<div class="finding finding-$($Finding.Severity.ToLower())">
    <div class="finding-header">
        <span class="finding-id">$($Finding.Id)</span>
        <span class="finding-title">$($Finding.Title)</span>
        <span class="severity-badge severity-$($Finding.Severity.ToLower())">$($Finding.Severity)</span>
    </div>
    <div class="finding-body">
        <p class="finding-description">$($Finding.Description)</p>
        <div class="finding-metrics">
            <span class="metric confidence-$($Finding.Confidence.ToLower())" title="Confidence: $($Finding.Confidence)">
                Confidence: $($Finding.Confidence)
            </span>
            <span class="metric evidence-$($Finding.EvidenceQuality.ToLower())" title="Evidence Quality: $($Finding.EvidenceQuality)">
                Evidence: $($Finding.EvidenceQuality)
            </span>
            <span class="metric reliability" title="Reliability Score: $($Finding.ReliabilityScore)%">
                Reliability: $($Finding.ReliabilityScore)%
            </span>
        </div>
        <div class="finding-affected">
            <strong>Affected Objects:</strong> $($Finding.AffectedObjects -join ', ')
        </div>
        <div class="finding-remediation">
            <strong>Remediation:</strong> $($Finding.Remediation)
        </div>
        <div class="finding-steps">
            <strong>Action Steps:</strong>
            <ol>
                $($Finding.RemediationSteps | ForEach-Object { "<li>$_</li>" })
            </ol>
        </div>
    </div>
</div>
"@
        } else {
            # Console output format
            $affectedStr = if ($Finding.AffectedObjects) {
                $Finding.AffectedObjects -join ', '
            } else { 'None' }
            
            $stepsStr = if ($Finding.RemediationSteps) {
                ($Finding.RemediationSteps | ForEach-Object { "  - $_" }) -join "`n"
            } else { '  - None provided' }
            
            $output = @"
═══════════════════════════════════════════════════════════════
FINDING: $($Finding.Id)
═══════════════════════════════════════════════════════════════
Title:      $($Finding.Title)
Severity:   $($Finding.Severity) [$($severityColor)]
Confidence: $($Finding.Confidence)
Evidence:   $($Finding.EvidenceQuality)
Reliability: $($Finding.ReliabilityScore)%
───────────────────────────────────────────────────────────────
Description:
$($Finding.Description)

Affected Objects:
$affectedStr

Remediation:
$($Finding.Remediation)

Action Steps:
$stepsStr

Metadata:
  Category:  $($Finding.Category)
  Source:    $($Finding.Source)
  Timestamp: $($Finding.Timestamp)
═══════════════════════════════════════════════════════════════
"@
        }
        
        return $output
    }
}

function Export-QuickChecksFinding {
    <#
    .SYNOPSIS
        Exports findings to JSON format.
    
    .DESCRIPTION
        Exports finding objects to a JSON file with standardized
        structure including all confidence and evidence quality data.
    
    .PARAMETER Findings
        Array of finding objects
    
    .PARAMETER OutputPath
        Path for the JSON output file
    
    .PARAMETER IncludeSummary
        Include executive summary in export
    
    .OUTPUTS
        string - Path to exported file
    
    .EXAMPLE
        Export-QuickChecksFinding -Findings $findings -OutputPath ".\report.json"
    
    .NOTES
        Added in version 1.1.0 for standardized JSON export.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [array]$Findings,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$false)]
        [bool]$IncludeSummary = $true
    )
    
    process {
        # Ensure output directory exists
        $directory = Split-Path $OutputPath -Parent
        if (-not (Test-Path $directory)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
        
        # Create export object
        $exportObject = [PSCustomObject]@{
            # Metadata
            exportedAt = (Get-Date -AsUTC).ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'")
            toolName = "IdentityFirst.QuickChecks"
            toolVersion = "1.1.0"
            schemaVersion = "1.1"
            
            # Findings
            findings = $Findings
            
            # Executive summary if requested
            executiveSummary = if ($IncludeSummary) {
                New-QuickChecksExecutiveSummary -Findings $Findings -ReportTitle "QuickChecks Report"
            } else { $null }
        }
        
        # Export to JSON
        $jsonOutput = $exportObject | ConvertTo-Json -Depth 10
        $jsonOutput | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
        
        Write-Verbose "Exported $($Findings.Count) findings to: $OutputPath"
        
        return $OutputPath
    }
}

# ============================================================================
# Core IdentityQuickChecks
# ============================================================================

function Invoke-BreakGlassReality {
    <#
    .SYNOPSIS
        Find break-glass accounts and check their posture.
    
    .DESCRIPTION
        Searches for accounts named or described as break-glass,
        emergency, or firecall accounts. Reports on their posture
        including password never expires, last logon, and risk factors.
    
    .EXAMPLE
        Invoke-BreakGlassReality -OutputPath ".\Reports"
    
    .NOTES
        Read-only: YES
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputPath = (Join-Path $PWD "IFQC-Output")
    )
    
    process {
        $null = Invoke-QCScript -ScriptName "BreakGlassReality" -OutputPath $OutputPath
        Write-Verbose "BreakGlassReality check completed"
    }
}

function Invoke-IdentityNamingHygiene {
    <#
    .SYNOPSIS
        Detect naming violations and ownership gaps.
    
    .EXAMPLE
        Invoke-IdentityNamingHygiene -OutputPath ".\Reports"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputPath = (Join-Path $PWD "IFQC-Output")
    )
    
    process {
        Invoke-QCScript -ScriptName "IdentityNamingHygiene" -OutputPath $OutputPath
    }
}

function Invoke-PasswordPolicyDrift {
    <#
    .SYNOPSIS
        Identify accounts bypassing password policies.
    
    .EXAMPLE
        Invoke-PasswordPolicyDrift -OutputPath ".\Reports"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputPath = (Join-Path $PWD "IFQC-Output")
    )
    
    process {
        Invoke-QCScript -ScriptName "PasswordPolicyDrift" -OutputPath $OutputPath
    }
}

function Invoke-PrivilegedNestingAbuse {
    <#
    .SYNOPSIS
        Find indirect privilege through nested groups.
    
    .EXAMPLE
        Invoke-PrivilegedNestingAbuse -OutputPath ".\Reports"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputPath = (Join-Path $PWD "IFQC-Output")
    )
    
    process {
        Invoke-QCScript -ScriptName "PrivilegedNestingAbuse" -OutputPath $OutputPath
    }
}

# ============================================================================
# IdentityTrustQuickChecks
# ============================================================================

function Invoke-ExternalTrustMapping {
    <#
    .SYNOPSIS
        Map AD trusts and flag external relationships.
    
    .EXAMPLE
        Invoke-ExternalTrustMapping -OutputPath ".\Reports"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputPath = (Join-Path $PWD "IFQC-Output")
    )
    
    process {
        Invoke-QCScript -ScriptName "ExternalTrustMapping" -OutputPath $OutputPath
    }
}

function Invoke-IdentityAttackSurface {
    <#
    .SYNOPSIS
        Identify accounts with elevated exposure.
    
    .EXAMPLE
        Invoke-IdentityAttackSurface -OutputPath ".\Reports"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputPath = (Join-Path $PWD "IFQC-Output")
    )
    
    process {
        Invoke-QCScript -ScriptName "IdentityAttackSurface" -OutputPath $OutputPath
    }
}

function Invoke-IdentityReviewDebt {
    <#
    .SYNOPSIS
        Find privileged access unchanged for years.
    
    .EXAMPLE
        Invoke-IdentityReviewDebt -OutputPath ".\Reports"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputPath = (Join-Path $PWD "IFQC-Output")
    )
    
    process {
        Invoke-QCScript -ScriptName "IdentityReviewDebt" -OutputPath $OutputPath
    }
}

function Invoke-IdentityLoggingGaps {
    <#
    .SYNOPSIS
        Check security logging configuration.
    
    .DESCRIPTION
        Identifies gaps in security logging configuration across
        the environment. Checks for missing log sources, disabled
        logging, and misconfigured log settings.
    
    .EXAMPLE
        Invoke-IdentityLoggingGaps -OutputPath ".\Reports"
    
    .NOTES
        The noun 'LoggingGaps' is intentionally plural as it refers
        to multiple potential logging gaps to be identified.
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputPath = (Join-Path $PWD "IFQC-Output")
    )
    
    process {
        Invoke-QCScript -ScriptName "IdentityLoggingGaps" -OutputPath $OutputPath
    }
}

# ============================================================================
# IdentityAssumptionQuickChecks
# ============================================================================

function Invoke-WeDontUseThatCheck {
    <#
    .SYNOPSIS
        Verify enabled features aren't assumed unused.
    
    .EXAMPLE
        Invoke-WeDontUseThatCheck -OutputPath ".\Reports"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputPath = (Join-Path $PWD "IFQC-Output")
    )
    
    process {
        Invoke-QCScript -ScriptName "WeDontUseThatCheck" -OutputPath $OutputPath
    }
}

function Invoke-IdentityOwnershipReality {
    <#
    .SYNOPSIS
        Verify ownership can actually be determined.
    
    .EXAMPLE
        Invoke-IdentityOwnershipReality -OutputPath ".\Reports"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputPath = (Join-Path $PWD "IFQC-Output")
    )
    
    process {
        Invoke-QCScript -ScriptName "IdentityOwnershipReality" -OutputPath $OutputPath
    }
}

# ============================================================================
# IdentityBoundaryQuickChecks
# ============================================================================

function Invoke-CrossEnvironmentBoundary {
    <#
    .SYNOPSIS
        Identify identities in multiple environments.
    
    .EXAMPLE
        Invoke-CrossEnvironmentBoundary -OutputPath ".\Reports"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputPath = (Join-Path $PWD "IFQC-Output")
    )
    
    process {
        Invoke-QCScript -ScriptName "CrossEnvironmentBoundary" -OutputPath $OutputPath
    }
}

function Invoke-IdentityTieringDrift {
    <#
    .SYNOPSIS
        Check if Tier 0 accounts touch Tier 1/2 systems.
    
    .EXAMPLE
        Invoke-IdentityTieringDrift -OutputPath ".\Reports"
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$OutputPath = (Join-Path $PWD "IFQC-Output")
    )
    
    process {
        Invoke-QCScript -ScriptName "IdentityTieringDrift" -OutputPath $OutputPath
    }
}

# ============================================================================
# Utility Functions
# ============================================================================

function Get-IFQCCommands {
    <#
    .SYNOPSIS
        Lists all available QuickChecks commands.
    
    .DESCRIPTION
        Returns a collection of all QuickChecks commands with their
        descriptions. The noun 'Commands' is intentionally plural
        as it refers to multiple command entries.
    
    .OUTPUTS
        PSCustomObject[] - Collection of command information objects
    #>
    [CmdletBinding()]
    param()
    
    $commands = @(
        'Invoke-BreakGlassReality',
        'Invoke-IdentityNamingHygiene',
        'Invoke-PasswordPolicyDrift',
        'Invoke-PrivilegedNestingAbuse',
        'Invoke-ExternalTrustMapping',
        'Invoke-IdentityAttackSurface',
        'Invoke-IdentityReviewDebt',
        'Invoke-IdentityLoggingGaps',
        'Invoke-WeDontUseThatCheck',
        'Invoke-IdentityOwnershipReality',
        'Invoke-CrossEnvironmentBoundary',
        'Invoke-IdentityTieringDrift',
        'New-QuickChecksFinding',
        'New-QuickChecksExecutiveSummary',
        'Format-QuickChecksFinding',
        'Export-QuickChecksFinding'
    )
    
    $commands | ForEach-Object {
        [PSCustomObject]@{
            Command = $_
            Description = (Get-Help $_ -ErrorAction SilentlyContinue).Synopsis
        }
    }
}

function Get-IFQCInfo {
    <#
    .SYNOPSIS
        Displays module information.
    .DESCRIPTION
        Returns module information as a structured object for display.
    .OUTPUTS
        PSCustomObject - Module information object
    #>
    [CmdletBinding()]
    param()
    
    $info = [PSCustomObject]@{
        Name = 'IdentityFirst QuickChecks Module'
        Version = '1.1.0'
        ModulePath = $script:ModuleRoot
        Features = @(
            'Standardized finding object structure',
            'Confidence scoring (High/Medium/Low)',
            'Evidence quality indicators (Direct/Indirect/Inferred)',
            'Executive summary with confidence-weighted scoring',
            'Detection reliability percentages',
            'Actionable remediation steps'
        )
    }
    
    Write-Output $info
    Write-Output ''
    Write-Output 'Available Commands:'
    Write-Output ''
    
    Get-IFQCCommands | Format-Table -AutoSize -HideTableHeaders
}

# Export all wrapper functions
Export-ModuleMember -Function @(
    'Invoke-BreakGlassReality',
    'Invoke-IdentityNamingHygiene',
    'Invoke-PasswordPolicyDrift',
    'Invoke-PrivilegedNestingAbuse',
    'Invoke-ExternalTrustMapping',
    'Invoke-IdentityAttackSurface',
    'Invoke-IdentityReviewDebt',
    'Invoke-IdentityLoggingGaps',
    'Invoke-WeDontUseThatCheck',
    'Invoke-IdentityOwnershipReality',
    'Invoke-CrossEnvironmentBoundary',
    'Invoke-IdentityTieringDrift',
    'New-QuickChecksFinding',
    'New-QuickChecksExecutiveSummary',
    'Format-QuickChecksFinding',
    'Export-QuickChecksFinding',
    'Get-IFQCCommands',
    'Get-IFQCInfo'
)
