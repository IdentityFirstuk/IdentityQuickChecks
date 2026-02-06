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

# ============================================================================
# Pester Tests for IdentityFirst.QuickChecks Module
# ============================================================================

Describe "IdentityFirst.QuickChecks - Finding Object Structure" -Tag "Confidence" {
    
    BeforeAll {
        # Import the module
        $modulePath = Join-Path $PSScriptRoot "..\Module\IdentityFirst.QuickChecks.psm1"
        if (Test-Path $modulePath) {
            Import-Module $modulePath -Force -ErrorAction Stop
        }
    }
    
    Context "New-QuickChecksFinding - Core Structure" {
        
        It "Should create a finding with all required properties" {
            $finding = New-QuickChecksFinding `
                -Id "TEST-001" `
                -Title "Test Finding" `
                -Description "Test description" `
                -Severity "High" `
                -Confidence "High" `
                -EvidenceQuality "Direct" `
                -Source "TestCheck" `
                -Category "Testing"
            
            $finding.Id | Should -Be "TEST-001"
            $finding.Title | Should -Be "Test Finding"
            $finding.Description | Should -Be "Test description"
            $finding.Severity | Should -Be "High"
            $finding.Confidence | Should -Be "High"
            $finding.EvidenceQuality | Should -Be "Direct"
            $finding.Source | Should -Be "TestCheck"
            $finding.Category | Should -Be "Testing"
        }
        
        It "Should set IsResolved to false by default" {
            $finding = New-QuickChecksFinding `
                -Id "TEST-002" `
                -Title "Test Finding" `
                -Description "Test" `
                -Severity "Medium" `
                -Confidence "Medium" `
                -EvidenceQuality "Indirect"
            
            $finding.IsResolved | Should -Be $false
        }
        
        It "Should allow setting IsResolved to true" {
            $finding = New-QuickChecksFinding `
                -Id "TEST-003" `
                -Title "Test" `
                -Description "Test" `
                -Severity "Low" `
                -Confidence "Low" `
                -EvidenceQuality "Inferred" `
                -IsResolved $true
            
            $finding.IsResolved | Should -Be $true
        }
        
        It "Should include AffectedObjects array" {
            $objects = @("Object1", "Object2")
            $finding = New-QuickChecksFinding `
                -Id "TEST-004" `
                -Title "Test" `
                -Description "Test" `
                -Severity "Critical" `
                -Confidence "High" `
                -EvidenceQuality "Direct" `
                -AffectedObjects $objects
            
            $finding.AffectedObjects.Count | Should -Be 2
            $finding.AffectedObjects[0] | Should -Be "Object1"
        }
        
        It "Should include RemediationSteps array" {
            $steps = @("Step 1", "Step 2", "Step 3")
            $finding = New-QuickChecksFinding `
                -Id "TEST-005" `
                -Title "Test" `
                -Description "Test" `
                -Severity "High" `
                -Confidence "Medium" `
                -EvidenceQuality "Indirect" `
                -Remediation "Test remediation" `
                -RemediationSteps $steps
            
            $finding.RemediationSteps.Count | Should -Be 3
            $finding.Remediation | Should -Be "Test remediation"
        }
        
        It "Should include ISO 8601 timestamp" {
            $finding = New-QuickChecksFinding `
                -Id "TEST-006" `
                -Title "Test" `
                -Description "Test" `
                -Severity "Medium" `
                -Confidence "Low" `
                -EvidenceQuality "Inferred"
            
            $finding.Timestamp | Should -Not -BeNullOrEmpty
            $finding.Timestamp | Should -Match "\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
        }
    }
    
    Context "New-QuickChecksFinding - Confidence Scoring" {
        
        It "Should calculate ReliabilityScore based on Confidence and EvidenceQuality" {
            # High confidence + Direct evidence = High reliability
            $finding = New-QuickChecksFinding `
                -Id "TEST-HC-DE" `
                -Title "Test" `
                -Description "Test" `
                -Severity "High" `
                -Confidence "High" `
                -EvidenceQuality "Direct"
            
            $finding.ReliabilityScore | Should -BeGreaterThan 80
        }
        
        It "Should assign lower ReliabilityScore for Low confidence" {
            $finding = New-QuickChecksFinding `
                -Id "TEST-LC" `
                -Title "Test" `
                -Description "Test" `
                -Severity "Low" `
                -Confidence "Low" `
                -EvidenceQuality "Inferred"
            
            $finding.ReliabilityScore | Should -BeLessThan 50
        }
        
        It "Should calculate PriorityScore based on Severity and Confidence" {
            $criticalFinding = New-QuickChecksFinding `
                -Id "TEST-CRIT" `
                -Title "Test" `
                -Description "Test" `
                -Severity "Critical" `
                -Confidence "High" `
                -EvidenceQuality "Direct"
            
            $lowFinding = New-QuickChecksFinding `
                -Id "TEST-LOW" `
                -Title "Test" `
                -Description "Test" `
                -Severity "Low" `
                -Confidence "Low" `
                -EvidenceQuality "Inferred"
            
            $criticalFinding.PriorityScore | Should -BeGreaterThan $lowFinding.PriorityScore
        }
        
        It "Should include ConfidenceValue enum" {
            $finding = New-QuickChecksFinding `
                -Id "TEST-ENUM" `
                -Title "Test" `
                -Description "Test" `
                -Severity "Medium" `
                -Confidence "Medium" `
                -EvidenceQuality "Indirect"
            
            $finding.ConfidenceValue | Should -Be 2  # Medium = 2
        }
        
        It "Should include EvidenceQualityValue enum" {
            $finding = New-QuickChecksFinding `
                -Id "TEST-EVID" `
                -Title "Test" `
                -Description "Test" `
                -Severity "Medium" `
                -Confidence "Medium" `
                -EvidenceQuality "Direct"
            
            $finding.EvidenceQualityValue | Should -Be 3  # Direct = 3
        }
    }
    
    Context "Confidence Levels - Validation" {
        
        It "Should reject invalid Confidence values" {
            { New-QuickChecksFinding `
                -Id "TEST-INV" `
                -Title "Test" `
                -Description "Test" `
                -Severity "High" `
                -Confidence "VeryHigh" `
                -EvidenceQuality "Direct" 
            } | Should -Throw
        }
        
        It "Should reject invalid EvidenceQuality values" {
            { New-QuickChecksFinding `
                -Id "TEST-INV2" `
                -Title "Test" `
                -Description "Test" `
                -Severity "High" `
                -Confidence "High" `
                -EvidenceQuality "VeryDirect" 
            } | Should -Throw
        }
        
        It "Should accept all valid Confidence values" {
            @("High", "Medium", "Low") | ForEach-Object {
                $finding = New-QuickChecksFinding `
                    -Id "TEST-$_" `
                    -Title "Test" `
                    -Description "Test" `
                    -Severity "High" `
                    -Confidence $_ `
                    -EvidenceQuality "Direct"
                
                $finding.Confidence | Should -Be $_
            }
        }
        
        It "Should accept all valid EvidenceQuality values" {
            @("Direct", "Indirect", "Inferred") | ForEach-Object {
                $finding = New-QuickChecksFinding `
                    -Id "TEST-EVID-$_" `
                    -Title "Test" `
                    -Description "Test" `
                    -Severity "High" `
                    -Confidence "High" `
                    -EvidenceQuality $_
                
                $finding.EvidenceQuality | Should -Be $_
            }
        }
    }
}

Describe "IdentityFirst.QuickChecks - Executive Summary" -Tag "ExecutiveSummary" {
    
    BeforeAll {
        $modulePath = Join-Path $PSScriptRoot "..\Module\IdentityFirst.QuickChecks.psm1"
        if (Test-Path $modulePath) {
            Import-Module $modulePath -Force -ErrorAction Stop
        }
    }
    
    Context "New-QuickChecksExecutiveSummary - Basic Structure" {
        
        It "Should create summary from findings" {
            $findings = @(
                New-QuickChecksFinding `
                    -Id "SUM-001" `
                    -Title "Test 1" `
                    -Description "Test" `
                    -Severity "Critical" `
                    -Confidence "High" `
                    -EvidenceQuality "Direct"
                
                New-QuickChecksFinding `
                    -Id "SUM-002" `
                    -Title "Test 2" `
                    -Description "Test" `
                    -Severity "High" `
                    -Confidence "Medium" `
                    -EvidenceQuality "Indirect"
            )
            
            $summary = New-QuickChecksExecutiveSummary -Findings $findings
            
            $summary.TotalFindings | Should -Be 2
            $summary.SeverityBreakdown.Critical | Should -Be 1
            $summary.SeverityBreakdown.High | Should -Be 1
        }
        
        It "Should calculate ConfidenceBreakdown" {
            $findings = @(
                New-QuickChecksFinding -Id "CB-001" -Title "Test" -Description "Test" `
                    -Severity "High" -Confidence "High" -EvidenceQuality "Direct"
                New-QuickChecksFinding -Id "CB-002" -Title "Test" -Description "Test" `
                    -Severity "Medium" -Confidence "Medium" -EvidenceQuality "Indirect"
                New-QuickChecksFinding -Id "CB-003" -Title "Test" -Description "Test" `
                    -Severity "Low" -Confidence "Low" -EvidenceQuality "Inferred"
            )
            
            $summary = New-QuickChecksExecutiveSummary -Findings $findings
            
            $summary.ConfidenceBreakdown.High | Should -Be 1
            $summary.ConfidenceBreakdown.Medium | Should -Be 1
            $summary.ConfidenceBreakdown.Low | Should -Be 1
        }
        
        It "Should calculate EvidenceBreakdown" {
            $findings = @(
                New-QuickChecksFinding -Id "EB-001" -Title "Test" -Description "Test" `
                    -Severity "High" -Confidence "High" -EvidenceQuality "Direct"
                New-QuickChecksFinding -Id "EB-002" -Title "Test" -Description "Test" `
                    -Severity "Medium" -Confidence "Medium" -EvidenceQuality "Indirect"
                New-QuickChecksFinding -Id "EB-003" -Title "Test" -Description "Test" `
                    -Severity "Low" -Confidence "Low" -EvidenceQuality "Inferred"
            )
            
            $summary = New-QuickChecksExecutiveSummary -Findings $findings
            
            $summary.EvidenceBreakdown.Direct | Should -Be 1
            $summary.EvidenceBreakdown.Indirect | Should -Be 1
            $summary.EvidenceBreakdown.Inferred | Should -Be 1
        }
        
        It "Should include detection reliability percentages" {
            $findings = @(
                New-QuickChecksFinding -Id "REL-001" -Title "Test" -Description "Test" `
                    -Severity "Critical" -Confidence "High" -EvidenceQuality "Direct"
                New-QuickChecksFinding -Id "REL-002" -Title "Test" -Description "Test" `
                    -Severity "Medium" -Confidence "Medium" -EvidenceQuality "Indirect"
            )
            
            $summary = New-QuickChecksExecutiveSummary -Findings $findings
            
            $summary.OverallConfidenceScore | Should -Not -BeNullOrEmpty
            $summary.HighConfidencePercentage | Should -Not -BeNullOrEmpty
            $summary.DirectEvidencePercentage | Should -Not -BeNullOrEmpty
        }
        
        It "Should include ReliabilityBreakdown" {
            $findings = @(
                New-QuickChecksFinding -Id "RLB-001" -Title "Test" -Description "Test" `
                    -Severity "Critical" -Confidence "High" -EvidenceQuality "Direct"
                New-QuickChecksFinding -Id "RLB-002" -Title "Test" -Description "Test" `
                    -Severity "Low" -Confidence "Low" -EvidenceQuality "Inferred"
            )
            
            $summary = New-QuickChecksExecutiveSummary -Findings $findings
            
            $summary.ReliabilityBreakdown.HighReliability | Should -BeGreaterThan 0
            $summary.ReliabilityBreakdown.LowReliability | Should -BeGreaterThan 0
        }
        
        It "Should return null for empty findings" {
            $summary = New-QuickChecksExecutiveSummary -Findings @()
            
            $summary | Should -Be $null
        }
        
        It "Should include ISO 8601 timestamp" {
            $finding = New-QuickChecksFinding `
                -Id "TS-001" `
                -Title "Test" `
                -Description "Test" `
                -Severity "Low" `
                -Confidence "Medium" `
                -EvidenceQuality "Indirect"
            
            $summary = New-QuickChecksExecutiveSummary -Findings @($finding)
            
            $summary.GeneratedAt | Should -Match "\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
        }
    }
    
    Context "New-QuickChecksExecutiveSummary - Remediation" {
        
        It "Should include remediation when requested" {
            $findings = @(
                New-QuickChecksFinding `
                    -Id "REM-001" `
                    -Title "Test" `
                    -Description "Test" `
                    -Severity "Critical" `
                    -Confidence "High" `
                    -EvidenceQuality "Direct" `
                    -Remediation "Fix this" `
                    -RemediationSteps @("Step 1")
            )
            
            $summary = New-QuickChecksExecutiveSummary -Findings $findings -IncludeRemediation $true
            
            $summary.RemediationIncluded | Should -Be $true
            $summary.TopRemediations.Count | Should -Be 1
        }
        
        It "Should not include remediation when disabled" {
            $findings = @(
                New-QuickChecksFinding `
                    -Id "REM-002" `
                    -Title "Test" `
                    -Description "Test" `
                    -Severity "High" `
                    -Confidence "High" `
                    -EvidenceQuality "Direct" `
                    -Remediation "Fix this"
            )
            
            $summary = New-QuickChecksExecutiveSummary -Findings $findings -IncludeRemediation $false
            
            $summary.RemediationIncluded | Should -Be $false
            $summary.TopRemediations | Should -BeNullOrEmpty
        }
    }
}

Describe "IdentityFirst.QuickChecks - Finding Formatting" -Tag "Formatting" {
    
    BeforeAll {
        $modulePath = Join-Path $PSScriptRoot "..\Module\IdentityFirst.QuickChecks.psm1"
        if (Test-Path $modulePath) {
            Import-Module $modulePath -Force -ErrorAction Stop
        }
    }
    
    Context "Format-QuickChecksFinding - Console Output" {
        
        It "Should format finding with ID and Title" {
            $finding = New-QuickChecksFinding `
                -Id "FMT-001" `
                -Title "Test Finding Title" `
                -Description "Test description" `
                -Severity "High" `
                -Confidence "High" `
                -EvidenceQuality "Direct"
            
            $output = Format-QuickChecksFinding -Finding $finding -AsHtml $false
            
            $output | Should -Contain "FMT-001"
            $output | Should -Contain "Test Finding Title"
        }
        
        It "Should include confidence and evidence quality" {
            $finding = New-QuickChecksFinding `
                -Id "FMT-002" `
                -Title "Test" `
                -Description "Test" `
                -Severity "Critical" `
                -Confidence "Medium" `
                -EvidenceQuality "Indirect"
            
            $output = Format-QuickChecksFinding -Finding $finding -AsHtml $false
            
            $output | Should -Contain "Confidence: Medium"
            $output | Should -Contain "Evidence: Indirect"
            $output | Should -Contain "Reliability:"
        }
        
        It "Should include affected objects" {
            $finding = New-QuickChecksFinding `
                -Id "FMT-003" `
                -Title "Test" `
                -Description "Test" `
                -Severity "Medium" `
                -Confidence "Low" `
                -EvidenceQuality "Inferred" `
                -AffectedObjects @("Object1", "Object2")
            
            $output = Format-QuickChecksFinding -Finding $finding -AsHtml $false
            
            $output | Should -Contain "Object1"
            $output | Should -Contain "Object2"
        }
        
        It "Should include remediation steps" {
            $finding = New-QuickChecksFinding `
                -Id "FMT-004" `
                -Title "Test" `
                -Description "Test" `
                -Severity "Low" `
                -Confidence "Medium" `
                -EvidenceQuality "Direct" `
                -Remediation "Fix this issue" `
                -RemediationSteps @("Do step 1", "Do step 2")
            
            $output = Format-QuickChecksFinding -Finding $finding -AsHtml $false
            
            $output | Should -Contain "Fix this issue"
            $output | Should -Contain "Do step 1"
        }
    }
    
    Context "Format-QuickChecksFinding - HTML Output" {
        
        It "Should generate valid HTML structure" {
            $finding = New-QuickChecksFinding `
                -Id "HTML-001" `
                -Title "HTML Test" `
                -Description "Test" `
                -Severity "High" `
                -Confidence "High" `
                -EvidenceQuality "Direct"
            
            $output = Format-QuickChecksFinding -Finding $finding -AsHtml $true
            
            $output | Should -Contain "<div class=""finding"
            $output | Should -Contain "finding-$($finding.Severity.ToLower())"
        }
        
        It "Should include severity badge" {
            $finding = New-QuickChecksFinding `
                -Id "HTML-002" `
                -Title "Test" `
                -Description "Test" `
                -Severity "Critical" `
                -Confidence "High" `
                -EvidenceQuality "Direct"
            
            $output = Format-QuickChecksFinding -Finding $finding -AsHtml $true
            
            $output | Should -Contain "severity-badge"
            $output | Should -Contain "severity-critical"
        }
    }
}

Describe "IdentityFirst.QuickChecks - Export" -Tag "Export" {
    
    BeforeAll {
        $modulePath = Join-Path $PSScriptRoot "..\Module\IdentityFirst.QuickChecks.psm1"
        if (Test-Path $modulePath) {
            Import-Module $modulePath -Force -ErrorAction Stop
        }
        
        $testOutputPath = Join-Path $PSScriptRoot "TestOutput"
        if (-not (Test-Path $testOutputPath)) {
            New-Item -ItemType Directory -Path $testOutputPath -Force | Out-Null
        }
    }
    
    AfterAll {
        if (Test-Path $testOutputPath) {
            Remove-Item -Path $testOutputPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    Context "Export-QuickChecksFinding - JSON Export" {
        
        It "Should export findings to JSON file" {
            $findings = @(
                New-QuickChecksFinding `
                    -Id "EXP-001" `
                    -Title "Test Export" `
                    -Description "Test" `
                    -Severity "High" `
                    -Confidence "High" `
                    -EvidenceQuality "Direct"
            )
            
            $outputFile = Join-Path $testOutputPath "test-export.json"
            
            $result = Export-QuickChecksFinding `
                -Findings $findings `
                -OutputPath $outputFile `
                -IncludeSummary $true
            
            $result | Should -Be $outputFile
            Test-Path $outputFile | Should -Be $true
        }
        
        It "Should include executive summary in export" {
            $findings = @(
                New-QuickChecksFinding `
                    -Id "EXP-SUM-001" `
                    -Title "Test" `
                    -Description "Test" `
                    -Severity "Medium" `
                    -Confidence "Medium" `
                    -EvidenceQuality "Indirect"
            )
            
            $outputFile = Join-Path $testOutputPath "test-export-summary.json"
            
            Export-QuickChecksFinding -Findings $findings -OutputPath $outputFile -IncludeSummary $true | Out-Null
            
            $jsonContent = Get-Content $outputFile -Raw | ConvertFrom-Json
            
            $jsonContent.executiveSummary | Should -Not -BeNullOrEmpty
            $jsonContent.executiveSummary.TotalFindings | Should -Be 1
        }
        
        It "Should create output directory if not exists" {
            $findings = @(
                New-QuickChecksFinding `
                    -Id "EXP-DIR-001" `
                    -Title "Test" `
                    -Description "Test" `
                    -Severity "Low" `
                    -Confidence "Low" `
                    -EvidenceQuality "Inferred"
            )
            
            $newDir = Join-Path $testOutputPath "NewSubDir"
            $outputFile = Join-Path $newDir "test-deep-export.json"
            
            Export-QuickChecksFinding -Findings $findings -OutputPath $outputFile -IncludeSummary $false | Out-Null
            
            Test-Path $newDir | Should -Be $true
        }
    }
}

Describe "IdentityFirst.QuickChecks - Severity Validation" -Tag "Severity" {
    
    BeforeAll {
        $modulePath = Join-Path $PSScriptRoot "..\Module\IdentityFirst.QuickChecks.psm1"
        if (Test-Path $modulePath) {
            Import-Module $modulePath -Force -ErrorAction Stop
        }
    }
    
    Context "Severity Values" {
        
        It "Should accept Critical severity" {
            $finding = New-QuickChecksFinding `
                -Id "SEV-CRIT" `
                -Title "Test" `
                -Description "Test" `
                -Severity "Critical" `
                -Confidence "High" `
                -EvidenceQuality "Direct"
            
            $finding.Severity | Should -Be "Critical"
            $finding.SeverityValue | Should -Be 5
        }
        
        It "Should accept all severity levels" {
            @("Critical", "High", "Medium", "Low", "Informational") | ForEach-Object {
                $finding = New-QuickChecksFinding `
                    -Id "SEV-$_" `
                    -Title "Test" `
                    -Description "Test" `
                    -Severity $_ `
                    -Confidence "Medium" `
                    -EvidenceQuality "Indirect"
                
                $finding.Severity | Should -Be $_
            }
        }
        
        It "Should reject invalid severity" {
            { New-QuickChecksFinding `
                -Id "SEV-INV" `
                -Title "Test" `
                -Description "Test" `
                -Severity "VeryHigh" `
                -Confidence "High" `
                -EvidenceQuality "Direct"
            } | Should -Throw
        }
    }
}

Describe "IdentityFirst.QuickChecks - Module Info" -Tag "Module" {
    
    BeforeAll {
        $modulePath = Join-Path $PSScriptRoot "..\Module\IdentityFirst.QuickChecks.psm1"
        if (Test-Path $modulePath) {
            Import-Module $modulePath -Force -ErrorAction Stop
        }
    }
    
    Context "Get-IFQCInfo" {
        
        It "Should return module information" {
            $info = Get-IFQCInfo
            
            $info.Name | Should -Be "IdentityFirst QuickChecks Module"
            $info.Version | Should -Be "1.1.0"
            $info.Features | Should -Not -BeNullOrEmpty
            $info.Features | Should -Contain "Standardized finding object structure"
            $info.Features | Should -Contain "Confidence scoring (High/Medium/Low)"
            $info.Features | Should -Contain "Evidence quality indicators (Direct/Indirect/Inferred)"
        }
    }
    
    Context "Get-IFQCCommands" {
        
        It "Should list all available commands" {
            $commands = Get-IFQCCommands
            
            $commands.Count | Should -BeGreaterThan 10
            ($commands | Where-Object { $_.Command -eq "New-QuickChecksFinding" }).Count | Should -Be 1
            ($commands | Where-Object { $_.Command -eq "New-QuickChecksExecutiveSummary" }).Count | Should -Be 1
            ($commands | Where-Object { $_.Command -eq "Export-QuickChecksFinding" }).Count | Should -Be 1
        }
    }
}
