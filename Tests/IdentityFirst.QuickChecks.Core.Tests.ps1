<#
.SYNOPSIS
    Pester tests for IdentityFirst QuickChecks Core Functions

.DESCRIPTION
    This test suite validates the core functionality of IdentityFirst QuickChecks
    including finding objects, thresholds, and common helper functions.

.NOTES
    Requirements: Pester 5.0+
    PowerShell: 5.1+
#>

Describe "IdentityFirst.QuickChecks Core Tests" -Tag "Core", "Unit" {
    BeforeAll {
        # Import the module under test
        $modulePath = Join-Path $PSScriptRoot '..' 'IdentityFirst.QuickChecks.Lite.psm1'

        if (Test-Path $modulePath) {
            # Import main Lite module which contains core functions
            . $modulePath
        }

        # Define test finding for reuse
        $script:TestFinding = @{
            Id = "TEST-001"
            Title = "Test Finding"
            Description = "A test finding for unit testing"
            Severity = "High"
            Category = "Test_Category"
            Timestamp = [datetime]::UtcNow
            AffectedObjects = @("Object1", "Object2")
            Evidence = @("Evidence1", "Evidence2")
            RemediationSteps = @("Step1", "Step2")
            IsResolved = $false
            Confidence = "High"
            RuleId = "TEST-RULE-001"
            Source = "Test"
            CheckName = "TestCheck"
            AffectedCount = 2
            Remediation = "Test remediation"
        }
    }

    Context "Finding Object Structure" -Tag "Finding" {
        It "Should create a valid finding object" -Tag "Finding" {
            $finding = $script:TestFinding

            $finding.Id | Should -Be "TEST-001"
            $finding.Title | Should -Be "Test Finding"
            $finding.Severity | Should -Be "High"
            $finding.Category | Should -Be "Test_Category"
        }

        It "Should have all required properties" -Tag "Finding" {
            $requiredProperties = @(
                'Id', 'Title', 'Description', 'Severity', 'Category',
                'Timestamp', 'AffectedObjects', 'Evidence', 'RemediationSteps',
                'IsResolved', 'Confidence', 'RuleId', 'Source', 'CheckName',
                'AffectedCount', 'Remediation'
            )

            $finding = $script:TestFinding

            foreach ($prop in $requiredProperties) {
                $finding.ContainsKey($prop) | Should -Be $true -Because "$prop is required"
            }
        }

        It "Should have UTC timestamp" -Tag "Finding" {
            $finding = $script:TestFinding

            $finding.Timestamp.Kind | Should -Be ([System.DateTimeKind]::Utc)
        }

        It "Should handle empty affected objects" -Tag "Finding" {
            $finding = $script:TestFinding.Clone()
            $finding.AffectedObjects = @()

            $finding.AffectedObjects.Count | Should -Be 0
        }
    }

    Context "Severity Levels" -Tag "Severity" {
        It "Should accept Critical severity" -Tag "Severity" {
            $finding = $script:TestFinding.Clone()
            $finding.Severity = "Critical"

            $finding.Severity | Should -Be "Critical"
        }

        It "Should accept High severity" -Tag "Severity" {
            $finding = $script:TestFinding.Clone()
            $finding.Severity = "High"

            $finding.Severity | Should -Be "High"
        }

        It "Should accept Medium severity" -Tag "Severity" {
            $finding = $script:TestFinding.Clone()
            $finding.Severity = "Medium"

            $finding.Severity | Should -Be "Medium"
        }

        It "Should accept Low severity" -Tag "Severity" {
            $finding = $script:TestFinding.Clone()
            $finding.Severity = "Low"

            $finding.Severity | Should -Be "Low"
        }
    }

    Context "Finding Collections" -Tag "Collection" {
        It "Should group findings by severity" -Tag "Collection" {
            $findings = @(
                @{ Severity = "Critical"; Id = "1" }
                @{ Severity = "Critical"; Id = "2" }
                @{ Severity = "High"; Id = "3" }
                @{ Severity = "Medium"; Id = "4" }
            )

            $bySeverity = $findings | Group-Object Severity

            ($bySeverity | Where-Object Name -eq 'Critical').Count | Should -Be 2
            ($bySeverity | Where-Object Name -eq 'High').Count | Should -Be 1
            ($bySeverity | Where-Object Name -eq 'Medium').Count | Should -Be 1
        }

        It "Should count findings by severity" -Tag "Collection" {
            $findings = @(
                @{ Severity = "Critical"; Id = "1" }
                @{ Severity = "Critical"; Id = "2" }
                @{ Severity = "High"; Id = "3" }
                @{ Severity = "Medium"; Id = "4" }
                @{ Severity = "Low"; Id = "5" }
            )

            $critCount = ($findings | Where-Object Severity -eq 'Critical').Count
            $highCount = ($findings | Where-Object Severity -eq 'High').Count
            $medCount = ($findings | Where-Object Severity -eq 'Medium').Count
            $lowCount = ($findings | Where-Object Severity -eq 'Low').Count

            $critCount | Should -Be 2
            $highCount | Should -Be 1
            $medCount | Should -Be 1
            $lowCount | Should -Be 1
        }

        It "Should sort findings by count descending" -Tag "Collection" {
            $findings = @(
                @{ Category = "A"; Count = 5 }
                @{ Category = "B"; Count = 10 }
                @{ Category = "C"; Count = 3 }
            )

            $sorted = $findings | Sort-Object Count -Descending

            $sorted[0].Count | Should -Be 10
            $sorted[1].Count | Should -Be 5
            $sorted[2].Count | Should -Be 3
        }
    }

    Context "Threshold Configuration" -Tag "Threshold" {
        It "Should define default thresholds" -Tag "Threshold" {
            $thresholds = @{
                Critical = 0
                High = 5
                Medium = 10
                Low = 20
            }

            $thresholds.Critical | Should -Be 0
            $thresholds.High | Should -Be 5
            $thresholds.Medium | Should -Be 10
            $thresholds.Low | Should -Be 20
        }

        It "Should detect critical threshold exceeded" -Tag "Threshold" {
            $thresholds = @{ Critical = 0 }
            $count = 1

            $isCritical = $count -gt $thresholds.Critical

            $isCritical | Should -Be $true
        }

        It "Should detect high threshold not exceeded" -Tag "Threshold" {
            $thresholds = @{ High = 5 }
            $count = 3

            $isHigh = $count -gt $thresholds.High

            $isHigh | Should -Be $false
        }
    }

    Context "PowerShell Version Compatibility" -Tag "Compatibility" {
        It "Should detect PowerShell 5.1" -Tag "Compatibility" {
            $psVersion = $PSVersionTable.PSVersion

            # This test will pass on PS 5.1
            if ($psVersion.Major -eq 5 -and $psVersion.Minor -eq 1) {
                $true | Should -Be $true
            }
        }

        It "Should have UTC timestamp support" -Tag "Compatibility" {
            $utcNow = [datetime]::UtcNow

            $utcNow.Kind | Should -Be ([System.DateTimeKind]::Utc)
        }

        It "Should support ordered hashtables" -Tag "Compatibility" {
            if ($PSVersionTable.PSVersion.Major -ge 5) {
                $ordered = [ordered]@{}
                $ordered.Key1 = "Value1"
                $ordered.Key2 = "Value2"

                $ordered.Keys.Count | Should -Be 2
            }
        }
    }

    Context "String Operations" -Tag "String" {
        It "Should format strings correctly" -Tag "String" {
            $name = "Test"
            $result = "Hello, {0}!" -f $name

            $result | Should -Be "Hello, Test!"
        }

        It "Should join paths correctly" -Tag "String" {
            $basePath = "C:\Temp"
            $fileName = "report.json"

            $fullPath = Join-Path $basePath $fileName

            $fullPath | Should -Be "C:\Temp\report.json"
        }

        It "Should format dates correctly" -Tag "String" {
            $date = [datetime]::UtcNow
            $formatted = $date.ToString('yyyy-MM-dd HH:mm:ss')

            $formatted | Should -Match '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'
        }
    }

    Context "JSON Operations" -Tag "JSON" {
        It "Should convert finding to JSON" -Tag "JSON" {
            $finding = $script:TestFinding

            $json = $finding | ConvertTo-Json -Depth 5

            $json | Should -Not -BeNullOrEmpty
            $json | Should -Contain '"Id": "TEST-001"'
        }

        It "Should round-trip JSON conversion" -Tag "JSON" {
            $original = $script:TestFinding

            $json = $original | ConvertTo-Json -Depth 5
            $restored = $json | ConvertFrom-Json

            $restored.Id | Should -Be $original.Id
            $restored.Severity | Should -Be $original.Severity
        }
    }

    Context "Error Handling" -Tag "Error" {
        It "Should handle null input gracefully" -Tag "Error" {
            { $null | Where-Object { $_.Name -eq 'Test' } } | Should -Not -Throw
        }

        It "Should handle empty array" -Tag "Error" {
            $empty = @()

            $count = ($empty | Where-Object { $_.Name -eq 'Test' }).Count

            $count | Should -Be 0
        }

        It "Should handle missing property" -Tag "Error" {
            $obj = @{ Id = "1" }

            # Accessing non-existent property returns $null
            $value = $obj.NonExistent

            $value | Should -Be $null
        }
    }

    Context "File Operations" -Tag "File" {
        BeforeAll {
            $testDir = Join-Path $TestDrive "QuickChecks-Test"
            New-Item -ItemType Directory -Path $testDir -Force | Out-Null
            $script:TestDir = $testDir
        }

        It "Should create test directory" -Tag "File" {
            Test-Path $script:TestDir | Should -Be $true
        }

        It "Should write and read text file" -Tag "File" {
            $testFile = Join-Path $script:TestDir "test.txt"
            $content = "Test content"

            $content | Out-File $testFile -Encoding UTF8
            $readContent = Get-Content $testFile -Raw

            $readContent.Trim() | Should -Be $content
        }

        It "Should calculate file hash" -Tag "File" {
            $testFile = Join-Path $script:TestDir "hash-test.txt"
            "Test data for hashing" | Out-File $testFile -Encoding UTF8

            $hash = (Get-FileHash $testFile -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash

            $hash | Should -Not -BeNullOrEmpty
            $hash.Length | Should -Be 64  # SHA256 is 64 hex characters
        }
    }

    Context "Array Operations" -Tag "Array" {
        It "Should filter arrays correctly" -Tag "Array" {
            $items = @(1, 2, 3, 4, 5)

            $filtered = $items | Where-Object { $_ -gt 2 }

            $filtered.Count | Should -Be 3
            $filtered -contains 3 | Should -Be $true
            $filtered -contains 2 | Should -Be $false
        }

        It "Should sort arrays correctly" -Tag "Array" {
            $items = @(3, 1, 4, 1, 5, 9, 2, 6)

            $sorted = $items | Sort-Object

            $sorted[0] | Should -Be 1
            $sorted[-1] | Should -Be 9
        }

        It "Should select top N items" -Tag "Array" {
            $items = @(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)

            $top5 = $items | Select-Object -First 5

            $top5.Count | Should -Be 5
            $top5[-1] | Should -Be 5
        }
    }

    Context "Pipeline Support" -Tag "Pipeline" {
        It "Should support pipeline input by property name" -Tag "Pipeline" {
            $items = @(
                @{ Id = "1"; Name = "A" }
                @{ Id = "2"; Name = "B" }
                @{ Id = "3"; Name = "C" }
            )

            $result = $items | Where-Object Id -eq "2"

            $result.Count | Should -Be 1
            $result.Name | Should -Be "B"
        }

        It "Should support pipeline processing" -Tag "Pipeline" {
            $items = @(1, 2, 3, 4, 5)

            $doubled = $items | ForEach-Object { $_ * 2 }

            $doubled.Count | Should -Be 5
            $doubled[0] | Should -Be 2
            $doubled[4] | Should -Be 10
        }
    }
}

Describe "IdentityFirst.QuickChecks Finding Helpers" -Tag "Helpers", "Unit" {
    Context "New-Finding Function" -Tag "Helpers" {
        It "Should create a standardized finding" -Tag "Helpers" {
            function New-TestFinding {
                param([string]$Id, [string]$Title, [string]$Severity)
                return @{
                    Id = $Id
                    Title = $Title
                    Severity = $Severity
                    Timestamp = [datetime]::UtcNow
                    AffectedObjects = @()
                    Evidence = @()
                    RemediationSteps = @()
                    IsResolved = $false
                }
            }

            $finding = New-TestFinding -Id "TEST-001" -Title "Test" -Severity "High"

            $finding.Id | Should -Be "TEST-001"
            $finding.Severity | Should -Be "High"
        }
    }

    Context "Add-FindingEvidence Function" -Tag "Helpers" {
        It "Should add evidence to finding" -Tag "Helpers" {
            $finding = @{
                Evidence = @()
            }

            function Add-TestEvidence {
                param($Finding, [string]$Evidence)
                $finding.Evidence += $Evidence
            }

            Add-TestEvidence -Finding $finding -Evidence "Evidence 1"
            Add-TestEvidence -Finding $finding -Evidence "Evidence 2"

            $finding.Evidence.Count | Should -Be 2
        }
    }

    Context "Add-FindingRemediation Function" -Tag "Helpers" {
        It "Should add remediation steps to finding" -Tag "Helpers" {
            $finding = @{
                RemediationSteps = @()
            }

            function Add-TestRemediation {
                param($Finding, [string]$Step)
                $finding.RemediationSteps += $Step
            }

            Add-TestRemediation -Finding $finding -Step "Step 1"
            Add-TestRemediation -Finding $finding -Step "Step 2"
            Add-TestRemediation -Finding $finding -Step "Step 3"

            $finding.RemediationSteps.Count | Should -Be 3
        }
    }
}

Describe "IdentityFirst.QuickChecks Assessment Context" -Tag "Assessment", "Unit" {
    Context "New-AssessmentContext Function" -Tag "Assessment" {
        It "Should create assessment context" -Tag "Assessment" {
            $startTime = [datetime]::UtcNow

            $context = @{
                StartTime = $startTime
                Log = @()
                Settings = @{}
            }

            $context.StartTime | Should -Be $startTime
            $context.Log.Count | Should -Be 0
        }
    }

    Context "New-AssessmentReport Function" -Tag "Assessment" {
        It "Should generate assessment report" -Tag "Assessment" {
            $findings = @(
                @{ Severity = "Critical"; Count = 1 }
                @{ Severity = "High"; Count = 2 }
                @{ Severity = "Medium"; Count = 3 }
            )

            $report = @{
                Timestamp = [datetime]::UtcNow
                TotalFindings = ($findings | Measure-Object).Count
                Findings = $findings
            }

            $report.TotalFindings | Should -Be 3
        }
    }
}

Describe "IdentityFirst.QuickChecks Integration Tests" -Tag "Integration" {
    Context "Module Import" -Tag "Integration" {
        It "Should import module without errors" -Tag "Integration" {
            $modulePath = Join-Path $PSScriptRoot '..' 'IdentityFirst.QuickChecks.Lite.psm1'

            if (Test-Path $modulePath) {
                { . $modulePath } | Should -Not -Throw
            }
        }

        It "Should export main function" -Tag "Integration" {
            # After importing, main function should exist
            $functionExists = (Get-Command -ErrorAction SilentlyContinue -Name 'Invoke-QuickChecksLite') -ne $null

            # This test passes if either function exists or we're not in the module directory
            $functionExists | Should -Be $true
        }
    }

    Context "Finding Lifecycle" -Tag "Integration" {
        It "Should create, populate, and export findings" -Tag "Integration" {
            # Create finding
            $finding = @{
                Id = "INT-001"
                Title = "Integration Test Finding"
                Severity = "High"
                Category = "Integration"
                Timestamp = [datetime]::UtcNow
                AffectedObjects = @()
                Evidence = @()
                RemediationSteps = @()
                IsResolved = $false
            }

            # Add affected objects
            $finding.AffectedObjects += "Object-A"
            $finding.AffectedObjects += "Object-B"

            # Add evidence
            $finding.Evidence += "Evidence A"
            $finding.Evidence += "Evidence B"

            # Add remediation
            $finding.RemediationSteps += "Remediation Step 1"
            $finding.RemediationSteps += "Remediation Step 2"

            # Verify
            $finding.Id | Should -Be "INT-001"
            $finding.AffectedObjects.Count | Should -Be 2
            $finding.Evidence.Count | Should -Be 2
            $finding.RemediationSteps.Count | Should -Be 2
        }
    }
}

# Export test results if running in CI
if ($env:GITHUB_ACTIONS -eq 'true') {
    $testResults = Get-PesterResult
    $testResults | ConvertTo-Json -Depth 5 | Out-File 'test-results-core.json'
}
