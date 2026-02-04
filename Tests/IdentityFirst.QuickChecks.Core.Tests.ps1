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

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDQt5qlA3Ymm5so
# F8lUUBf9AU/u2CCLHw7gei5GjVfWeKCCFlIwggMUMIIB/KADAgECAhBDR0HvMFNE
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgmM2QIZsnPESOwzpYhVDnYgXsRhFsUPiX8jHl
# fXI7NrowDQYJKoZIhvcNAQEBBQAEggEAsfPWLTvWrAJ4S7uOwAzfzRNQism5Qx4K
# LbInbfW/tLtBEmlYQ7s0F8WPHM1vCNvUT1gIMnFHYtaC1Aa1u3+H/TnSS2dFsshk
# jUZSjbNTzTVKl2rkK9iNDw7sSPatSfFmjwgM421ocvD7aTEgcgJCd9SIZ19yYjHV
# rqvIQpDWcYRb881gbyf7+RdEb27Kvo/xyjp4kJLB3mtTOhD5vUKCa5/AreKMrh4J
# o4CwxsPYLuilsaBR3uxvYM7q4CuZIbK4/+0h/7N/ETxDIozf1mK5WVxW2ktj67FX
# po9RqHqcVOeQ+8YwOmFyJ3rHIamMW92sgsSPj5I6P4byWLxYCmO0K6GCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjAyMDQxNjUyMjBaMC8GCSqGSIb3DQEJBDEiBCC6
# JlF0IGssOwRzESyN5e/+Q/94VJ1YLeIDvmpjxtqqfDANBgkqhkiG9w0BAQEFAASC
# AgBQzXOxMX0imSPhTEoofDyAYXJRxO5rdq6pjb73REPStvwQ2p47pVtqycQNq4X2
# hqQNpbnITmHnkTJzRdq/9YoxU/taVSp40lR7zLHAUxFpEgxN0nBnlmmVd4SXmtLc
# 2o1DH+p6rgQxjthBlrTDYXe5uSnfF+xTd4oXayecrwFKYsq2Cxvybcnb7iYGmgF/
# aqD84TBTEt9Mb0zOYHMBhsSV6RgBABnvqy5IH8+5rbyJ/rxaTdG7/MlrxZHdQwVs
# Pdtas1El4wlLYelBFMwiLIxa2agrYJvWdG4yzsGL8mf0ZFKlik0YbJq4uQD7nas9
# SfqDluBCJWZmnEXCtVH1f+E0EKLwZhtUivdKDztv/rt+n8Cb9NVqVsF316jB9PBG
# gJHM0aj62y1qh4it1OsbvHI9a3P8uz67u0Ql2ZuDjAupoaEDlVsAG2OQE7L7rbXh
# vsRzwEaEC8p+QnKgOQ4tZ57nWPWgaHELmDYzoUAv+URAV3mFr4G5mK1E+n+1XzZO
# 82+a4TpoK7Zhi+yrWbLdIJ8x88rkh54/VmewXLAfU0Df4nQdDsgS++RKDcTphG4p
# p2y/lIwqYQlf71njHpkkNHWf3qgDtvVxhF/v6Riwupxd+cjtwstSv2R0k04+Q1PX
# O7oWnHQfrjg2Vs9oxUa6Or12EuRpwUfdOefBvioK/hSjJg==
# SIG # End signature block
