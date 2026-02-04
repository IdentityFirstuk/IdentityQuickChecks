# Contributing to IdentityFirst QuickChecks

Thank you for your interest in contributing to IdentityFirst QuickChecks! This document provides guidelines and standards for contributing.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Coding Standards](#coding-standards)
- [PowerShell Compatibility](#powershell-compatibility)
- [Module Structure](#module-structure)
- [Submitting Changes](#submitting-changes)
- [Code Review Process](#code-review-process)

## Getting Started

### Prerequisites

- PowerShell 5.1 (minimum) or PowerShell 7+ (recommended)
- Git
- Visual Studio Code (recommended) with PowerShell extension
- Required modules: Microsoft.Graph, Az.Accounts (for full testing)

### Setting Up Development Environment

1. **Fork the repository** on GitHub

2. **Clone your fork locally**:
   ```powershell
   git clone https://github.com/YOUR-USERNAME/IdentityFirst-Free.git
   cd IdentityFirst-Free
   ```

3. **Create a feature branch**:
   ```powershell
   git checkout -b feature/your-feature-name
   ```

4. **Install development tools**:
   ```powershell
   # Install PSScriptAnalyzer for code quality checks
   Install-Module -Name PSScriptAnalyzer -Scope CurrentUser -Force

   # Install Pester for testing
   Install-Module -Name Pester -Scope CurrentUser -Force
   ```

## Coding Standards

### General Principles

1. **Readability First**: Code should be self-documenting
2. **Error Handling**: Always use Try/Catch/Finally for external calls
3. **Verbosity Control**: Use `-Verbose` switch for detailed output
4. **Progress Reporting**: Use Write-Progress for long-running operations

### Naming Conventions

| Element | Convention | Example |
|---------|-----------|---------|
| Functions | Verb-Noun | `Invoke-QuickChecksValidation` |
| Variables | PascalCase or $script: | `$Findings`, `$script:DefaultThresholds` |
| Constants | UPPER_SNAKE_CASE | `$MAX_RETRY_COUNT` |
| Parameters | PascalCase | `$OutputDir`, `$Format` |
| Hashtable Keys | PascalCase | `$finding.Id`, `$finding.Severity` |

### Function Structure

```powershell
function Verb-Noun {
    <#
    .SYNOPSIS
        Brief description of what the function does.

    .DESCRIPTION
        Detailed description explaining the function's purpose,
        behavior, and any important considerations.

    .PARAMETER ParameterName
        Description of each parameter.

    .EXAMPLE
        Verb-Noun -ParameterName "Value"
        Example usage with explanation.

    .NOTES
        Author: your.name@identityfirst.net
        Requirements: PowerShell 5.1+
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$ParameterName
    )

    begin {
        # Initialization code
        $script:Thresholds = Get-DefaultThresholds
    }

    process {
        # Core logic - runs for each pipeline input
        try {
            # Implementation
        }
        catch {
            Write-Error "Failed to process: $($_.Exception.Message)"
            throw
        }
    }

    end {
        # Cleanup code
    }
}
```

### Error Handling Guidelines

```powershell
# DO: Use Try/Catch for external operations
try {
    $result = Get-Data -ErrorAction Stop
    Write-Verbose "Successfully retrieved data"
}
catch [System.Management.Automation.CommandNotFoundException] {
    Write-Warning "Required module not available - skipping check"
    return @()
}
catch {
    Write-Error "Unexpected error: $($_.Exception.Message)"
    throw  # Re-throw for caller to handle
}

# DO: Use ErrorAction appropriately
$content = Get-Content $path -ErrorAction SilentlyContinue
if (-not $content) {
    Write-Warning "File not found or empty: $path"
}

# DON'T: Use empty catch blocks
catch {
    # Empty - bad practice!
}

# DO: Use custom error records for finding objects
catch {
    $errorRecord = [System.Management.Automation.ErrorRecord]::new(
        [Exception]::new("Custom error message"),
        "ErrorId",
        [System.Management.Automation.ErrorCategory]::InvalidOperation,
        $targetObject
    )
    $PSCmdlet.WriteError($errorRecord)
}
```

### Finding Object Structure

All security findings should follow this structure:

```powershell
$finding = @{
    Id = "UNIQUE-ID-001"           # Unique identifier (e.g., SEC-CRED-001)
    Title = "Brief finding title"   # Short, descriptive title
    Description = "Detailed description of the finding"
    Severity = 'Critical'           # Critical, High, Medium, Low
    Category = "Category_Name"      # Category for grouping
    Timestamp = [datetime]::UtcNow  # Always use UTC
    AffectedObjects = @()           # Array of affected objects
    Evidence = @()                 # Array of evidence
    RemediationSteps = @()         # Array of remediation steps
    IsResolved = $false            # Resolution status
    Confidence = "High"             # High, Medium, Low
    RuleId = "Rule-Reference"      # Reference to rule
    Source = "ModuleName"          # Source module
    CheckName = "CheckName"        # Name of check function
    AffectedCount = 0              # Count of affected items
    Remediation = "Summary text"   # Single-line remediation summary
}
```

## PowerShell Compatibility

### Minimum Requirements

- **Windows PowerShell 5.1** (minimum, Windows only)
- **PowerShell 7.0+** (recommended, cross-platform)

### Compatibility Guidelines

1. **Avoid Windows-specific modules on non-Windows**:
   ```powershell
   # Use conditional code
   if ($IsWindows -or $PSEdition -eq 'Desktop') {
       # Windows-only code
       $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
   }
   else {
       # Cross-platform alternative
       Write-Warning "This check requires Windows"
   }
   ```

2. **Use cross-platform cmdlets**:
   ```powershell
   # AVOID: Windows-specific
   # Get-Service, Stop-Process (Windows-only)

   # USE: Cross-platform
   Get-Process, Get-Content, Get-ChildItem
   ```

3. **JSON Handling**:
   ```powershell
   # PowerShell 7+ has AsHashtable parameter
   $data = $json | ConvertFrom-Json -AsHashtable

   # PowerShell 5.1
   $data = $json | ConvertFrom-Json
   ```

4. **Platform Detection Variables**:
   ```powershell
   $IsWindows = $PSVersionTable.PSVersion.Major -lt 7 -or $IsWindows
   $IsLinux = $IsLinux -eq $true
   $IsMacOS = $IsMacOS -eq $true
   ```

5. **String Handling**:
   ```powershell
   # Use -f for string formatting (works in both)
   "Value: {0}" -f $value

   # Avoid embedded expressions in strings
   # BAD: "Value: $value here"
   # GOOD: "Value: $($value) here"
   ```

### Module Manifest Requirements

Each module must have a valid PSD1 file with:

```powershell
@{
    ModuleVersion = '1.0.0'
    GUID = 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
    Author = 'IdentityFirst Team'
    Description = 'Module description'
    PowerShellVersion = '5.1'
    RequiredModules = @(
        @{ ModuleName = 'Microsoft.Graph'; ModuleVersion = '2.0.0' }
    )
    FunctionsToExport = @(
        'Invoke-FunctionName'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
}
```

## Module Structure

### Standard Module Layout

```
ModuleName/
├── ModuleName.psd1          # Module manifest
├── ModuleName.psm1          # Main module file
├── Private/                 # Private functions
│   └── Private-Function.ps1
├── Public/                  # Public functions
│   └── Public-Function.ps1
├── Classes/                # PowerShell classes
│   └── Finding.ps1
└── Tests/                  # Pester tests
    └── ModuleName.Tests.ps1
```

### Finding Module Pattern

```powershell
# In ModuleName.psm1

# Always export main function
Export-ModuleMember -Function Invoke-ModuleCheck

# Use script-scoped variables for configuration
$script:DefaultThresholds = @{
    Critical = 0
    High = 5
    Medium = 10
    Low = 20
}

# Finding helper functions
function New-Finding {
    param([string]$Id, [string]$Title, [string]$Severity)
    # Returns standardized finding object
}

function Add-FindingObject {
    param($Finding, $AffectedObject)
    # Adds object to finding's AffectedObjects array
}
```

## Submitting Changes

### Pull Request Guidelines

1. **Create a descriptive PR title**:
   - `fix: Resolve encoding issues in Validation module`
   - `feat: Add new Guest Account detection check`
   - `docs: Update README with installation instructions`

2. **Fill out the PR template completely**

3. **Include tests** for new functionality

4. **Update documentation** as needed

5. **Ensure CI passes** before requesting review

### Commit Message Format

```
type(scope): subject

body

footer
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Formatting (no code change)
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance tasks

Example:
```
feat(EntraID): Add guest account expiration check

Implemented new detection logic for stale guest accounts
that haven't been used in over 90 days.

Fixes #123
```

## Code Review Process

### Review Checklist

- [ ] Code follows naming conventions
- [ ] Functions have complete documentation
- [ ] Error handling is appropriate
- [ ] PowerShell 5.1 compatibility maintained
- [ ] No hardcoded credentials or secrets
- [ ] Finding objects follow standard structure
- [ ] Tests pass locally
- [ ] No linting errors (PSScriptAnalyzer)

### PSScriptAnalyzer Rules

Run before submitting:

```powershell
Invoke-ScriptAnalyzer -Path .\ModuleName.psm1 -Settings PSGallery
```

Common rules to follow:
- `PSAvoidUsingCmdletAliases` - Avoid `gci` instead of `Get-ChildItem`
- `PSAvoidUsingPlainTextForPassword` - Use secure strings
- `PSUseApprovedVerbs` - Use approved PowerShell verbs
- `PSUseDeclaredVarsMoreThanAssignments` - Remove unused variables
- `PSAvoidGlobalVars` - Use script-scoped instead

### Testing Requirements

Each new check function should have:

1. **Unit tests** for individual functions
2. **Integration tests** for end-to-end scenarios
3. **Test data** that covers edge cases

Example Pester test:

```powershell
Describe "New-Finding" {
    It "Should create a valid finding object" {
        $finding = New-Finding -Id "TEST-001" -Title "Test" -Severity "High"
        $finding.Id | Should -Be "TEST-001"
        $finding.Severity | Should -Be "High"
    }

    It "Should have all required properties" {
        $finding = New-Finding -Id "TEST-001" -Title "Test" -Severity "High"
        $finding.ContainsKey('Id') | Should -Be $true
        $finding.ContainsKey('Severity') | Should -Be $true
    }
}
```

## Additional Resources

- [PowerShell Documentation](https://docs.microsoft.com/en-us/powershell/)
- [PSScriptAnalyzer Rules](https://github.com/PowerShell/PSScriptAnalyzer)
- [Pester Testing Framework](https://pester.dev/)
- [PowerShell Best Practices](https://docs.microsoft.com/en-us/powershell/scripting/powershell-best-practices)

## Questions?

Contact the team at: mark.ahearne@identityfirst.net
