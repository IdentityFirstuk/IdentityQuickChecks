<#
    IdentityFirst QuickChecks Common Module
    Provides cross-version compatibility helpers for PowerShell 5.1 and 7+
    
    This module contains shared functions used across all quick check scripts
    to ensure consistent behavior and enterprise-grade error handling.
#>

#region Version Detection
# PowerShell version detection for cross-version compatibility
$script:IsPS5 = $PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1
$script:IsPS7 = $PSVersionTable.PSVersion.Major -ge 7
$script:IsCore = $PSVersionTable.PSEdition -eq 'Core' -or $IsCore
$script:IsWindows = if ($IsWindows -ne $null) { $IsWindows } else { $true }
$script:IsLinux = if ($IsLinux -ne $null) { $IsLinux } else { $false }
$script:IsMacOS = if ($IsMacOS -ne $null) { $IsMacOS } else { $false }
#endregion

#region Configuration
# Default configuration values
$script:DefaultOutputPath = $PWD.Path
$script:TranscriptPath = $null
$script:VerboseEnabled = $false
$script:DebugEnabled = $false
$script:CredentialCache = @{}
$script:ModuleAvailabilityCache = @{}
#endregion

#region Logging Functions
function Write-QCLog {
    <#
    .SYNOPSIS
        Centralized logging function for all quick check scripts.
    .DESCRIPTION
        Provides consistent logging across PowerShell versions with multiple output levels.
        Writes to console and optionally to a transcript file.
    .PARAMETER Message
        The message to log.
    .PARAMETER Level
        Log level: Info, Warning, Error, Success, Debug, Verbose
    .PARAMETER NoConsole
        Suppress console output (for transcript-only logging).
    .EXAMPLE
        Write-QCLog -Message "Starting check" -Level Info
    .EXAMPLE
        Write-QCLog -Message "Module not found" -Level Warning
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Debug', 'Verbose')]
        [string]$Level = 'Info',
        
        [Parameter(Mandatory = $false)]
        [switch]$NoConsole
    )
    
    # Get timestamp in ISO 8601 format
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    # Format log entry
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Determine colors for console output
    $foregroundColor = 'White'
    switch ($Level) {
        'Warning' { $foregroundColor = 'Yellow' }
        'Error'   { $foregroundColor = 'Red' }
        'Success' { $foregroundColor = 'Green' }
        'Debug'   { $foregroundColor = 'Cyan' }
        'Verbose' { $foregroundColor = 'Gray' }
    }
    
    # Write to console (PS5 compatible)
    if (-not $NoConsole) {
        if ($script:IsPS7 -and $Host.Name -eq 'ConsoleHost') {
            # PS7 has better color support
            Write-Host $logEntry -ForegroundColor $foregroundColor
        }
        else {
            # PS5 fallback
            switch ($Level) {
                'Warning' { Write-Warning $Message }
                'Error'   { Write-Error $Message }
                'Debug'   { if ($script:DebugEnabled) { Write-Host $logEntry -ForegroundColor $foregroundColor } }
                'Verbose' { if ($script:VerboseEnabled) { Write-Host $logEntry -ForegroundColor $foregroundColor } }
                default    { Write-Host $logEntry -ForegroundColor $foregroundColor }
            }
        }
    }
    
    # Write to transcript if enabled
    if ($script:TranscriptPath -and (Test-Path $script:TranscriptPath -IsValid)) {
        try {
            Add-Content -Path $script:TranscriptPath -Value $logEntry -ErrorAction Stop
        }
        catch {
            # Silently fail if transcript writing fails
            Write-Debug "Failed to write to transcript: $($_.Exception.Message)"
        }
    }
    
    # Also output to pipeline for capturing
    Write-Output $logEntry
}

function Start-QCTranscript {
    <#
    .SYNOPSIS
        Starts logging to a transcript file.
    .DESCRIPTION
        Creates a transcript file for persistent logging of all script activity.
    .PARAMETER Path
        Path to the transcript file.
    .EXAMPLE
        Start-QCTranscript -Path "C:\Logs\quickcheck.log"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Path = (Join-Path $script:DefaultOutputPath "QuickChecks_$(Get-Date -Format 'yyyyMMdd_HHmmss').log")
    )
    
    $script:TranscriptPath = $Path
    
    # Ensure directory exists
    $directory = Split-Path $Path -Parent
    if (-not (Test-Path $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    
    # Write header
    $header = @"
================================================================================
IdentityFirst QuickChecks Transcript
Started: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
PowerShell Version: $($PSVersionTable.PSVersion.ToString())
OS: $($PSVersionTable.OS)
User: $ENV:USERNAME@$ENV:COMPUTERNAME
================================================================================
"@
    
    Add-Content -Path $Path -Value $header -Encoding UTF8
    Write-QCLog -Message "Transcript started: $Path" -Level Info
}

function Stop-QCTranscript {
    <#
    .SYNOPSIS
        Stops the transcript logging.
    .DESCRIPTION
        Closes the transcript file and writes footer.
    #>
    [CmdletBinding()]
    param()
    
    if ($script:TranscriptPath) {
        $footer = @"

================================================================================
Transcript ended: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
================================================================================
"@
        Add-Content -Path $script:TranscriptPath -Value $footer -Encoding UTF8
        Write-QCLog -Message "Transcript ended: $script:TranscriptPath" -Level Info
        $script:TranscriptPath = $null
    }
}
#endregion

#region Module Loading Functions
function Import-QCModule {
    <#
    .SYNOPSIS
        Attempts to import a PowerShell module with comprehensive error handling.
    .DESCRIPTION
        Checks module availability, handles different PowerShell versions, and provides
        specific guidance when modules are unavailable.
    .PARAMETER Name
        Name of the module to import.
    .PARAMETER RequiredVersion
        Optional specific version to import.
    .PARAMETER PassThru
        Return the module object if successful.
    .EXAMPLE
        Import-QCModule -Name "ActiveDirectory" -RequiredVersion "1.0.0.0"
    .OUTPUTS
        Boolean or PSModuleInfo object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$RequiredVersion,
        
        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )
    
    # Check cache first
    if ($script:ModuleAvailabilityCache.ContainsKey($Name)) {
        if ($script:ModuleAvailabilityCache[$Name]) {
            if ($PassThru) { return (Get-Module -Name $Name) }
            return $true
        }
        return $false
    }
    
    # Check if already loaded
    $existingModule = Get-Module -Name $Name -ErrorAction SilentlyContinue
    if ($existingModule) {
        $script:ModuleAvailabilityCache[$Name] = $true
        if ($PassThru) { return $existingModule }
        return $true
    }
    
    # Try to import
    try {
        $importParams = @{
            Name = $Name
            ErrorAction = 'Stop'
        }
        
        if ($RequiredVersion) {
            $importParams['RequiredVersion'] = $RequiredVersion
        }
        
        $module = Import-Module @importParams -PassThru:$PassThru
        $script:ModuleAvailabilityCache[$Name] = $true
        Write-QCLog -Message "Module '$Name' imported successfully" -Level Verbose
        return $module
    }
    catch {
        $script:ModuleAvailabilityCache[$Name] = $false
        Write-QCLog -Message "Failed to import module '$Name': $($_.Exception.Message)" -Level Warning
        
        # Provide specific guidance
        $guidance = Get-ModuleInstallationGuidance -ModuleName $Name
        if ($guidance) {
            Write-QCLog -Message $guidance -Level Info
        }
        
        return $false
    }
}

function Get-ModuleInstallationGuidance {
    <#
    .SYNOPSIS
        Provides installation guidance for unavailable modules.
    .DESCRIPTION
        Returns specific instructions for installing common modules based on
        PowerShell version and operating system.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )
    
    $guidance = @{
        'ActiveDirectory' = @{
            PS5 = @"
To install ActiveDirectory module on Windows PowerShell 5.1:
1. Install RSAT-ADDS-Tools feature:
   Install-WindowsFeature -Name RSAT-ADDS-Tools
2. Or via Settings > Apps > Optional Features > Add a feature > RSAT: Active Directory
"@
            PS7 = @"
ActiveDirectory module requires Windows with RSAT installed.
For PowerShell 7 on Windows: Install RSAT-ADDS-Tools, then import the module.
For PowerShell 7 on Linux/macOS: Use Microsoft Graph PowerShell SDK instead:
   Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser
   Connect-MgGraph -Scopes "Directory.Read.All"
"@
        }
        'Microsoft.Graph.Authentication' = @"
Install Microsoft Graph PowerShell SDK:
   Install-Module -Name Microsoft.Graph.Authentication -Scope CurrentUser
   # For all Graph modules:
   Install-Module -Name Microsoft.Graph -Scope CurrentUser
"@
        'Az.Accounts' = @"
Install Azure PowerShell module:
   Install-Module -Name Az.Accounts -Scope CurrentUser -AllowClobber
"@
        'AWS.Tools.Common' = @"
Install AWS Tools for PowerShell:
   Install-Module -Name AWS.Tools.Common -Scope CurrentUser
   # Or for all AWS Tools modules:
   Install-Module -Name AWS.Tools.Installer -Scope CurrentUser
   Install-AWSToolsModule -ModuleName AWS.Tools.Common
"@
    }
    
    $key = $ModuleName
    if ($guidance.ContainsKey($key)) {
        $os = if ($script:IsWindows) { 'PS5' } else { 'PS7' }
        return $guidance[$key]
    }
    
    return $null
}

function Test-QCModuleAvailability {
    <#
    .SYNOPSIS
        Tests if a module is available without importing it.
    .DESCRIPTION
        Checks if a module is installed and available for import.
    .PARAMETER Name
        Name of the module to test.
    .EXAMPLE
        if (Test-QCModuleAvailability -Name "ActiveDirectory") { ... }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name
    )
    
    # Check cache
    if ($script:ModuleAvailabilityCache.ContainsKey($Name)) {
        return $script:ModuleAvailabilityCache[$Name]
    }
    
    # Test availability
    $available = $false
    try {
        $null = Get-Module -Name $Name -ListAvailable -ErrorAction Stop
        $available = $true
    }
    catch {
        $available = $false
    }
    
    $script:ModuleAvailabilityCache[$Name] = $available
    return $available
}
#endregion

#region Credential Management
function Get-QCCredential {
    <#
    .SYNOPSIS
        Securely retrieves credentials with caching.
    .DESCRIPTION
        Prompts for credentials if not already cached and provides secure storage.
    .PARAMETER Target
        Description of what the credentials are for (used for display and caching).
    .PARAMETER ClearCache
        Clears the cached credential for the specified target.
    .EXAMPLE
        $cred = Get-QCCredential -Target "Domain Admin"
    .OUTPUTS
        PSCredential object.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Prompt')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Prompt')]
        [ValidateNotNullOrEmpty()]
        [string]$Target,
        
        [Parameter(Mandatory = $false, ParameterSetName = 'Clear')]
        [switch]$ClearCache
    )
    
    if ($ClearCache) {
        $cacheKey = $Target -replace '[^a-zA-Z0-9]', '_'
        $script:CredentialCache.Remove($cacheKey)
        Write-QCLog -Message "Credential cache cleared for: $Target" -Level Verbose
        return
    }
    
    $cacheKey = $Target -replace '[^a-zA-Z0-9]', '_'
    
    # Check cache
    if ($script:CredentialCache.ContainsKey($cacheKey)) {
        Write-QCLog -Message "Using cached credential for: $Target" -Level Verbose
        return $script:CredentialCache[$cacheKey]
    }
    
    # Prompt for credentials
    $cred = Get-Credential -Message "Enter credentials for: $Target"
    
    # Cache the credential
    if ($cred) {
        $script:CredentialCache[$cacheKey] = $cred
        Write-QCLog -Message "Credential cached for: $Target" -Level Verbose
    }
    
    return $cred
}

function Clear-QCCredentialCache {
    <#
    .SYNOPSIS
        Clears all cached credentials.
    .DESCRIPTION
        Removes all credentials from the in-memory cache.
    #>
    [CmdletBinding()]
    param()
    
    $script:CredentialCache.Clear()
    Write-QCLog -Message "All credentials cleared from cache" -Level Info
}
#endregion

#region DateTime Helpers
function ConvertFrom-LastLogonTimestamp {
    <#
    .SYNOPSIS
        Converts AD lastLogonTimestamp to readable date format.
    .DESCRIPTION
        Safely converts the 64-bit integer lastLogonTimestamp to a DateTime object.
    .PARAMETER Timestamp
        The lastLogonTimestamp value (64-bit integer or FileTime).
    .PARAMETER OutputFormat
        Output format string (default: yyyy-MM-dd).
    .PARAMETER DefaultValue
        Value to return if timestamp is null or invalid (default: "Never").
    .EXAMPLE
        ConvertFrom-LastLogonTimestamp -Timestamp 133123456789012345
    .OUTPUTS
        String representation of the date.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [AllowNull()]
        $Timestamp,
        
        [Parameter(Mandatory = $false)]
        [string]$OutputFormat = "yyyy-MM-dd",
        
        [Parameter(Mandatory = $false)]
        [string]$DefaultValue = "Never"
    )
    
    process {
        # Handle null or zero
        if ($null -eq $Timestamp -or $Timestamp -eq 0) {
            return $DefaultValue
        }
        
        # Handle different input types
        try {
            $fileTime = [long]$Timestamp
            $dateTime = [DateTime]::FromFileTime($fileTime)
            return $dateTime.ToString($OutputFormat)
        }
        catch {
            Write-QCLog -Message "Invalid timestamp format: $Timestamp" -Level Debug
            return $DefaultValue
        }
    }
}

function ConvertFrom-FileTime {
    <#
    .SYNOPSIS
        Converts Windows FILETIME to DateTime object.
    .DESCRIPTION
        Handles the conversion with proper error handling for invalid values.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [AllowNull()]
        [long]$FileTime
    )
    
    process {
        if ($null -eq $FileTime -or $FileTime -eq 0) {
            return $null
        }
        
        try {
            return [DateTime]::FromFileTime($FileTime)
        }
        catch {
            Write-QCLog -Message "Failed to convert FileTime: $FileTime" -Level Warning
            return $null
        }
    }
}
#endregion

#region JSON Output Helpers
function Save-QCReport {
    <#
    .SYNOPSIS
        Saves a report object to JSON file with cross-version compatibility.
    .DESCRIPTION
        Handles encoding differences between PowerShell 5.1 and 7+.
    .PARAMETER Report
        The report object to serialize.
    .PARAMETER Path
        Output file path.
    .PARAMETER Depth
        Serialization depth (default: 10).
    .EXAMPLE
        Save-QCReport -Report $report -Path "output.json"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [PSObject]$Report,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,
        
        [Parameter(Mandatory = $false)]
        [int]$Depth = 10
    )
    
    # Ensure directory exists
    $directory = Split-Path $Path -Parent
    if (-not (Test-Path $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    
    try {
        # Cross-version compatible JSON serialization
        if ($script:IsPS7) {
            # PS7+ supports -AsHashtable and utf8NoBOM
            $json = $Report | ConvertTo-Json -Depth $Depth -ErrorAction Stop
            $json | Set-Content -Path $Path -Encoding utf8NoBOM -ErrorAction Stop
        }
        else {
            # PS5.1 fallback
            $Report | ConvertTo-Json -Depth $Depth | Out-File -FilePath $Path -Encoding UTF8 -ErrorAction Stop
        }
        
        Write-QCLog -Message "Report saved: $Path" -Level Success
        return $true
    }
    catch {
        Write-QCLog -Message "Failed to save report to $Path : $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Import-QCReport {
    <#
    .SYNOPSIS
        Imports a JSON report file with cross-version compatibility.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )
    
    if (-not (Test-Path $Path)) {
        Write-QCLog -Message "Report file not found: $Path" -Level Warning
        return $null
    }
    
    try {
        if ($script:IsPS7) {
            return Get-Content -Path $Path -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
        }
        else {
            return Get-Content -Path $Path | ConvertFrom-Json -ErrorAction Stop
        }
    }
    catch {
        Write-QCLog -Message "Failed to import report from $Path : $($_.Exception.Message)" -Level Error
        return $null
    }
}
#endregion

#region Prerequisite Checks
function Test-QCPrerequisites {
    <#
    .SYNOPSIS
        Validates all prerequisites before running a quick check.
    .DESCRIPTION
        Checks module availability, credential access, and connectivity.
    .PARAMETER RequiredModules
        Array of module names that must be available.
    .PARAMETER RequireDomainConnectivity
        If true, tests domain controller connectivity.
    .OUTPUTS
        PSObject containing check results.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$RequiredModules = @('ActiveDirectory'),
        
        [Parameter(Mandatory = $false)]
        [switch]$RequireDomainConnectivity
    )
    
    $results = [PSCustomObject]@{
        Passed = $true
        Tests = @()
        Timestamp = (Get-Date).ToString("o")
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
    
    # Test 1: Module availability
    foreach ($module in $RequiredModules) {
        $test = [PSCustomObject]@{
            Name = "Module: $module"
            Passed = (Test-QCModuleAvailability -Name $module)
            Message = if ((Test-QCModuleAvailability -Name $module)) { "Available" } else { "Not available" }
        }
        $results.Tests += $test
        if (-not $test.Passed) { $results.Passed = $false }
    }
    
    # Test 2: Domain connectivity (if required)
    if ($RequireDomainConnectivity -and (Test-QCModuleAvailability -Name 'ActiveDirectory')) {
        try {
            $null = Get-ADDomain -ErrorAction Stop
            $domainTest = [PSCustomObject]@{
                Name = "Domain Connectivity"
                Passed = $true
                Message = "Connected to domain"
            }
        }
        catch {
            $domainTest = [PSCustomObject]@{
                Name = "Domain Connectivity"
                Passed = $false
                Message = $_.Exception.Message
            }
            $results.Passed = $false
        }
        $results.Tests += $domainTest
    }
    
    # Test 3: Output directory writable
    try {
        $testPath = Join-Path $script:DefaultOutputPath "write_test_$(Get-Date -Format 'yyyyMMddHHmmss').tmp"
        $null = New-Item -ItemType File -Path $testPath -Force -ErrorAction Stop
        Remove-Item -Path $testPath -Force -ErrorAction SilentlyContinue
        $writeTest = [PSCustomObject]@{
            Name = "Output Directory Writable"
            Passed = $true
            Message = "Directory is writable"
        }
        $results.Tests += $writeTest
    }
    catch {
        $writeTest = [PSCustomObject]@{
            Name = "Output Directory Writable"
            Passed = $false
            Message = "Cannot write to output directory: $($_.Exception.Message)"
        }
        $results.Tests += $writeTest
        $results.Passed = $false
    }
    
    return $results
}
#endregion

#region Result Standardization
function New-QCResult {
    <#
    .SYNOPSIS
        Creates a standardized quick check result object.
    .DESCRIPTION
        Provides consistent result structure across all quick checks.
    .PARAMETER CheckName
        Name of the quick check.
    .PARAMETER Status
        Overall status: Pass, Warning, Fail, Error.
    .PARAMETER Data
        Main data returned by the check.
    .PARAMETER Summary
        Summary statistics or counts.
    .PARAMETER Warnings
        Array of warning messages.
    .PARAMETER Errors
        Array of error messages encountered during execution.
    .OUTPUTS
        Standardized result object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CheckName,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet('Pass', 'Warning', 'Fail', 'Error')]
        [string]$Status,
        
        [Parameter(Mandatory = $false)]
        [PSObject]$Data,
        
        [Parameter(Mandatory = $false)]
        [PSObject]$Summary,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Warnings,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Errors
    )
    
    return [PSCustomObject]@{
        PSTypeName = 'IdentityFirst.QuickCheckResult'
        CheckName = $CheckName
        Status = $Status
        Timestamp = (Get-Date).ToString("o")
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        Platform = if ($script:IsWindows) { 'Windows' } elseif ($script:IsLinux) { 'Linux' } elseif ($script:IsMacOS) { 'macOS' } else { 'Unknown' }
        Data = $Data
        Summary = $Summary
        Warnings = @($Warnings)
        Errors = @($Errors)
        Meta = [PSCustomObject]@{
            ExecutionTime = if ($script:ExecutionStartTime) { (Get-Date).Subtract($script:ExecutionStartTime).TotalSeconds } else { 0 }
            User = $ENV:USERNAME
            Computer = $ENV:COMPUTERNAME
        }
    }
}

function Format-QCResult {
    <#
    .SYNOPSIS
        Formats a result object for console output.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Result
    )
    
    $statusColor = 'White'
    switch ($Result.Status) {
        'Pass'    { $statusColor = 'Green' }
        'Warning' { $statusColor = 'Yellow' }
        'Fail'    { $statusColor = 'Red' }
        'Error'   { $statusColor = 'Red' }
    }
    
    Write-Host ""
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ("  " + $Result.CheckName) -ForegroundColor $statusColor
    Write-Host ("=" * 80) -ForegroundColor Cyan
    Write-Host ""
    Write-Host ("  Status: " + $Result.Status) -ForegroundColor $statusColor
    Write-Host ("  Timestamp: " + $Result.Timestamp)
    Write-Host ("  PowerShell: " + $Result.PowerShellVersion)
    
    if ($Result.Meta.ExecutionTime -gt 0) {
        Write-Host ("  Execution Time: " + [math]::Round($Result.Meta.ExecutionTime, 2) + " seconds")
    }
    
    if ($Result.Summary) {
        Write-Host ""
        Write-Host "  Summary:" -ForegroundColor Cyan
        foreach ($prop in $Result.Summary.PSObject.Properties) {
            Write-Host ("    " + $prop.Name + ": " + $prop.Value)
        }
    }
    
    if ($Result.Warnings) {
        Write-Host ""
        Write-Host "  Warnings:" -ForegroundColor Yellow
        foreach ($warning in $Result.Warnings) {
            Write-Host ("    - " + $warning)
        }
    }
    
    if ($Result.Errors) {
        Write-Host ""
        Write-Host "  Errors:" -ForegroundColor Red
        foreach ($error in $Result.Errors) {
            Write-Host ("    - " + $error)
        }
    }
    
    Write-Host ""
}
#endregion

#region AD Helper Functions
function Get-QCPrivilegedGroups {
    <#
    .SYNOPSIS
        Returns the standard privileged groups to check.
    .DESCRIPTION
        Provides a configurable list of privileged groups.
    #>
    [CmdletBinding()]
    param()
    
    return @(
        "Domain Admins"
        "Enterprise Admins"
        "Schema Admins"
        "Administrators"
        "Account Operators"
        "Server Operators"
        "Print Operators"
        "Backup Operators"
        "Replicator"
        "Group Policy Creator Owners"
        "Enterprise Key Admins"
        "Key Admins"
    )
}

function Get-QCBreakGlassPatterns {
    <#
    .SYNOPSIS
        Returns regex patterns for identifying break-glass accounts.
    #>
    [CmdletBinding()]
    param()
    
    return @{
        SamAccountNamePatterns = @(
            '(?i)(break[\s\-\.]?glass)',
            '(?i)(emerg(?:ency)?)',
            '(?i)(bg[\-\s]?)',
            '(?i)(fire[\s\-\.]?wall)',
            '(?i)(root[\-\s]?admin)',
            '(?i)(永[^\s]*)',  # Chinese: eternal/forever
            '(?i)(停[^\s]*)'   # Chinese: stop/pause
        )
        DescriptionPatterns = @(
            '(?i)(break[\s\-\.]?glass)',
            '(?i)(emerg(?:ency)?)',
            '(?i)(emergency[\s\-\.]?access)',
            '(?i)(disaster[\s\-\.]?recovery)'
        )
    }
}

function Test-QCNamingConvention {
    <#
    .SYNOPSIS
        Tests if an account name follows naming conventions.
    .DESCRIPTION
        Validates against common naming patterns for different account types.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SamAccountName,
        
        [Parameter(Mandatory = $false)]
        [string[]]$RequiredPrefixes = @('svc-', 'adm-', 'usr-', 'app-')
    )
    
    # Check if it's a computer account (ends with $)
    if ($SamAccountName.EndsWith('$')) {
        return @{
            Compliant = $true
            Reason = "Computer account"
            AccountType = "Computer"
        }
    }
    
    # Check for required prefixes
    foreach ($prefix in $RequiredPrefixes) {
        if ($SamAccountName.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            return @{
                Compliant = $true
                Reason = "Has required prefix: $prefix"
                AccountType = "Service/Application"
            }
        }
    }
    
    # Check for common violation patterns
    $violationPatterns = @(
        '(?i)(^[a-z]{2,3}\d{4,}$)'
    )
    
    foreach ($pattern in $violationPatterns) {
        if ($SamAccountName -match $pattern) {
            return @{
                Compliant = $false
                Reason = "Matches violation pattern: $pattern"
                AccountType = "Unknown"
            }
        }
    }
    
    return @{
        Compliant = $false
        Reason = "Does not follow naming conventions"
        AccountType = "Unknown"
    }
}
#endregion

#region Output Formatting
function Format-QCTable {
    <#
    .SYNOPSIS
        Formats data for table output with cross-version compatibility.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [PSObject]$InputObject,
        
        [Parameter(Mandatory = $false)]
        [string[]]$Properties,
        
        [Parameter(Mandatory = $false)]
        [switch]$AutoSize,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxWidth = 50
    )
    
    process {
        $data = if ($Properties) {
            $InputObject | Select-Object -Property $Properties
        }
        else {
            $InputObject
        }
        
        if ($script:IsPS7) {
            $data | Format-Table -AutoSize -Wrap
        }
        else {
            $data | Format-Table -AutoSize
        }
    }
}

function Format-QCOutput {
    <#
    .SYNOPSIS
        Formats output based on configured verbosity level.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Data,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Table', 'List', 'Json')]
        [string]$Format = 'Table',
        
        [Parameter(Mandatory = $false)]
        [int]$MaxItems = 50
    )
    
    if (-not $Data) {
        Write-QCLog -Message "No data to display" -Level Info
        return
    }
    
    switch ($Format) {
        'Table' {
            if ($Data -is [Array]) {
                $Data | Select-Object -First $MaxItems | Format-Table -AutoSize
                if ($Data.Count -gt $MaxItems) {
                    Write-Host ("  ... and " + ($Data.Count - $MaxItems) + " more items") -ForegroundColor Gray
                }
            }
            else {
                $Data | Format-Table -AutoSize
            }
        }
        'List' {
            $Data | Format-List
        }
        'Json' {
            $Data | ConvertTo-Json -Depth 5
        }
    }
}
#endregion

#region Utility Functions
function Test-QCEmpty {
    <#
    .SYNOPSIS
        Tests if a collection is null or empty.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowNull()]
        $InputObject
    )
    
    process {
        if ($null -eq $InputObject) { return $true }
        if ($InputObject -is [string] -and [string]::IsNullOrEmpty($InputObject)) { return $true }
        if ($InputObject -is [Array] -and $InputObject.Count -eq 0) { return $true }
        return $false
    }
}

function Split-QCBatch {
    <#
    .SYNOPSIS
        Splits a collection into batches for processing.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowNull()]
        [PSObject]$InputObject,
        
        [Parameter(Mandatory = $true)]
        [int]$BatchSize
    )
    
    process {
        if ($null -eq $InputObject) { return }
        
        $buffer = @()
        foreach ($item in $InputObject) {
            $buffer += $item
            if ($buffer.Count -ge $BatchSize) {
                ,$buffer
                $buffer = @()
            }
        }
        if ($buffer.Count -gt 0) {
            ,$buffer
        }
    }
}

function Measure-QCExecution {
    <#
    .SYNOPSIS
        Measures execution time of a script block.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ScriptBlock]$ScriptBlock,
        
        [Parameter(Mandatory = $false)]
        [string]$Name
    )
    
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        & $ScriptBlock
        $stopwatch.Stop()
        Write-QCLog -Message "Completed: $Name in $($stopwatch.Elapsed.TotalSeconds) seconds" -Level Verbose
        return [PSCustomObject]@{
            Success = $true
            Duration = $stopwatch.Elapsed.TotalSeconds
            Error = $null
        }
    }
    catch {
        $stopwatch.Stop()
        Write-QCLog -Message "Failed: $Name - $($_.Exception.Message)" -Level Error
        return [PSCustomObject]@{
            Success = $false
            Duration = $stopwatch.Elapsed.TotalSeconds
            Error = $_.Exception.Message
        }
    }
}
#endregion

#region Initialization
# Export module members
$exportedFunctions = @(
    'Write-QCLog'
    'Start-QCTranscript'
    'Stop-QCTranscript'
    'Import-QCModule'
    'Test-QCModuleAvailability'
    'Get-QCCredential'
    'Clear-QCCredentialCache'
    'ConvertFrom-LastLogonTimestamp'
    'ConvertFrom-FileTime'
    'Save-QCReport'
    'Import-QCReport'
    'Test-QCPrerequisites'
    'New-QCResult'
    'Format-QCResult'
    'Get-QCPrivilegedGroups'
    'Get-QCBreakGlassPatterns'
    'Test-QCNamingConvention'
    'Format-QCTable'
    'Format-QCOutput'
    'Test-QCEmpty'
    'Split-QCBatch'
    'Measure-QCExecution'
)

# Export functions for module use
Export-ModuleMember -Function $exportedFunctions -Verbose:$false

# Log module load
Write-QCLog -Message "IdentityFirst QuickChecks Common Module loaded" -Level Verbose
Write-QCLog -Message "PowerShell Version: $($PSVersionTable.PSVersion.ToString())" -Level Verbose
Write-QCLog -Message "Platform: $(if ($script:IsWindows) { 'Windows' } elseif ($script:IsLinux) { 'Linux' } elseif ($script:IsMacOS) { 'macOS' } else { 'Unknown' })" -Level Verbose
#endregion
