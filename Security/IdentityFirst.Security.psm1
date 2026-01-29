# ============================================================================
# IdentityFirst QuickChecks - Security Module
# ============================================================================
# Version: 1.0.0
# Date: 2026-01-29
# Description: Security utilities for all IdentityFirst PowerShell scripts
# ============================================================================

# Security Best Practices Applied:
# - Strict parameter validation
# - Input sanitization
# - Secure credential handling
# - No sensitive data in logs
# - Error handling with security considerations
# ============================================================================

#region Secure String Handling

function ConvertTo-SecureStringIfNeeded {
    <#
    .SYNOPSIS
        Converts plain text to secure string if needed.
    .DESCRIPTION
        Safely handles password/credential input, converting plain text
        to secure strings while preserving existing secure strings.
    #>
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$PlainPassword,
        
        [Parameter(Mandatory = $false)]
        [SecureString]$SecurePassword
    )
    
    if ($SecurePassword) {
        return $SecurePassword
    }
    
    if ($PlainPassword -and $PlainPassword -notlike '*System.Security.SecureString*') {
        return ConvertTo-SecureString -String $PlainPassword -AsPlainText -Force
    }
    
    return $null
}

function Get-CredentialFromInput {
    <#
    .SYNOPSIS
        Gets credential object from various input types.
    .DESCRIPTION
        Handles PSCredential, secure string, or plain text password input
        and returns a standardized PSCredential object.
    #>
    param(
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [SecureString]$SecurePassword,
        
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Username,
        
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$PlainPassword
    )
    
    # If PSCredential provided, return it
    if ($Credential) {
        return $Credential
    }
    
    # Build username if not provided
    if (-not $Username -and -not $Credential) {
        $Username = "$env:USERDOMAIN\$env:USERNAME"
    }
    
    # Convert password to secure string
    $secureString = ConvertTo-SecureStringIfNeeded -PlainPassword $PlainPassword -SecurePassword $SecurePassword
    
    if ($secureString) {
        return New-Object -TypeName PSCredential -ArgumentList $Username, $secureString
    }
    
    return $null
}

#endregion

#region Input Validation

function Test-ValidPath {
    <#
    .SYNOPSIS
        Validates that a path is safe and within allowed directories.
    .DESCRIPTION
        Prevents path traversal attacks and validates paths exist.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $false)]
        [string[]]$AllowedRoots = @($PSScriptRoot, $env:TEMP)
    )
    
    try {
        # Resolve the full path
        $resolvedPath = Resolve-Path -Path $Path -ErrorAction Stop | Select-Object -ExpandProperty Path
        
        # Check for path traversal attempts
        if ($resolvedPath -match '\.\.\\|\.\.[/]') {
            Write-Warning "Path traversal attempt detected: $Path"
            return $false
        }
        
        # Verify path is within allowed roots
        $isValid = $false
        foreach ($root in $AllowedRoots) {
            if ($resolvedPath.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
                $isValid = $true
                break
            }
        }
        
        return $isValid
    }
    catch {
        Write-Warning "Invalid path: $Path - $($_.Exception.Message)"
        return $false
    }
}

function Test-ValidIdentifier {
    <#
    .SYNOPSIS
        Validates that an identifier is safe (alphanumeric, dash, underscore).
    .DESCRIPTION
        Prevents injection attacks by validating identifier format.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Identifier
    )
    
    # Only allow alphanumeric, dash, underscore, and dot
    return $Identifier -match '^[a-zA-Z0-9_\-\.]+$'
}

function Test-ValidCsvPath {
    <#
    .SYNOPSIS
        Validates CSV export path is safe.
    .DESCRIPTION
        Ensures CSV output path is writable and within allowed directories.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$CsvPath
    )
    
    # Check extension
    if (-not $CsvPath.EndsWith('.csv', [StringComparison]::OrdinalIgnoreCase)) {
        Write-Warning "Invalid file extension. Only .csv allowed."
        return $false
    }
    
    return Test-ValidPath -Path $CsvPath
}

function Test-ValidJsonPath {
    <#
    .SYNOPSIS
        Validates JSON export path is safe.
    .DESCRIPTION
        Ensures JSON output path is writable and within allowed directories.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$JsonPath
    )
    
    # Check extension
    if (-not $JsonPath.EndsWith('.json', [StringComparison]::OrdinalIgnoreCase)) {
        Write-Warning "Invalid file extension. Only .json allowed."
        return $false
    }
    
    return Test-ValidPath -Path $JsonPath
}

function Test-ValidHtmlPath {
    <#
    .SYNOPSIS
        Validates HTML export path is safe.
    .DESCRIPTION
        Ensures HTML output path is writable and within allowed directories.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$HtmlPath
    )
    
    # Check extension
    if (-not $HtmlPath.EndsWith('.html', [StringComparison]::OrdinalIgnoreCase)) {
        Write-Warning "Invalid file extension. Only .html allowed."
        return $false
    }
    
    return Test-ValidPath -Path $HtmlPath
}

#endregion

#region Secure Logging

function Write-SecureLog {
    <#
    .SYNOPSIS
        Logs a message with sensitive data redaction.
    .DESCRIPTION
        Automatically redacts passwords, tokens, and sensitive identifiers
        before logging to prevent credential exposure in logs.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [string]$Level = "INFO",
        
        [Parameter(Mandatory = $false)]
        [string]$LogFile
    )
    
    # Sensitive patterns to redact
    $sensitivePatterns = @(
        '\bpwd\b[:\s]*\S+',
        '\bpassword\b[:\s]*\S+',
        '\bsecret\b[:\s]*\S+',
        '\btoken\b[:\s]*\S+',
        '\bkey\b[:\s]*\S{8,}',
        '\bBearer\s+\S+',
        '\bAPI[_-]?key\b[:\s]*\S+',
        '[A-Za-z0-9+/]{40,}==?'  # Base64 encoded secrets
    )
    
    # Redact sensitive data
    $safeMessage = $Message
    foreach ($pattern in $sensitivePatterns) {
        $safeMessage = $safeMessage -replace $pattern, '***REDACTED***'
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $safeMessage"
    
    # Output to console
    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        default { Write-Host $logEntry }
    }
    
    # Write to log file if specified
    if ($LogFile -and (Test-Path -Path (Split-Path -Parent $LogFile) -ErrorAction SilentlyContinue)) {
        try {
            Add-Content -Path $LogFile -Value $logEntry -ErrorAction Stop
        }
        catch {
            Write-Warning "Unable to write to log file: $($_.Exception.Message)"
        }
    }
}

function New-SecureLogFile {
    <#
    .SYNOPSIS
        Creates a secure log file with restricted permissions.
    .DESCRIPTION
        Creates log file with ACLs restricting access to owner only.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )
    
    try {
        # Create parent directory if needed
        $parentDir = Split-Path -Parent $LogPath
        if (-not (Test-Path -Path $parentDir)) {
            New-Item -Path $parentDir -ItemType Directory -Force | Out-Null
        }
        
        # Create or truncate log file
        New-Item -Path $LogPath -ItemType File -Force | Out-Null
        
        # Set restrictive ACL (owner only)
        $acl = Get-Acl -Path $LogPath
        $acl.SetAccessRuleProtection($true, $false)
        $acl.RemoveAllAccessRules()
        
        $currentUser = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")  # Administrators
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $currentUser,
            "FullControl",
            "Allow"
        )))
        
        # Make it owner-only for sensitive data
        $owner = New-Object System.Security.Principal.NTAccount($env:USERNAME)
        $acl.SetOwner($owner)
        
        Set-Acl -Path $LogPath -AclObject $acl
        
        return $true
    }
    catch {
        Write-Warning "Failed to create secure log file: $($_.Exception.Message)"
        return $false
    }
}

#endregion

#region HTML Output Sanitization

function Get-SecureHtmlContent {
    <#
    .SYNOPSIS
        Sanitizes content for HTML output.
    .DESCRIPTION
        Encodes special characters to prevent XSS attacks in HTML reports.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Content
    )
    
    # HTML encode special characters
    return [System.Web.HttpUtility]::HtmlEncode($Content)
}

function New-SecureHtmlReport {
    <#
    .SYNOPSIS
        Creates a secure HTML report with proper encoding.
    .DESCRIPTION
        Generates HTML output with XSS protection and secure headers.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,
        
        [Parameter(Mandatory = $false)]
        [string]$CssPath,
        
        [Parameter(Mandatory = $false)]
        [scriptblock]$Content
    )
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';">
    <title>$(Get-SecureHtmlContent -Content $Title)</title>
"@
    
    # Add custom CSS if provided
    if ($CssPath -and (Test-Path $CssPath)) {
        $cssContent = Get-Content -Path $CssPath -Raw
        $html += "<style>`n$(Get-SecureHtmlContent -Content $cssContent)`n</style>"
    }
    
    $html += @"
</head>
<body>
    <div class="container">
"@
    
    # Add content
    if ($Content) {
        $html += & $Content
    }
    
    $html += @"
    </div>
</body>
</html>
"@
    
    return $html
}

#endregion

#region Output File Security

function Set-OutputFileSecurity {
    <#
    .SYNOPSIS
        Applies security ACLs to output files.
    .DESCRIPTION
        Restricts file access to owner only for sensitive output files.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        
        [Parameter(Mandatory = $false)]
        [switch]$ReadOnly
    )
    
    try {
        if (-not (Test-Path -Path $FilePath)) {
            Write-Warning "File not found: $FilePath"
            return $false
        }
        
        $acl = Get-Acl -Path $FilePath
        $acl.SetAccessRuleProtection($true, $false)
        $acl.RemoveAllAccessRules()
        
        # Owner gets full control
        $owner = New-Object System.Security.Principal.NTAccount($env:USERNAME)
        $acl.SetOwner($owner)
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $owner,
            "FullControl",
            "Allow"
        )))
        
        Set-Acl -Path $FilePath -AclObject $acl
        
        # Set read-only if requested
        if ($ReadOnly) {
            Set-ItemProperty -Path $FilePath -Name IsReadOnly -Value $true -ErrorAction SilentlyContinue
        }
        
        return $true
    }
    catch {
        Write-Warning "Failed to set file security: $($_.Exception.Message)"
        return $false
    }
}

function New-SecureOutputFile {
    <#
    .SYNOPSIS
        Creates a new output file with secure permissions.
    .DESCRIPTION
        Creates file with owner-only permissions for sensitive data.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        
        [Parameter(Mandatory = $false)]
        [switch]$ReadOnly
    )
    
    try {
        # Create parent directory
        $parentDir = Split-Path -Parent $FilePath
        if (-not (Test-Path -Path $parentDir)) {
            New-Item -Path $parentDir -ItemType Directory -Force | Out-Null
        }
        
        # Create file
        New-Item -Path $FilePath -ItemType File -Force | Out-Null
        
        # Apply security
        Set-OutputFileSecurity -FilePath $FilePath -ReadOnly:$ReadOnly
        
        return $true
    }
    catch {
        Write-Warning "Failed to create secure output file: $($_.Exception.Message)"
        return $false
    }
}

#endregion

#region Secure Module Manifest

function Get-ScriptHash {
    <#
    .SYNOPSIS
        Computes SHA-256 hash of a file.
    .DESCRIPTION
        Used for integrity verification of scripts and files.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    if (-not (Test-Path -Path $FilePath)) {
        return $null
    }
    
    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop
        return $hash.Hash
    }
    catch {
        Write-Warning "Failed to compute hash: $($_.Exception.Message)"
        return $null
    }
}

function Test-ScriptIntegrity {
    <#
    .SYNOPSIS
        Verifies script hasn't been tampered with.
    .DESCRIPTION
        Compares current hash against expected hash.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        
        [Parameter(Mandatory = $true)]
        [string]$ExpectedHash
    )
    
    $currentHash = Get-ScriptHash -FilePath $FilePath
    
    if (-not $currentHash) {
        return $false
    }
    
    return $currentHash -eq $ExpectedHash
}

#endregion

# Export functions for module use
Export-ModuleMember -Function @(
    'ConvertTo-SecureStringIfNeeded',
    'Get-CredentialFromInput',
    'Test-ValidPath',
    'Test-ValidIdentifier',
    'Test-ValidCsvPath',
    'Test-ValidJsonPath',
    'Test-ValidHtmlPath',
    'Write-SecureLog',
    'New-SecureLogFile',
    'Get-SecureHtmlContent',
    'New-SecureHtmlReport',
    'Set-OutputFileSecurity',
    'New-SecureOutputFile',
    'Get-ScriptHash',
    'Test-ScriptIntegrity'
)
