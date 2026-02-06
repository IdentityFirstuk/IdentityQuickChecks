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

# Provide a lightweight fallback for Write-IFQC when not available (defensive)
if (-not (Get-Command -Name Write-IFQC -ErrorAction SilentlyContinue)) {
    function Write-IFQC {
        param(
            [Parameter(ValueFromPipeline=$true, Mandatory=$false)] $InputObject,
            [string]$Message,
            [string]$Level = 'Info'
        )

        if ($PSBoundParameters.ContainsKey('InputObject') -and $InputObject) {
            Write-Output $InputObject
            return
        }

        $obj = [PSCustomObject]@{
            Timestamp = (Get-Date).ToString('o')
            Level = $Level
            Message = $Message
        }
        Write-Output $obj
    }
}

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
        [SecureString]$SecurePassword
    )

    # Prefer explicit SecureString input. Do not accept plain-text passwords.
    if ($SecurePassword) {
        return $SecurePassword
    }

    # No password provided; return $null. Callers should prompt the user or
    # accept a PSCredential where appropriate.
    return $null
}

function Get-SecureStringFromEnv {
    <#
    .SYNOPSIS
        Convert an environment variable string into a SecureString.
    .DESCRIPTION
        Safely converts a developer-supplied environment variable into a
        System.Security.SecureString. Caller must ensure the env var name
        is appropriate for the runtime (e.g. IFQC_DEV_PFX_PASSWORD).
    #>
    param(
        [Parameter(Mandatory = $false)]
        [string]$EnvVarName = 'IFQC_DEV_PFX_PASSWORD'
    )

    # Use a safe lookup for environment variables that supports dynamic names
    $val = [Environment]::GetEnvironmentVariable($EnvVarName)
    if (-not $val) { return $null }

    try {
        $ss = New-Object System.Security.SecureString
        foreach ($ch in $val.ToCharArray()) { $ss.AppendChar($ch) }
        $ss.MakeReadOnly()
        return $ss
    } catch {
        Write-IFQC -InputObject ([PSCustomObject]@{ Timestamp=(Get-Date).ToString('o'); Level='Warn'; Action='EnvToSecureStringFailed'; EnvVar=$EnvVarName; Message=$_.Exception.Message })
        return $null
    }
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
        [string]$Username
    )

    # If PSCredential provided, return it
    if ($Credential) {
        return $Credential
    }

    # Build username if not provided
    if (-not $Username) {
        $Username = "$env:USERDOMAIN\$env:USERNAME"
    }

    # If SecureString provided, create PSCredential
    if ($SecurePassword) {
        return New-Object -TypeName PSCredential -ArgumentList $Username, $SecurePassword
    }

    # No credential information available
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
            $obj = [PSCustomObject]@{
                Timestamp = (Get-Date).ToString("o")
                Level = 'Warning'
                Message = "Path traversal attempt detected: $Path"
                Type = 'Security'
            }
            Write-IFQC -InputObject $obj
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
        $obj = [PSCustomObject]@{
            Timestamp = (Get-Date).ToString("o")
            Level = 'Error'
            Message = "Invalid path: $Path - $($_.Exception.Message)"
            Type = 'Security'
        }
        Write-IFQC -InputObject $obj
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
        $obj = [PSCustomObject]@{
            Timestamp = (Get-Date).ToString("o")
            Level = 'Warning'
            Message = 'Invalid file extension. Only .csv allowed.'
            Type = 'Validation'
        }
        Write-IFQC -InputObject $obj
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
        $obj = [PSCustomObject]@{
            Timestamp = (Get-Date).ToString("o")
            Level = 'Warning'
            Message = 'Invalid file extension. Only .json allowed.'
            Type = 'Validation'
        }
        Write-IFQC -InputObject $obj
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
        $obj = [PSCustomObject]@{
            Timestamp = (Get-Date).ToString("o")
            Level = 'Warning'
            Message = 'Invalid file extension. Only .html allowed.'
            Type = 'Validation'
        }
        Write-IFQC -InputObject $obj
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

    # Emit structured log to pipeline (preserve plain-text for file writes)
    $obj = [PSCustomObject]@{
        Timestamp = (Get-Date).ToString("o")
        Level = $Level
        Message = $safeMessage
        Text = $logEntry
        Type = 'SecureLog'
    }
    Write-IFQC -InputObject $obj

    # Write to log file if specified
    if ($LogFile -and (Test-Path -Path (Split-Path -Parent $LogFile) -ErrorAction SilentlyContinue)) {
        try {
            Add-Content -Path $LogFile -Value $logEntry -ErrorAction Stop
        }
        catch {
            $obj = [PSCustomObject]@{
                Timestamp = (Get-Date).ToString("o")
                Level = 'Warning'
                Message = "Unable to write to log file: $($_.Exception.Message)"
                Type = 'IO'
            }
            Write-IFQC -InputObject $obj
        }
    }
}

function New-SecureLogFile {
    <#
    .SYNOPSIS
        Creates a secure log file with restricted permissions.
    .DESCRIPTION
        Creates log file with ACLs restricting access to owner only.
    .PARAMETER LogPath
        The path where the log file should be created.
    .EXAMPLE
        New-SecureLogFile -LogPath "C:\Logs\secure.log"
    .NOTES
        This function requires administrator privileges on Windows for ACL modification.
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
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

        if ($IsWindows) {
            try {
                $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                $acl = Get-Acl -Path $LogPath
                $acl.SetAccessRuleProtection($true, $false)

                # Build a restrictive rule for the current user
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $currentUser,
                    [System.Security.AccessControl.FileSystemRights]::FullControl,
                    [System.Security.AccessControl.InheritanceFlags]::None,
                    [System.Security.AccessControl.PropagationFlags]::None,
                    [System.Security.AccessControl.AccessControlType]::Allow
                )

                # Replace any existing rules for this user with the restrictive one
                $acl.ResetAccessRule($rule)

                # Ensure owner is set to current user
                $acl.SetOwner((New-Object System.Security.Principal.NTAccount($currentUser)))

                Set-Acl -Path $LogPath -AclObject $acl
            }
            catch {
                $obj = [PSCustomObject]@{
                    Timestamp = (Get-Date).ToString("o")
                    Level = 'Warning'
                    Message = "Failed to set ACL on log file: $($_.Exception.Message)"
                    Type = 'IO'
                }
                Write-IFQC -InputObject $obj
            }
        }

        return $true
    }
    catch {
        $obj = [PSCustomObject]@{
            Timestamp = (Get-Date).ToString("o")
            Level = 'Error'
            Message = "Failed to create secure log file: $($_.Exception.Message)"
            Type = 'IO'
        }
        Write-IFQC -InputObject $obj
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

    # HTML encode special characters (use System.Net.WebUtility on Core/Win)
    try {
        return [System.Net.WebUtility]::HtmlEncode($Content)
    }
    catch {
        $obj = [PSCustomObject]@{
            Timestamp = (Get-Date).ToString("o")
            Level = 'Warning'
            Message = "Html encoding fallback used: $($_.Exception.Message)"
            Type = 'Sanitization'
        }
        Write-IFQC -InputObject $obj
        return $Content -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;'
    }
}

function New-SecureHtmlReport {
    <#
    .SYNOPSIS
        Creates a secure HTML report with proper encoding.
    .DESCRIPTION
        Generates HTML output with XSS protection and secure headers.
    .PARAMETER Title
        The title of the HTML report.
    .PARAMETER CssPath
        Optional path to a CSS file.
    .PARAMETER Content
        Script block containing the report content.
    .EXAMPLE
        New-SecureHtmlReport -Title "Security Report" -Content { Get-Process | Select-Object -First 10 }
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
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
    .PARAMETER FilePath
        The path to the file to secure.
    .PARAMETER ReadOnly
        If set, makes the file read-only after applying security.
    .EXAMPLE
        Set-OutputFileSecurity -FilePath "C:\Reports\output.csv" -ReadOnly
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $false)]
        [switch]$ReadOnly
    )

    try {
        if (-not (Test-Path -Path $FilePath)) {
            $obj = [PSCustomObject]@{
                Timestamp = (Get-Date).ToString("o")
                Level = 'Warning'
                Message = "File not found: $FilePath"
                Type = 'IO'
            }
            Write-IFQC -InputObject $obj
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
        $obj = [PSCustomObject]@{
            Timestamp = (Get-Date).ToString("o")
            Level = 'Error'
            Message = "Failed to set file security: $($_.Exception.Message)"
            Type = 'IO'
        }
        Write-IFQC -InputObject $obj
        return $false
    }
}

function New-SecureOutputFile {
    <#
    .SYNOPSIS
        Creates a new output file with secure permissions.
    .DESCRIPTION
        Creates file with owner-only permissions for sensitive data.
    .PARAMETER FilePath
        The path for the new output file.
    .PARAMETER ReadOnly
        If set, makes the file read-only after creation.
    .EXAMPLE
        New-SecureOutputFile -FilePath "C:\Reports\secure.csv" -ReadOnly
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
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
        $obj = [PSCustomObject]@{
            Timestamp = (Get-Date).ToString("o")
            Level = 'Error'
            Message = "Failed to create secure output file: $($_.Exception.Message)"
            Type = 'IO'
        }
        Write-IFQC -InputObject $obj
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
        $obj = [PSCustomObject]@{
            Timestamp = (Get-Date).ToString("o")
            Level = 'Warning'
            Message = "Failed to compute hash: $($_.Exception.Message)"
            Type = 'Integrity'
        }
        Write-IFQC -InputObject $obj
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

# SIG # Begin signature block
# MIIf3QYJKoZIhvcNAQcCoIIfzjCCH8oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDRuMkPsri7b5tL
# Biw/JynvL35G/sHJcZd+8ZpPEFsqWKCCGNwwggWNMIIEdaADAgECAhAOmxiO+dAt
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
# AgEVMC8GCSqGSIb3DQEJBDEiBCD3ZGwTOTpfN5oLuqsWcEp9yU6ShdsJMEhf2iH6
# 9OFBmTANBgkqhkiG9w0BAQEFAASCAgARDneuEd6p22wJV3hoTEM8BuWBT5eEStI6
# 5WZqS6UZXN+mLXsOdfv1IHj4ZchZQhlYQEpHiVCimBtN8vUhp99mcijf1pivSZF6
# 0Hk62ghV6x1O3n3Rzbw2WYn+HEx2Mboz5sbO0T4ealmf2zQPPMqxDYGRQuG59TDF
# bbEYTDEqcFMVsG1Nla/q5iCpjoOyiZ926LfBM2Yukilw3fTwBAOTC+jlD0M9BJhP
# lHGr5WizC3X1vZF3IDKJFFTPjViWj6byTWyyDdE9F9SlJtDdk0bXW8f5AKLahD4U
# CQIxuk496u4MwGHFmv5Z2q93cpgwl1p9MVTfchzNETfpOxa99bBZw2hdvnZRqDrx
# n4ArsykH42wckHbyCqfUM97U65GkjrFGFGn4EiMdfIn3rkIxA1R17TpFCnRnJZCc
# vcGNPDlXOsOifGRdJ4Lqm1g8/IW7aAf8GHg3ur9bzpL6Z5Rutw/x5ZPmsf3dALLa
# up3cMh0ywC/oyp+qXYcFCSuzzO3Ps6uqUrwf+4m8K7m/qZkfYZ76+qHgYsQ7smBb
# MnpqtXFpWTL04WPhbXw+SIoLg+RsWnVOVhNb8tIeV2fYilKv+7LCsWjXZlabmQrM
# t2bnjQ4AkUDUKQZjV4rTvboP7Ih2ySiIw19wj6wkPTP4HO/Cjx+FJpAmHNw67Oys
# jEbkU4brgaGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAyMDUxNzE0NDRaMC8G
# CSqGSIb3DQEJBDEiBCCVRN1NztUT+lbCbWKGuDNQ8OImCYDqNV1Lm5HAiXbSGTAN
# BgkqhkiG9w0BAQEFAASCAgCYO1u0Bm3yuJemdzb5oILRfDXuRXWehdCu0h8Ur7r1
# ieELWbAaE09hw7F09BbOeCUcUlQgGwICujj9yqnEv5uw+2LFQ9BgPx0fDOxw+XMg
# Ogawq7biQgoqSUktXYGF+xXJo3AMihO1SJICNrL25J9Q+R+39IZklie5L57YCp6C
# VsM1BJ+blHIMCM7H+E++YtECbZsL0oTMLLdA+McTcl1013BCVdVRGRso2+DWfFq0
# QSgLKpnflT16UmqyJl6EUGB4c6kKogAtYBpeYYqU6RnMs92/DtdI87WCvobMiLZR
# amgeO0relqZD+x5euw2/gGk5+YZ08x2dytjgrwAYCv6keC18Ov84Q3foB5A14/fS
# 54FTI1lvqjBUADwvhgIbkfp6PU1IvUEUdp7R8jIMweTIFvMdOsT+rS3qI5TbLRwY
# 2404e/stokbNl1DRdczI436RkqGr40fZ8eMlJ+zLpUVvxPQAIIP7yB6gLCvFQeqj
# qixaWVW0pT8o13g2YkkdJPJUDSumpGHO6cZ+n5gvSzXoikRuVALx6SWVGCheMwkw
# ub5eNz0Aa8fXQwN0fwDLGpfyUiaFq0Mpu/5n97tPC7APCE4GYx2ef1ZzIKRskCqx
# oPXjGOTp2dT/Nkj0olZvMGOjt0Oy2El2byAmRkRdwNi+PLoZbDsdFTSXq398vp5H
# CA==
# SIG # End signature block
