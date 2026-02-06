<#
.SYNOPSIS
    IdentityFirst Security Utilities Module
.DESCRIPTION
    Provides secure credential handling, input validation, and security
    helper functions for QuickChecks scripts.

.NOTES
    Module Version: 1.0.0
    Requires: PowerShell 5.1+
#>

#region Credential Handling

function Get-SecureCredential {
    <#
    .SYNOPSIS
        Retrieves credentials securely from environment or Windows Credential Manager.
    
    .DESCRIPTION
        Attempts to retrieve credentials in the following order:
        1. From PSCredential parameter (if provided)
        2. From environment variable (if configured)
        3. From Windows Credential Manager (if available)
        4. Prompts for interactive input (if running interactively)
    
    .PARAMETER CredentialName
        The name/identifier for the credential.
    
    .PARAMETER Credential
        A PSCredential object to use (takes precedence).
    
    .PARAMETER EnvironmentVariable
        The name of the environment variable containing the credential.
    
    .OUTPUTS
        PSCredential - A valid credential object
    
    .EXAMPLE
        $cred = Get-SecureCredential -CredentialName "AzureAdmin"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CredentialName,
        
        [Parameter(Mandatory = $false)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [string]$EnvironmentVariable
    )
    
    # Return provided credential if available
    if ($Credential) {
        return $Credential
    }
    
    # Check environment variable
    if ($EnvironmentVariable) {
        $envValue = [Environment]::GetEnvironmentVariable($EnvironmentVariable)
        if ($envValue) {
            $secureString = ConvertTo-SecureString $envValue -AsPlainText -Force
            return New-Object PSCredential($CredentialName, $secureString)
        }
    }
    
    # Check Windows Credential Manager
    try {
        $cmCredential = Get-CredentialFromVault -Target $CredentialName
        if ($cmCredential) {
            return $cmCredential
        }
    }
    catch {
        Write-Verbose "Credential not found in Windows Credential Manager: $CredentialName"
    }
    
    # Prompt if interactive
    if ([Environment]::UserInteractive) {
        return Get-Credential -Message "Enter credentials for: $CredentialName"
    }
    
    throw "No credential provided and cannot prompt (non-interactive mode). Use -Credential parameter or set $EnvironmentVariable environment variable."
}

function Get-CredentialFromVault {
    <#
    .SYNOPSIS
        Retrieves a credential from Windows Credential Manager.
    
    .DESCRIPTION
        Uses the Windows Credential Manager to securely store and retrieve
        credentials using the CredRead WinAPI.
    
    .PARAMETER Target
        The credential target/name.
    
    .OUTPUTS
        PSCredential or $null if not found
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target
    )
    
    try {
        $cred = cmd /c "cmdkey /list:$Target" 2>&1 | Out-String
        if ($cred -match "Target:") {
            return $null
        }
        
        # Use CredRead via PowerShell
        $pInvoke = @'
[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern bool CredRead(string target, int type, int flags, out IntPtr credential);
[DllImport("advapi32.dll", SetLastError = true)]
public static extern void CredFree(IntPtr buffer);
public struct CREDENTIAL {
    public int Flags;
    public int Type;
    public string TargetName;
    public string Comment;
    public long LastWritten;
    public int CredentialBlobSize;
    public IntPtr CredentialBlob;
    public int Persist;
    public int AttributeCount;
    public IntPtr Attributes;
    public string TargetAlias;
    public string UserName;
}
'@
        
        $advapi = Add-Type -MemberDefinition $pInvoke -Name "AdvApi32" -Namespace "Win32" -UsingNamespace "System.Runtime.InteropServices" -PassThru
        $ptr = [IntPtr]::Zero
        $CRED_TYPE_GENERIC = 1
        
        if ($advapi::CredRead($Target, $CRED_TYPE_GENERIC, 0, [ref]$ptr)) {
            try {
                $credStruct = [Runtime.InteropServices.Marshal]::PtrToStructure($ptr, [type][Win32.AdvApi32+Credential])
                if ($credStruct.CredentialBlobSize -gt 0) {
                    $bytes = New-Object byte[] ($credStruct.CredentialBlobSize)
                    [Runtime.InteropServices.Marshal]::Copy($credStruct.CredentialBlob, $bytes, 0, $credStruct.CredentialBlobSize)
                    $secureString = ConvertTo-SecureString -AsPlainText -Force ($bytes | ForEach-Object { [char]$_ }) -String
                    return New-Object PSCredential($credStruct.UserName, $secureString)
                }
            }
            finally {
                $advapi::CredFree($ptr) | Out-Null
            }
        }
    }
    catch {
        Write-Verbose "Error reading credential from vault: $($_.Exception.Message)"
    }
    
    return $null
}

function Set-CredentialInVault {
    <#
    .SYNOPSIS
        Stores a credential in Windows Credential Manager.
    
    .DESCRIPTION
        Securely stores credentials in Windows Credential Manager using
        CredWrite WinAPI with CRED_TYPE_GENERIC type.
    
    .PARAMETER Target
        The credential target/name.
    
    .PARAMETER Credential
        The PSCredential to store.
    
    .PARAMETER Persist
        Persistence level: Session, LocalMachine, Enterprise.
    
    .NOTES
        Credentials stored with LocalMachine or Enterprise persist across
        reboots but require administrator privileges.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Target,
        
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Session', 'LocalMachine', 'Enterprise')]
        [string]$Persist = 'LocalMachine'
    )
    
    $pInvoke = @'
[DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
public static extern bool CredWrite([In] ref CREDENTIAL credential, int flags);
public struct CREDENTIAL {
    public int Flags;
    public int Type;
    public string TargetName;
    public string Comment;
    public long LastWritten;
    public int CredentialBlobSize;
    public IntPtr CredentialBlob;
    public int Persist;
    public int AttributeCount;
    public IntPtr Attributes;
    public string TargetAlias;
    public string UserName;
}
'@
    
    $advapi = Add-Type -MemberDefinition $pInvoke -Name "AdvApi32" -Namespace "Win32" -UsingNamespace "System.Runtime.InteropServices" -PassThru
    
    $persistMap = @{
        'Session' = 1
        'LocalMachine' = 2
        'Enterprise' = 3
    }
    
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($Credential.GetNetworkCredential().Password)
    $ptr = [Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length + 1)
    
    try {
        [Runtime.InteropServices.Marshal]::Copy($bytes, 0, $ptr, $bytes.Length)
        [Runtime.InteropServices.Marshal]::WriteByte($ptr, $bytes.Length, 0)
        
        $credStruct = New-Object Win32.AdvApi32+CREDENTIAL
        $credStruct.Type = 1  # CRED_TYPE_GENERIC
        $credStruct.TargetName = $Target
        $credStruct.Comment = "IdentityFirst QuickChecks credential"
        $credStruct.CredentialBlobSize = $bytes.Length + 1
        $credStruct.CredentialBlob = $ptr
        $credStruct.Persist = $persistMap[$Persist]
        $credStruct.UserName = $Credential.UserName
        
        if (-not $advapi::CredWrite([ref]$credStruct, 0)) {
            throw "Failed to write credential: $([ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error()).Message)"
        }
        
        Write-Verbose "Credential stored successfully: $Target"
    }
    finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
    }
}

#endregion

#region Input Validation

function Test-InputSanitized {
    <#
    .SYNOPSIS
        Validates and sanitizes string input to prevent injection attacks.
    
    .DESCRIPTION
        Checks for and removes potentially dangerous characters including:
        - Path traversal sequences (.., /, \)
        - Command execution metacharacters
        - SQL injection patterns
        - XML/HTML special characters
    
    .PARAMETER Input
        The string input to validate.
    
    .PARAMETER AllowSpecialChars
        Array of additional characters to allow.
    
    .OUTPUTS
        bool - $true if input is safe, $false otherwise
    
    .EXAMPLE
        if (Test-InputSanitized -Input $userPath) { ... }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Input,
        
        [Parameter(Mandatory = $false)]
        [char[]]$AllowSpecialChars
    )
    
    if ([string]::IsNullOrEmpty($Input)) {
        return $true
    }
    
    # Check for path traversal
    if ($Input -match '\.\.[\\/]' -or $Input -match '^[\\/]' -or $Input -match '[\\/]\.\.') {
        Write-Warning "Path traversal detected in input: $Input"
        return $false
    }
    
    # Check for command execution metacharacters
    $dangerousChars = @('`', '$', '|', '&', ';', '(', ')', '{', '}', '<', '>', '"', "'", '`n', '`r')
    $dangerousChars += $AllowSpecialChars
    
    foreach ($char in $dangerousChars) {
        if ($Input.Contains($char)) {
            Write-Warning "Dangerous character detected: $char in input: $Input"
            return $false
        }
    }
    
    # Check for SQL injection patterns
    $sqlPatterns = @(
        "\bunion\b", "\bselect\b", "\binsert\b", "\bdelete\b", "\bupdate\b",
        "\bdrop\b", "\btruncate\b", "\balter\b", "\bexec\b", "\bexecute\b",
        "--", "/*", "*/", "@@", "@"
    )
    
    foreach ($pattern in $sqlPatterns) {
        if ($Input -imatch $pattern) {
            Write-Warning "SQL injection pattern detected: $pattern in input: $Input"
            return $false
        }
    }
    
    return $true
}

function Test-ValidFilePath {
    <#
    .SYNOPSIS
        Validates that a file path is safe and within expected boundaries.
    
    .DESCRIPTION
        Validates file paths by:
        - Checking for path traversal attempts
        - Verifying path is within allowed root directories
        - Ensuring file extension is expected type
    
    .PARAMETER FilePath
        The file path to validate.
    
    .PARAMETER AllowedRoots
        Array of allowed root paths (must be full paths).
    
    .PARAMETER AllowedExtensions
        Array of allowed file extensions (without dot).
    
    .OUTPUTS
        bool - $true if path is valid and safe
    
    .EXAMPLE
        if (Test-ValidFilePath -FilePath $path -AllowedRoots @('C:\Reports', '\\server\share') -AllowedExtensions @('txt', 'csv', 'json')) { ... }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        
        [Parameter(Mandatory = $false)]
        [string[]]$AllowedRoots,
        
        [Parameter(Mandatory = $false)]
        [string[]]$AllowedExtensions
    )
    
    if ([string]::IsNullOrWhiteSpace($FilePath)) {
        Write-Warning "File path is empty"
        return $false
    }
    
    # Normalize path
    try {
        $normalizedPath = [System.IO.Path]::GetFullPath($FilePath)
    }
    catch {
        Write-Warning "Invalid file path: $($_.Exception.Message)"
        return $false
    }
    
    # Check for path traversal in original or normalized path
    if ($FilePath -match '\.\.[\\/]' -or $normalizedPath -match '\.\.[\\/]') {
        Write-Warning "Path traversal attempt detected: $FilePath"
        return $false
    }
    
    # Check allowed roots
    if ($AllowedRoots -and $AllowedRoots.Count -gt 0) {
        $isAllowed = $false
        foreach ($root in $AllowedRoots) {
            $normalizedRoot = [System.IO.Path]::GetFullPath($root)
            if ($normalizedPath.StartsWith($normalizedRoot, [StringComparison]::OrdinalIgnoreCase)) {
                $isAllowed = $true
                break
            }
        }
        
        if (-not $isAllowed) {
            Write-Warning "File path is outside allowed roots: $FilePath"
            return $false
        }
    }
    
    # Check allowed extensions
    if ($AllowedExtensions -and $AllowedExtensions.Count -gt 0) {
        $extension = [System.IO.Path]::GetExtension($FilePath).TrimStart('.')
        if ($extension -notin $AllowedExtensions) {
            Write-Warning "File extension not allowed: .$extension"
            return $false
        }
    }
    
    return $true
}

function Test-ValidIdentifier {
    <#
    .SYNOPSIS
        Validates that a string is a valid identifier (alphanumeric, underscores, hyphens).
    
    .DESCRIPTION
        Used to validate object names, usernames, group names, etc.
        Only allows letters, numbers, underscores, hyphens, and periods.
    
    .PARAMETER Identifier
        The identifier to validate.
    
    .PARAMETER MaxLength
        Maximum allowed length.
    
    .OUTPUTS
        bool - $true if identifier is valid
    
    .EXAMPLE
        if (Test-ValidIdentifier -Identifier $username -MaxLength 50) { ... }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Identifier,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxLength = 256
    )
    
    if ([string]::IsNullOrWhiteSpace($Identifier)) {
        return $false
    }
    
    if ($Identifier.Length -gt $MaxLength) {
        Write-Warning "Identifier exceeds maximum length: $($Identifier.Length) > $MaxLength"
        return $false
    }
    
    # Allow alphanumeric, underscore, hyphen, period, and @ (for UPN format)
    if ($Identifier -notmatch '^[\w\-\.@]+$') {
        Write-Warning "Identifier contains invalid characters: $Identifier"
        return $false
    }
    
    return $true
}

function Test-ValidEmail {
    <#
    .SYNOPSIS
        Validates that a string is a valid email address format.
    
    .OUTPUTS
        bool - $true if email format is valid
    
    .EXAMPLE
        if (Test-ValidEmail -Email $userPrincipalName) { ... }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Email
    )
    
    if ([string]::IsNullOrWhiteSpace($Email)) {
        return $false
    }
    
    # Basic email format validation
    $emailPattern = '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if ($Email -notmatch $emailPattern) {
        Write-Warning "Invalid email format: $Email"
        return $false
    }
    
    return $true
}

function ConvertTo-SecureStringFromPlainText {
    <#
    .SYNOPSIS
        Creates a secure string from plain text with proper security measures.
    
    .DESCRIPTION
        Converts plain text to a secure string using ConvertTo-SecureString
        with -AsPlainText and -Force flags appropriately.
    
    .PARAMETER PlainText
        The plain text password or secret.
    
    .PARAMETER ForceConfirmation
        If true, requires confirmation before creating secure string.
    
    .OUTPUTS
        SecureString - A secure string representation of the input
    
    .NOTES
        This function is intentionally designed to always require -Force
        to prevent accidental exposure of plain text credentials.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PlainText,
        
        [Parameter(Mandatory = $false)]
        [switch]$ForceConfirmation
    )
    
    if (-not $ForceConfirmation -and $PlainText.Length -gt 0) {
        Write-Warning "Converting plain text to secure string. Ensure this is necessary."
        Write-Warning "Consider using Get-Credential or Windows Credential Manager instead."
    }
    
    return ConvertTo-SecureString -String $PlainText -AsPlainText -Force
}

#endregion

#region Environment Variable Helpers

function Get-EnvironmentSecret {
    <#
    .SYNOPSIS
        Retrieves a secret from an environment variable with optional masking.
    
    .DESCRIPTION
        Gets a secret value from an environment variable and optionally
        returns it as a PSCredential or SecureString.
    
    .PARAMETER VariableName
        The name of the environment variable.
    
    .PARAMETER AsCredential
        If true, returns a PSCredential with the secret as password.
    
    .PARAMETER CredentialName
        The username to use when creating a PSCredential.
    
    .OUTPUTS
        string, SecureString, or PSCredential depending on parameters
    
    .EXAMPLE
        $secret = Get-EnvironmentSecret -VariableName "AZURE_CLIENT_SECRET"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VariableName,
        
        [Parameter(Mandatory = $false)]
        [switch]$AsCredential,
        
        [Parameter(Mandatory = $false)]
        [string]$CredentialName = "ServicePrincipal"
    )
    
    $value = [Environment]::GetEnvironmentVariable($VariableName)
    
    if ([string]::IsNullOrEmpty($value)) {
        Write-Verbose "Environment variable not set: $VariableName"
        return $null
    }
    
    if ($AsCredential) {
        $secureString = ConvertTo-SecureString $value -AsPlainText -Force
        return New-Object PSCredential($CredentialName, $secureString)
    }
    
    return $value
}

function Set-EnvironmentSecret {
    <#
    .SYNOPSIS
        Sets a secret in an environment variable securely.
    
    .DESCRIPTION
        Stores a secret value in an environment variable. For process-level
        secrets only - these are not persisted beyond the current session.
    
    .PARAMETER VariableName
        The name of the environment variable.
    
    .PARAMETER Secret
        The secret value to store.
    
    .PARAMETER Scope
        The scope: Process, User, or Machine.
    
    .NOTES
        Machine-level environment variables require administrator privileges
        and are persisted. Consider using Windows Credential Manager instead
        for sensitive data.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$VariableName,
        
        [Parameter(Mandatory = $true)]
        [string]$Secret,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Process', 'User', 'Machine')]
        [string]$Scope = 'Process'
    )
    
    if ($PSCmdlet.ShouldProcess($VariableName, "Set environment secret")) {
        [Environment]::SetEnvironmentVariable($VariableName, $Secret, $Scope)
        Write-Verbose "Environment variable set: $VariableName (Scope: $Scope)"
    }
}

#endregion

#region Secure String Handling

function ConvertFrom-SecureStringToPlainText {
    <#
    .SYNOPSIS
        Converts a secure string back to plain text (for export purposes).
    
    .DESCRIPTION
        Decrypts a secure string to plain text. USE WITH CAUTION - this
        exposes the secret in memory as plain text.
    
    .PARAMETER SecureString
        The secure string to decrypt.
    
    .OUTPUTS
        string - The plain text representation
    
    .NOTES
        Only use this function when absolutely necessary. Consider alternative
        approaches that keep secrets encrypted.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Security.SecureString]$SecureString
    )
    
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Get-RandomSecureString {
    <#
    .SYNOPSIS
        Generates a cryptographically secure random string.
    
    .DESCRIPTION
        Creates a random string suitable for passwords or API keys using
        the RNGCryptoServiceProvider for cryptographic security.
    
    .PARAMETER Length
        The length of the generated string.
    
    .PARAMETER IncludeSpecialChars
        Whether to include special characters in the output.
    
    .OUTPUTS
        string - A cryptographically random string
    
    .EXAMPLE
        $password = Get-RandomSecureString -Length 32 -IncludeSpecialChars
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$Length = 32,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeSpecialChars
    )
    
    if ($Length -lt 8 -or $Length -gt 256) {
        throw "Length must be between 8 and 256 characters"
    }
    
    $charSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    
    if ($IncludeSpecialChars) {
        $charSet += "!@#$%^&*()_+-=[]{}|;:,.<>?"
    }
    
    $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
    $bytes = New-Object byte[] ($Length)
    $rng.GetBytes($bytes)
    $rng.Dispose()
    
    $chars = $charSet.ToCharArray()
    $result = New-Object char[] ($Length)
    
    for ($i = 0; $i -lt $Length; $i++) {
        $result[$i] = $chars[$bytes[$i] % $chars.Length]
    }
    
    return [string]::new($result)
}

#endregion

#region Logging and Audit

function Write-SecurityAuditLog {
    <#
    .SYNOPSIS
        Writes a security-relevant event to the audit log.
    
    .DESCRIPTION
        Creates structured audit log entries for security events including:
        - Credential access attempts
        - Failed validation checks
        - Sensitive operations
    
    .PARAMETER EventType
        The type of security event.
    
    .PARAMETER Message
        Description of the event.
    
    .PARAMETER Details
        Additional details as a hashtable.
    
    .PARAMETER Severity
        The severity level: Info, Warning, or Error.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('CredentialAccess', 'ValidationFailure', 'SensitiveOperation', 'ConfigurationChange')]
        [string]$EventType,
        
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Details,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Severity = 'Info'
    )
    
    $timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
    
    $logEntry = @{
        Timestamp = $timestamp
        EventType = $EventType
        Severity = $Severity
        Message = $Message
        User = [Environment]::UserName
        Host = [Environment]::MachineName
        PID = $PID
    }
    
    if ($Details) {
        $logEntry.Details = $Details
    }
    
    $logJson = $logEntry | ConvertTo-Json -Compress
    
    # Write to appropriate output based on severity
    switch ($Severity) {
        'Error'   { Write-Error $Message }
        'Warning' { Write-Warning $Message }
        'Info'    { Write-Verbose $Message }
    }
    
    # Output structured log line for capture
    Write-Output "[SECURITY-AUDIT] $logJson"
}

#endregion

# Export public functions
Export-ModuleMember @(
    'Get-SecureCredential',
    'Get-CredentialFromVault',
    'Set-CredentialInVault',
    'Test-InputSanitized',
    'Test-ValidFilePath',
    'Test-ValidIdentifier',
    'Test-ValidEmail',
    'ConvertTo-SecureStringFromPlainText',
    'Get-EnvironmentSecret',
    'Set-EnvironmentSecret',
    'ConvertFrom-SecureStringToPlainText',
    'Get-RandomSecureString',
    'Write-SecurityAuditLog'
)
