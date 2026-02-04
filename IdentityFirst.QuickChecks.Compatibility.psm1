<#
.SYNOPSIS
    IdentityFirst QuickChecks - PowerShell 7 Compatibility Layer

.DESCRIPTION
    This module provides cross-platform compatibility for IdentityFirst QuickChecks
    between PowerShell 5.1 (Windows) and PowerShell 7+ (Cross-platform).

    It automatically detects the PowerShell version and applies appropriate
    workarounds and alternative implementations.

.NOTES
    Author: mark.ahearne@identityfirst.net
    Requirements: PowerShell 5.1 or later
#>

# Detect PowerShell version
$script:PSVersion = $PSVersionTable.PSVersion
$script:IsPS7Plus = $script:PSVersion.Major -ge 7
$script:IsWindows = $IsWindows -or ($PSEdition -eq 'Desktop')

# =============================================================================
# Compatibility Helper Functions
# =============================================================================

function Get-CompatiblePlatform {
    <#
    .SYNOPSIS
        Returns the current platform information.
    #>
    return @{
        PSVersion = $script:PSVersion
        IsPS7Plus = $script:IsPS7Plus
        IsWindows = $script:IsWindows
        IsLinux = $IsLinux
        IsMacOS = $IsMacOS
    }
}

function Test-IsWindowsOnly {
    <#
    .SYNOPSIS
        Checks if the current operation requires Windows.
    #>
    [CmdletBinding()]
    param()

    return $script:IsWindows
}

function Get-CompatibleCredential {
    <#
    .SYNOPSIS
        Gets credentials in a cross-platform compatible way.
    #>
    [CmdletBinding()]
    param(
        [string]$Message = "Enter credentials",
        [string]$UserName = $null
    )

    if ($script:IsWindows -and -not $script:IsPS7Plus) {
        # PowerShell 5.1 on Windows - use Get-Credential
        if ($UserName) {
            return Get-Credential -Message $Message -UserName $UserName
        }
        return Get-Credential -Message $Message
    }
    else {
        # PowerShell 7+ - use cross-platform Get-Credential
        if ($UserName) {
            return Get-Credential -Message $Message -UserName $UserName
        }
        return Get-Credential -Message $Message
    }
}

# =============================================================================
# Windows-Only Functions (with graceful fallbacks)
# =============================================================================

function Get-WindowsIdentity {
    <#
    .SYNOPSIS
        Gets the current Windows identity. Windows only.
    #>
    [CmdletBinding()]
    param()

    if (-not $script:IsWindows) {
        Write-Warning "Get-WindowsIdentity is not available on non-Windows platforms"
        return $null
    }

    try {
        return [System.Security.Principal.WindowsIdentity]::GetCurrent()
    }
    catch {
        Write-Error "Failed to get Windows identity: $($_.Exception.Message)"
        return $null
    }
}

function Test-IsAdministrator {
    <#
    .SYNOPSIS
        Checks if running as administrator. Windows only.
    #>
    [CmdletBinding()]
    param()

    if (-not $script:IsWindows) {
        Write-Warning "Test-IsAdministrator is not available on non-Windows platforms"
        return $false
    }

    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        Write-Error "Failed to check administrator status: $($_.Exception.Message)"
        return $false
    }
}

function Get-AuthenticodeSignature {
    <#
    .SYNOPSIS
        Gets Authenticode signature. Windows only.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$Path
    )

    if (-not $script:IsWindows) {
        Write-Warning "Get-AuthenticodeSignature is not available on non-Windows platforms"
        return @{
            Status = 'NotSupported'
            SignerCertificate = $null
            TimeStamperCertificate = $null
        }
    }

    try {
        return Get-AuthenticodeSignature -Path $Path -ErrorAction Stop
    }
    catch {
        return @{
            Status = 'UnknownError'
            SignerCertificate = $null
            TimeStamperCertificate = $null
            Error = $_.Exception.Message
        }
    }
}

# =============================================================================
# Cross-Platform Alternative Functions
# =============================================================================

function Get-FileHashCrossPlatform {
    <#
    .SYNOPSIS
        Gets file hash in a cross-platform compatible way.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [ValidateSet('MD5', 'SHA1', 'SHA256', 'SHA384', 'SHA512')]
        [string]$Algorithm = 'SHA256'
    )

    if ($script:IsPS7Plus) {
        return Get-FileHash -Path $Path -Algorithm $Algorithm -ErrorAction Stop
    }
    else {
        # PowerShell 5.1 fallback
        $hash = [System.Security.Cryptography.SHA256]::Create()
        try {
            $stream = [System.IO.File]::OpenRead($Path)
            $hashValue = $hash.ComputeHash($stream)
            $stream.Close()
            return @{
                Algorithm = $Algorithm
                Hash = [BitConverter]::ToString($hashValue).Replace('-', '').ToLowerInvariant()
                Path = $Path
            }
        }
        catch {
            throw "Failed to compute hash: $($_.Exception.Message)"
        }
        finally {
            $hash.Dispose()
        }
    }
}

function Invoke-RestMethodCrossPlatform {
    <#
    .SYNOPSIS
        Invokes REST API call with cross-platform compatibility.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,
        [ValidateSet('GET', 'POST', 'PUT', 'DELETE', 'PATCH')]
        [string]$Method = 'GET',
        [hashtable]$Headers = @{},
        [string]$Body = $null,
        [string]$ContentType = 'application/json'
    )

    $splat = @{
        Uri = $Uri
        Method = $Method
        Headers = $Headers
        ContentType = $ContentType
        ErrorAction = 'Stop'
    }

    if ($Body) {
        $splat.Body = $Body
    }

    return Invoke-RestMethod @splat
}

# =============================================================================
# JSON Compatibility Functions
# =============================================================================

function ConvertTo-JsonCrossPlatform {
    <#
    .SYNOPSIS
        Converts to JSON with consistent behavior across versions.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowNull()]
        $InputObject,
        [int]$Depth = 10,
        [switch]$Compress
    )

    if ($script:IsPS7Plus) {
        return $InputObject | ConvertTo-Json -Depth $Depth -Compress:$Compress
    }
    else {
        # PowerShell 5.1 has limited depth (2 by default)
        return $InputObject | ConvertTo-Json -Depth $Depth
    }
}

function ConvertFrom-JsonCrossPlatform {
    <#
    .SYNOPSIS
        Converts from JSON with cross-platform compatibility.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$InputObject
    )

    if ($script:IsPS7Plus) {
        return $InputObject | ConvertFrom-Json -AsHashtable
    }
    else {
        return $InputObject | ConvertFrom-Json
    }
}

# =============================================================================
# Module Initialization
# =============================================================================

# Export module member information
$exportedFunctions = @(
    'Get-CompatiblePlatform'
    'Test-IsWindowsOnly'
    'Get-CompatibleCredential'
    'Get-WindowsIdentity'
    'Test-IsAdministrator'
    'Get-AuthenticodeSignature'
    'Get-FileHashCrossPlatform'
    'Invoke-RestMethodCrossPlatform'
    'ConvertTo-JsonCrossPlatform'
    'ConvertFrom-JsonCrossPlatform'
)

# Conditional exports based on platform
if ($script:IsWindows) {
    $exportedFunctions += @(
        'Get-WindowsIdentity'
        'Test-IsAdministrator'
        'Get-AuthenticodeSignature'
    )
}

# Always export cross-platform functions
$exportedFunctions += @(
    'Get-CompatiblePlatform'
    'Get-CompatibleCredential'
    'Get-FileHashCrossPlatform'
    'Invoke-RestMethodCrossPlatform'
    'ConvertTo-JsonCrossPlatform'
    'ConvertFrom-JsonCrossPlatform'
)

Export-ModuleMember -Function $exportedFunctions

# Log module load
if ($VerbosePreference -eq 'Continue') {
    Write-Verbose "IdentityFirst QuickChecks Compatibility Layer loaded"
    Write-Verbose "  PowerShell Version: $($script:PSVersion)"
    Write-Verbose "  Platform: $(if ($script:IsWindows) { 'Windows' } elseif ($IsLinux) { 'Linux' } elseif ($IsMacOS) { 'macOS' } else { 'Unknown' })"
    Write-Verbose "  Functions Exported: $($exportedFunctions.Count)"
}
