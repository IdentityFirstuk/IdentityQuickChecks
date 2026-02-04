<#
.SYNOPSIS
    IdentityFirst QuickChecks Module
.DESCRIPTION
    PowerShell module providing wrapper functions for QuickChecks scripts.
    
    Usage:
        Import-Module IdentityFirst.QuickChecks
        Invoke-BreakGlassReality -OutputPath ".\Reports"

.NOTES
    Module Version: 1.0.0
    PowerShell: 5.1+
#>

#Requires -Version 5.1

# Get the module base path
$script:ModuleRoot = $PSScriptRoot
if (-not $script:ModuleRoot) {
    $script:ModuleRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
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
        $result = Invoke-QCScript -ScriptName "BreakGlassReality" -OutputPath $OutputPath
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
    
    .EXAMPLE
        Invoke-IdentityLoggingGaps -OutputPath ".\Reports"
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
        'Invoke-IdentityTieringDrift'
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
    #>
    [CmdletBinding()]
    param()
    
    Write-Host ""
    Write-Host "  IdentityFirst QuickChecks Module" -ForegroundColor Cyan
    Write-Host "  =================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Version: 1.0.0" -ForegroundColor Gray
    Write-Host "  Module Path: $script:ModuleRoot" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Available Commands:" -ForegroundColor White
    Write-Host ""
    
    Get-IFQCCommands | Format-Table -AutoSize
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
    'Get-IFQCCommands',
    'Get-IFQCInfo'
)
