<#
.SYNOPSIS
    Shared report formatting functions for IdentityFirst QuickChecks
.DESCRIPTION
    Provides cross-version compatible report formatting utilities
    for PowerShell 5.1 and 7+
#>

# Cross-version compatible encoding selection
# PowerShell 5.1 uses UTF8BOM by default, PowerShell 7+ uses utf8NoBOM
function Get-OutputEncoding {
    <#
    .SYNOPSIS
        Returns the appropriate encoding for file output
    .DESCRIPTION
        Returns Encoding object based on PowerShell version
    #>
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        return [System.Text.Encoding]::UTF8
    }
    else {
        return New-Object System.Text.UTF8Encoding($false)  # UTF8 without BOM for PS5
    }
}

function Format-JsonOutput {
    <#
    .SYNOPSIS
        Converts object to JSON with cross-version compatibility
    .DESCRIPTION
        Uses -Depth 10 to handle complex nested objects and
        ensures consistent formatting across PS5 and PS7
    #>
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [AllowNull()]
        $InputObject
    )
    
    process {
        if ($null -eq $InputObject) { return }
        
        try {
            $InputObject | ConvertTo-Json -Depth 10 -ErrorAction Stop
        }
        catch {
            Write-Error "Failed to convert object to JSON: $($_.Exception.Message)"
            return $null
        }
    }
}

function Write-QCReport {
    <#
    .SYNOPSIS
        Writes a report to file with appropriate encoding
    .PARAMETER Report
        The report object to serialize
    .PARAMETER Path
        Output file path
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Report,
        
        [Parameter(Mandatory=$true)]
        [string]$Path
    )
    
    process {
        try {
            $json = $Report | ConvertTo-Json -Depth 10 -ErrorAction Stop
            
            # Use Set-Content which handles encoding automatically
            # PowerShell 5.1 defaults to UTF8BOM, PS7 to UTF8 without BOM
            $json | Set-Content -Path $Path -ErrorAction Stop
            
            return $true
        }
        catch {
            Write-Error "Failed to write report to '$Path': $($_.Exception.Message)"
            return $false
        }
    }
}

function New-QCTimestamp {
    <#
    .SYNOPSIS
        Creates a timestamp string for filenames
    #>
    return Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
}

function New-QCReportHeader {
    <#
    .SYNOPSIS
        Creates a standardized report header
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$CheckName
    )
    
    return @{
        CheckName = $CheckName
        Timestamp = (Get-Date -Format "o")
        ModuleVersion = "1.0.0"
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        PS5Compatible = ($PSVersionTable.PSVersion.Major -eq 5)
    }
}

Export-ModuleMember -Function @(
    'Get-OutputEncoding',
    'Format-JsonOutput',
    'Write-QCReport',
    'New-QCTimestamp',
    'New-QCReportHeader'
)
