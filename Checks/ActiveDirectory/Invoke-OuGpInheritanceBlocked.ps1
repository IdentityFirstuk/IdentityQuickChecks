# ============================================================================
# ATTRIBUTION
# ============================================================================
# Author: Mark Ahearne
# Email: mark.ahearne@identityfirst.net
# Company: IdentityFirst Ltd
#
# This script is provided by IdentityFirst Ltd for identity security assessment.
# All rights reserved.
#
# License: See EULA.txt for license terms.
# ============================================================================
<#
.SYNOPSIS
    Detects Organizational Units with blocked Group Policy inheritance.

.DESCRIPTION
    Identifies OUs where GP inheritance has been blocked (gpOptions=1), which can 
    indicate intentional security boundaries or potentially overlooked security controls.
    This check is useful for identifying where policies may not be applying as expected.

.NOTES
    File Name      : Invoke-OuGpInheritanceBlocked.ps1
    Prerequisite   : PowerShell 5.1 or 7, ActiveDirectory module
    Author         : IdentityFirst Security Team
    Copyright      : (c) 2025 IdentityFirst Ltd
    License        : MIT License
    Version        : 1.0.0
    Compatible     : PowerShell 5.1, 7.x, Windows Server 2012 R2+
#>

[CmdletBinding()]
param()

# PowerShell 5.1/7 Cross-compatibility: Define proper output structure
if ($PSVersionTable.PSVersion.Major -ge 7) {
    # PowerShell 7+ uses ordered dictionary for faster serialization
    $script:OutputData = [ordered]@{}
} else {
    # PowerShell 5.1 compatible hashtable conversion
    $script:OutputData = @{}
}

# Get the calling context for reporting
$CheckId = "AD-GP-INHERITANCE-001"
$CheckName = "OU Group Policy Inheritance Blocked"
$CheckCategory = "Active Directory"
$CheckSeverity = "Medium"
$CheckDescription = "Identifies Organizational Units with blocked Group Policy inheritance"

# Initialize result collection
$script:BlockedOUs = @()
$script:CheckPassed = $true

function Get-OUGPInheritanceBlocked {
    <#
    .SYNOPSIS
        Finds OUs with blocked Group Policy inheritance.
    .DESCRIPTION
        Uses LDAP filter to find OUs where gpOptions=1, indicating blocked inheritance.
        Returns detailed information about each affected OU.
    .EXAMPLE
        Get-OUGPInheritanceBlocked | Format-Table
    #>
    
    try {
        # LDAP filter for OUs with blocked inheritance
        # gpOptions=1 means "blocked" in AD schema
        $ldapFilter = '(&(objectclass=OrganizationalUnit)(gpoptions=1))'
        
        # Use cross-platform compatible search
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            # PowerShell 7 - use Get-ADObject with newer parameters
            $searcher = Get-ADObject -Filter $ldapFilter -Properties Name, DistinguishedName, gpOptions -ErrorAction Stop
        } else {
            # PowerShell 5.1 - use DirectorySearcher for better compatibility
            $rootDSE = [ADSI]"LDAP://RootDSE"
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.SearchRoot = "LDAP://$($rootDSE.defaultNamingContext)"
            $searcher.Filter = $ldapFilter
            $searcher.PropertiesToLoad.Add("name") | Out-Null
            $searcher.PropertiesToLoad.Add("distinguishedName") | Out-Null
            $searcher.PropertiesToLoad.Add("gpOptions") | Out-Null
            $searcher.PageSize = 1000
            $searcher = $searcher.FindAll()
        }
        
        return $searcher
    }
    catch {
        Write-Warning "Error querying for blocked OU inheritance: $($_.Exception.Message)"
        return $null
    }
}

# Main execution block
try {
    Write-Verbose "Starting Group Policy Inheritance Blocked check..."
    
    # Perform the check
    $blockedOUs = Get-OUGPInheritanceBlocked
    
    if ($null -eq $blockedOUs) {
        Write-Verbose "No blocked OUs found or error occurred during query"
        $script:BlockedOUs = @()
    }
    else {
        # Process results based on PowerShell version
        if ($blockedOUs -is [System.Collections.ArrayList]) {
            # PowerShell 5.1 DirectorySearcher results
            foreach ($ou in $blockedOUs) {
                $props = $ou.Properties
                $script:BlockedOUs += [PSCustomObject]@{
                    Name = $props['name'][0]
                    DistinguishedName = $props['distinguishedName'][0]
                    gpOptions = $props['gpOptions'][0]
                }
            }
        }
        else {
            # PowerShell 7+ Get-ADObject results
            $script:BlockedOUs = $blockedOUs | ForEach-Object {
                [PSCustomObject]@{
                    Name = $_.Name
                    DistinguishedName = $_.DistinguishedName
                    gpOptions = $_.gpOptions
                }
            }
        }
        
        # If any blocked OUs found, the check did NOT pass
        if ($script:BlockedOUs.Count -gt 0) {
            $script:CheckPassed = $false
        }
    }
    
    # Determine finding status
    if ($script:CheckPassed) {
        $FindingStatus = "Pass"
        $RiskLevel = "None"
    }
    else {
        $FindingStatus = "Fail"
        $RiskLevel = "Medium"
    }
    
    # Build the comprehensive result object
    $Result = [PSCustomObject]@{
        CheckId = $CheckId
        CheckName = $CheckName
        Category = $CheckCategory
        Severity = $CheckSeverity
        Status = $FindingStatus
        RiskLevel = $RiskLevel
        Description = $CheckDescription
        Details = @{
            BlockedOUCount = $script:BlockedOUs.Count
            BlockedOUs = $script:BlockedOUs
            Recommendation = if ($script:BlockedOUs.Count -gt 0) {
                "Review $($script:BlockedOUs.Count) OU(s) with blocked GP inheritance to ensure this is intentional and documented. Verify security boundaries are properly implemented."
            } else {
                "No action required - no OUs with blocked GP inheritance detected."
            }
        }
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
    
    # Output the result
    return $Result
}
catch {
    # Error handling with proper exception logging
    Write-Error "Check failed with exception: $($_.Exception.Message)"
    
    # Return error result object
    return [PSCustomObject]@{
        CheckId = $CheckId
        CheckName = $CheckName
        Category = $CheckCategory
        Severity = $CheckSeverity
        Status = "Error"
        RiskLevel = "Unknown"
        Description = "$CheckDescription (Error during execution)"
        Details = @{
            ErrorMessage = $_.Exception.Message
            BlockedOUCount = -1
            BlockedOUs = @()
        }
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
}
