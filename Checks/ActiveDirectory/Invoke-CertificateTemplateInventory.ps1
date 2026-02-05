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
    Inventories Active Directory Certificate Services templates.

.DESCRIPTION
    Lists all certificate templates with their configurations including:
    - Template names and display names
    - Certificate validity periods
    - Key lengths and algorithms
    - Enrollment settings
    - Issuance requirements

.NOTES
    File Name      : Invoke-CertificateTemplateInventory.ps1
    Prerequisite   : PowerShell 5.1 or 7, ADCS module (or LDAP)
    Author         : IdentityFirst Security Team
    Copyright      : (c) 2025 IdentityFirst Ltd
    License        : MIT License
    Version        : 1.0.0
    Compatible     : PowerShell 5.1, 7.x, Windows Server 2012 R2+
#>

[CmdletBinding()]
param()

# PowerShell 5.1/7 Cross-compatibility
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $script:OutputData = [ordered]@{}
} else {
    $script:OutputData = @{}
}

# Check identification
$CheckId = "AD-CERT-INVENTORY-001"
$CheckName = "Certificate Template Inventory"
$CheckCategory = "Active Directory"
$CheckSeverity = "Low"
$CheckDescription = "Inventories AD Certificate Services templates"

# Initialize results
$script:Templates = @()
$script:CheckPassed = $true

function Get-CertificateTemplates {
    <#
    .SYNOPSIS
        Retrieves all certificate templates from AD.
    .DESCRIPTION
        Uses LDAP to query the Certificate Templates container.
    #>
    
    try {
        $templates = @()
        
        # Find a Certificate Authority or use LDAP directly
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $configNC = $rootDSE.configurationNamingContext
        
        # Query Certificate Templates container
        $templatesDN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
        
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = "LDAP://$templatesDN"
        $searcher.Filter = "(objectClass=pKICertificateTemplate)"
        $searcher.PropertiesToLoad.Add("cn") | Out-Null
        $searcher.PropertiesToLoad.Add("displayName") | Out-Null
        $searcher.PropertiesToLoad.Add("pKICertificateTemplate") | Out-Null
        $searcher.PropertiesToLoad.Add("pKIExpirationPeriod") | Out-Null
        $searcher.PropertiesToLoad.Add("pKIKeyUsage") | Out-Null
        $searcher.PropertiesToLoad.Add("pKIMaxIssuingDepth") | Out-Null
        $searcher.PropertiesToLoad.Add("msPKI-RA-Signature") | Out-Null
        $searcher.PropertiesToLoad.Add("msPKI-Enrollment-Flag") | Out-Null
        $searcher.PropertiesToLoad.Add("msPKI-Private-Key-Flag") | Out-Null
        $searcher.PropertiesToLoad.Add("msPKI-Certificate-Name-Flag") | Out-Null
        $searcher.PropertiesToLoad.Add("msPKI-Minimal-Key-Size") | Out-Null
        $searcher.PageSize = 1000
        
        $results = $searcher.FindAll()
        
        foreach ($r in $results) {
            $templates += [PSCustomObject]@{
                Name = $r.Properties['cn'][0]
                DisplayName = if ($r.Properties['displayName']) { $r.Properties['displayName'][0] } else { $null }
                TemplateOID = if ($r.Properties['pKICertificateTemplate']) { $r.Properties['pKICertificateTemplate'][0] } else { $null }
                ValidityPeriod = Get-ValidityPeriod -Bytes $r.Properties['pKIExpirationPeriod']
                KeyUsage = Get-KeyUsage -Bytes $r.Properties['pKIKeyUsage']
                MaxIssuingDepth = if ($r.Properties['pKIMaxIssuingDepth']) { $r.Properties['pKIMaxIssuingDepth'][0] } else { $null }
                RASignature = if ($r.Properties['msPKI-RA-Signature']) { $r.Properties['msPKI-RA-Signature'][0] } else { 0 }
                EnrollmentFlag = if ($r.Properties['msPKI-Enrollment-Flag']) { $r.Properties['msPKI-Enrollment-Flag'][0] } else { 0 }
                PrivateKeyFlag = if ($r.Properties['msPKI-Private-Key-Flag']) { $r.Properties['msPKI-Private-Key-Flag'][0] } else { 0 }
                CertificateNameFlag = if ($r.Properties['msPKI-Certificate-Name-Flag']) { $r.Properties['msPKI-Certificate-Name-Flag'][0] } else { 0 }
                MinimalKeySize = if ($r.Properties['msPKI-Minimal-Key-Size']) { $r.Properties['msPKI-Minimal-Key-Size'][0] } else { 0 }
            }
        }
        
        return $templates
    }
    catch {
        Write-Warning "Error querying certificate templates: $($_.Exception.Message)"
        return @()
    }
}

function Get-ValidityPeriod {
    param([byte[]]$Bytes)
    
    if ($null -eq $Bytes -or $Bytes.Length -lt 8) { return "Unknown" }
    
    try {
        # Convert FILETIME to TimeSpan
        $fileTime = [BitConverter]::ToInt64($Bytes, 0)
        $dateTime = [DateTime]::FromFileTime($fileTime)
        $baseDate = [DateTime]::FromFileTime(0)
        $span = $dateTime - $baseDate
        
        return "$($span.Days) days"
    }
    catch {
        return "Unknown"
    }
}

function Get-KeyUsage {
    param([byte[]]$Bytes)
    
    if ($null -eq $Bytes -or $Bytes.Length -lt 4) { return "Unknown" }
    
    try {
        $flags = [BitConverter]::ToInt32($Bytes, 0)
        $usages = @()
        
        if ($flags -band 0x80) { $usages += "Digital Signature" }
        if ($flags -band 0x40) { $usages += "Non-Repudiation" }
        if ($flags -band 0x20) { $usages += "Key Encipherment" }
        if ($flags -band 0x10) { $usages += "Data Encipherment" }
        if ($flags -band 0x08) { $usages += "Key Agreement" }
        if ($flags -band 0x04) { $usages += "Key Cert Sign" }
        if ($flags -band 0x02) { $usages += "CRL Sign" }
        if ($flags -band 0x01) { $usages += "Encipher Only" }
        
        return ($usages -join ", ")
    }
    catch {
        return "Unknown"
    }
}

# Main execution
try {
    Write-Verbose "Starting Certificate Template Inventory..."
    
    # Get all templates
    Write-Verbose "Retrieving certificate templates..."
    $script:Templates = Get-CertificateTemplates
    
    # Analyze templates
    $templateCount = $script:Templates.Count
    $script:CheckPassed = $templateCount -gt 0
    
    # Check for potentially dangerous templates
    $dangerousPatterns = @("Auth", "CodeSigning", "EFS", "SmartCard", "User")
    $highValueTemplates = $script:Templates | Where-Object {
        $_.Name -match ($dangerousPatterns -join "|")
    }
    
    # Calculate risk level
    $riskLevel = if ($templateCount -eq 0) {
        "Low"
    } elseif ($highValueTemplates.Count -gt 10) {
        "Medium"
    } else {
        "Low"
    }
    
    $status = if ($templateCount -gt 0) { "Pass" } else { "Warning" }
    
    # Build result object
    $Result = [PSCustomObject]@{
        CheckId = $CheckId
        CheckName = $CheckName
        Category = $CheckCategory
        Severity = $CheckSeverity
        Status = $status
        RiskLevel = $riskLevel
        Description = $CheckDescription
        Details = @{
            TotalTemplates = $templateCount
            Templates = $script:Templates | Select-Object Name, DisplayName, ValidityPeriod, KeyUsage, MinimalKeySize | Sort-Object Name
            HighValueTemplates = @{
                Count = $highValueTemplates.Count
                List = $highValueTemplates | Select-Object Name, DisplayName
            }
            Recommendation = if ($templateCount -gt 0) {
                "Found $templateCount certificate templates. Review high-value templates (Code Signing, EFS, SmartCard) for proper access controls. Use AD CS Assessment check for detailed vulnerability analysis."
            } else {
                "No certificate templates found. Either AD CS is not installed or templates container is not accessible."
            }
        }
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
    
    return $Result
}
catch {
    Write-Error "Check failed with exception: $($_.Exception.Message)"
    
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
            TotalTemplates = -1
            Templates = @()
        }
        Timestamp = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
}
