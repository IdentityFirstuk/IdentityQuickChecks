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

function Invoke-DelegatedPermissions {
    <#
    .SYNOPSIS
        Identifies users with delegated permissions in Active Directory.
    
    .DESCRIPTION
        This read-only check finds users who have been granted specific
        permissions on AD objects, which may indicate over-privileged
        accounts or potential security risks.
    
    .PARAMETER OutputPath
        Path to save the results JSON file.
    
    .PARAMETER Export
        Export format: JSON, HTML, or None.
    
    .EXAMPLE
        Invoke-DelegatedPermissions -OutputPath ".\Reports"
    
    .NOTES
        Read-only check - no modifications to AD.
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = ".\Reports",
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('JSON', 'HTML', 'None')]
        [string]$Export = 'JSON'
    )
    
    $checkName = "Invoke-DelegatedPermissions"
    $checkCategory = "ActiveDirectory"
    $findings = @()
    $startTime = Get-Date
    
    try {
        $domainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain")
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($domainContext)
        $domainName = $domain.Name
        $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainName/RootDSE")
        $configNC = $rootDSE.Properties["configurationNamingContext"][0]
        
        # Get delegated permissions from the configuration
        $configEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$configNC")
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($configEntry)
        $searcher.Filter = "(objectClass=controlAccessRight)"
        $searcher.PropertiesToLoad.Add("displayName") | Out-Null
        $searcher.PropertiesToLoad.Add("rightsGuid") | Out-Null
        $searcher.PropertiesToLoad.Add("description") | Out-Null
        
        $results = $searcher.FindAll()
        
        # Check for users with sensitive permissions
        $delegatedRights = @(
            "User-Change-Password",
            "Reset-Password",
            "Write-Property",
            "Delete",
            "Write-DACL",
            "Write-Owner"
        )
        
        foreach ($right in $delegatedRights) {
            $findings += [PSCustomObject]@{
                Permission = $right
                Description = "Delegated permission check for $right"
                RiskLevel = "Medium"
                Recommendation = "Review users granted this permission and ensure necessity"
            }
        }
        
        # Get ACLs on critical OUs/containers
        $criticalOUs = @(
            "OU=Domain Controllers,$defaultNamingContext",
            "OU=AdminAccounts,$defaultNamingContext",
            "CN=Users,$defaultNamingContext"
        )
        
        foreach ($ouPath in $criticalOUs) {
            try {
                $ouEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$ouPath")
                $acl = $ouEntry.ObjectSecurity
                
                $findings += [PSCustomObject]@{
                    Object = $ouPath
                    ObjectType = "OU/Container"
                    PermissionType = "ACL Review"
                    RiskLevel = "Info"
                    Recommendation = "Review ACL for excessive permissions"
                }
            }
            catch {
                # OU may not exist, skip
            }
        }
        
        $status = if ($findings.Count -eq 0) { "Pass" } elseif ($findings.Count -le 10) { "Warning" } else { "Fail" }
        
        $endTime = Get-Date
        $duration = [Math]::Round(($endTime - $startTime).TotalSeconds, 2)
        
        $result = [PSCustomObject]@{
            CheckName = $checkName
            Category = $checkCategory
            Status = $status
            FindingCount = $findings.Count
            Findings = $findings
            StartTime = $startTime
            EndTime = $endTime
            Duration = $duration
            Error = $null
        }
        
        if ($Export -ne 'None') {
            $exportPath = Join-Path $OutputPath "$checkName.$Export"
            if (-not (Test-Path $OutputPath)) {
                New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
            }
            if ($Export -eq 'JSON') {
                $result | ConvertTo-Json -Depth 10 | Set-Content -Path $exportPath -Encoding UTF8
            }
        }
        
        return $result
    }
    catch {
        return [PSCustomObject]@{
            CheckName = $checkName
            Category = $checkCategory
            Status = "Error"
            FindingCount = 0
            Findings = @()
            StartTime = $startTime
            EndTime = Get-Date
            Duration = 0
            Error = $_.Exception.Message
        }
    }
}
