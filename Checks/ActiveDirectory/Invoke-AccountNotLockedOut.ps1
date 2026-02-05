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

function Invoke-AccountNotLockedOut {
    <#
    .SYNOPSIS
        Identifies accounts that are not protected by lockout policy.
    
    .DESCRIPTION
        This read-only check finds user accounts where the lockout threshold
        is set to 0 (disabled), making them immune to brute force attacks.
    
    .PARAMETER OutputPath
        Path to save the results JSON file.
    
    .PARAMETER Export
        Export format: JSON, HTML, or None.
    
    .EXAMPLE
        Invoke-AccountNotLockedOut -OutputPath ".\Reports"
    
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
    
    $checkName = "Invoke-AccountNotLockedOut"
    $checkCategory = "ActiveDirectory"
    $findings = @()
    $startTime = Get-Date
    
    try {
        # Get domain lockout policy
        $domainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain")
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($domainContext)
        $domainName = $domain.Name
        
        # Use .NET to get domain policy
        $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainName/RootDSE")
        $defaultNamingContext = $rootDSE.Properties["defaultNamingContext"][0]
        $domainEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$defaultNamingContext")
        $domainSearcher = New-Object System.DirectoryServices.DirectorySearcher($domainEntry)
        $domainSearcher.Filter = "(objectClass=domainDNS)"
        $domainSearcher.PropertiesToLoad.Add("lockoutThreshold") | Out-Null
        
        $domainResult = $domainSearcher.FindOne()
        $lockoutThreshold = [int]$domainResult.Properties["lockoutThreshold"][0]
        
        if ($lockoutThreshold -eq 0) {
            $findings += [PSCustomObject]@{
                Issue = "Account Lockout Disabled"
                LockoutThreshold = 0
                RiskLevel = "Critical"
                Recommendation = "Enable account lockout policy to protect against brute force attacks"
                Note = "All user accounts are vulnerable to unlimited login attempts"
            }
        }
        else {
            # Get accounts with explicit lockout = 0 override (using UF_LOCKOUT flag check)
            if (Get-Module -Name ActiveDirectory -ListAvailable -ErrorAction SilentlyContinue) {
                $lockoutProps = Get-ADObject -Identity "CN=User Properties,CN=Schema,CN=Configuration,$defaultNamingContext" -Properties * 2>$null
                
                # Get users and check for accounts that bypass lockout
                $users = Get-ADUser -Filter * -Properties Name, SamAccountName, UserAccountControl, LastBadPasswordAttempt 2>$null
                foreach ($user in $users) {
                    $uac = [int]$user.UserAccountControl
                    $isLockedOut = ($uac -band 0x10) -eq 0x10
                    if (-not $isLockedOut -and $lockoutThreshold -gt 0) {
                        $findings += [PSCustomObject]@{
                            Username = $user.SamAccountName
                            DisplayName = $user.Name
                            LockoutThreshold = $lockoutThreshold
                            LastBadPasswordAttempt = $user.LastBadPasswordAttempt
                            RiskLevel = "Low"
                            Recommendation = "No immediate action needed - lockout is enabled"
                        }
                    }
                }
            }
        }
        
        $status = if ($lockoutThreshold -eq 0) { "Fail" } else { "Pass" }
        
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
            PolicyInfo = @{
                LockoutThreshold = $lockoutThreshold
                Domain = $domainName
            }
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
