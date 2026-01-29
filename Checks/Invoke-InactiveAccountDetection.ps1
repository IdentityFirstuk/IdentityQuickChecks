<#
.SYNOPSIS
    Inactive Account Detection - Cross-platform identity dormancy check.

.DESCRIPTION
    Detects inactive/dormant accounts across Active Directory, Entra ID, 
    AWS IAM, and GCP. Identifies accounts that haven't been used and may 
    represent risk.

.OUTPUTS
    - JSON report
    - HTML report
    - Log file

.NOTES
    Author: mark.ahearne@identityfirst.net | Owner: IdentityFirst Ltd
    Safety: Read-only. No account changes or lockouts.
    Platforms: AD (on-prem), Entra ID, AWS, GCP
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path $PWD "IFQC-Output"),
    
    [Parameter()]
    [ValidateSet("Normal","Detailed")]
    [string]$DetailLevel = "Normal",
    
    [Parameter()]
    [int]$InactiveDaysThreshold = 90,
    
    [Parameter()]
    [string[]]$Platforms = @("AD", "Entra", "AWS", "GCP")
)

$modulePath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $modulePath "Module\IdentityFirst.QuickChecks.psm1") -Force

$ctx = New-IFQCContext -ToolName "InactiveAccountDetection" -OutputDirectory $OutputDirectory -DetailLevel $DetailLevel
Add-IFQCNote -Context $ctx -Note "Read-only detection of inactive/dormant accounts."
Add-IFQCNote -Context $ctx -Note "Does not lock, disable, or modify accounts."
Add-IFQCNote -Context $ctx -Note "Threshold: $InactiveDaysThreshold days of inactivity."
Add-IFQCNote -Context $ctx -Note "Platforms: $($Platforms -join ', ')"

function Get-EvidenceLimit {
    param([string]$DetailLevel)
    if ($DetailLevel -eq "Detailed") { return 100 }
    return 25
}

Invoke-IFQCSafe -Context $ctx -Name "Inactive account detection" -Block {
    $cutoffDate = (Get-Date).AddDays(-$InactiveDaysThreshold)
    $ctx.Data.cutoffDate = $cutoffDate.ToString("o")
    $ctx.Data.thresholdDays = $InactiveDaysThreshold
    
    $allInactive = @{
        AD = @{ accounts = @(); count = 0 }
        Entra = @{ accounts = @(); count = 0 }
        AWS = @{ accounts = @(); count = 0 }
        GCP = @{ accounts = @(); count = 0 }
    }
    
    # ---------------------------
    # Active Directory Detection
    # ---------------------------
    if ("AD" -in $Platforms) {
        Write-IFQCLog -Context $ctx -Level INFO -Message "Checking AD for inactive accounts..."
        
        try {
            $adModule = Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue
            if ($adModule) {
                Import-Module ActiveDirectory -Force
                
                # Get all users with lastLogonTimestamp (approximate)
                $adUsers = Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonTimestamp, PasswordLastSet, whenCreated -ErrorAction SilentlyContinue
                
                foreach ($u in $adUsers) {
                    $lastLogon = if ($u.LastLogonTimestamp) { [DateTime]$u.LastLogonTimestamp } else { $null }
                    $pwdAge = if ($u.PasswordLastSet) { (New-TimeSpan -Start $u.PasswordLastSet -End (Get-Date)).Days } else { -1 }
                    
                    # Consider inactive if lastLogon > threshold OR password never set > threshold
                    $isInactive = $false
                    $inactivityReason = @()
                    
                    if ($null -eq $lastLogon -or $lastLogon -lt $cutoffDate) {
                        $isInactive = $true
                        $inactivityReason += "LastLogon: $($lastLogon.ToString('yyyy-MM-dd') ?? 'Never')"
                    }
                    
                    if ($pwdAge -gt $InactiveDaysThreshold -and $pwdAge -ge 0) {
                        $isInactive = $true
                        $inactivityReason += "PasswordAge: $pwdAge days"
                    }
                    
                    if ($isInactive) {
                        $allInactive.AD.accounts += [PSCustomObject]@{
                            SamAccountName = $u.SamAccountName
                            Name = $u.Name
                            LastLogon = $lastLogon
                            PasswordAgeDays = $pwdAge
                            Created = $u.whenCreated
                            InactivityReasons = $inactivityReason -join "; "
                        }
                    }
                }
                
                $allInactive.AD.count = ($allInactive.AD.accounts | Measure-Object).Count
                $ctx.Data.AD.checked = $true
                $ctx.Data.AD.found = $allInactive.AD.count
            } else {
                Write-IFQCLog -Context $ctx -Level WARN -Message "AD module not available"
                $ctx.Data.AD.checked = $false
                $ctx.Data.AD.reason = "RSAT/AD module not installed"
            }
        } catch {
            Write-IFQCLog -Context $ctx -Level WARN -Message "AD check failed: $($_.Exception.Message)"
            $ctx.Data.AD.checked = $false
            $ctx.Data.AD.error = $_.Exception.Message
        }
    }
    
    # ---------------------------
    # Entra ID Detection
    # ---------------------------
    if ("Entra" -in $Platforms) {
        Write-IFQCLog -Context $ctx -Level INFO -Message "Checking Entra ID for inactive accounts..."
        
        try {
            $graphAvailable = $false
            if (Get-Module -ListAvailable -Name Microsoft.Graph.Identity.DirectoryManagement -ErrorAction SilentlyContinue) {
                Import-Module Microsoft.Graph.Identity.DirectoryManagement -Force
                Connect-MgGraph -Scopes "Directory.Read.All" -ErrorAction Stop | Out-Null
                $graphAvailable = $true
            }
            
            if ($graphAvailable) {
                $users = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,LastSignInDateTime,CreatedDateTime,AccountEnabled -ErrorAction SilentlyContinue
                
                foreach ($u in $users) {
                    $lastSignIn = if ($u.LastSignInDateTime) { [DateTime]$u.LastSignInDateTime } else { $null }
                    
                    $isInactive = $false
                    $inactivityReason = @()
                    
                    if ($null -eq $lastSignIn -or $lastSignIn -lt $cutoffDate) {
                        $isInactive = $true
                        $inactivityReason += "LastSignIn: $($lastSignIn.ToString('yyyy-MM-dd') ?? 'Never')"
                    }
                    
                    if ($isInactive -and $u.AccountEnabled) {
                        $allInactive.Entra.accounts += [PSCustomObject]@{
                            DisplayName = $u.DisplayName
                            UserPrincipalName = $u.UserPrincipalName
                            LastSignIn = $lastSignIn
                            Created = $u.CreatedDateTime
                            Enabled = $u.AccountEnabled
                            InactivityReasons = $inactivityReason -join "; "
                        }
                    }
                }
                
                $allInactive.Entra.count = ($allInactive.Entra.accounts | Measure-Object).Count
                $ctx.Data.Entra.checked = $true
                $ctx.Data.Entra.found = $allInactive.Entra.count
                
                Disconnect-MgGraph | Out-Null
            } else {
                $ctx.Data.Entra.checked = $false
                $ctx.Data.Entra.reason = "Microsoft Graph not available"
            }
        } catch {
            Write-IFQCLog -Context $ctx -Level WARN -Message "Entra check failed: $($_.Exception.Message)"
            $ctx.Data.Entra.checked = $false
            $ctx.Data.Entra.error = $_.Exception.Message
        }
    }
    
    # ---------------------------
    # AWS Detection
    # ---------------------------
    if ("AWS" -in $Platforms) {
        Write-IFQCLog -Context $ctx -Level INFO -Message "Checking AWS for inactive IAM users..."
        
        try {
            $useCli = $false
            if (Get-Command "aws" -ErrorAction SilentlyContinue) {
                $useCli = $true
            } elseif (Get-Module -ListAvailable -Name AWS.Tools.IdentityManagement -ErrorAction SilentlyContinue) {
                Import-Module AWS.Tools.IdentityManagement -Force
            } else {
                throw "Neither AWS CLI nor AWS.Tools available"
            }
            
            $awsUsers = @()
            
            if ($useCli) {
                $userJson = aws iam list-users --output json 2>$null | ConvertFrom-Json
                $awsUsers = $userJson.Users
            } else {
                $awsUsers = Get-IAMUser
            }
            
            foreach ($u in $awsUsers) {
                $userName = if ($useCli) { $u.UserName } else { $u.UserName }
                
                # Get access key last used
                $keyUsed = $null
                if ($useCli) {
                    $keyJson = aws iam list-access-keys --user-name $userName --output json 2>$null | ConvertFrom-Json
                    $keys = $keyJson.AccessKeyMetadata
                    foreach ($k in $keys) {
                        $usedJson = aws iam get-access-key-last-used --access-key-id $k.AccessKeyId --output json 2>$null | ConvertFrom-Json
                        if ($usedJson.AccessKeyLastUsed.LastUsedDate) {
                            $keyUsed = [DateTime]$usedJson.AccessKeyLastUsed.LastUsedDate
                        }
                    }
                } else {
                    $keys = Get-IAMAccessKey -UserName $userName
                    foreach ($k in $keys) {
                        $used = Get-IAMAccessKeyLastUsed -AccessKeyId $k.AccessKeyId
                        if ($used.AccessKeyLastUsedDate) {
                            $keyUsed = [DateTime]$used.AccessKeyLastUsedDate
                        }
                    }
                }
                
                $isInactive = $false
                $inactivityReason = @()
                
                if ($null -eq $keyUsed -or $keyUsed -lt $cutoffDate) {
                    $isInactive = $true
                    $inactivityReason += "AccessKeyLastUsed: $($keyUsed.ToString('yyyy-MM-dd') ?? 'Never')"
                }
                
                if ($isInactive) {
                    $allInactive.AWS.accounts += [PSCustomObject]@{
                        UserName = $userName
                        AccessKeyLastUsed = $keyUsed
                        InactivityReasons = $inactivityReason -join "; "
                    }
                }
            }
            
            $allInactive.AWS.count = ($allInactive.AWS.accounts | Measure-Object).Count
            $ctx.Data.AWS.checked = $true
            $ctx.Data.AWS.found = $allInactive.AWS.count
        } catch {
            Write-IFQCLog -Context $ctx -Level WARN -Message "AWS check failed: $($_.Exception.Message)"
            $ctx.Data.AWS.checked = $false
            $ctx.Data.AWS.error = $_.Exception.Message
        }
    }
    
    # ---------------------------
    # GCP Detection
    # ---------------------------
    if ("GCP" -in $Platforms) {
        Write-IFQCLog -Context $ctx -Level INFO -Message "Checking GCP for inactive service accounts..."
        
        try {
            if (-not (Get-Command "gcloud" -ErrorAction SilentlyContinue)) {
                throw "gcloud CLI not available"
            }
            
            $projects = @()
            try {
                $projJson = gcloud projects list --format=json 2>$null | ConvertFrom-Json
                $projects = $projJson.projectId
            } catch {
                $projects = @("default")
            }
            
            foreach ($proj in $projects) {
                gcloud config set project $proj 2>$null | Out-Null
                
                $saJson = gcloud iam service-accounts list --format=json 2>$null | ConvertFrom-Json
                foreach ($sa in $saJson) {
                    # Get key usage (approximation - last key creation doesn't mean usage)
                    $keyJson = gcloud iam service-accounts keys list --iam-account $sa.email --format=json 2>$null | ConvertFrom-Json
                    
                    $lastKeyCreated = $null
                    foreach ($k in $keyJson) {
                        if ($k.validAfterTime) {
                            $keyDate = [DateTime]$k.validAfterTime
                            if ($null -eq $lastKeyCreated -or $keyDate -gt $lastKeyCreated) {
                                $lastKeyCreated = $keyDate
                            }
                        }
                    }
                    
                    # Note: GCP doesn't provide service account last-used API for regular keys
                    # This is a best-effort check based on key age
                    $isInactive = $false
                    $inactivityReason = @()
                    
                    if ($null -eq $lastKeyCreated -or $lastKeyCreated -lt $cutoffDate) {
                        $isInactive = $true
                        $inactivityReason += "KeyCreated: $($lastKeyCreated.ToString('yyyy-MM-dd') ?? 'Never')"
                    }
                    
                    if ($isInactive -and -not $sa.disabled) {
                        $allInactive.GCP.accounts += [PSCustomObject]@{
                            Project = $proj
                            Email = $sa.email
                            DisplayName = $sa.displayName
                            Disabled = $sa.disabled
                            KeyCreated = $lastKeyCreated
                            InactivityReasons = $inactivityReason -join "; "
                        }
                    }
                }
            }
            
            $allInactive.GCP.count = ($allInactive.GCP.accounts | Measure-Object).Count
            $ctx.Data.GCP.checked = $true
            $ctx.Data.GCP.found = $allInactive.GCP.count
        } catch {
            Write-IFQCLog -Context $ctx -Level WARN -Message "GCP check failed: $($_.Exception.Message)"
            $ctx.Data.GCP.checked = $false
            $ctx.Data.GCP.error = $_.Exception.Message
        }
    }
    
    # ---------------------------
    # Store Results
    # ---------------------------
    $ctx.Data.platforms = $allInactive
    
    # ---------------------------
    # Findings
    # ---------------------------
    $evidenceLimit = Get-EvidenceLimit -DetailLevel $DetailLevel
    $totalInactive = ($allInactive.AD.count + $allInactive.Entra.count + $allInactive.AWS.count + $allInactive.GCP.count)
    
    # Finding: Inactive AD accounts
    if ($allInactive.AD.count -gt 0) {
        Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
            -Id "INACTIVE-AD" `
            -Title "Inactive AD accounts detected" `
            -Severity "Medium" `
            -Description "$($allInactive.AD.count) Active Directory accounts have had no logon activity in $InactiveDaysThreshold days." `
            -Count $allInactive.AD.count `
            -Evidence ($allInactive.AD.accounts | Select-Object -First $evidenceLimit) `
            -Recommendation "Review inactive accounts. Disable or remove accounts that are no longer needed."
        )
    }
    
    # Finding: Inactive Entra accounts
    if ($allInactive.Entra.count -gt 0) {
        Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
            -Id "INACTIVE-ENTRA" `
            -Title "Inactive Entra ID accounts detected" `
            -Severity "Medium" `
            -Description "$($allInactive.Entra.count) Entra ID users have had no sign-in activity in $InactiveDaysThreshold days." `
            -Count $allInactive.Entra.count `
            -Evidence ($allInactive.Entra.accounts | Select-Object -First $evidenceLimit) `
            -Recommendation "Review inactive users. Consider disabling or removing access for unused accounts."
        )
    }
    
    # Finding: Inactive AWS users
    if ($allInactive.AWS.count -gt 0) {
        Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
            -Id "INACTIVE-AWS" `
            -Title "Inactive AWS IAM users detected" `
            -Severity "Medium" `
            -Description "$($allInactive.AWS.count) IAM users have not used access keys in $InactiveDaysThreshold days." `
            -Count $allInactive.AWS.count `
            -Evidence ($allInactive.AWS.accounts | Select-Object -First $evidenceLimit) `
            -Recommendation "Review inactive IAM users. Remove unused access keys or deactivate users."
        )
    }
    
    # Finding: Inactive GCP service accounts
    if ($allInactive.GCP.count -gt 0) {
        Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
            -Id "INACTIVE-GCP" `
            -Title "Inactive GCP service accounts detected" `
            -Severity "Medium" `
            -Description "$($allInactive.GCP.count) GCP service accounts have not had new keys created in $InactiveDaysThreshold days." `
            -Count $allInactive.GCP.count `
            -Evidence ($allInactive.GCP.accounts | Select-Object -First $evidenceLimit) `
            -Recommendation "Review inactive service accounts. Disable or delete accounts that are no longer needed."
        )
    }
    
    # Summary
    $ctx.Data.summary = @{
        totalInactive = $totalInactive
        AD = $allInactive.AD.count
        Entra = $allInactive.Entra.count
        AWS = $allInactive.AWS.count
        GCP = $allInactive.GCP.count
    }
}

$output = Save-IFQCReport -Context $ctx

Write-Host ""
Write-Host "InactiveAccountDetection check complete." -ForegroundColor Green
Write-Host "  JSON: $($output.Json)" -ForegroundColor Cyan
Write-Host "  HTML: $($output.Html)" -ForegroundColor Cyan
