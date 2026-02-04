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

# Emit structured report saved event
$reportEvent = [PSCustomObject]@{
    Timestamp = (Get-Date).ToString('o')
    Level = 'Info'
    Action = 'ReportSaved'
    Tool = $ctx.ToolName
    Json = $output.Json
    Html = $output.Html
}
Write-IFQC -InputObject $reportEvent
Write-IFQCLog -Context $ctx -Level INFO -Message "InactiveAccountDetection check complete."
Write-IFQCLog -Context $ctx -Level INFO -Message "Report files: JSON: $($output.Json); HTML: $($output.Html)"
Write-Output $output

# SIG # Begin signature block
# MIIJyAYJKoZIhvcNAQcCoIIJuTCCCbUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCy1h+3z4Hd7naD
# 9TzwKyClaj7T8QaQqEB24UUMQHGIKqCCBdYwggXSMIIDuqADAgECAhAxVnqog0nQ
# oULr1YncnW59MA0GCSqGSIb3DQEBCwUAMIGAMQswCQYDVQQGEwJHQjEXMBUGA1UE
# CAwOTm9ydGh1bWJlcmxhbmQxFzAVBgNVBAcMDk5vcnRodW1iZXJsYW5kMRowGAYD
# VQQKDBFJZGVudGl0eUZpcnN0IEx0ZDEjMCEGA1UEAwwaSWRlbnRpdHlGaXJzdCBD
# b2RlIFNpZ25pbmcwHhcNMjYwMTI5MjExMDU3WhcNMzEwMTI5MjEyMDU2WjCBgDEL
# MAkGA1UEBhMCR0IxFzAVBgNVBAgMDk5vcnRodW1iZXJsYW5kMRcwFQYDVQQHDA5O
# b3J0aHVtYmVybGFuZDEaMBgGA1UECgwRSWRlbnRpdHlGaXJzdCBMdGQxIzAhBgNV
# BAMMGklkZW50aXR5Rmlyc3QgQ29kZSBTaWduaW5nMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEAtrU2HprgcHe9mxlmt5X72OsSk7cXDyUhoOAcLE9f4lS2
# rOx7VbZSMSi0r4lt8a/S5m/JIWCdYO+GrWZCgS2S73H3KNDszR5HDPbMhv+leoWA
# qLT7C0awpjcTnvWIDxnHyHHane/TNl3ehY9Jek5qrbiNgJDatV6SEYVFlK8Nk9kE
# 3TiveVvRKokNT2xY4/h1rohFCHnF+g7dCn06xAZwoGnFVlmPop3jItAlZdUQz3zR
# /xSNW01sQXgW6/TYd2VzXXuQihMQ3ikjoNGX1L8SlcV4ih2J+r2kSHjhkZ8c+wJE
# v2iiUHqpwmch31UwQOb4qklGKg1A+SAUGdf0cTTc6ApSFsqrol1euObreoy0zdAA
# k47NELuGhKA4N0Dk9Ar616JGFt/03s1waukNisnH/sk9PmPGUo9QtKH1IQpBtwWw
# uKel0w3MmgTwi2vBwfyh2/oTDkTfic7AT3+wh6O/9mFxxu2Fsq6VSlYRpSTSpgxF
# c/YsVlQZaueZs6WB6/HzftGzv1Mmz7is8DNnnhkADTEMj+NDo4wq+lUCE7XNDnnH
# KBN8MkDh4IljXVSkP/xwt4wLLd9g7oAOW91SDA2wJniyjSUy9c+auW3lbA8ybSfL
# TrQgZiSoepcCjW2otZIXrmDnJ7BtqmmiRff4CCacdJXxqNWdFnv6y7Yy6DQmECEC
# AwEAAaNGMEQwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0G
# A1UdDgQWBBQBfqZy0Xp6lbG6lqI+cAlT7ardlTANBgkqhkiG9w0BAQsFAAOCAgEA
# IwBi/lJTGag5ac5qkMcnyholdDD6H0OaBSFtux1vPIDqNd35IOGYBsquL0BZKh8O
# AHiuaKbo2Ykevpn5nzbXDBVHIW+gN1yu5fWCXSezCPN/NgVgdH6CQ6vIuKNq4BVm
# E8AEhm7dy4pm4WPLqEzWT2fwJhnJ8JYBnPbuUVE8F8acyqG8l3QMcGICG26NWgGs
# A28YvlkzZsny+HAzLvmJn/IhlfWte1kGu0h0G7/KQG6hei5afsn0HxWHKqxI9JsG
# EF3SsMVQW3YJtDzAiRkNtII5k0PyywjrgzIGViVNOrKMT9dKlsTev6Ca/xQX13xM
# 0prtnvxiTXGtT031EBGXAUhOzvx2Hp1WFnZTEIJyX1J2qI+DQsPb9Y1jWcdGBwv3
# /m1nAHE7FpPGsSv+UIP3QQFD/j6nLl5zUoWxqAZMcV4K4t4WkPQjPAXzomoRaqc6
# toXHlXhKHKZ0kfAIcPCFlMwY/Rho82GiATIxHXjB/911VRcpv+xBoPCZkXDnsr9k
# /aRuPNt9DDSrnocJIoTtqIdel/GJmD0D75Lg4voUX9J/1iBuUzta2hoBA8fSVPS5
# 6plrur3Sn5QQG2kJt9I4z5LS3UZSfT+29+xJz7WSyp8+LwU7jaNUuWr3lpUnY2nS
# pohDlw2BFFNGT6/DZ0loRJrUMt58UmfdUX8FPB7uNuIxggNIMIIDRAIBATCBlTCB
# gDELMAkGA1UEBhMCR0IxFzAVBgNVBAgMDk5vcnRodW1iZXJsYW5kMRcwFQYDVQQH
# DA5Ob3J0aHVtYmVybGFuZDEaMBgGA1UECgwRSWRlbnRpdHlGaXJzdCBMdGQxIzAh
# BgNVBAMMGklkZW50aXR5Rmlyc3QgQ29kZSBTaWduaW5nAhAxVnqog0nQoULr1Ync
# nW59MA0GCWCGSAFlAwQCAQUAoIGEMBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAw
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIN6jqtlHNcRHC1wOB2APwwOZBuj6VbWD
# 9fG4wPEQ3VbxMA0GCSqGSIb3DQEBAQUABIICADvT5MCWNWU7XUPBOLGdWM3efS3Q
# uZmt/Me6dVR2ZNwRVNjVv5zQSwWG7q0eu3Vj2nSPOZ4V3qNKq44PUBd0vga24NZw
# 0TrklaZzNaRZ1+wq0mRTtOnjjUFLCLzcHnyMGJPI5b9JEr/DD9UAGv6w75X3qQOY
# XYKhlZ6b5vPCKoKa7z939XcWoFGISOoIqunLQhMD2o7/rkmheGqKen2k0KRPtlOt
# UiUSYKLJN2b5WTr1ffKvQRf7LO3ai4/DQyvxl4MjcnwhMWJ36r/XcamSuGTkdKL5
# DeZU+QVUvjnV7AuH+6XVtOswvyE3BAlpdPF0EiHPODCAgq5wcDAfcHtEN7fChqmb
# jY/vMeryPmhpmON4mmxtlo1TF2Kq6SAK7I7ziYitfiBXAZlke93OqrAdjmptcT/j
# VDEsjVmwHZ/GltYMV7LHdPSLM8fADHpwg30ofHsjBN9MjVONXzUvY4WakpkVThhm
# spezeugnNr5BoR1EU0/lKNeFv+PcxpqaTDSf5ogk3FoQAd83ANAj7w9dJ/B6VfNy
# g3WVtQSUPtF/LA2BdTGqnhOdUgUIYeQXs/ahjUKzk6LPeABcNzn/WbEqGzcyK+Yc
# x1csnnv08fDrvN078Qrk3/M/k9OO9IGhKKNYB/7IZbTPI7cSU4SZHQwGAw5pvCGF
# cArWaBKpVQig/vFm
# SIG # End signature block

