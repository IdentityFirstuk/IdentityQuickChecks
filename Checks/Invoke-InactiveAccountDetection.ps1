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
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB5ulgT98Pvd/8g
# egJM0AhNDuBYg7i3cgqvZ1n9c8NdBKCCFlIwggMUMIIB/KADAgECAhBDR0HvMFNE
# lkJ70azsYRwnMA0GCSqGSIb3DQEBCwUAMCIxIDAeBgNVBAMMF0lkZW50aXR5Rmly
# c3QgQ29kZSBTaWduMB4XDTI2MDIwNDE2NDE0OFoXDTI3MDIwNDE3MDE0OFowIjEg
# MB4GA1UEAwwXSWRlbnRpdHlGaXJzdCBDb2RlIFNpZ24wggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQDWJrlUCUN9yoS4qyJUFIIrjVVnfoFqTXwze3ijNE5q
# wUAAiypU86tc6ct9/wQ9Q9qOn6gjKU3vDhq8XojyQhi/q0ffxG1pP8bHfCQtrMFc
# kTOKLZRgQO73caKFxunCuRdAGxdDxy94NNjwITySkaaLFb3gULH1wbfmu5l2v9ga
# CgpRJGoofRbYbjBS5B7TTNVXlyxl5I3toq9cYRwauWq0Fqj2h6gZ/8izDVU6nMGX
# k+ZfsQwTsVSxfiiWHozhjU7Rt8ckxfVt1YLyPamewESLxw4ijFgHYZUrxNtbm2DP
# QUUG4ekzdDQlBLBzjdIJh8hIz+gcqvyXIQpoFjF2xyoFAgMBAAGjRjBEMA4GA1Ud
# DwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQU0LvUry7V
# 3WlfTmidD6yCOpbcmSQwDQYJKoZIhvcNAQELBQADggEBAAWDzEqYgCCQHZwHCMlU
# ob2Jkqcbk6GYylmfTwW9EQ7iJjyKHFJlbUGuDJxClDwDteBCVpxhfbi0fJjkib8r
# b4Fbk9Rex5rJxEMidBYbnASWnLuJD7dsHbwf6N4SM/LsYhiEtllGb0UsKET6PyuO
# f1sYdDY+UcTssCzDAElCrlVIl4Z4/JBlXOhInMD7AnP6Xx2r4hCAVEWhHtJ+ahY/
# bFAJ7v+EsTET2Pa34kiymxJ7yYRNSxwxyb1umUx/Q6pui0lYjyNXt8AAg4A0ybyj
# ABLNYct6zilczJ6JqPCBJLL0ZbCDpg8SkmAn3G3Y+bSztlOIUo4eXpjXV1DE7oB/
# kuAwggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUA
# MGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsT
# EHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQg
# Um9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqcl
# LskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YF
# PFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceIt
# DBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZX
# V59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1
# ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2Tox
# RJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdp
# ekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF
# 30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9
# t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQ
# UOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXk
# aS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud
# DgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEt
# UYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsG
# AQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0
# dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RD
# QS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAw
# DQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72arKGHLOyF
# XqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFIDyE7QKt76
# LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8L
# punyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2
# CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si
# /xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQwgga0MIIEnKADAgEC
# AhANx6xXBf8hmS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcw
# MDAwMDBaFw0zODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1l
# U3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZ
# loMsVO1DahGPNRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM
# 2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj
# 7GH8BLuxBG5AvftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQ
# Sku2Ws3IfDReb6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZ
# lDwFt+cVFBURJg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+
# 8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRx
# ykvq6gbylsXQskBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yG
# OP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqI
# MRvUBDx6z1ev+7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm
# 1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBj
# UwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729T
# SunkBnx6yuKQVvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4c
# D08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUF
# BwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEG
# CCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAX
# MAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaA
# HP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQ
# M2qEJPe36zwbSI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt
# 6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7
# bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmS
# Nq1UH410ANVko43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69
# M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnF
# RsjsYg39OlV8cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmM
# Thi0vw9vODRzW6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oa
# Qf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx
# 9yHbxtl5TPau1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3
# /BAPvIXKUjPSxyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN
# 8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQg
# VGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAw
# MDAwMFoXDTM2MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBU
# aW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx
# +wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvN
# Zh6wW2R6kSu9RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlL
# nh00Cll8pjrUcCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmn
# cOOMA3CoB/iUSROUINDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5KqCvpSduSwhw
# UmotuQhcg9tw2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL
# 4Q1OpbybpMe46YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdoRORVbPR1VVnD
# uSeHVZlc4seAO+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCy
# FG1roSrgHjSHlq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7rlRyTlaCCfw7a
# SUROwnu7zER6EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K096V1hE0yZIXe+gi
# AwW00aHzrDchIc2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGj
# ggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39/dfzkXFjGVBD
# z2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8E
# BAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGF
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUH
# MAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRH
# NFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBW
# MFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVk
# RzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkw
# FzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3x
# HCcEua5gQezRCESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh
# 8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim8/9yJmZS
# e2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUqW4daIqToXFE/
# JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMnxYOX8VBRKe1u
# NnzQVTeLni2nHkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq
# 8/gVutDojBIFeRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AWcIQfVjnzrvwi
# CZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJgddJ35XTxfUlQ
# +8Hggt8l2Yv7roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1
# R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVccAvlKV9jEnstr
# niLvUxxVZE/rptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8atufk+EMF/cWu
# iC7POGT75qaL6vdCvHlshtjdNXOCIUjsarfNZzGCBRIwggUOAgEBMDYwIjEgMB4G
# A1UEAwwXSWRlbnRpdHlGaXJzdCBDb2RlIFNpZ24CEENHQe8wU0SWQnvRrOxhHCcw
# DQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkq
# hkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGC
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgb7p3eLPoJJfVRexHa2MOG1CB8Dxgh0wSlJr5
# RwDuR8UwDQYJKoZIhvcNAQEBBQAEggEASOvFa+LF1wgPuTmm3PSBvH3VGS2+zMZk
# LntdgNZREptbkwq3UHomiRmIkF/FZTyS8kT2YBBG9bJixjdQnIBF9SSjsuZcT187
# mJbtesHM9VoTbcXehUekiqqC+tAO0N9ic04SpMv+wiTgovNZYlFP57DLEEFwNVG/
# LEsjO66YOXFvEdFrB+F55qFMS4bST6+tiTF3Lq9S51757Tr1qbu7/92fJW71pnn7
# 6Tf3Jn+DAVxsq5kIdOeF1QJa/Bx3xKcL3lxRR+U1DeeQ/TlNVMSlqlNsPkGZEFeq
# JKIuWL2gF+IfOAlYd11o8BNLtxg3o92JCI+L324+Tu7B0EV3N/NZaKGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjAyMDQxNjUyMTNaMC8GCSqGSIb3DQEJBDEiBCBQ
# MUG5aUxN3nD85clu7n+gG0b70KTTHN8YUDUrn94tCDANBgkqhkiG9w0BAQEFAASC
# AgBp1c1xqOnBetMkAow3jiA/uUAYyiSOQ8EohYyfQmIy515D196s95xPwf5tmV0x
# is1VZH9qS8nY3E/h8olLntS45h++nkyIk/C+czDJe39f1ghvTQLryDPWwc6oAtBu
# kh9dVUAjT9s2YCVeLZjeN/5xuih9l8ZRaZx3GL9Om0X95e6xuBrB3WS5iLUwhRfZ
# e+HlY3fQClHuRLnlqDMVMOWLOSWdFneDN7j1FiuvwIkCbUwnw2oiAtHinMGypv9C
# FUvaDI9WZp1QK0tJgsgz31IWOIXtp9cznhzob0kVaGSY556QgcICPg7MfqyXYOf1
# oaRW3njNFmRA83i3Orfyc4Lm9Ho2s9lG2IGVl29hPA+fUmX7cB0F1SW6eAexu84+
# w04jC/X4STvHU3BwgWbIR19BFVwh+MoLYK0dh4f47rqMci0AGsMjI1arVOsrD8+2
# d/kxnhbrrYGFcuilpAb+Q1/wHLSIH68zqFYq8UQOPZA31QBlv/9HToaMkmexZh/K
# BqkhqgTDIlyG2hXMAkdH5JTGMLo7BZj0fTuj/wfTEhbXNn5bv+C38NXMVi/IJQJt
# URgiZ52nRkTP87AGQwaJeUFWqMXHbH/HsJEVL7PbELCGrttUcZ9debaIfIGZl94s
# cthUJdakerc7B6bWIfU1dFpb/EZ0uh/ow3ZTcC4j8h4GyQ==
# SIG # End signature block
