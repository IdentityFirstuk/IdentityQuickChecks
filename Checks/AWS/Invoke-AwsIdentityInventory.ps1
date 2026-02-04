<#
.SYNOPSIS
    AWS Identity Inventory using AWS CLI or AWS Tools for PowerShell.

.DESCRIPTION
    Reads IAM users, access keys, roles, and cross-account trusts.
    Supports both AWS CLI (aws iam) and AWS.Tools modules.

.OUTPUTS
    - JSON report
    - HTML report
    - Log file

.NOTES
    Author: mark.ahearne@identityfirst.net | Owner: IdentityFirst Ltd
    Safety: Read-only. No changes are made.
    Requires: AWS CLI or AWS.Tools for PowerShell
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path $PWD "IFQC-Output"),

    [Parameter()]
    [ValidateSet("Normal","Detailed")]
    [string]$DetailLevel = "Normal",

    [Parameter()]
    [switch]$UseCli
)

$modulePath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $modulePath "Module\IdentityFirst.QuickChecks.psm1") -Force

$ctx = New-IFQCContext -ToolName "AwsIdentityInventory" -OutputDirectory $OutputDirectory -DetailLevel $DetailLevel
Add-IFQCNote -Context $ctx -Note "Read-only IAM inventory. No remediation or policy changes."
Add-IFQCNote -Context $ctx -Note "Uses AWS CLI or AWS.Tools. Requires iam:GetUser, iam:ListUsers, iam:ListRoles permissions."

function Get-EvidenceLimit {
    param([string]$DetailLevel)
    if ($DetailLevel -eq "Detailed") { return 200 }
    return 40
}

Invoke-IFQCSafe -Context $ctx -Name "AWS IAM inventory" -Block {
    # Detect method
    $useCli = $UseCli -or (-not (Get-Module -ListAvailable -Name AWS.Tools.IdentityManagement))

    $ctx.Data.method = if ($useCli) { "AWS CLI" } else { "AWS.Tools" }

    $users = @()
    $roles = @()
    $accessKeys = @()
    $adminPolicies = @()

    # Get users
    if ($useCli) {
        $userJson = aws iam list-users --output json 2>$null
        if ($userJson) {
            $users = $userJson | ConvertFrom-Json | Select-Object -ExpandProperty Users
        }

        # Get roles
        $roleJson = aws iam list-roles --output json 2>$null
        if ($roleJson) {
            $roles = $roleJson | ConvertFrom-Json | Select-Object -ExpandProperty Roles
        }

        # Get access keys per user
        foreach ($u in $users) {
            $akJson = aws iam list-access-keys --user-name $u.UserName --output json 2>$null
            if ($akJson) {
                $keys = $akJson | ConvertFrom-Json | Select-Object -ExpandProperty AccessKeyMetadata
                foreach ($k in $keys) {
                    $accessKeys += [PSCustomObject]@{
                        UserName = $u.UserName
                        AccessKeyId = $k.AccessKeyId
                        Status = $k.Status
                        CreateDate = $k.CreateDate
                    }
                }
            }
        }
    } else {
        try {
            Import-Module AWS.Tools.IdentityManagement -ErrorAction Stop
            $users = Get-IAMUser
            $roles = Get-IAMRole

            foreach ($u in $users) {
                $keys = Get-IAMAccessKey -UserName $u.UserName -ErrorAction SilentlyContinue
                foreach ($k in $keys) {
                    $accessKeys += [PSCustomObject]@{
                        UserName = $u.UserName
                        AccessKeyId = $k.AccessKeyId
                        Status = $k.Status
                        CreateDate = $k.CreateDate
                    }
                }
            }
        } catch {
            throw "AWS.Tools not available and -UseCli not specified. Install AWS.Tools or use AWS CLI."
        }
    }

    # Get account ID for context
    $accountId = (aws sts get-caller-identity --output json 2>$null | ConvertFrom-Json).Account
    if (-not $accountId) { $accountId = "unknown" }
    $ctx.Data.awsAccountId = $accountId

    # Find admin-like policies
    $adminPatterns = @("AdministratorAccess", "FullAdmin", "PowerUserAccess")
    foreach ($r in $roles) {
        $policyJson = aws iam list-attached-role-policies --role-name $r.RoleName --output json 2>$null | ConvertFrom-Json
        $attached = $policyJson.AttachedPolicies

        foreach ($p in $attached) {
            if ($p.PolicyName -match "AdministratorAccess|PowerUserAccess|FullAdmin") {
                $adminPolicies += [PSCustomObject]@{
                    RoleName = $r.RoleName
                    PolicyName = $p.PolicyName
                    PolicyArn = $p.PolicyArn
                }
            }
        }

        # Check for AssumeRole trusts
        if ($r.AssumeRolePolicyDocument) {
            $trustDoc = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($r.AssumeRolePolicyDocument))
            if ($trustDoc -match '"AWS":' -or $trustDoc -match '"Service":') {
                # Check for external principals
                if ($trustDoc -notmatch $accountId) {
                    $ctx.Data.externalTrusts += [PSCustomObject]@{
                        RoleName = $r.RoleName
                        TrustDocument = "Contains external principal"
                    }
                }
            }
        }
    }

    $ctx.Data.userCount = ($users | Measure-Object).Count
    $ctx.Data.roleCount = ($roles | Measure-Object).Count
    $ctx.Data.accessKeyCount = ($accessKeys | Measure-Object).Count

    $evidenceLimit = Get-EvidenceLimit -DetailLevel $DetailLevel

    # Finding: Access keys older than 180 days
    $cutoff = (Get-Date).AddDays(-180)
    $oldKeys = $accessKeys | Where-Object {
        $_.CreateDate -and [DateTime]$_.CreateDate -lt $cutoff -and $_.Status -eq "Active"
    }

    Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
        -Id "AWS-ACCESSKEYS-OLD" `
        -Title "IAM access keys older than 180 days" `
        -Severity "High" `
        -Description "Long-lived access keys increase compromise risk. Regular rotation is an AWS Well-Architected Security Pillar recommendation." `
        -Count ($oldKeys.Count) `
        -Evidence ($oldKeys | Select-Object -First $evidenceLimit) `
        -Recommendation "Rotate access keys regularly. Prefer IAM roles for services and use AWS Secrets Manager for credential management."
    )

    # Finding: Admin-level roles
    Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
        -Id "AWS-ADMIN-ROLES" `
        -Title "Roles with administrator-level policies" `
        -Severity "High" `
        -Description "Roles with AdministratorAccess or similar policies have complete account control. These require strict governance." `
        -Count ($adminPolicies.Count) `
        -Evidence ($adminPolicies | Select-Object -First $evidenceLimit) `
        -Recommendation "Apply least privilege. Use permission boundaries and SCPs. Prefer short-lived credentials via AssumeRole with external ID."
    )

    # Finding: Users without MFA (need to check each user)
    $usersWithoutMfa = @()
    foreach ($u in $users) {
        if ($useCli) {
            $mfaJson = aws iam list-mfa-devices --user-name $u.UserName --output json 2>$null
            if (-not $mfaJson -or $mfaJson.Contains("[]")) {
                $usersWithoutMfa += $u
            }
        } else {
            $mfa = Get-IAMMFADevice -UserName $u.UserName -ErrorAction SilentlyContinue
            if (-not $mfa) {
                $usersWithoutMfa += $u
            }
        }
    }

    Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
        -Id "AWS-USERS-NO-MFA" `
        -Title "IAM users without MFA device" `
        -Severity "High" `
        -Description "Users without MFA are vulnerable to credential compromise. MFA should be required for all human users." `
        -Count ($usersWithoutMfa.Count) `
        -Evidence ($usersWithoutMfa | Select-Object -First $evidenceLimit) `
        -Recommendation "Enable MFA for all IAM users. Enforce via IAM policy conditions (aws:MultiFactorAuthPresent)."
    )
}

$output = Save-IFQCReport -Context $ctx

Write-IFQCLog -Context $ctx -Level INFO -Message "AwsIdentityInventory check complete."
Write-IFQCLog -Context $ctx -Level INFO -Message "Report files: JSON: $($output.Json); HTML: $($output.Html)"
Write-Output $output

# SIG # Begin signature block
# MIIJyAYJKoZIhvcNAQcCoIIJuTCCCbUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBv0HNHJwnoxV7H
# MhLOCTpEpBgoINGAMwKwvmNq600yFqCCBdYwggXSMIIDuqADAgECAhAxVnqog0nQ
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
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIO6aQaMMXNVaMkxFGhivmzxET+qJhr6+
# gxX9WjG3QlzoMA0GCSqGSIb3DQEBAQUABIICABcuYr8mSajJDxGSR/GDz8hPhmQd
# 48/VCJTuZJcv/EMpczjcCaFlQnDhQkTJ79gJq/kINzrzdsFDpGOdCWqUn+DZkGa9
# bTuGWTzxLbqj1G927mb9jsWixsDAFtEalPEp0uYuv23sQ4zVaI5tsvLLWyCcjRL1
# ATFuGrL/2o3ezb82agwuGdAEAp0CvdefaIHKAMB1i054pmu3oejg8Qt22hi8XNpJ
# 5a5WwmCf6BmkQrmDp1xos6/Ecasdxz8XpeV6CWBO1MY8Y4ZUj2Q/CdmFAF6EDS7Y
# T/UQSedZn/QXJqLaQthFEJSiA3WVOq0FQ/05lxL6k2rlvAw5FACl5VdAwpm5QVVG
# KHkfQHhNOT1Ei2ahcd0ILNpuluaNRipUNbAOpHPaPOPOI7Tkmf6oOtxF/05E6tjK
# igJWFwdDGhdSV6pHSb4oXEZdGih3bGmSlh8WhHnZwircWhdaZ2oZqB422KANYXVG
# 8tocCUBKEtXQohSQvTj+f6Cx0QguCWricUeqlSqpT+QR6XuOy+YKExQocbym3Kdp
# QGv/G82SxtkLRyXLJOQcCPvMAAKO+j5+/ItXTLJEiVnRszH/4t8EuEpur+Gay4WY
# kpFAP5Rbn1fz8gkHPHmIDOMMiQCVW0xKwnnwYNFK/1Zis1x6N2Ot0lMdvGJNpQi3
# yGz8vRtqteZssIIG
# SIG # End signature block

