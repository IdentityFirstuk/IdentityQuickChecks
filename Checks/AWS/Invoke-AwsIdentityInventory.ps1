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

Write-Host ""
Write-Host "AwsIdentityInventory check complete." -ForegroundColor Green
Write-Host "  JSON: $($output.Json)" -ForegroundColor Cyan
Write-Host "  HTML: $($output.Html)" -ForegroundColor Cyan
