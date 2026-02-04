<#
.SYNOPSIS
    IdentityFirst QuickChecks - Additional Security Checks
    
.DESCRIPTION
    Extended security checks for AWS, GCP, and Active Directory.
    - AWS: S3 public buckets, VPC flow logs, IAM password policy
    - GCP: VPC service controls, organization policies, service account keys
    - AD: SID history, constrained delegation, LAPS status
    
.NOTES
    Requires: PowerShell 5.1+
    Requires: AWS CLI, gcloud CLI, or Az module as appropriate
#>

# =============================================================================
# AWS Additional Security Checks
# =============================================================================

function Invoke-AwsS3PublicBucketCheck {
    <#
    .SYNOPSIS
        Check for S3 buckets with public access or public ACLs.
    #>
    param($Context)
    $findings = @()
    try {
        $buckets = aws s3api list-buckets --output json 2>$null | ConvertFrom-Json
        if ($buckets -and $buckets.Buckets) {
            foreach ($bucket in $buckets.Buckets) {
                # Check public access block configuration
                $publicBlock = aws s3api get-public-access-block --bucket $bucket.Name 2>$null | ConvertFrom-Json
                $isPublic = $false
                
                if ($publicBlock) {
                    $isPublic = -not ($publicBlock.PublicAccessBlockConfiguration.BlockPublicAcls -eq $true -and 
                                       $publicBlock.PublicAccessBlockConfiguration.IgnorePublicAcls -eq $true -and
                                       $publicBlock.PublicAccessBlockConfiguration.BlockPublicPolicy -eq $true -and
                                       $publicBlock.PublicAccessBlockConfiguration.RestrictPublicBuckets -eq $true)
                }
                else {
                    $isPublic = $true
                }
                
                if ($isPublic) {
                    $f = @{ Id = "AWS-S3-001"; Title = "S3 bucket potentially public: $($bucket.Name)"; 
                            Description = "Bucket $($bucket.Name) may have public access enabled";
                            Severity = $script:FindingSeverity.High; Category = "AWS_PublicS3Bucket";
                            Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @();
                            RemediationSteps = @(); IsResolved = $false; Confidence = "Medium";
                            RuleId = "AWS-S3-001"; RuleDescription = "Checks for S3 buckets with public access";
                            Source = "AWS"; CheckName = "S3PublicBucketCheck"; AffectedCount = 0; Remediation = "" }
                    $f.Remediation = "Enable S3 Block Public Access and review bucket ACLs."
                    $f.RemediationSteps = @("Enable Block Public Access at account level", "Review bucket policy", 
                                           "Remove public ACLs", "Enable server-side encryption")
                    Add-FindingObject $f $bucket.Name
                    $findings += $f
                }
            }
        }
    }
    catch { $Context.Log("S3 check failed: $($_.Exception.Message)", "Error") }
    return $findings
}

function Invoke-AwsVpcFlowLogsCheck {
    <#
    .SYNOPSIS
        Check if VPC flow logs are enabled.
    #>
    param($Context)
    $findings = @()
    try {
        $vpcs = aws ec2 describe-vpcs --output json 2>$null | ConvertFrom-Json
        if ($vpcs -and $vpcs.Vpcs) {
            foreach ($vpc in $vpcs.Vpcs) {
                $flowLogs = aws ec2 describe-flow-logs --filter "Name=resource-id,Values=$($vpc.VpcId)" --output json 2>$null | ConvertFrom-Json
                if (-not $flowLogs.FlowLogs) {
                    $f = @{ Id = "AWS-VPC-001"; Title = "VPC $($vpc.VpcId) has no flow logs enabled";
                            Description = "Flow logs are not enabled for this VPC";
                            Severity = $script:FindingSeverity.Low; Category = "AWS_VpcFlowLogs";
                            Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @();
                            RemediationSteps = @(); IsResolved = $false; Confidence = "Medium";
                            RuleId = "AWS-VPC-001"; RuleDescription = "Checks for VPC flow log configuration";
                            Source = "AWS"; CheckName = "VpcFlowLogsCheck"; AffectedCount = 0; Remediation = "" }
                    $f.Remediation = "Enable VPC flow logs for network monitoring."
                    $f.RemediationSteps = @("Create flow log for VPC", "Send to CloudWatch Logs", "Define log format")
                    Add-FindingObject $f $vpc.VpcId
                    $findings += $f
                }
            }
        }
    }
    catch { $Context.Log("VPC flow logs check failed", "Error") }
    return $findings
}

function Invoke-AwsIamPasswordPolicyCheck {
    <#
    .SYNOPSIS
        Check IAM password policy compliance.
    #>
    param($Context)
    $findings = @()
    try {
        $policy = aws iam get-account-password-policy --output json 2>$null | ConvertFrom-Json
        if ($policy) {
            $p = $policy.PasswordPolicy
            $issues = @()
            if ($p.MaxPasswordAge -gt 90) { $issues += "Password max age $($p.MaxPasswordAge) days (recommend 90)" }
            if ($p.MinimumPasswordLength -lt 14) { $issues += "Min password length $($p.MinimumPasswordLength) (recommend 14)" }
            if ($p.RequireUppercaseCharacters -eq $false) { $issues += "Uppercase not required" }
            if ($p.RequireLowercaseCharacters -eq $false) { $issues += "Lowercase not required" }
            if ($p.RequireNumbers -eq $false) { $issues += "Numbers not required" }
            if ($p.RequireSymbols -eq $false) { $issues += "Symbols not required" }
            if ($p.PasswordLastUsed -and -not $p.AllowUsersToChangePassword) { $issues += "Users cannot change password" }
            
            if ($issues.Count -gt 0) {
                $f = @{ Id = "AWS-IAM-001"; Title = "IAM password policy has security gaps";
                        Description = "Password policy issues: $($issues -join ', ')";
                        Severity = $script:FindingSeverity.Medium; Category = "AWS_PasswordPolicy";
                        Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @();
                        RemediationSteps = @(); IsResolved = $false; Confidence = "High";
                        RuleId = "AWS-IAM-001"; RuleDescription = "Checks IAM password policy configuration";
                        Source = "AWS"; CheckName = "IamPasswordPolicyCheck"; AffectedCount = 0; Remediation = "" }
                $f.Remediation = "Update IAM password policy to meet security requirements."
                $f.RemediationSteps = @("Set max age to 90 days", "Require 14+ characters", 
                                       "Require upper, lower, numbers, symbols", "Allow users to change password")
                Add-FindingObject $f "Account Password Policy"
                $findings += $f
            }
        }
        else {
            $f = @{ Id = "AWS-IAM-002"; Title = "No IAM password policy configured";
                    Description = "Account does not have a password policy set";
                    Severity = $script:FindingSeverity.High; Category = "AWS_PasswordPolicy";
                    Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @();
                    RemediationSteps = @(); IsResolved = $false; Confidence = "High";
                    RuleId = "AWS-IAM-002"; RuleDescription = "Checks for IAM password policy existence";
                    Source = "AWS"; CheckName = "IamPasswordPolicyCheck"; AffectedCount = 0; Remediation = "" }
            $f.Remediation = "Create and configure IAM password policy."
            $f.RemediationSteps = @("Create password policy via IAM console", "Set requirements per CIS benchmark")
            Add-FindingObject $f "Account Password Policy"
            $findings += $f
        }
    }
    catch { $Context.Log("IAM password policy check failed", "Error") }
    return $findings
}

function Invoke-AwsRootAccountCheck {
    <#
    .SYNOPSIS
        Check root account security settings.
    #>
    param($Context)
    $findings = @()
    try {
        # Check if root has MFA
        $mfaDevices = aws iam list-virtual-mfa-devices --output json 2>$null | ConvertFrom-Json
        if (-not $mfaDevices) {
            $f = @{ Id = "AWS-ROOT-001"; Title = "Root account has no MFA enabled";
                    Description = "AWS root account does not have a virtual MFA device";
                    Severity = $script:FindingSeverity.Critical; Category = "AWS_RootSecurity";
                    Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @();
                    RemediationSteps = @(); IsResolved = $false; Confidence = "High";
                    RuleId = "AWS-ROOT-001"; RuleDescription = "Checks root account MFA configuration";
                    Source = "AWS"; CheckName = "RootAccountCheck"; AffectedCount = 0; Remediation = "" }
            $f.Remediation = "Enable MFA on root account immediately."
            $f.RemediationSteps = @("Go to IAM > Dashboard", "Activate MFA on root account", 
                                   "Use hardware MFA for production", "Store MFA backup securely")
            Add-FindingObject $f "Root Account"
            $findings += $f
        }
        
        # Check recent root usage
        $recentActivity = aws cloudtrail lookup-events --lookup-attributes "AttributeKey=EventName,AttributeValue=ConsoleLogin" --output json 2>$null | ConvertFrom-Json
        if ($recentActivity -and $recentActivity.Events) {
            $rootLogins = $recentActivity.Events | Where-Object { $_.Username -eq 'root' -or $_.CloudTrailEvent | Select-String '"userIdentity":\{"type":"Root"' }
            if ($rootLogins) {
                $lastLogin = $rootLogins[0].EventTime
                $f = @{ Id = "AWS-ROOT-002"; Title = "Root account was used recently";
                        Description = "Root account used at $lastRootLogin. Consider using IAM users instead.";
                        Severity = $script:FindingSeverity.Low; Category = "AWS_RootSecurity";
                        Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @();
                        RemediationSteps = @(); IsResolved = $false; Confidence = "Medium";
                        RuleId = "AWS-ROOT-002"; RuleDescription = "Checks root account usage";
                        Source = "AWS"; CheckName = "RootAccountCheck"; AffectedCount = 0; Remediation = "" }
                $f.Remediation = "Use IAM users for daily tasks. Root only for account-closing."
                $f.RemediationSteps = @("Create IAM users with least privilege", "Enable CloudTrail on root actions",
                                       "Set up alerts for root usage", "Document root access justification")
                Add-FindingObject $f "Root Account - Last used: $lastLogin"
                $findings += $f
            }
        }
    }
    catch { $Context.Log("Root account check failed", "Error") }
    return $findings
}

# =============================================================================
# GCP Additional Security Checks
# =============================================================================

function Invoke-GcpVpcServiceControlsCheck {
    <#
    .SYNOPSIS
        Check if VPC Service Controls are enabled for sensitive projects.
    #>
    param($Context)
    $findings = @()
    try {
        $projects = gcloud projects list --format=json 2>$null | ConvertFrom-Json
        $sensitiveProjects = @("production", "prod", "pci", "soc2", "customer-data", "pii")
        
        foreach ($project in $projects) {
            $name = $project.name.ToLower()
            $isSensitive = $sensitiveProjects | Where-Object { $name -match $_ }
            
            if ($isSensitive) {
                $perimeter = gcloud access-context-manager perimeters list --organization=$(gcloud organizations list --format=json 2>$null | ConvertFrom-Json | Select-Object -First 1).name 2>$null | Select-String $project.projectId
                
                if (-not $perimeter) {
                    $f = @{ Id = "GCP-VPC-001"; Title = "Sensitive project $($project.projectId) has no VPC Service Controls";
                            Description = "Project contains sensitive data but VPC Service Controls perimeter not found";
                            Severity = $script:FindingSeverity.High; Category = "GCP_VpcServiceControls";
                            Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @();
                            RemediationSteps = @(); IsResolved = $false; Confidence = "Medium";
                            RuleId = "GCP-VPC-001"; RuleDescription = "Checks VPC Service Controls on sensitive projects";
                            Source = "GCP"; CheckName = "VpcServiceControlsCheck"; AffectedCount = 0; Remediation = "" }
                    $f.Remediation = "Create VPC Service Controls perimeter for this project."
                    $f.RemediationSteps = @("Create access context manager perimeter", "Add project to perimeter",
                                           "Define access levels", "Configure service boundary")
                    Add-FindingObject $f $project.projectId
                    $findings += $f
                }
            }
        }
    }
    catch { $Context.Log("VPC Service Controls check failed", "Error") }
    return $findings
}

function Invoke-GcpOrgPolicyCheck {
    <#
    .SYNOPSIS
        Check organization policy constraints.
    #>
    param($Context)
    $findings = @()
    try {
        $orgId = (gcloud organizations list --format=json 2>$null | ConvertFrom-Json | Select-Object -First 1).name
        
        # Check if constraints exist
        $constraints = gcloud org-policies list --organization=$orgId --format=json 2>$null | ConvertFrom-Json
        $importantConstraints = @(
            "constraints/iam.allowedPolicyMemberDomains",
            "constraints/compute.disableSerialPortAccess",
            "constraints/iam.disableServiceAccountKeyCreation",
            "constraints/sql.restrictPublicIp"
        )
        
        foreach ($constraint in $importantConstraints) {
            $exists = $constraints | Where-Object { $_.spec.rules } | Select-Object -ExpandProperty name | Select-String $constraint
            if (-not $exists) {
                $f = @{ Id = "GCP-ORG-001"; Title = "Organization policy $constraint not configured";
                        Description = "Important organization policy constraint is not enforced";
                        Severity = $script:FindingSeverity.Medium; Category = "GCP_OrgPolicy";
                        Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @();
                        RemediationSteps = @(); IsResolved = $false; Confidence = "Medium";
                        RuleId = "GCP-ORG-001"; RuleDescription = "Checks organization policy configuration";
                        Source = "GCP"; CheckName = "OrgPolicyCheck"; AffectedCount = 0; Remediation = "" }
                $f.Remediation = "Set organization policy constraint."
                $f.RemediationSteps = @("Go to Organization Policies", "Create policy for constraint", "Define allowed/denied values")
                Add-FindingObject $f $constraint
                $findings += $f
            }
        }
    }
    catch { $Context.Log("Organization policy check failed", "Error") }
    return $findings
}

function Invoke-GcpServiceAccountKeyAgeCheck {
    <#
    .SYNOPSIS
        Check for old service account keys.
    #>
    param($Context)
    $findings = @()
    try {
        $projects = gcloud projects list --format=json 2>$null | ConvertFrom-Json
        
        foreach ($project in $projects) {
            $keys = gcloud iam service-accounts keys list --iam-account=($project.projectId -replace '-','@') + ".iam.gserviceaccount.com" --format=json 2>$null | ConvertFrom-Json
            
            if ($keys) {
                $oldKeys = $keys | Where-Object { 
                    $key = $_; 
                    $key.validAfterTime -and ([datetime]$key.validAfterTime -lt (Get-Date).AddDays(-90))
                }
                
                if ($oldKeys.Count -gt 0) {
                    $f = @{ Id = "GCP-SA-001"; Title = "Service account keys older than 90 days in $($project.projectId)";
                            Description = "$($oldKeys.Count) service account keys are older than 90 days";
                            Severity = $script:FindingSeverity.Medium; Category = "GCP_ServiceAccountKey";
                            Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @();
                            RemediationSteps = @(); IsResolved = $false; Confidence = "Medium";
                            RuleId = "GCP-SA-001"; RuleDescription = "Checks service account key age";
                            Source = "GCP"; CheckName = "ServiceAccountKeyAgeCheck"; AffectedCount = 0; Remediation = "" }
                    $f.Remediation = "Rotate old service account keys."
                    $f.RemediationSteps = @("Create new key for service account", "Update applications to use new key",
                                           "Delete old keys", "Implement key rotation automation")
                    foreach ($k in $oldKeys) { Add-FindingObject $f "$($project.projectId): $($k.name)" }
                    $findings += $f
                }
            }
        }
    }
    catch { $Context.Log("Service account key check failed", "Error") }
    return $findings
}

function Invoke-GcpPublicAccessCheck {
    <#
    .SYNOPSIS
        Check for GCP resources with public access.
    #>
    param($Context)
    $findings = @()
    try {
        $projects = gcloud projects list --format=json 2>$null | ConvertFrom-Json
        
        foreach ($project in $projects) {
            # Check Cloud Storage buckets for public access
            $buckets = gcloud storage buckets list --project=$($project.projectId) --format=json 2>$null | ConvertFrom-Json
            
            if ($buckets) {
                foreach ($bucket in $buckets) {
                    $iam = gcloud storage buckets get-iam-policy $bucket.name --format=json 2>$null | ConvertFrom-Json
                    
                    if ($iam) {
                        $publicBindings = $iam.bindings | Where-Object { 
                            $role = $_.role; 
                            $members = $_.members | Where-Object { $_ -match 'allUsers|allAuthenticatedUsers' }
                            $members.Count -gt 0
                        }
                        
                        if ($publicBindings) {
                            $f = @{ Id = "GCP-GCS-001"; Title = "GCS bucket $($bucket.name) has public access";
                                    Description = "Bucket has IAM bindings allowing public access";
                                    Severity = $script:FindingSeverity.Critical; Category = "GCP_PublicAccess";
                                    Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @();
                                    RemediationSteps = @(); IsResolved = $false; Confidence = "High";
                                    RuleId = "GCP-GCS-001"; RuleDescription = "Checks GCS bucket public access";
                                    Source = "GCP"; CheckName = "PublicAccessCheck"; AffectedCount = 0; Remediation = "" }
                            $f.Remediation = "Remove public access from bucket immediately."
                            $f.RemediationSteps = @("Remove allUsers and allAuthenticatedUsers from bindings",
                                                   "Use uniform bucket-level access", "Review data classification")
                            Add-FindingObject $f $bucket.name
                            $findings += $f
                        }
                    }
                }
            }
        }
    }
    catch { $Context.Log("Public access check failed", "Error") }
    return $findings
}

# =============================================================================
# AD Additional Security Checks
# =============================================================================

function Invoke-AdSidHistoryCheck {
    <#
    .SYNOPSIS
        Check for accounts with SID History (potential privilege escalation).
    #>
    param($Context)
    $findings = @()
    try {
        $users = Get-ADUser -Filter { SIDHistory -like "*" } -Properties SIDHistory, Name -ErrorAction SilentlyContinue
        
        if ($users.Count -gt 0) {
            $f = @{ Id = "AD-SID-001"; Title = "Accounts with SID History detected";
                    Description = "$($users.Count) accounts have SID History, which can indicate privilege escalation";
                    Severity = $script:FindingSeverity.High; Category = "AD_SidHistory";
                    Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @();
                    RemediationSteps = @(); IsResolved = $false; Confidence = "High";
                    RuleId = "AD-SID-001"; RuleDescription = "Checks for SID History on accounts";
                    Source = "ActiveDirectory"; CheckName = "SidHistoryCheck"; AffectedCount = 0; Remediation = "" }
            $f.Remediation = "Investigate accounts with SID History. Clear SID History unless migration is active."
            $f.RemediationSteps = @("Identify all users with SID History", "Determine if from legitimate migration",
                                   "Clear SID History if not needed", "Monitor for SID History additions")
            foreach ($u in $users) { Add-FindingObject $f $u.Name }
            $findings += $f
        }
    }
    catch { $Context.Log("SID History check failed", "Error") }
    return $findings
}

function Invoke-AdConstrainedDelegationCheck {
    <#
    .SYNOPSIS
        Check for accounts with unconstrained delegation.
    #>
    param($Context)
    $findings = @()
    try {
        # Find accounts with unconstrained delegation
        $unconstrained = Get-ADObject -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)" `
                                       -Properties Name, DistinguishedName -ErrorAction SilentlyContinue
        
        if ($unconstrained.Count -gt 0) {
            $f = @{ Id = "AD-DEL-001"; Title = "Accounts with unconstrained delegation detected";
                    Description = "$($unconstrained.Count) accounts have 'Trust this computer for delegation to any service' enabled";
                    Severity = $script:FindingSeverity.High; Category = "AD_Delegation";
                    Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @();
                    RemediationSteps = @(); IsResolved = $false; Confidence = "High";
                    RuleId = "AD-DEL-001"; RuleDescription = "Checks for unconstrained delegation";
                    Source = "ActiveDirectory"; CheckName = "ConstrainedDelegationCheck"; AffectedCount = 0; Remediation = "" }
            $f.Remediation = "Convert to constrained delegation or remove delegation if not needed."
            $f.RemediationSteps = @("Identify services using these accounts", "Configure constrained delegation to specific SPNs",
                                   "Consider Kerberos Armoring", "Regular review of delegation settings")
            foreach ($u in $unconstrained) { Add-FindingObject $f $u.Name }
            $findings += $f
        }
    }
    catch { $Context.Log("Constrained delegation check failed", "Error") }
    return $findings
}

function Invoke-AdLapsCheck {
    <#
    .SYNOPSIS
        Check if LAPS is configured for workstations.
    #>
    param($Context)
    $findings = @()
    try {
        # Check for LAPS schema extension
        $schema = Get-ADObject -SearchBase "CN=Schema,CN=Configuration,$((Get-ADDomain).DistinguishedName)" `
                               -Filter { Name -eq "ms-MCS-AdmPwd" } -ErrorAction SilentlyContinue
        
        if (-not $schema) {
            $f = @{ Id = "AD-LAPS-001"; Title = "LAPS not deployed in environment";
                    Description = "LAPS (Local Administrator Password Solution) schema extension not found";
                    Severity = $script:FindingSeverity.Medium; Category = "AD_Laps";
                    Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @();
                    RemediationSteps = @(); IsResolved = $false; Confidence = "High";
                    RuleId = "AD-LAPS-001"; RuleDescription = "Checks LAPS deployment status";
                    Source = "ActiveDirectory"; CheckName = "LapsCheck"; AffectedCount = 0; Remediation = "" }
            $f.Remediation = "Deploy LAPS to manage local administrator passwords."
            $f.RemediationSteps = @("Extend AD schema for LAPS", "Deploy LAPS client to workstations",
                                   "Configure GPO settings", "Assign LAPS password readers")
            Add-FindingObject $f "AD Schema"
            $findings += $f
        }
        else {
            # Check if any workstations have LAPS enabled
            $workstationsWithLaps = Get-ADComputer -Filter { OperatingSystem -like "*Windows*" } `
                                                    -Properties Name, ms-MCS-AdmPwd, ms-MCS-AdmPwdExpirationTime `
                                                    -ErrorAction SilentlyContinue | Where-Object { $_.ms-MCS-AdmPwd }
            
            if ($workstationsWithLaps.Count -eq 0) {
                $f = @{ Id = "AD-LAPS-002"; Title = "LAPS not being used despite schema extension";
                        Description = "No computer accounts have LAPS password attributes set";
                        Severity = $script:FindingSeverity.Low; Category = "AD_Laps";
                        Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @();
                        RemediationSteps = @(); IsResolved = $false; Confidence = "Medium";
                        RuleId = "AD-LAPS-002"; RuleDescription = "Checks LAPS usage status";
                        Source = "ActiveDirectory"; CheckName = "LapsCheck"; AffectedCount = 0; Remediation = "" }
                $f.Remediation = "Configure GPO to enable LAPS on workstations."
                $f.RemediationSteps = @("Create LAPS GPO", "Configure password settings", "Link to workstations OU",
                                       "Verify computers have password generated")
                Add-FindingObject $f "Workstations"
                $findings += $f
            }
        }
    }
    catch { $Context.Log("LAPS check failed", "Error") }
    return $findings
}

function Invoke-AdAdminCountCheck {
    <#
    .SYNOPSIS
        Check for accounts with AdminCount > 0 (protected by AdminSDHolder).
    #>
    param($Context)
    $findings = @()
    try {
        $protectedUsers = Get-ADUser -Filter { AdminCount -eq $true } -Properties Name, AdminCount, LastLogonTimestamp `
                                     -ErrorAction SilentlyContinue
        
        if ($protectedUsers.Count -gt 0) {
            $inactive = $protectedUsers | Where-Object { $_.LastLogonTimestamp -and 
                                                        $_.LastLogonTimestamp -lt (Get-Date).AddDays(-90) }
            
            if ($inactive.Count -gt 0) {
                $f = @{ Id = "AD-ADMIN-001"; Title = "Protected accounts inactive for 90+ days";
                        Description = "$($inactive.Count) accounts with AdminCount=1 have not logged in for 90+ days";
                        Severity = $script:FindingSeverity.Medium; Category = "AD_ProtectedAccounts";
                        Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @();
                        RemediationSteps = @(); IsResolved = $false; Confidence = "High";
                        RuleId = "AD-ADMIN-001"; RuleDescription = "Checks for inactive protected accounts";
                        Source = "ActiveDirectory"; CheckName = "AdminCountCheck"; AffectedCount = 0; Remediation = "" }
                $f.Remediation = "Review and disable inactive privileged accounts."
                $f.RemediationSteps = @("Review each inactive account", "Contact manager for status",
                                       "Disable or remove if no longer needed", "Document decisions")
                foreach ($u in $inactive) { Add-FindingObject $f $u.Name }
                $findings += $f
            }
        }
    }
    catch { $Context.Log("AdminCount check failed", "Error") }
    return $findings
}

function Invoke-AdDuplicateSpnCheck {
    <#
    .SYNOPSIS
        Check for duplicate SPNs (can cause authentication issues).
    #>
    param($Context)
    $findings = @()
    try {
        # Get all users/computers with SPN
        $objectsWithSpn = Get-ADObject -Filter { ServicePrincipalName -like "*" } `
                                       -Properties Name, ServicePrincipalName, DistinguishedName `
                                       -ErrorAction SilentlyContinue
        
        $spnCounts = @{}
        foreach ($obj in $objectsWithSpn) {
            foreach ($spn in $obj.ServicePrincipalName) {
                $spnCounts[$spn] = @($spnCounts[$spn] + 1)
            }
        }
        
        $duplicateSpns = $spnCounts.GetEnumerator() | Where-Object { $_.Value -gt 1 }
        
        if ($duplicateSpns.Count -gt 0) {
            $f = @{ Id = "AD-SPN-001"; Title = "Duplicate SPNs detected";
                    Description = "$($duplicateSpns.Count) SPNs are registered on multiple accounts";
                    Severity = $script:FindingSeverity.Medium; Category = "AD_SpnConfig";
                    Timestamp = [datetime]::UtcNow; AffectedObjects = @(); Evidence = @();
                    RemediationSteps = @(); IsResolved = $false; Confidence = "High";
                    RuleId = "AD-SPN-001"; RuleDescription = "Checks for duplicate SPN registrations";
                    Source = "ActiveDirectory"; CheckName = "DuplicateSpnCheck"; AffectedCount = 0; Remediation = "" }
            $f.Remediation = "Remove duplicate SPNs to prevent authentication failures."
            $f.RemediationSteps = @("Identify all accounts with duplicate SPN", "Determine correct owner",
                                   "Remove SPN from incorrect accounts", "Verify Kerberos authentication")
            foreach ($spn in $duplicateSpns) { Add-FindingObject $f "$($spn.Key): $($spn.Value) accounts" }
            $findings += $f
        }
    }
    catch { $Context.Log("Duplicate SPN check failed", "Error") }
    return $findings
}

# =============================================================================
# Main Entry Point
# =============================================================================

function Invoke-ExtendedQuickChecks {
    <#
    .SYNOPSIS
        Runs all extended security checks.
    #>
    [CmdletBinding()] param(
        [string]$OutputDir = ".\QuickChecks-Extended-Output",
        [ValidateSet('Console', 'Json')][string]$Format = 'Console',
        [int]$CriticalThreshold = 1, [int]$HighThreshold = 5,
        [switch]$IncludeAWS, [switch]$IncludeGCP, [switch]$IncludeAD,
        [switch]$Help
    )
    
    if ($Help) {
        Write-Host @"
IdentityFirst QuickChecks - Extended Security Checks
====================================================
AWS Checks: S3 Public Buckets, VPC Flow Logs, IAM Password Policy, Root Account
GCP Checks: VPC Service Controls, Org Policies, SA Key Age, Public Access
AD Checks: SID History, Constrained Delegation, LAPS, AdminCount, Duplicate SPN

USAGE:
    Invoke-ExtendedQuickChecks [-IncludeAWS] [-IncludeGCP] [-IncludeAD]

FLAGS:
    -IncludeAWS    Run AWS security checks (requires AWS CLI)
    -IncludeGCP    Run GCP security checks (requires gcloud CLI)
    -IncludeAD    Run AD security checks (requires ActiveDirectory module)
    -OutputDir    Output directory for reports
    -Format       Console or JSON output
"@
        return
    }
    
    Write-Host "`n╔═══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  IdentityFirst QuickChecks - Extended Security Assessment           ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    $context = New-AssessmentContext
    $config = @{ CriticalThreshold = $CriticalThreshold; HighThreshold = $HighThreshold; 
                 HealthyScoreThreshold = 80; OutputDirectory = $OutputDir }
    
    $allFindings = @()
    
    if ($IncludeAWS -or (-not $IncludeAD -and -not $IncludeGCP)) {
        Write-Host "`n[AWS] Running AWS security checks..." -ForegroundColor Yellow
        $allFindings += Invoke-AwsS3PublicBucketCheck -Context $context
        $allFindings += Invoke-AwsVpcFlowLogsCheck -Context $context
        $allFindings += Invoke-AwsIamPasswordPolicyCheck -Context $context
        $allFindings += Invoke-AwsRootAccountCheck -Context $context
    }
    
    if ($IncludeGCP) {
        Write-Host "`n[GCP] Running GCP security checks..." -ForegroundColor Yellow
        $allFindings += Invoke-GcpVpcServiceControlsCheck -Context $context
        $allFindings += Invoke-GcpOrgPolicyCheck -Context $context
        $allFindings += Invoke-GcpServiceAccountKeyAgeCheck -Context $context
        $allFindings += Invoke-GcpPublicAccessCheck -Context $context
    }
    
    if ($IncludeAD -or (-not $IncludeAWS -and -not $IncludeGCP)) {
        Write-Host "`n[AD] Running Active Directory security checks..." -ForegroundColor Yellow
        $allFindings += Invoke-AdSidHistoryCheck -Context $context
        $allFindings += Invoke-AdConstrainedDelegationCheck -Context $context
        $allFindings += Invoke-AdLapsCheck -Context $context
        $allFindings += Invoke-AdAdminCountCheck -Context $context
        $allFindings += Invoke-AdDuplicateSpnCheck -Context $context
    }
    
    # Generate report
    $report = New-AssessmentReport -Findings $allFindings -Config $config
    
    # Display results
    $scoreColor = if ($report.HealthStatus -eq 'Healthy') { 'Green' } 
                   elseif ($report.HealthStatus -eq 'Warning') { 'Yellow' } else { 'Red' }
    
    Write-Host "`n═══════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host " RESULTS " -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "`n  Score:  $($report.OverallScore)/100 - " -NoNewline; Write-Host $report.HealthStatus -ForegroundColor $scoreColor
    Write-Host "`n  Findings:"
    Write-Host "    Critical: $($report.CriticalCount)" -ForegroundColor Red
    Write-Host "    High:     $($report.HighCount)" -ForegroundColor DarkRed
    Write-Host "    Medium:   $($report.MediumCount)" -ForegroundColor Yellow
    Write-Host "    Low:      $($report.LowCount)" -ForegroundColor Cyan
    
    if ($report.CriticalCount -gt 0) {
        Write-Host "`n CRITICAL FINDINGS" -ForegroundColor Red
        foreach ($f in $allFindings | Where-Object { $_.Severity -eq 'Critical' }) {
            Write-Host "`n  [!] $($f.Title)" -ForegroundColor Red
            Write-Host "      $($f.Description)"
        }
    }
    
    Write-Host "`n═══════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    
    return $report
}

Export-ModuleMember -Function Invoke-ExtendedQuickChecks
