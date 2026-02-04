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
# DEFAULT THRESHOLDS - Configurable Security Thresholds
# =============================================================================

$script:DefaultThresholds = @{
    # AWS Thresholds
    AwsS3PublicBucketThreshold = 0
    AwsIamPasswordMaxAge = 90
    AwsIamPasswordMinLength = 14
    AwsRootMfaRequired = $true
    AwsRootActivityWarningDays = 30
    
    # GCP Thresholds
    GcpServiceAccountKeyAge = 90
    GcpSensitiveProjectPattern = @("production", "prod", "pci", "soc2", "customer-data", "pii")
    
    # AD Thresholds
    AdAdminCountInactivityDays = 90
    AdDuplicateSpnThreshold = 1
    
    # Scoring Thresholds
    HealthyScoreThreshold = 80
    CriticalThreshold = 1
    HighThreshold = 5
    
    # Finding Weights
    CriticalWeight = 25
    HighWeight = 10
    MediumWeight = 5
    LowWeight = 2
}

# =============================================================================
# FINDING HELPER FUNCTIONS
# =============================================================================

function New-Finding {
    <#
    .SYNOPSIS
        Creates a new security finding object.
    
    .DESCRIPTION
        Creates a standardized finding object for security assessment results.
    
    .PARAMETER Id
        Unique identifier for the finding.
    
    .PARAMETER Title
        Brief, descriptive title of the finding.
    
    .PARAMETER Description
        Detailed explanation of the security issue.
    
    .PARAMETER Severity
        Severity level: Critical, High, Medium, Low, or Info.
    
    .PARAMETER Category
        Category classification for the finding.
    
    .EXAMPLE
        New-Finding -Id "AWS-S3-001" -Title "Public S3 Bucket" `
            -Description "Bucket is publicly accessible" -Severity High -Category "AWS_PublicS3Bucket"
    
    .OUTPUTS
        Hashtable representing the finding object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, HelpMessage = "Unique finding identifier")]
        [ValidateNotNullOrEmpty()]
        [string]$Id,
        
        [Parameter(Mandatory = $true, HelpMessage = "Brief finding title")]
        [ValidateNotNullOrEmpty()]
        [string]$Title,
        
        [Parameter(Mandatory = $true, HelpMessage = "Detailed description")]
        [ValidateNotNullOrEmpty()]
        [string]$Description,
        
        [Parameter(Mandatory = $true, HelpMessage = "Severity level")]
        [ValidateSet("Critical", "High", "Medium", "Low", "Info")]
        [string]$Severity,
        
        [Parameter(Mandatory = $true, HelpMessage = "Category classification")]
        [ValidateNotNullOrEmpty()]
        [string]$Category
    )
    
    return @{
        Id = $Id
        Title = $Title
        Description = $Description
        Severity = $Severity
        Category = $Category
        Timestamp = [datetime]::UtcNow
        AffectedObjects = @()
        Evidence = @()
        RemediationSteps = @()
        IsResolved = $false
        Confidence = "Medium"
        RuleId = $Id
        RuleDescription = ""
        Source = ""
        CheckName = ""
        AffectedCount = 0
        Remediation = ""
    }
}

function Add-FindingObject {
    <#
    .SYNOPSIS
        Adds an affected object to a finding.
    
    .DESCRIPTION
        Appends an affected object to the finding's collection.
    
    .PARAMETER Finding
        The finding object to modify.
    
    .PARAMETER Object
        The object affected by this finding.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Finding,
        
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Object
    )
    
    $Finding.AffectedObjects += $Object
    $Finding.AffectedCount = $Finding.AffectedObjects.Count
}

function Add-FindingEvidence {
    <#
    .SYNOPSIS
        Adds evidence to a finding.
    
    .DESCRIPTION
        Appends evidence details to the finding's Evidence collection.
    
    .PARAMETER Finding
        The finding object to modify.
    
    .PARAMETER Source
        The data source that provided this evidence.
    
    .PARAMETER Detail
        Detailed description of the evidence.
    
    .PARAMETER Confidence
        Confidence level in the evidence.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Finding,
        
        [Parameter(Mandatory = $true)]
        [string]$Source,
        
        [Parameter(Mandatory = $true)]
        [string]$Detail,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Low", "Medium", "High")]
        [string]$Confidence = "Medium"
    )
    
    $Finding.Evidence += @{
        Source = $Source
        Detail = $Detail
        Confidence = $Confidence
        Timestamp = [datetime]::UtcNow
    }
}

# =============================================================================
# AWS ADDITIONAL SECURITY CHECKS
# =============================================================================

function Invoke-AwsS3PublicBucketCheck {
    <#
    .SYNOPSIS
        Check for S3 buckets with public access or public ACLs.
    
    .DESCRIPTION
        Scans all S3 buckets to identify those with public access enabled,
        which could expose data to unauthorized access.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = @{ Log = @{} }
        $findings = Invoke-AwsS3PublicBucketCheck -Context $context
    
    .OUTPUTS
        Array of finding objects for public S3 buckets.
    
    .NOTES
        Requires: AWS CLI with appropriate permissions.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    $threshold = $script:DefaultThresholds.AwsS3PublicBucketThreshold
    
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
                    $f = New-Finding -Id "AWS-S3-001" -Title "S3 bucket potentially public: $($bucket.Name)" `
                        -Description "Bucket $($bucket.Name) may have public access enabled" `
                        -Severity $script:FindingSeverity.High -Category "AWS_PublicS3Bucket"
                    $f.RuleId = "AWS-S3-001"
                    $f.RuleDescription = "Checks for S3 buckets with public access"
                    $f.Source = "AWS"
                    $f.CheckName = "S3PublicBucketCheck"
                    $f.Remediation = "Enable S3 Block Public Access and review bucket ACLs."
                    $f.RemediationSteps = @(
                        "Enable Block Public Access at account level",
                        "Review bucket policy",
                        "Remove public ACLs",
                        "Enable server-side encryption"
                    )
                    Add-FindingObject -Finding $f -Object $bucket.Name
                    Add-FindingEvidence -Finding $f -Source "aws s3api get-public-access-block" `
                        -Detail "Public access configuration" -Confidence "Medium"
                    $findings += $f
                }
            }
        }
    }
    catch {
        if ($Context) { $Context.Log("S3 check failed: $($_.Exception.Message)", "Error") }
    }
    return $findings
}

function Invoke-AwsVpcFlowLogsCheck {
    <#
    .SYNOPSIS
        Check if VPC flow logs are enabled.
    
    .DESCRIPTION
        Verifies that VPC flow logs are enabled for network monitoring
        and security analysis purposes.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = @{ Log = @{} }
        $findings = Invoke-AwsVpcFlowLogsCheck -Context $context
    
    .OUTPUTS
        Array of finding objects for VPCs without flow logs.
    
    .NOTES
        Requires: AWS CLI with EC2 permissions.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    try {
        $vpcs = aws ec2 describe-vpcs --output json 2>$null | ConvertFrom-Json
        if ($vpcs -and $vpcs.Vpcs) {
            foreach ($vpc in $vpcs.Vpcs) {
                $flowLogs = aws ec2 describe-flow-logs --filter "Name=resource-id,Values=$($vpc.VpcId)" --output json 2>$null | ConvertFrom-Json
                if (-not $flowLogs.FlowLogs) {
                    $f = New-Finding -Id "AWS-VPC-001" -Title "VPC $($vpc.VpcId) has no flow logs enabled" `
                        -Description "Flow logs are not enabled for this VPC" `
                        -Severity $script:FindingSeverity.Low -Category "AWS_VpcFlowLogs"
                    $f.RuleId = "AWS-VPC-001"
                    $f.RuleDescription = "Checks for VPC flow log configuration"
                    $f.Source = "AWS"
                    $f.CheckName = "VpcFlowLogsCheck"
                    $f.Remediation = "Enable VPC flow logs for network monitoring."
                    $f.RemediationSteps = @(
                        "Create flow log for VPC",
                        "Send to CloudWatch Logs",
                        "Define log format"
                    )
                    Add-FindingObject -Finding $f -Object $vpc.VpcId
                    Add-FindingEvidence -Finding $f -Source "aws ec2 describe-flow-logs" `
                        -Detail "No flow logs found" -Confidence "Medium"
                    $findings += $f
                }
            }
        }
    }
    catch {
        if ($Context) { $Context.Log("VPC flow logs check failed: $($_.Exception.Message)", "Error") }
    }
    return $findings
}

function Invoke-AwsIamPasswordPolicyCheck {
    <#
    .SYNOPSIS
        Check IAM password policy compliance.
    
    .DESCRIPTION
        Validates the AWS IAM password policy against security best practices
        including password length, complexity requirements, and max age.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = @{ Log = @{} }
        $findings = Invoke-AwsIamPasswordPolicyCheck -Context $context
    
    .OUTPUTS
        Array of finding objects for password policy issues.
    
    .NOTES
        Requires: AWS CLI with IAM read permissions.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    $maxAgeThreshold = $script:DefaultThresholds.AwsIamPasswordMaxAge
    $minLengthThreshold = $script:DefaultThresholds.AwsIamPasswordMinLength
    
    try {
        $policy = aws iam get-account-password-policy --output json 2>$null | ConvertFrom-Json
        if ($policy) {
            $p = $policy.PasswordPolicy
            $issues = @()
            
            if ($p.MaxPasswordAge -gt $maxAgeThreshold) {
                $issues += "Password max age $($p.MaxPasswordAge) days (recommend $maxAgeThreshold)"
            }
            if ($p.MinimumPasswordLength -lt $minLengthThreshold) {
                $issues += "Min password length $($p.MinimumPasswordLength) (recommend $minLengthThreshold)"
            }
            if ($p.RequireUppercaseCharacters -eq $false) { $issues += "Uppercase not required" }
            if ($p.RequireLowercaseCharacters -eq $false) { $issues += "Lowercase not required" }
            if ($p.RequireNumbers -eq $false) { $issues += "Numbers not required" }
            if ($p.RequireSymbols -eq $false) { $issues += "Symbols not required" }
            if ($p.PasswordLastUsed -and -not $p.AllowUsersToChangePassword) { $issues += "Users cannot change password" }
            
            if ($issues.Count -gt 0) {
                $f = New-Finding -Id "AWS-IAM-001" -Title "IAM password policy has security gaps" `
                    -Description "Password policy issues: $($issues -join ', ')" `
                    -Severity $script:FindingSeverity.Medium -Category "AWS_PasswordPolicy"
                $f.RuleId = "AWS-IAM-001"
                $f.RuleDescription = "Checks IAM password policy configuration"
                $f.Source = "AWS"
                $f.CheckName = "IamPasswordPolicyCheck"
                $f.Remediation = "Update IAM password policy to meet security requirements."
                $f.RemediationSteps = @(
                    "Set max age to $maxAgeThreshold days",
                    "Require $minLengthThreshold+ characters",
                    "Require upper, lower, numbers, symbols",
                    "Allow users to change password"
                )
                Add-FindingObject -Finding $f -Object "Account Password Policy"
                Add-FindingEvidence -Finding $f -Source "aws iam get-account-password-policy" `
                    -Detail "$($issues.Count) policy issues" -Confidence "High"
                $findings += $f
            }
        }
        else {
            $f = New-Finding -Id "AWS-IAM-002" -Title "No IAM password policy configured" `
                -Description "Account does not have a password policy set" `
                -Severity $script:FindingSeverity.High -Category "AWS_PasswordPolicy"
            $f.RuleId = "AWS-IAM-002"
            $f.RuleDescription = "Checks for IAM password policy existence"
            $f.Source = "AWS"
            $f.CheckName = "IamPasswordPolicyCheck"
            $f.Remediation = "Create and configure IAM password policy."
            $f.RemediationSteps = @(
                "Create password policy via IAM console",
                "Set requirements per CIS benchmark"
            )
            Add-FindingObject -Finding $f -Object "Account Password Policy"
            Add-FindingEvidence -Finding $f -Source "aws iam get-account-password-policy" `
                -Detail "No policy configured" -Confidence "High"
            $findings += $f
        }
    }
    catch {
        if ($Context) { $Context.Log("IAM password policy check failed: $($_.Exception.Message)", "Error") }
    }
    return $findings
}

function Invoke-AwsRootAccountCheck {
    <#
    .SYNOPSIS
        Check root account security settings.
    
    .DESCRIPTION
        Verifies that the AWS root account has MFA enabled and monitors
        for recent root account usage, which should be avoided.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = @{ Log = @{} }
        $findings = Invoke-AwsRootAccountCheck -Context $context
    
    .OUTPUTS
        Array of finding objects for root account security issues.
    
    .NOTES
        Requires: AWS CLI with IAM and CloudTrail permissions.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    $mfaRequired = $script:DefaultThresholds.AwsRootMfaRequired
    $activityWarningDays = $script:DefaultThresholds.AwsRootActivityWarningDays
    
    try {
        # Check if root has MFA
        $mfaDevices = aws iam list-virtual-mfa-devices --output json 2>$null | ConvertFrom-Json
        
        if ($mfaRequired -and (-not $mfaDevices)) {
            $f = New-Finding -Id "AWS-ROOT-001" -Title "Root account has no MFA enabled" `
                -Description "AWS root account does not have a virtual MFA device" `
                -Severity $script:FindingSeverity.Critical -Category "AWS_RootSecurity"
            $f.RuleId = "AWS-ROOT-001"
            $f.RuleDescription = "Checks root account MFA configuration"
            $f.Source = "AWS"
            $f.CheckName = "RootAccountCheck"
            $f.Remediation = "Enable MFA on root account immediately."
            $f.RemediationSteps = @(
                "Go to IAM > Dashboard",
                "Activate MFA on root account",
                "Use hardware MFA for production",
                "Store MFA backup securely"
            )
            Add-FindingObject -Finding $f -Object "Root Account"
            Add-FindingEvidence -Finding $f -Source "aws iam list-virtual-mfa-devices" `
                -Detail "No MFA device found" -Confidence "High"
            $findings += $f
        }
        
        # Check recent root usage
        $recentActivity = aws cloudtrail lookup-events --lookup-attributes "AttributeKey=EventName,AttributeValue=ConsoleLogin" --output json 2>$null | ConvertFrom-Json
        if ($recentActivity -and $recentActivity.Events) {
            $rootLogins = $recentActivity.Events | Where-Object {
                $_.Username -eq 'root' -or $_.CloudTrailEvent | Select-String '"userIdentity":\{"type":"Root"'
            }
            if ($rootLogins) {
                $lastLogin = $rootLogins[0].EventTime
                $lastLoginDate = [datetime]$lastLogin
                $daysAgo = (New-TimeSpan -Start $lastLoginDate -End (Get-Date)).Days
                
                if ($daysAgo -le $activityWarningDays) {
                    $f = New-Finding -Id "AWS-ROOT-002" -Title "Root account was used recently" `
                        -Description "Root account used $daysAgo days ago. Consider using IAM users instead." `
                        -Severity $script:FindingSeverity.Low -Category "AWS_RootSecurity"
                    $f.RuleId = "AWS-ROOT-002"
                    $f.RuleDescription = "Checks root account usage"
                    $f.Source = "AWS"
                    $f.CheckName = "RootAccountCheck"
                    $f.Remediation = "Use IAM users for daily tasks. Root only for account-closing."
                    $f.RemediationSteps = @(
                        "Create IAM users with least privilege",
                        "Enable CloudTrail on root actions",
                        "Set up alerts for root usage",
                        "Document root access justification"
                    )
                    Add-FindingObject -Finding $f -Object "Root Account - Last used: $lastLogin"
                    Add-FindingEvidence -Finding $f -Source "aws cloudtrail lookup-events" `
                        -Detail "Recent root activity" -Confidence "Medium"
                    $findings += $f
                }
            }
        }
    }
    catch {
        if ($Context) { $Context.Log("Root account check failed: $($_.Exception.Message)", "Error") }
    }
    return $findings
}

# =============================================================================
# GCP ADDITIONAL SECURITY CHECKS
# =============================================================================

function Invoke-GcpVpcServiceControlsCheck {
    <#
    .SYNOPSIS
        Check if VPC Service Controls are enabled for sensitive projects.
    
    .DESCRIPTION
        Verifies that sensitive GCP projects have VPC Service Controls
        perimeters configured for data exfiltration protection.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = @{ Log = @{} }
        $findings = Invoke-GcpVpcServiceControlsCheck -Context $context
    
    .OUTPUTS
        Array of finding objects for sensitive projects without VPC SC.
    
    .NOTES
        Requires: gcloud CLI with appropriate permissions.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    $sensitivePatterns = $script:DefaultThresholds.GcpSensitiveProjectPattern
    
    try {
        $projects = gcloud projects list --format=json 2>$null | ConvertFrom-Json
        
        foreach ($project in $projects) {
            $name = $project.name.ToLower()
            $isSensitive = $sensitivePatterns | Where-Object { $name -match $_ }
            
            if ($isSensitive) {
                $orgName = gcloud organizations list --format=json 2>$null | ConvertFrom-Json | Select-Object -First 1
                if ($orgName) {
                    $perimeter = gcloud access-context-manager perimeters list --organization=$orgName.name 2>$null | Select-String $project.projectId
                    
                    if (-not $perimeter) {
                        $f = New-Finding -Id "GCP-VPC-001" -Title "Sensitive project $($project.projectId) has no VPC Service Controls" `
                            -Description "Project contains sensitive data but VPC Service Controls perimeter not found" `
                            -Severity $script:FindingSeverity.High -Category "GCP_VpcServiceControls"
                        $f.RuleId = "GCP-VPC-001"
                        $f.RuleDescription = "Checks VPC Service Controls on sensitive projects"
                        $f.Source = "GCP"
                        $f.CheckName = "VpcServiceControlsCheck"
                        $f.Remediation = "Create VPC Service Controls perimeter for this project."
                        $f.RemediationSteps = @(
                            "Create access context manager perimeter",
                            "Add project to perimeter",
                            "Define access levels",
                            "Configure service boundary"
                        )
                        Add-FindingObject -Finding $f -Object $project.projectId
                        Add-FindingEvidence -Finding $f -Source "gcloud access-context-manager perimeters list" `
                            -Detail "No perimeter found" -Confidence "Medium"
                        $findings += $f
                    }
                }
            }
        }
    }
    catch {
        if ($Context) { $Context.Log("VPC Service Controls check failed: $($_.Exception.Message)", "Error") }
    }
    return $findings
}

function Invoke-GcpOrgPolicyCheck {
    <#
    .SYNOPSIS
        Check organization policy constraints.
    
    .DESCRIPTION
        Verifies that important organization policy constraints are
        configured for security compliance.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = @{ Log = @{} }
        $findings = Invoke-GcpOrgPolicyCheck -Context $context
    
    .OUTPUTS
        Array of finding objects for missing organization policies.
    
    .NOTES
        Requires: gcloud CLI with organization-level permissions.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    try {
        $orgName = gcloud organizations list --format=json 2>$null | ConvertFrom-Json | Select-Object -First 1
        if ($orgName) {
            $orgId = $orgName.name -replace 'organizations/', ''
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
                    $f = New-Finding -Id "GCP-ORG-001" -Title "Organization policy $constraint not configured" `
                        -Description "Important organization policy constraint is not enforced" `
                        -Severity $script:FindingSeverity.Medium -Category "GCP_OrgPolicy"
                    $f.RuleId = "GCP-ORG-001"
                    $f.RuleDescription = "Checks organization policy configuration"
                    $f.Source = "GCP"
                    $f.CheckName = "OrgPolicyCheck"
                    $f.Remediation = "Set organization policy constraint."
                    $f.RemediationSteps = @(
                        "Go to Organization Policies",
                        "Create policy for constraint",
                        "Define allowed/denied values"
                    )
                    Add-FindingObject -Finding $f -Object $constraint
                    Add-FindingEvidence -Finding $f -Source "gcloud org-policies list" `
                        -Detail "Policy not configured" -Confidence "Medium"
                    $findings += $f
                }
            }
        }
    }
    catch {
        if ($Context) { $Context.Log("Organization policy check failed: $($_.Exception.Message)", "Error") }
    }
    return $findings
}

function Invoke-GcpServiceAccountKeyAgeCheck {
    <#
    .SYNOPSIS
        Check for old service account keys.
    
    .DESCRIPTION
        Identifies service account keys older than the configured threshold,
        which should be rotated for security.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = @{ Log = @{} }
        $findings = Invoke-GcpServiceAccountKeyAgeCheck -Context $context
    
    .OUTPUTS
        Array of finding objects for old service account keys.
    
    .NOTES
        Requires: gcloud CLI with IAM permissions.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    $keyAgeThreshold = $script:DefaultThresholds.GcpServiceAccountKeyAge
    
    try {
        $projects = gcloud projects list --format=json 2>$null | ConvertFrom-Json
        
        foreach ($project in $projects) {
            $email = "$($project.projectId -replace '-','@').iam.gserviceaccount.com"
            $keys = gcloud iam service-accounts keys list --iam-account=$email --format=json 2>$null | ConvertFrom-Json
            
            if ($keys) {
                $oldKeys = $keys | Where-Object {
                    $key = $_
                    $key.validAfterTime -and ([datetime]$key.validAfterTime -lt (Get-Date).AddDays(-$keyAgeThreshold))
                }
                
                if ($oldKeys.Count -gt 0) {
                    $f = New-Finding -Id "GCP-SA-001" -Title "Service account keys older than $keyAgeThreshold days in $($project.projectId)" `
                        -Description "$($oldKeys.Count) service account keys are older than $keyAgeThreshold days" `
                        -Severity $script:FindingSeverity.Medium -Category "GCP_ServiceAccountKey"
                    $f.RuleId = "GCP-SA-001"
                    $f.RuleDescription = "Checks service account key age"
                    $f.Source = "GCP"
                    $f.CheckName = "ServiceAccountKeyAgeCheck"
                    $f.Remediation = "Rotate old service account keys."
                    $f.RemediationSteps = @(
                        "Create new key for service account",
                        "Update applications to use new key",
                        "Delete old keys",
                        "Implement key rotation automation"
                    )
                    foreach ($k in $oldKeys) {
                        Add-FindingObject -Finding $f -Object "$($project.projectId): $($k.name)"
                    }
                    Add-FindingEvidence -Finding $f -Source "gcloud iam service-accounts keys list" `
                        -Detail "$($oldKeys.Count) old keys" -Confidence "Medium"
                    $findings += $f
                }
            }
        }
    }
    catch {
        if ($Context) { $Context.Log("Service account key check failed: $($_.Exception.Message)", "Error") }
    }
    return $findings
}

function Invoke-GcpPublicAccessCheck {
    <#
    .SYNOPSIS
        Check for GCP resources with public access.
    
    .DESCRIPTION
        Scans Cloud Storage buckets for IAM bindings that allow
        public (allUsers) or authenticated (allAuthenticatedUsers) access.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = @{ Log = @{} }
        $findings = Invoke-GcpPublicAccessCheck -Context $context
    
    .OUTPUTS
        Array of finding objects for publicly accessible GCS buckets.
    
    .NOTES
        Requires: gcloud CLI with Storage permissions.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    try {
        $projects = gcloud projects list --format=json 2>$null | ConvertFrom-Json
        
        foreach ($project in $projects) {
            $buckets = gcloud storage buckets list --project=$($project.projectId) --format=json 2>$null | ConvertFrom-Json
            
            if ($buckets) {
                foreach ($bucket in $buckets) {
                    $iam = gcloud storage buckets get-iam-policy $bucket.name --format=json 2>$null | ConvertFrom-Json
                    
                    if ($iam) {
                        $publicBindings = $iam.bindings | Where-Object {
                            $role = $_.role
                            $members = $_.members | Where-Object { $_ -match 'allUsers|allAuthenticatedUsers' }
                            $members.Count -gt 0
                        }
                        
                        if ($publicBindings) {
                            $f = New-Finding -Id "GCP-GCS-001" -Title "GCS bucket $($bucket.name) has public access" `
                                -Description "Bucket has IAM bindings allowing public access" `
                                -Severity $script:FindingSeverity.Critical -Category "GCP_PublicAccess"
                            $f.RuleId = "GCP-GCS-001"
                            $f.RuleDescription = "Checks GCS bucket public access"
                            $f.Source = "GCP"
                            $f.CheckName = "PublicAccessCheck"
                            $f.Remediation = "Remove public access from bucket immediately."
                            $f.RemediationSteps = @(
                                "Remove allUsers and allAuthenticatedUsers from bindings",
                                "Use uniform bucket-level access",
                                "Review data classification"
                            )
                            Add-FindingObject -Finding $f -Object $bucket.name
                            Add-FindingEvidence -Finding $f -Source "gcloud storage buckets get-iam-policy" `
                                -Detail "Public IAM bindings found" -Confidence "High"
                            $findings += $f
                        }
                    }
                }
            }
        }
    }
    catch {
        if ($Context) { $Context.Log("Public access check failed: $($_.Exception.Message)", "Error") }
    }
    return $findings
}

# =============================================================================
# AD ADDITIONAL SECURITY CHECKS
# =============================================================================

function Invoke-AdSidHistoryCheck {
    <#
    .SYNOPSIS
        Check for accounts with SID History.
    
    .DESCRIPTION
        Identifies accounts with SID History attribute, which can indicate
        privilege escalation from domain migrations.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = @{ Log = @{} }
        $findings = Invoke-AdSidHistoryCheck -Context $context
    
    .OUTPUTS
        Array of finding objects for accounts with SID History.
    
    .NOTES
        Requires: ActiveDirectory module.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    try {
        $users = Get-ADUser -Filter { SIDHistory -like "*" } -Properties SIDHistory, Name -ErrorAction SilentlyContinue
        
        if ($users.Count -gt 0) {
            $f = New-Finding -Id "AD-SID-001" -Title "Accounts with SID History detected" `
                -Description "$($users.Count) accounts have SID History, which can indicate privilege escalation" `
                -Severity $script:FindingSeverity.High -Category "AD_SidHistory"
            $f.RuleId = "AD-SID-001"
            $f.RuleDescription = "Checks for SID History on accounts"
            $f.Source = "ActiveDirectory"
            $f.CheckName = "SidHistoryCheck"
            $f.Remediation = "Investigate accounts with SID History. Clear SID History unless migration is active."
            $f.RemediationSteps = @(
                "Identify all users with SID History",
                "Determine if from legitimate migration",
                "Clear SID History if not needed",
                "Monitor for SID History additions"
            )
            foreach ($u in $users) {
                Add-FindingObject -Finding $f -Object $u.Name
            }
            Add-FindingEvidence -Finding $f -Source "Get-ADUser" `
                -Detail "$($users.Count) accounts with SID History" -Confidence "High"
            $findings += $f
        }
    }
    catch {
        if ($Context) { $Context.Log("SID History check failed: $($_.Exception.Message)", "Error") }
    }
    return $findings
}

function Invoke-AdConstrainedDelegationCheck {
    <#
    .SYNOPSIS
        Check for accounts with unconstrained delegation.
    
    .DESCRIPTION
        Identifies accounts with unconstrained delegation enabled,
        which is a significant security risk for Kerberos-based attacks.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = @{ Log = @{} }
        $findings = Invoke-AdConstrainedDelegationCheck -Context $context
    
    .OUTPUTS
        Array of finding objects for accounts with unconstrained delegation.
    
    .NOTES
        Requires: ActiveDirectory module.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    try {
        $unconstrained = Get-ADObject -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=524288)" `
                                       -Properties Name, DistinguishedName -ErrorAction SilentlyContinue
        
        if ($unconstrained.Count -gt 0) {
            $f = New-Finding -Id "AD-DEL-001" -Title "Accounts with unconstrained delegation detected" `
                -Description "$($unconstrained.Count) accounts have 'Trust this computer for delegation to any service' enabled" `
                -Severity $script:FindingSeverity.High -Category "AD_Delegation"
            $f.RuleId = "AD-DEL-001"
            $f.RuleDescription = "Checks for unconstrained delegation"
            $f.Source = "ActiveDirectory"
            $f.CheckName = "ConstrainedDelegationCheck"
            $f.Remediation = "Convert to constrained delegation or remove delegation if not needed."
            $f.RemediationSteps = @(
                "Identify services using these accounts",
                "Configure constrained delegation to specific SPNs",
                "Consider Kerberos Armoring",
                "Regular review of delegation settings"
            )
            foreach ($u in $unconstrained) {
                Add-FindingObject -Finding $f -Object $u.Name
            }
            Add-FindingEvidence -Finding $f -Source "Get-ADObject" `
                -Detail "$($unconstrained.Count) accounts" -Confidence "High"
            $findings += $f
        }
    }
    catch {
        if ($Context) { $Context.Log("Constrained delegation check failed: $($_.Exception.Message)", "Error") }
    }
    return $findings
}

function Invoke-AdLapsCheck {
    <#
    .SYNOPSIS
        Check if LAPS is configured for workstations.
    
    .DESCRIPTION
        Verifies that Local Administrator Password Solution (LAPS) is
        deployed and managing local admin passwords securely.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = @{ Log = @{} }
        $findings = Invoke-AdLapsCheck -Context $context
    
    .OUTPUTS
        Array of finding objects for LAPS configuration issues.
    
    .NOTES
        Requires: ActiveDirectory module.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    try {
        $schema = Get-ADObject -SearchBase "CN=Schema,CN=Configuration,$((Get-ADDomain).DistinguishedName)" `
                               -Filter { Name -eq "ms-MCS-AdmPwd" } -ErrorAction SilentlyContinue
        
        if (-not $schema) {
            $f = New-Finding -Id "AD-LAPS-001" -Title "LAPS not deployed in environment" `
                -Description "LAPS (Local Administrator Password Solution) schema extension not found" `
                -Severity $script:FindingSeverity.Medium -Category "AD_Laps"
            $f.RuleId = "AD-LAPS-001"
            $f.RuleDescription = "Checks LAPS deployment status"
            $f.Source = "ActiveDirectory"
            $f.CheckName = "LapsCheck"
            $f.Remediation = "Deploy LAPS to manage local administrator passwords."
            $f.RemediationSteps = @(
                "Extend AD schema for LAPS",
                "Deploy LAPS client to workstations",
                "Configure GPO settings",
                "Assign LAPS password readers"
            )
            Add-FindingObject -Finding $f -Object "AD Schema"
            Add-FindingEvidence -Finding $f -Source "Get-ADObject" `
                -Detail "Schema extension not found" -Confidence "High"
            $findings += $f
        }
        else {
            $workstationsWithLaps = @()
            $computers = Get-ADComputer -Filter { OperatingSystem -like "*Windows*" } `
                                        -Properties Name, 'ms-MCS-AdmPwd', ms-MCS-AdmPwdExpirationTime `
                                        -ErrorAction SilentlyContinue
            foreach ($comp in $computers) {
                if ($comp.'ms-MCS-AdmPwd') { $workstationsWithLaps += $comp }
            }
            
            if ($workstationsWithLaps.Count -eq 0) {
                $f = New-Finding -Id "AD-LAPS-002" -Title "LAPS not being used despite schema extension" `
                    -Description "No computer accounts have LAPS password attributes set" `
                    -Severity $script:FindingSeverity.Low -Category "AD_Laps"
                $f.RuleId = "AD-LAPS-002"
                $f.RuleDescription = "Checks LAPS usage status"
                $f.Source = "ActiveDirectory"
                $f.CheckName = "LapsCheck"
                $f.Remediation = "Configure GPO to enable LAPS on workstations."
                $f.RemediationSteps = @(
                    "Create LAPS GPO",
                    "Configure password settings",
                    "Link to workstations OU",
                    "Verify computers have password generated"
                )
                Add-FindingObject -Finding $f -Object "Workstations"
                Add-FindingEvidence -Finding $f -Source "Get-ADComputer" `
                    -Detail "No LAPS usage detected" -Confidence "Medium"
                $findings += $f
            }
        }
    }
    catch {
        if ($Context) { $Context.Log("LAPS check failed: $($_.Exception.Message)", "Error") }
    }
    return $findings
}

function Invoke-AdAdminCountCheck {
    <#
    .SYNOPSIS
        Check for accounts with AdminCount > 0.
    
    .DESCRIPTION
        Identifies protected accounts (AdminCount=1) that have been
        inactive for an extended period, representing potential risk.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = @{ Log = @{} }
        $findings = Invoke-AdAdminCountCheck -Context $context
    
    .OUTPUTS
        Array of finding objects for inactive protected accounts.
    
    .NOTES
        Requires: ActiveDirectory module.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    $inactiveDays = $script:DefaultThresholds.AdAdminCountInactivityDays
    
    try {
        $protectedUsers = Get-ADUser -Filter { AdminCount -eq $true } -Properties Name, AdminCount, LastLogonTimestamp `
                                     -ErrorAction SilentlyContinue
        
        if ($protectedUsers.Count -gt 0) {
            $inactive = $protectedUsers | Where-Object {
                $_.LastLogonTimestamp -and $_.LastLogonTimestamp -lt (Get-Date).AddDays(-$inactiveDays)
            }
            
            if ($inactive.Count -gt 0) {
                $f = New-Finding -Id "AD-ADMIN-001" -Title "Protected accounts inactive for $inactiveDays+ days" `
                    -Description "$($inactive.Count) accounts with AdminCount=1 have not logged in for $inactiveDays+ days" `
                    -Severity $script:FindingSeverity.Medium -Category "AD_ProtectedAccounts"
                $f.RuleId = "AD-ADMIN-001"
                $f.RuleDescription = "Checks for inactive protected accounts"
                $f.Source = "ActiveDirectory"
                $f.CheckName = "AdminCountCheck"
                $f.Remediation = "Review and disable inactive privileged accounts."
                $f.RemediationSteps = @(
                    "Review each inactive account",
                    "Contact manager for status",
                    "Disable or remove if no longer needed",
                    "Document decisions"
                )
                foreach ($u in $inactive) {
                    Add-FindingObject -Finding $f -Object $u.Name
                }
                Add-FindingEvidence -Finding $f -Source "Get-ADUser" `
                    -Detail "$($inactive.Count) inactive protected accounts" -Confidence "High"
                $findings += $f
            }
        }
    }
    catch {
        if ($Context) { $Context.Log("AdminCount check failed: $($_.Exception.Message)", "Error") }
    }
    return $findings
}

function Invoke-AdDuplicateSpnCheck {
    <#
    .SYNOPSIS
        Check for duplicate SPNs.
    
    .DESCRIPTION
        Identifies duplicate Service Principal Names registered on
        multiple accounts, which can cause authentication failures.
    
    .PARAMETER Context
        The assessment context object containing configuration and logging.
    
    .EXAMPLE
        $context = @{ Log = @{} }
        $findings = Invoke-AdDuplicateSpnCheck -Context $context
    
    .OUTPUTS
        Array of finding objects for duplicate SPNs.
    
    .NOTES
        Requires: ActiveDirectory module.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [hashtable]$Context
    )
    
    $findings = @()
    
    $threshold = $script:DefaultThresholds.AdDuplicateSpnThreshold
    
    try {
        $objectsWithSpn = Get-ADObject -Filter { ServicePrincipalName -like "*" } `
                                       -Properties Name, ServicePrincipalName, DistinguishedName `
                                       -ErrorAction SilentlyContinue
        
        $spnCounts = @{}
        foreach ($obj in $objectsWithSpn) {
            foreach ($spn in $obj.ServicePrincipalName) {
                $spnCounts[$spn] = @($spnCounts[$spn] + 1)
            }
        }
        
        $duplicateSpns = $spnCounts.GetEnumerator() | Where-Object { $_.Value -gt $threshold }
        
        if ($duplicateSpns.Count -gt 0) {
            $f = New-Finding -Id "AD-SPN-001" -Title "Duplicate SPNs detected" `
                -Description "$($duplicateSpns.Count) SPNs are registered on multiple accounts" `
                -Severity $script:FindingSeverity.Medium -Category "AD_SpnConfig"
            $f.RuleId = "AD-SPN-001"
            $f.RuleDescription = "Checks for duplicate SPN registrations"
            $f.Source = "ActiveDirectory"
            $f.CheckName = "DuplicateSpnCheck"
            $f.Remediation = "Remove duplicate SPNs to prevent authentication failures."
            $f.RemediationSteps = @(
                "Identify all accounts with duplicate SPN",
                "Determine correct owner",
                "Remove SPN from incorrect accounts",
                "Verify Kerberos authentication"
            )
            foreach ($spn in $duplicateSpns) {
                Add-FindingObject -Finding $f -Object "$($spn.Key): $($spn.Value) accounts"
            }
            Add-FindingEvidence -Finding $f -Source "Get-ADObject" `
                -Detail "$($duplicateSpns.Count) duplicate SPNs" -Confidence "High"
            $findings += $f
        }
    }
    catch {
        if ($Context) { $Context.Log("Duplicate SPN check failed: $($_.Exception.Message)", "Error") }
    }
    return $findings
}

# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

function Invoke-ExtendedQuickChecks {
    <#
    .SYNOPSIS
        Runs all extended security checks.
    
    .DESCRIPTION
        Main entry point for the Extended QuickChecks module.
        Executes AWS, GCP, and AD security checks based on parameters.
    
    .PARAMETER OutputDir
        Directory path for output files. Default is ".\QuickChecks-Extended-Output".
    
    .PARAMETER Format
        Output format: Console or Json. Default is Console.
    
    .PARAMETER CriticalThreshold
        Number of critical findings to trigger Critical status. Default is 1.
    
    .PARAMETER HighThreshold
        Number of high findings to trigger Warning status. Default is 5.
    
    .PARAMETER IncludeAWS
        Run AWS security checks (requires AWS CLI).
    
    .PARAMETER IncludeGCP
        Run GCP security checks (requires gcloud CLI).
    
    .PARAMETER IncludeAD
        Run AD security checks (requires ActiveDirectory module).
    
    .PARAMETER Help
        Display help information and exit.
    
    .EXAMPLE
        Invoke-ExtendedQuickChecks -IncludeAWS -IncludeGCP -IncludeAD -Format All
    
    .OUTPUTS
        Hashtable containing the assessment report.
    
    .NOTES
        Requires appropriate CLI tools for each cloud platform.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, HelpMessage = "Output directory for reports")]
        [ValidateNotNullOrEmpty()]
        [string]$OutputDir = ".\QuickChecks-Extended-Output",
        
        [Parameter(Mandatory = $false, HelpMessage = "Output format")]
        [ValidateSet('Console', 'Json')]
        [string]$Format = 'Console',
        
        [Parameter(Mandatory = $false, HelpMessage = "Critical findings threshold")]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$CriticalThreshold = 1,
        
        [Parameter(Mandatory = $false, HelpMessage = "High findings threshold")]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$HighThreshold = 5,
        
        [Parameter(Mandatory = $false, HelpMessage = "Run AWS security checks")]
        [switch]$IncludeAWS,
        
        [Parameter(Mandatory = $false, HelpMessage = "Run GCP security checks")]
        [switch]$IncludeGCP,
        
        [Parameter(Mandatory = $false, HelpMessage = "Run AD security checks")]
        [switch]$IncludeAD,
        
        [Parameter(Mandatory = $false, HelpMessage = "Display help information")]
        [switch]$Help
    )
    
    if ($Help) {
        Write-Host @"
IdentityFirst QuickChecks - Extended Security Checks
===================================================
AWS Checks: S3 Public Buckets, VPC Flow Logs, IAM Password Policy, Root Account
GCP Checks: VPC Service Controls, Org Policies, SA Key Age, Public Access
AD Checks: SID History, Constrained Delegation, LAPS, AdminCount, Duplicate SPN

USAGE:
    Invoke-ExtendedQuickChecks [-IncludeAWS] [-IncludeGCP] [-IncludeAD]
                              [-OutputDir <path>] [-Format <format>]
                              [-CriticalThreshold <n>] [-HighThreshold <n>]
                              [-Help]

PARAMETERS:
    -OutputDir          Output directory (default: .\QuickChecks-Extended-Output)
    -Format             Console or JSON output (default: Console)
    -CriticalThreshold  Critical findings for Critical status (default: 1)
    -HighThreshold      High findings for Warning status (default: 5)
    -IncludeAWS         Run AWS checks (requires AWS CLI)
    -IncludeGCP         Run GCP checks (requires gcloud CLI)
    -IncludeAD          Run AD checks (requires ActiveDirectory module)
    -Help               Show this help message

EXIT CODES:
    0 = Healthy
    1 = Warning
    2 = Critical
    3 = Error
"@
        return
    }
    
    Write-Host "`n" -ForegroundColor Cyan
    Write-Host "  IdentityFirst QuickChecks - Extended Security Assessment           " -ForegroundColor Cyan
    Write-Host "" -ForegroundColor Cyan
    
    $context = @{ Configuration = @{}; Log = @(); StartTime = [datetime]::UtcNow }
    $config = @{
        CriticalThreshold = $CriticalThreshold
        HighThreshold = $HighThreshold
        HealthyScoreThreshold = 80
        OutputDirectory = $OutputDir
    }
    
    $allFindings = @()
    
    $runAWS = $IncludeAWS -or (-not $IncludeAD -and -not $IncludeGCP)
    $runGCP = $IncludeGCP
    $runAD = $IncludeAD -or (-not $IncludeAWS -and -not $IncludeGCP)
    
    if ($runAWS) {
        Write-Host "`n[AWS] Running AWS security checks..." -ForegroundColor Yellow
        $allFindings += Invoke-AwsS3PublicBucketCheck -Context $context
        $allFindings += Invoke-AwsVpcFlowLogsCheck -Context $context
        $allFindings += Invoke-AwsIamPasswordPolicyCheck -Context $context
        $allFindings += Invoke-AwsRootAccountCheck -Context $context
    }
    
    if ($runGCP) {
        Write-Host "`n[GCP] Running GCP security checks..." -ForegroundColor Yellow
        $allFindings += Invoke-GcpVpcServiceControlsCheck -Context $context
        $allFindings += Invoke-GcpOrgPolicyCheck -Context $context
        $allFindings += Invoke-GcpServiceAccountKeyAgeCheck -Context $context
        $allFindings += Invoke-GcpPublicAccessCheck -Context $context
    }
    
    if ($runAD) {
        Write-Host "`n[AD] Running Active Directory security checks..." -ForegroundColor Yellow
        $allFindings += Invoke-AdSidHistoryCheck -Context $context
        $allFindings += Invoke-AdConstrainedDelegationCheck -Context $context
        $allFindings += Invoke-AdLapsCheck -Context $context
        $allFindings += Invoke-AdAdminCountCheck -Context $context
        $allFindings += Invoke-AdDuplicateSpnCheck -Context $context
    }
    
    # Calculate score
    $score = 100
    foreach ($f in $allFindings) {
        switch ($f.Severity) {
            "Critical" { $score -= $script:DefaultThresholds.CriticalWeight }
            "High" { $score -= $script:DefaultThresholds.HighWeight }
            "Medium" { $score -= $script:DefaultThresholds.MediumWeight }
            "Low" { $score -= $script:DefaultThresholds.LowWeight }
        }
    }
    $score = [Math]::Max(0, [Math]::Min(100, $score))
    
    $crit = ($allFindings | Where-Object { $_.Severity -eq 'Critical' }).Count
    $high = ($allFindings | Where-Object { $_.Severity -eq 'High' }).Count
    
    $healthyThreshold = $script:DefaultThresholds.HealthyScoreThreshold
    
    $status = if ($crit -ge $CriticalThreshold) { "Critical" }
              elseif ($high -ge $HighThreshold) { "Warning" }
              elseif ($score -lt 60) { "Critical" }
              elseif ($score -lt $healthyThreshold) { "Warning" }
              else { "Healthy" }
    
    $scoreColor = if ($status -eq 'Healthy') { 'Green' } elseif ($status -eq 'Warning') { 'Yellow' } else { 'Red' }
    
    Write-Host "`n" -ForegroundColor Cyan
    Write-Host " RESULTS " -ForegroundColor White
    Write-Host "" -ForegroundColor Cyan
    Write-Host "`n  Score:  $score/100 - " -NoNewline
    Write-Host $status -ForegroundColor $scoreColor
    Write-Host "`n  Findings:"
    Write-Host "    Critical: $crit" -ForegroundColor Red
    Write-Host "    High:     $high" -ForegroundColor DarkRed
    Write-Host "    Medium:   $(($allFindings | Where-Object { $_.Severity -eq 'Medium' }).Count)" -ForegroundColor Yellow
    Write-Host "    Low:      $(($allFindings | Where-Object { $_.Severity -eq 'Low' }).Count)" -ForegroundColor Cyan
    
    if ($crit -gt 0) {
        Write-Host "`n CRITICAL FINDINGS" -ForegroundColor Red
        foreach ($f in $allFindings | Where-Object { $_.Severity -eq 'Critical' }) {
            Write-Host "`n  [!] $($f.Title)" -ForegroundColor Red
            Write-Host "      $($f.Description)"
        }
    }
    
    Write-Host "`n" -ForegroundColor Cyan
    
    $exitCode = switch ($status) { 'Healthy' { 0 } 'Warning' { 1 } 'Critical' { 2 } default { 3 } }
    Write-Host "Exit Code: $exitCode" -ForegroundColor Gray
    
    return @{
        OverallScore = $score
        HealthStatus = $status
        Findings = $allFindings
        CriticalCount = $crit
        HighCount = $high
    }
}

Export-ModuleMember -Function Invoke-ExtendedQuickChecks
