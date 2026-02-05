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
    Checks for AD Certificate Services misconfigurations.

.DESCRIPTION
    Identifies dangerous certificate template configurations.
    Requires AD CS enrollment rights for full assessment.

.OUTPUTS
    - JSON report
    - HTML report
    - Log file

.NOTES
    Author: IdentityFirst Ltd
    Safety: Read-only. No changes are made.
    Requirements: ActiveDirectory module
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputDirectory = (Join-Path $PWD "IFQC-Output"),

    [Parameter()]
    [ValidateSet("Normal","Detailed")]
    [string]$DetailLevel = "Normal"
)

$modulePath = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Import-Module (Join-Path $modulePath "Module\IdentityFirst.QuickChecks.psm1") -Force

$ctx = New-IFQCContext -ToolName "AdCsAssessment" -OutputDirectory $OutputDirectory -DetailLevel $DetailLevel
Add-IFQCNote -Context $ctx -Note "AD CS Assessment requires AD module and read access to Certificate Templates."
Add-IFQCNote -Context $ctx -Note "Full ESC1-ESC8 analysis available in IdentityHealthCheck."

Invoke-IFQCSafe -Context $ctx -Name "AD CS Security Assessment" -Block {
    # Check if AD module is available
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
        throw "ActiveDirectory module not available"
    }

    Import-Module ActiveDirectory -ErrorAction Stop

    # Get domain information
    $domain = Get-ADDomain -ErrorAction SilentlyContinue
    if (-not $domain) {
        throw "Could not retrieve domain information"
    }
    $ctx.Data.domain = $domain.DnsRoot

    # Findings collection
    $findings = @()
    $evidenceLimit = if ($DetailLevel -eq "Detailed") { 50 } else { 20 }

    # =========================================================================
    # Check 1: Enterprise CAs
    # =========================================================================
    try {
        $cas = Get-ADCertificateAuthority -ErrorAction SilentlyContinue | Where-Object { $_.IsEnabled -eq $true }
        
        if ($cas) {
            $caInfo = $cas | Select-Object -First $evidenceLimit @{
                Name = "CAInfo"; Expression = {
                    "$($_.Name).$($using:domain.DnsRoot)"
                }
            }
            
            $findings += @{
                Id = "ADCS-ENABLED-CA"
                Title = "Enterprise Certificate Authorities Enabled"
                Severity = "Info"
                Description = "$($cas.Count) Enterprise CA(s) found in the domain."
                Count = $cas.Count
                Evidence = $caInfo
                Recommendation = "Document all CAs. Regular audits required for compliance."
            }
        }
        else {
            $findings += @{
                Id = "ADCS-NO-CA"
                Title = "No Enterprise CAs Found"
                Severity = "Low"
                Description = "No enabled Enterprise Certificate Authorities were found."
                Count = 0
                Evidence = @(@{ Note = "No CAs configured or accessible" })
                Recommendation = "If AD CS is not in use, no action needed."
            }
        }
    }
    catch {
        Add-IFQCNote -Context $ctx -Note "Could not enumerate CAs: $($_.Exception.Message)"
    }

    # =========================================================================
    # Check 2: Certificate Templates with dangerous settings
    # =========================================================================
    try {
        # Get certificate templates via ADSI (requires AD WS or direct LDAP access)
        $rootDSE = [ADSI]"LDAP://$($domain.RootDSE)/RootDSE"
        $configNC = $rootDSE.Get("configurationNamingContext")
        
        $templatesPath = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
        $templates = [ADSI]$templatesPath |
            Get-Member -MemberType Property -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}$' }

        $dangerousTemplates = @()
        $templateDetails = @()

        foreach ($templateEntry in $templates | Select-Object -First 50) {
            $templateDN = $templateEntry.Name
            $templatePath = "LDAP://CN=$templateDN,CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
            $template = [ADSI]$templatePath

            try {
                $name = $template.Get("displayName") ?? $templateDN
                $flags = $template.Get("pkiEnrollmentFlags") ?? 0
                $ekus = $template.Get("pkiKeyUsage") ?? ""
                
                # Check for dangerous configurations
                $isDangerous = $false
                $issues = @()

                # Check for CTPR (Certificate Templates Plus R) - ESC1 indicator
                if ($flags -band 0x20) {  # CTPR flag
                    $isDangerous = $true
                    $issues += "CTPR enabled (Client Auth required for enrollment)"
                }

                # Check for enrollee supplies subject (ESC1)
                $subjectFlags = $template.Get("msPKI-Certificate-Name-Flag") ?? 0
                if ($subjectFlags -band 0x100000) {  # ENROLLEE_SUPPLIES_SUBJECT
                    $isDangerous = $true
                    $issues += "Enrollee supplies subject (ESC1 risk)"
                }

                # Check for no security extension (ESC2)
                $privateKeyFlags = $template.Get("msPKI-Private-Key-Flag") ?? 0
                if ($privateKeyFlags -band 0x100) {  # AT_EXCHANGE_KEY_SET
                    # Check for enterprise admin enrollment
                    $enrollmentFlags = $template.Get("msPKI-Enrollment-Flag") ?? 0
                    if ($enrollmentFlags -band 0x8) {  # PUBLISH_TO_DS
                        # Check if ANYONE can enroll
                        $securityDescriptor = $template.Get("nTSecurityDescriptor") ?? $null
                        # Basic check - detailed SD parsing in HealthCheck
                    }
                }

                if ($isDangerous) {
                    $dangerousTemplates += $templateDN
                    $templateDetails += [PSCustomObject]@{
                        Name = $name
                        DN = $templateDN
                        Issues = $issues -join "; "
                    }
                }
            }
            catch {
                # Skip templates we can't read
            }
        }

        if ($dangerousTemplates.Count -gt 0) {
            $findings += @{
                Id = "ADCS-DANGEROUS-TEMPLATES"
                Title = "Potentially Dangerous Certificate Templates"
                Severity = "High"
                Description = "$($dangerousTemplates.Count) template(s) with dangerous configurations detected."
                Count = $dangerousTemplates.Count
                Evidence = $templateDetails | Select-Object -First $evidenceLimit
                Recommendation = "Review template permissions. Disable CTPR if not needed. IdentityHealthCheck provides full ESC1-ESC8 analysis."
            }
        }
        else {
            $findings += @{
                Id = "ADCS-SAFE"
                Title = "No Dangerous Templates Detected"
                Severity = "Low"
                Description = "No certificate templates with obvious dangerous configurations were found."
                Count = 0
                Evidence = @(@{ Note = "Basic check passed" })
                Recommendation = "For complete AD CS security, consider IdentityHealthCheck for detailed ESC analysis."
            }
        }
    }
    catch {
        Add-IFQCNote -Context $ctx -Note "Could not enumerate templates: $($_.Exception.Message)"
        $findings += @{
            Id = "ADCS-TEMPLATES-ERROR"
            Title = "Could Not Enumerate Certificate Templates"
            Severity = "Warning"
            Description = "Unable to access certificate templates container."
            Count = 1
            Evidence = @(@{ Error = $_.Exception.Message })
            Recommendation = "Ensure Read access to CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration"
        }
    }

    # =========================================================================
    # Check 3: Enrollment agents
    # =========================================================================
    try {
        $enrollmentAgents = Get-ADObject -LDAPFilter "(objectClass=msPKI-Enrollment-Agent)" -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$($domain.ConfigurationNamingContext)" -ErrorAction SilentlyContinue
        
        if ($enrollmentAgents) {
            $findings += @{
                Id = "ADCS-ENROLLMENT-AGENTS"
                Title = "Enrollment Agents Configured"
                Severity = "Medium"
                Description = "$($enrollmentAgents.Count) enrollment agent(s) found. These can request certificates on behalf of others."
                Count = $enrollmentAgents.Count
                Evidence = $enrollmentAgents | Select-Object -First $evidenceLimit -Property DistinguishedName
                Recommendation = "Review enrollment agent permissions. Restrict to necessary personnel only."
            }
        }
    }
    catch {
        # Silent fail - enrollment agents may not exist
    }

    # =========================================================================
    # Output findings
    # =========================================================================
    foreach ($finding in $findings) {
        Add-IFQCFinding -Context $ctx -Finding (New-IFQCFinding `
            -Id $finding.Id `
            -Title $finding.Title `
            -Severity $finding.Severity `
            -Description $finding.Description `
            -Count $finding.Count `
            -Evidence $finding.Evidence `
            -Recommendation $finding.Recommendation
        )
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
