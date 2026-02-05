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
# IdentityFirst QuickChecks - Configuration Template
# Copy this file to QuickChecks.config.ps1 and modify values

@{
    # =========================================================================
    # Output Settings
    # =========================================================================
    
    # Default output directory for reports
    DefaultOutputDirectory = ".\IFQC-Output"
    
    # Default detail level: "Normal" or "Detailed"
    DefaultDetailLevel = "Normal"
    
    # Evidence limit per finding (Normal: 15, Detailed: 50)
    EvidenceLimitNormal = 15
    EvidenceLimitDetailed = 50
    
    # =========================================================================
    # Inactive Account Detection Settings
    # =========================================================================
    
    # Days before account considered inactive
    InactiveDaysThreshold = 90
    
    # Platforms to check: "AD", "Entra", "AWS", "GCP"
    InactiveCheckPlatforms = @("AD", "Entra", "AWS", "GCP")
    
    # =========================================================================
    # Legacy Authentication Detection Settings
    # =========================================================================
    
    # Lookback days for sign-in analysis
    LegacyAuthLookbackDays = 30
    
    # Protocols to detect
    LegacyAuthProtocols = @{
        SMTP = $true
        IMAP = $true
        POP = $true
        EAS = $true      # Exchange ActiveSync
        EWS = $true      # Exchange Web Services
        PowerShell = $true
        BasicAuth = $true
        MAPI = $true
    }
    
    # =========================================================================
    # Cloud Provider Settings
    # =========================================================================
    
    # AWS Settings
    AWS = @{
        # Use AWS CLI instead of AWS.Tools
        PreferCLI = $true
        
        # Admin policy patterns to detect
        AdminPolicyPatterns = @(
            "AdministratorAccess"
            "PowerUserAccess"
            "FullAdmin"
        )
        
        # Access key age threshold (days)
        AccessKeyAgeThreshold = 180
    }
    
    # GCP Settings
    GCP = @{
        # Projects to scan (leave empty for all accessible)
        ProjectsToScan = @()
        
        # Service account key age threshold (days)
        KeyAgeThreshold = 180
        
        # External domain patterns to flag
        ExternalDomainPatterns = @(
            "gmail.com"
        )
    }
    
    # =========================================================================
    # Hybrid Sync Settings
    # =========================================================================
    
    HybridSync = @{
        # Stale sync threshold (hours)
        StaleSyncThreshold = 24
        
        # Check sync errors
        CheckForErrors = $true
    }
    
    # =========================================================================
    # Report Settings
    # =========================================================================
    
    Reports = @{
        # Include host information in reports
        IncludeHostInfo = $true
        
        # Include run ID for tracking
        IncludeRunId = $true
        
        # HTML report template (default is embedded)
        # CustomTemplatePath = ".\custom-template.html"
    }
    
    # =========================================================================
    # Logging Settings
    # =========================================================================
    
    Logging = @{
        # Log level: "INFO", "WARN", "ERROR"
        Level = "INFO"
        
        # Include timestamps in console output
        TimestampedOutput = $true
    }
    
    # =========================================================================
    # IdentityHealthCheck CTA
    # =========================================================================
    
    UpgradeCTA = @{
        # Show IdentityHealthCheck upgrade message
        Enabled = $true
        
        # CTA link
        UpgradeUrl = "https://www.identityfirst.net"
        
        # CTA text
        CTAText = "Upgrade to IdentityHealthCheck"
    }
}

