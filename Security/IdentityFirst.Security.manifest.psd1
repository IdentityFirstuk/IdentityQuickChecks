@{
    # Security Manifest for IdentityFirst QuickChecks
    # Version: 1.0.0
    # Date: 2026-01-29
    
    # Security Features Enabled
    SecurityFeatures = @{
        InputValidation = $true
        PathTraversalProtection = $true
        XssProtection = $true
        CredentialRedaction = $true
        FileAclProtection = $true
        CodeSigning = $true
        TimestampVerification = $true
    }
    
    # Encryption Standards
    Encryption = @{
        CertificateKeySize = 4096
        CertificateAlgorithm = "RSA"
        HashAlgorithm = "SHA-256"
        PfxEncryption = "AES-256"
        TlsVersion = "1.2+"
    }
    
    # PowerShell Security Settings
    PowerShellSettings = @{
        ExecutionPolicyRecommended = "RemoteSigned"
        TranscriptLogging = $false
        ScriptBlockLogging = $false
        ModuleLogging = $false
    }
    
    # Required Modules
    RequiredModules = @(
        @{ Name = "Az.Accounts"; MinimumVersion = "2.12.0"; AllowPrerelease = $false }
        @{ Name = "Microsoft.Graph.Identity.DirectoryManagement"; MinimumVersion = "1.9.0"; AllowPrerelease = $false }
        @{ Name = "AWS.Tools.Common"; MinimumVersion = "4.1.0"; AllowPrerelease = $false }
        @{ Name = "Google.Cloud.IdentityToolkit"; MinimumVersion = "1.0.0"; AllowPrerelease = $false }
    )
    
    # Security Recommendations
    Recommendations = @(
        "Always run scripts with RemoteSigned execution policy",
        "Import IdentityFirst.Security.psm1 for security functions",
        "Use -WhatIf parameter when testing export functions",
        "Review logs for suspicious activity",
        "Rotate certificates annually",
        "Use least-privilege service accounts"
    )
    
    # Known Security Limitations
    Limitations = @(
        "Self-signed certificates show 'Unknown publisher' warnings",
        "Scripts require PowerShell 5.1 or later",
        "Some checks require admin privileges",
        "Cloud provider permissions must be configured separately"
    )
}
