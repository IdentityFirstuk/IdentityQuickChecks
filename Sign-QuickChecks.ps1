<#
.SYNOPSIS
    Sign all IdentityFirst QuickChecks PowerShell scripts.

.DESCRIPTION
    Digitally signs all .ps1 and .psm1 files in the QuickChecks module.
    Requires a valid Code Signing certificate.

.OUTPUTS
    - Signed script files
    - Console output showing sign status

.NOTES
    Author: IdentityFirst Ltd
    Requirements:
        - PowerShell 5.1+
        - Code Signing certificate (from trusted CA)
        - Local certificate store access or PFX file

.USAGE
    # Sign with certificate from local store
    .\Sign-QuickChecks.ps1
    
    # Sign with PFX file
    .\Sign-QuickChecks.ps1 -CertPath ".\cert.pfx" -CertPassword "password"
    
    # Dry run (show what would be signed)
    .\Sign-QuickChecks.ps1 -DryRun
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ModulePath = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    
    [Parameter()]
    [string]$CertPath,
    
    [Parameter()]
    [securestring]$CertPassword,
    
    [Parameter()]
    [switch]$DryRun,
    
    [Parameter()]
    [switch]$Help
)

if ($Help) {
    Write-Host @"
IdentityFirst QuickChecks - Script Signing Tool
================================================

This script digitally signs all PowerShell scripts in the QuickChecks module.

PREREQUISITES:
- PowerShell 5.1+
- Code Signing certificate from a trusted Certificate Authority
- Certificate must be in Local Machine or Current User store, or provided as PFX

USAGE:
  .\Sign-QuickChecks.ps1                    # Sign with cert from store
  .\Sign-QuickChecks.ps1 -CertPath ".\cert.pfx" -CertPassword (ConvertTo-SecureString "password" -AsPlainText -Force)
  .\Sign-QuickChecks.ps1 -DryRun            # Show what would be signed

WHAT GETS SIGNED:
- *.ps1 files (scripts)
- *.psm1 files (modules)
- *.psd1 files (module manifests)

WHY SIGN?
- Verifies script integrity
- Prevents tampering
- Establishes trust
- Required for some security policies

CERTIFICATE REQUIREMENTS:
- Template: Code Signing
- Extended Key Usage: Code Signing (1.3.6.1.5.5.7.3.3)
- Must be from trusted CA (e.g., DigiCert, Sectigo, GoDaddy)

AFTER SIGNING:
1. Test scripts still work
2. Distribute to users
3. Users may need to trust your publisher certificate

"@
    exit 0
}

$script:signCount = 0
$script:failCount = 0
$script:skipCount = 0

function Write-SignedLog {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "HH:mm:ss"
    $color = if ($Level -eq "ERROR") { "Red" } elseif ($Level -eq "WARN") { "Yellow" } else { "Gray" }
    Write-Host "[$ts] [$Level] $Message" -ForegroundColor $color
}

function Get-Certificate {
    <#
    .SYNOPSIS
        Gets the code signing certificate.
    #>
    
    # Try PFX file first
    if ($CertPath) {
        Write-SignedLog -Message "Loading certificate from PFX: $CertPath" -Level INFO
        
        if (-not $CertPassword) {
            $CertPassword = Read-Host "Enter PFX password" -AsSecureString
        }
        
        try {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
                $CertPath,
                $CertPassword,
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
            )
            return $cert
        } catch {
            Write-SignedLog -Message "Failed to load PFX: $($_.Exception.Message)" -Level ERROR
            return $null
        }
    }
    
    # Try local machine store
    Write-SignedLog -Message "Searching for Code Signing certificate in Local Machine store..." -Level INFO
    
    $cert = Get-ChildItem -Path Cert:\LocalMachine\My |
        Where-Object {
            $_.NotAfter -gt (Get-Date) -and
            $_.EnhancedKeyUsageList.ObjectIdentifier -contains "1.3.6.1.5.5.7.3.3"
        } | Sort-Object -Property NotAfter -Descending | Select-Object -First 1
    
    if ($cert) {
        Write-SignedLog -Message "Found certificate: $($cert.Subject)" -Level INFO
        return $cert
    }
    
    # Try current user store
    Write-SignedLog -Message "Searching for Code Signing certificate in Current User store..." -Level INFO
    
    $cert = Get-ChildItem -Path Cert:\CurrentUser\My |
        Where-Object {
            $_.NotAfter -gt (Get-Date) -and
            $_.EnhancedKeyUsageList.ObjectIdentifier -contains "1.3.6.1.5.5.7.3.3"
        } | Sort-Object -Property NotAfter -Descending | Select-Object -First 1
    
    if ($cert) {
        Write-SignedLog -Message "Found certificate: $($cert.Subject)" -Level INFO
        return $cert
    }
    
    Write-SignedLog -Message "No Code Signing certificate found." -Level ERROR
    Write-SignedLog -Message "Install a code signing certificate or provide -CertPath to PFX file." -Level WARN
    return $null
}

function Set-AuthenticodeSignature {
    <#
    .SYNOPSIS
        Signs a single file.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        
        [Parameter(Mandatory=$true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    
    if ($DryRun) {
        Write-SignedLog -Message "[DRY RUN] Would sign: $FilePath" -Level INFO
        return $true
    }
    
    try {
        # Check if already signed
        $existingSig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
        if ($existingSig -and $existingSig.Status -eq "Valid") {
            Write-SignedLog -Message "Already signed: $FilePath" -Level INFO
            $script:skipCount++
            return $true
        }
        
        # Sign the file
        $sig = Set-AuthenticodeSignature -FilePath $FilePath -Certificate $Certificate -TimestampServer "http://timestamp.digicert.com" -ErrorAction Stop
        
        if ($sig.Status -eq "Valid") {
            Write-SignedLog -Message "Signed: $FilePath" -Level INFO
            $script:signCount++
            return $true
        } else {
            Write-SignedLog -Message "Signature status: $($sig.Status) for $FilePath" -Level WARN
            return $false
        }
    } catch {
        Write-SignedLog -Message "Failed to sign $FilePath : $($_.Exception.Message)" -Level ERROR
        $script:failCount++
        return $false
    }
}

function Get-ScriptFiles {
    <#
    .SYNOPSIS
        Gets all signable files from the module path.
    #>
    param([string]$Path)
    
    $files = @()
    
    # Get ps1, psm1, psd1 files
    $files += Get-ChildItem -Path $Path -Recurse -Filter "*.ps1" -ErrorAction SilentlyContinue
    $files += Get-ChildItem -Path $Path -Recurse -Filter "*.psm1" -ErrorAction SilentlyContinue
    $files += Get-ChildItem -Path $Path -Recurse -Filter "*.psd1" -ErrorAction SilentlyContinue
    
    return $files
}

# Main execution
Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║       IdentityFirst QuickChecks - Script Signing          ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host ""

if ($DryRun) {
    Write-Host "  MODE: DRY RUN (no changes will be made)" -ForegroundColor Yellow
}

Write-Host "  Module Path: $ModulePath" -ForegroundColor Gray
Write-Host ""

# Get certificate
$certificate = Get-Certificate
if (-not $certificate) {
    Write-Host ""
    Write-SignedLog -Message "Cannot proceed without a valid certificate." -Level ERROR
    exit 1
}

Write-Host ""
Write-SignedLog -Message "Certificate: $($certificate.Subject)" -Level INFO
Write-SignedLog -Message "Expires: $($certificate.NotAfter.ToString('yyyy-MM-dd'))" -Level INFO
Write-Host ""

# Get all files to sign
$files = Get-ScriptFiles -Path $ModulePath
Write-SignedLog -Message "Found $($files.Count) files to process" -Level INFO
Write-Host ""

# Process files
foreach ($file in $files) {
    $null = Set-AuthenticodeSignature -FilePath $file.FullName -Certificate $certificate
}

# Summary
Write-Host ""
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Signing Complete" -ForegroundColor White
Write-Host "════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Signed:   $script:signCount" -ForegroundColor $(if ($script:signCount -gt 0) { "Green" } else { "Gray" })
Write-Host "  Skipped:  $script:skipCount" -ForegroundColor Gray
Write-Host "  Failed:   $script:failCount" -ForegroundColor $(if ($script:failCount -gt 0) { "Red" } else { "Gray" })
Write-Host ""

if ($DryRun) {
    Write-SignedLog -Message "Run without -DryRun to actually sign the files." -Level WARN
}

if ($script:failCount -gt 0) {
    Write-SignedLog -Message "Some files failed to sign. Check errors above." -Level ERROR
    exit 1
}

Write-SignedLog -Message "All done!" -Level INFO
