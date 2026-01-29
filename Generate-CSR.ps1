<#
.SYNOPSIS
    Generate Code Signing Certificate Request (CSR).

.DESCRIPTION
    Creates a Certificate Signing Request (CSR) and private key for code signing.
    The CSR can be submitted to a Certificate Authority (CA) to obtain a signed certificate.

.OUTPUTS
    - CSR file (.csr)
    - Private key file (.key)

.NOTES
    Author: IdentityFirst Ltd
    Requirements: OpenSSL or PowerShell 7+

.USAGE
    # Generate CSR
    .\Generate-CSR.ps1

    # Generate CSR with custom details
    .\Generate-CSR.ps1 -Organization "My Company" -CommonName "My Code Signing"
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = ".",

    [Parameter()]
    [string]$Organization = "IdentityFirst Ltd",

    [Parameter()]
    [string]$OrganizationalUnit = "IT",

    [Parameter()]
    [string]$CommonName = "IdentityFirst QuickChecks",

    [Parameter()]
    [string]$Country = "GB",

    [Parameter()]
    [string]$State = "London",

    [Parameter()]
    [string]$Locality = "London",

    [Parameter()]
    [string]$Email = "mark.ahearne@identityfirst.net",

    [Parameter()]
    [int]$KeySize = 2048,

    [Parameter()]
    [switch]$Help
)

if ($Help) {
    Write-Host @"
IdentityFirst QuickChecks - CSR Generator
==========================================

Generates a Certificate Signing Request (CSR) for code signing certificates.

USAGE:
  .\Generate-CSR.ps1                          # Default settings
  .\Generate-CSR.ps1 -OutputPath ".\certs"    # Custom output
  .\Generate-CSR.ps1 -KeySize 4096            # Stronger key (4096-bit)

OUTPUT FILES:
  identityfirst-codesign.csr    - Certificate Signing Request
  identityfirst-codesign.key    - Private key (KEEP SECURE!)

WHAT TO DO NEXT:
1. Submit the .csr file to your Certificate Authority
2. CA will issue a signed certificate (.cer/.crt)
3. Combine certificate + private key into .pfx
4. Use with Sign-QuickChecks.ps1

"@
    exit 0
}

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║       IdentityFirst QuickChecks - CSR Generator            ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check for OpenSSL
$opensslPath = $null

# Try common OpenSSL locations
$opensslLocations = @(
    "openssl.exe",
    "C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
    "C:\Program Files (x86)\OpenSSL-Win64\bin\openssl.exe",
    "/usr/bin/openssl"
)

foreach ($loc in $opensslLocations) {
    try {
        $result = Get-Command $loc -ErrorAction SilentlyContinue
        if ($result) {
            $opensslPath = $result.Source
            break
        }
    } catch { }
}

if (-not $opensslPath) {
    Write-Host "OpenSSL not found. Generating CSR using PowerShell..." -ForegroundColor Yellow
    Write-Host ""
    
    # Generate using PowerShell (New-SelfSignedCertificate doesn't export CSR directly)
    # We'll create a config file for external CSR generation
    
    $configContent = @"
[req]
default_bits = $KeySize
prompt = no
default_md = sha256
distinguished_name = dn

[dn]
C = $Country
ST = $State
L = $Locality
O = $Organization
OU = $OrganizationalUnit
CN = $CommonName
emailAddress = $Email
"@
    
    $configPath = Join-Path $OutputPath "openssl.cnf"
    $configContent | Out-File -FilePath $configPath -Encoding UTF8
    
    Write-Host "OpenSSL configuration created: $configPath" -ForegroundColor Gray
    Write-Host ""
    Write-Host "To generate CSR with OpenSSL, run:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  openssl req -new -newkey rsa:$KeySize -nodes -keyout identityfirst.key -out identityfirst.csr -config openssl.cnf" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Or install OpenSSL and rerun this script." -ForegroundColor Gray
    
    exit 0
}

# Generate CSR using OpenSSL
Write-Host "Using OpenSSL at: $opensslPath" -ForegroundColor Gray
Write-Host ""

# Create output directory if needed
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Create OpenSSL config
$configContent = @"
[req]
default_bits = $KeySize
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_ext

[dn]
C = $Country
ST = $State
L = $Locality
O = $Organization
OU = $OrganizationalUnit
CN = $CommonName
emailAddress = $Email

[v3_ext]
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = codeSigning
"@

$configPath = Join-Path $OutputPath "identityfirst-openssl.cnf"
$configContent | Out-File -FilePath $configPath -Encoding UTF8

$csrPath = Join-Path $OutputPath "identityfirst-codesign.csr"
$keyPath = Join-Path $OutputPath "identityfirst-codesign.key"

# Generate private key and CSR
Write-Host "Generating $KeySize-bit RSA private key..." -ForegroundColor Gray

try {
    $env:OPENSSL_CONF = $configPath
    
    # Generate key and CSR
    $args = @("req", "-newkey", "rsa:$KeySize", "-nodes", "-keyout", $keyPath, "-out", $csrPath, "-subj", "/C=$Country/ST=$State/L=$Locality/O=$Organization/OU=$OrganizationalUnit/CN=$CommonName/emailAddress=$Email")
    $process = Start-Process -FilePath $opensslPath -ArgumentList $args -Wait -PassThru -NoNewWindow
    
    if ($process.ExitCode -eq 0 -and (Test-Path $csrPath)) {
        Write-Host "✓ CSR generated successfully!" -ForegroundColor Green
        Write-Host ""
        Write-Host "Files created:" -ForegroundColor Gray
        Write-Host "  CSR:  $csrPath" -ForegroundColor Cyan
        Write-Host "  Key:  $keyPath" -ForegroundColor Cyan
        Write-Host ""
        
        # Show CSR contents
        Write-Host "CSR Contents:" -ForegroundColor Gray
        Write-Host ("─" * 60) -ForegroundColor Gray
        Get-Content $csrPath | Write-Host -ForegroundColor DarkGray
        Write-Host ("─" * 60) -ForegroundColor Gray
        Write-Host ""
        
        Write-Host "NEXT STEPS:" -ForegroundColor Yellow
        Write-Host "1. Submit the CSR file to your Certificate Authority" -ForegroundColor Gray
        Write-Host "2. CA will issue a signed certificate (.cer/.crt)" -ForegroundColor Gray
        Write-Host "3. Convert to PFX: openssl pkcs12 -export -in cert.cer -inkey identityfirst.key -out identityfirst.pfx" -ForegroundColor Gray
        Write-Host ""
        Write-Host "⚠️  Keep your private key (.key) secure!" -ForegroundColor Red
    } else {
        Write-Host "✗ Failed to generate CSR" -ForegroundColor Red
    }
} catch {
    Write-Host "✗ Error: $($_.Exception.Message)" -ForegroundColor Red
}

# Clean up config
Remove-Item $configPath -ErrorAction SilentlyContinue
