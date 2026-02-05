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

    # Sign with PFX file (recommended: pass SecureString or set IFQC_DEV_PFX_PASSWORD)
    .\Sign-QuickChecks.ps1 -CertPath ".\cert.pfx" -CertPassword (Read-Host "PFX password" -AsSecureString)

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
    ,
    [Parameter()]
    [pscredential]$CertCredential
)

if ($Help) {
    Write-Output @"
IdentityFirst QuickChecks - Script Signing Tool
================================================

This script digitally signs all PowerShell scripts in the QuickChecks module.

PREREQUISITES:
- PowerShell 5.1+
- Code Signing certificate from a trusted Certificate Authority
- Certificate must be in Local Machine or Current User store, or provided as PFX

USAGE:
  .\Sign-QuickChecks.ps1                    # Sign with cert from store
    .\Sign-QuickChecks.ps1 -CertPath ".\cert.pfx" -CertPassword (Read-Host "PFX password" -AsSecureString)
    .\Sign-QuickChecks.ps1 -CertPath ".\cert.pfx" -CertCredential (Get-Credential)
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
    $color = if ($Level -eq "ERROR") { "Red" } elseif ($Level -eq "WARN" -or $Level -eq 'WARNING') { "Yellow" } else { "Gray" }
    $line = "[$ts] [$Level] $Message"

    # Emit structured log object to pipeline for capture
    $obj = [PSCustomObject]@{
        Timestamp = (Get-Date).ToString('o')
        ShortTimestamp = $ts
        Level = $Level
        Message = $Message
        Text = $line
        Type = 'Signing'
    }
    Write-IFQC -InputObject $obj

    # Also write human-friendly colored output to console
    try {
        $oldColor = $null
        try { $oldColor = $host.UI.RawUI.ForegroundColor } catch { }
        try { $host.UI.RawUI.ForegroundColor = [System.ConsoleColor]::$color } catch { }
        Write-Output $line
        if ($oldColor -ne $null) { try { $host.UI.RawUI.ForegroundColor = $oldColor } catch { } }
    } catch {
        Write-Output $line
    }
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
            # If caller provided a PSCredential, prefer its `Password` (SecureString)
            if ($CertCredential -and -not $CertPassword) {
                $CertPassword = $CertCredential.Password
                Write-SignedLog -Message "Using PFX password from provided PSCredential" -Level INFO
            }
            # Prefer centralized env->SecureString helper
            $envSecure = $null
            try { Import-Module -Name Security\IdentityFirst.Security -ErrorAction SilentlyContinue } catch { }
            if (Get-Command -Name Get-SecureStringFromEnv -ErrorAction SilentlyContinue) {
                $envSecure = Get-SecureStringFromEnv -EnvVarName 'IFQC_DEV_PFX_PASSWORD'
            }
            if ($envSecure) {
                $CertPassword = $envSecure
                Write-SignedLog -Message "Using PFX password from IFQC_DEV_PFX_PASSWORD environment variable" -Level INFO
            } else {
                $CertPassword = Read-Host "Enter PFX password" -AsSecureString
            }
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
Write-SignedLog -Message "IdentityFirst QuickChecks - Script Signing" -Level INFO

if ($DryRun) {
    Write-SignedLog -Message "MODE: DRY RUN (no changes will be made)" -Level WARN
}

Write-SignedLog -Message "Module Path: $ModulePath" -Level INFO


# Get certificate
$certificate = Get-Certificate
# Certificate validation
if (-not $certificate) {
    Write-SignedLog -Message "Cannot proceed without a valid certificate." -Level ERROR
    exit 1
}

Write-SignedLog -Message "Certificate: $($certificate.Subject)" -Level INFO
Write-SignedLog -Message "Expires: $($certificate.NotAfter.ToString('yyyy-MM-dd'))" -Level INFO

# Get all files to sign
$files = Get-ScriptFiles -Path $ModulePath
Write-SignedLog -Message "Found $($files.Count) files to process" -Level INFO

# Process files
foreach ($file in $files) {
    $null = Set-AuthenticodeSignature -FilePath $file.FullName -Certificate $certificate
}

# Summary
Write-SignedLog -Message "Signing Complete" -Level INFO
Write-SignedLog -Message "Signed: $script:signCount; Skipped: $script:skipCount; Failed: $script:failCount" -Level INFO

if ($DryRun) {
    Write-SignedLog -Message "Run without -DryRun to actually sign the files." -Level WARN
}

if ($script:failCount -gt 0) {
    Write-SignedLog -Message "Some files failed to sign. Check errors above." -Level ERROR
    exit 1
}

Write-SignedLog -Message "All done!" -Level INFO
Write-Output ([PSCustomObject]@{ Signed = $script:signCount; Skipped = $script:skipCount; Failed = $script:failCount })

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAS7xbRv/VgI6cT
# rgv3jev/vj60XclwvTZOFXJwjuTG7qCCFlIwggMUMIIB/KADAgECAhBDR0HvMFNE
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
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgSYFFmUTJU0SS4T/bElcklGOEAuh2Jz9uSiao
# SBWlw4swDQYJKoZIhvcNAQEBBQAEggEAIpr6mEIgUl56LRRW9ue1puv3CG8ymb0Q
# zeJOnmkwWhvdVcbFC8ZcgqjqxWVnM5dSpi5d7vOZDvqypcxeiSjR3Z0rWchcMwc9
# 3LoqwJeRYGFLJbXdgG/dbfQ6cN/ei84r+szTRCgKpgt5zvKkd2cZDw5eiJqV9k/e
# FNvtSI2VltqKl+HEYY21jAwxS3S3T0T069wuaWNFxk+KcXliyZ0eiuwBeyGDgWQc
# V69HL6u0uYJNiv85ITjeCVeuaZrPuTYQNyJIum8Fb1MTw1vuBqLLkByhBf9nvvoh
# /v8GiKbOON4Fj7LWqGKdLLX+I7fOzK0l452eCE//+hNCLOx0mgN1/qGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjAyMDQxNjUyMTBaMC8GCSqGSIb3DQEJBDEiBCCF
# qCugfTEMv3NUr2AeEABy5XsjWPyo8Jc5BrRXebw72TANBgkqhkiG9w0BAQEFAASC
# AgCJAAFZBu1/s1aKxggmUX9rto0UBkZdo7GWj3xW70wZN0t4h3zkMnNC1ohR19/6
# C6Hw5xH33Xq4wtHUtYD8WFczWt7cZHi6axCd98udlM5nE7iMpKGh+lGaN1rU//aC
# 0nja1VzichOtcNEs/9p44jPGJB7JfXm5GAiynQElzCqE6whE/86ENbaEQXPCsZUZ
# 9S4/gtCQ/lL+bzvb/B+96K/tjnMSfu5iUlGt4eY4dftFbsvoxAUdXoqRM5NLR9jo
# aSr0XsOrk3/+EH/gMaGfbb2OnOof4vUMmtiMiEuozM27QJ9Ii/ejUW3nn3MBZMyn
# jBNGR9F1aDGVemEJM9XS7O+WPHWXGDyg8Qbv6lCME+7wqlAjkx44fLiknbjf5kI1
# zKL6P8vSl83aU7vEDHfEAYiBC7plD9hLh5y05UE25soS0uVQIyr12rNaXLSiHAjS
# VbnS7OAI+GKIfwKmROWLVYMiN6eqApXRskYlAPUAEdWbaWOUR8T3ZLC6enU4BN6Y
# j32zCVVyjuR2qAeHeYmki1HUoM157vEpeXBuvPh3rWfc7YJ/HJeuVIeJ4BZVjOEG
# CeiJvDshBdm1F7CbL12Z1VreGvFj3XFltnNenX+/e4FUBIRnySC+TbIx9w/cQxnq
# q1dlRPpfM9rvmr9sy7CKq5+gqg4kKMnD3L1bk/1uMxVz4A==
# SIG # End signature block
