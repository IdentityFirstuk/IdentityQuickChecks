<#
.SYNOPSIS
    Installs IdentityFirst QuickChecks PowerShell modules with certificate trust.

.DESCRIPTION
    This script installs the IdentityFirst QuickChecks modules and configures
    the system to trust the self-signed code signing certificate for script
    integrity verification.

.NOTES
    File Name      : Install-QuickChecks.ps1
    Prerequisite   : PowerShell 5.1 or 7+
    Author         : IdentityFirst Ltd
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$InstallPath = "$env:ProgramData\IdentityFirst\QuickChecks",
    
    [Parameter()]
    [switch]$InstallModules,
    
    [Parameter()]
    [switch]$TrustCertificate,
    
    [Parameter()]
    [switch]$Force
)

# Certificate configuration
$Script:RootCAThumbprint = '602A77B6D1CAC3C6AD875CBED65A8D227BF77189'
$Script:RootCASubject = 'CN=IdentityFirst Root CA'
$Script:CertPath = Join-Path -Path $PSScriptRoot -ChildPath 'IdentityFirst-Root-CA.cer'

function Install-RootCertificate {
    <#
    .SYNOPSIS
        Installs the IdentityFirst Root CA certificate to the local machine trust store.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CertificatePath,
        
        [Parameter()]
        [string]$Thumbprint
    )
    
    begin {
        Write-Verbose "[Install-RootCertificate] Starting certificate installation..."
    }
    
    process {
        try {
            # Check if running as administrator
            $isAdmin = Test-AdministratorRole
            
            if (-not $isAdmin) {
                Write-Warning "Administrator privileges required to install certificate to Local Machine store."
                Write-Warning "Run as administrator or use -Force to attempt installation to Current User store."
                return $false
            }
            
            # Check if certificate file exists
            if (-not (Test-Path -Path $CertificatePath -PathType Leaf)) {
                Write-Error "Certificate file not found: $CertificatePath"
                return $false
            }
            
            # Check if certificate is already installed
            $existingCert = Get-ChildItem -Path 'Cert:\LocalMachine\Root' | 
                Where-Object { $_.Thumbprint -eq $Thumbprint } |
                Select-Object -First 1
            
            if ($existingCert) {
                Write-Host "[✓] Root CA certificate already installed." -ForegroundColor Green
                Write-Verbose "  Thumbprint: $($existingCert.Thumbprint)"
                Write-Verbose "  Subject: $($existingCert.Subject)"
                return $true
            }
            
            # Import the certificate
            Write-Host "[*] Installing Root CA certificate..." -ForegroundColor Cyan
            $cert = Import-Certificate -FilePath $CertificatePath -CertStoreLocation 'Cert:\LocalMachine\Root' -ErrorAction Stop
            
            if ($cert) {
                Write-Host "[✓] Root CA certificate installed successfully." -ForegroundColor Green
                Write-Verbose "  Thumbprint: $($cert.Thumbprint)"
                Write-Verbose "  Subject: $($cert.Subject)"
                Write-Verbose "  Valid From: $($cert.NotBefore)"
                Write-Verbose "  Valid To: $($cert.NotAfter)"
                return $true
            }
            else {
                Write-Error "Failed to install Root CA certificate."
                return $false
            }
        }
        catch {
            Write-Error "Error installing certificate: $($_.Exception.Message)"
            return $false
        }
    }
    
    end {
        Write-Verbose "[Install-RootCertificate] Completed."
    }
}

function Install-QuickChecksModules {
    <#
    .SYNOPSIS
        Installs IdentityFirst QuickChecks modules to the system.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DestinationPath,
        
        [Parameter()]
        [switch]$Force
    )
    
    begin {
        Write-Verbose "[Install-QuickChecksModules] Starting module installation..."
    }
    
    process {
        try {
            # Create destination directory
            if (-not (Test-Path -Path $DestinationPath -PathType Container)) {
                Write-Host "[*] Creating installation directory: $DestinationPath" -ForegroundColor Cyan
                New-Item -Path $DestinationPath -ItemType Directory -Force | Out-Null
            }
            
            # Define module folders to install
            $moduleFolders = @(
                'IdentityQuickChecks',
                'IdentityAssumptionQuickChecks',
                'IdentityBoundaryQuickChecks',
                'IdentityTrustQuickChecks'
            )
            
            $sourceRoot = Join-Path -Path $PSScriptRoot -ChildPath '..'
            
            foreach ($folder in $moduleFolders) {
                $sourcePath = Join-Path -Path $sourceRoot -ChildPath $folder
                $destPath = Join-Path -Path $DestinationPath -ChildPath $folder
                
                if (Test-Path -Path $sourcePath -PathType Container) {
                    if ((Test-Path -Path $destPath -PathType Container) -and -not $Force) {
                        Write-Host "[✓] $folder already installed (use -Force to reinstall)" -ForegroundColor Yellow
                    }
                    else {
                        Write-Host "[*] Installing $folder..." -ForegroundColor Cyan
                        Copy-Item -Path "$sourcePath\*" -Destination $destPath -Recurse -Force -ErrorAction Stop
                        Write-Host "[✓] $folder installed" -ForegroundColor Green
                    }
                }
            }
            
            # Install module manifests
            $moduleFiles = Get-ChildItem -Path $DestinationPath -Filter '*.psd1' -Recurse -ErrorAction SilentlyContinue
            Write-Host "[*] Found $($moduleFiles.Count) module files" -ForegroundColor Cyan
            
            # Return success
            return $true
        }
        catch {
            Write-Error "Error installing modules: $($_.Exception.Message)"
            return $false
        }
    }
    
    end {
        Write-Verbose "[Install-QuickChecksModules] Completed."
    }
}

function Test-AdministratorRole {
    <#
    .SYNOPSIS
        Tests if the current PowerShell session is running with administrator privileges.
    #>
    $currentUser = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList (
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ScriptDirectory {
    <#
    .SYNOPSIS
        Gets the directory containing the current script.
    #>
    if ($PSVersionTable.PSVersion.Major -ge 3) {
        return $PSScriptRoot
    }
    else {
        return Split-Path -Path $MyInvocation.MyCommand.Path -Parent
    }
}

# Main execution
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║       IdentityFirst QuickChecks Installation Script         ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Get script directory
$scriptDir = Get-ScriptDirectory
Write-Verbose "Script directory: $scriptDir"

# Determine certificate path
if (Test-Path -Path $CertPath -PathType Leaf) {
    Write-Verbose "Certificate found at: $CertPath"
}
else {
    # Try alternate location
    $altCertPath = Join-Path -Path $scriptDir -ChildPath '..\IdentityFirst-Root-CA.cer'
    if (Test-Path -Path $altCertPath -PathType Leaf) {
        $CertPath = $altCertPath
        Write-Verbose "Certificate found at alternate location: $CertPath"
    }
    else {
        Write-Warning "Certificate file not found. Certificate trust will be skipped."
        Write-Warning "Expected: $CertPath"
    }
}

# Install Root CA certificate if requested
if ($TrustCertificate -or $InstallModules) {
    if ($CertPath -and (Test-Path -Path $CertPath -PathType Leaf)) {
        Write-Host "[*] Installing Root CA Certificate..." -ForegroundColor Cyan
        $certResult = Install-RootCertificate -CertificatePath $CertPath -Thumbprint $RootCAThumbprint
        if (-not $certResult) {
            Write-Warning "Certificate installation failed. Scripts may show untrusted publisher warnings."
        }
    }
}

# Install modules if requested
if ($InstallModules) {
    Write-Host ""
    Write-Host "[*] Installing QuickChecks Modules..." -ForegroundColor Cyan
    $moduleResult = Install-QuickChecksModules -DestinationPath $InstallPath -Force:$Force
}

# Summary
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                       Installation Summary                    ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Install Path: $InstallPath"
Write-Host ""
Write-Host "  Next Steps:"
Write-Host "  1. Open PowerShell as Administrator"
Write-Host "  2. Run: Install-QuickChecks -InstallModules -TrustCertificate"
Write-Host "  3. Import a module: Import-Module IdentityQuickChecks"
Write-Host ""
Write-Host "  Documentation: $InstallPath\README.md"
Write-Host ""

# Export functions for manual use
Export-ModuleMember -Function @(
    'Install-RootCertificate',
    'Install-QuickChecksModules',
    'Test-AdministratorRole'
) -ErrorAction SilentlyContinue

# SIG # Begin signature block
# MIIcFwYJKoZIhvcNAQcCoIIcCDCCHAQCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBl7v8XEar19U92
# Bx1+ALvZ/eTTmdZdW+a3E3zrS7rbyqCCFlgwggMaMIICAqADAgECAhBf+irPCn8a
# h0egI+kXM/O8MA0GCSqGSIb3DQEBCwUAMCUxIzAhBgNVBAMMGklkZW50aXR5Rmly
# c3QgQ29kZSBTaWduaW5nMB4XDTI2MDIwNjEzMzQ1NloXDTMxMDIwNjEzNDQ1Nlow
# JTEjMCEGA1UEAwwaSWRlbnRpdHlGaXJzdCBDb2RlIFNpZ25pbmcwggEiMA0GCSqG
# SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDeIxBFnRbFAFXNkoZ2ZGEfjKtc5nqrodwc
# cKV2S7cpHmKT3usCJnHbzQv0tE220IOuSWO7d/Od2q6k+J5osRngkWu5+4ujklFa
# AZP2pXCxLQBYT4fhB+C7p6ULFYMYPmvaKaSsd/5RplW+LPuIaHr+YdnZDabHVvZR
# hWz84cKSm1S2I8ekeZF7JDHMlQvWWW1z7mzY+uCtmoiTKEvWfr7O1baBXwyq40uI
# oRoR4IV4l9z59rT8HG6jsD39h30e7r33cnbP9AJR8max8ocOlSaWsx6Ey2djT/ft
# CI/PYHZPqdr3HwmAZxRT//8Q5mDtt5Bk3iYA64x696V9vo7tyHAhAgMBAAGjRjBE
# MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQU
# AApdetN2wXAWY01eV4BKyETsUgowDQYJKoZIhvcNAQELBQADggEBAAqUQnXgw+B/
# 38QTmxTiTCTBDIsQCYxAl88wraWtISY+w4xVc9Z5pST4OovkTZK2qRKp8RS6kpND
# gGnaRlN5KvIp3hwkXFQrlHp1W9KYSKzer1/w80CcuWwGu6TSp2LaFf7pwDGodC+2
# wFXD3qlGiePZPqz4TlGugouYZ6giii4E7g9q+vAxhMTZ7zB/q4WS5iW49ikWBVNu
# PethyeI3GMZTIq0s1R7k5BkNixZ97LILmfWzYkWkc5cawOwb3bhpg8d4bsBrHb+M
# JY2czc8knu7iJI0KXjXk+G4vQ0Lh1uWOnxm5ptBKsK5uve0qFH60b3MHN7RRlazB
# zqcr2XUvIdMwggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3
# DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAX
# BgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3Vy
# ZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIx
# CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3
# dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBH
# NDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIw
# aTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLK
# EdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4Tm
# dDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembu
# d8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnD
# eMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1
# XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVld
# QnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTS
# YW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSm
# M9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzT
# QRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6Kx
# fgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/
# MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv
# 9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBr
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUH
# MAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJ
# RFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYG
# BFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72a
# rKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFID
# yE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/o
# Wajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv
# 76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30
# fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQwgga0MIIE
# nKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0y
# NTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqG
# SIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51N
# rY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5ba
# p+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf7
# 7S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF
# 2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80Fio
# cSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzV
# yhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl
# 92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGP
# RdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//
# Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4O
# Lu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM
# 7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4E
# FgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5n
# P+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcG
# CCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQu
# Y29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGln
# aUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8v
# Y3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNV
# HSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIB
# ABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM
# 0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqW
# Gd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr
# 0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35
# k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKq
# MVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiy
# fTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDU
# phPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTj
# d6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2Z
# yJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWC
# nb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQ
# CoDvGEuN8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0
# ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1
# MDYwNDAwMDAwMFoXDTM2MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNV
# BAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNB
# NDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEB
# BQADggIPADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMy
# qJnfFNZx+wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4Q
# KpVD7dvNZh6wW2R6kSu9RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8
# SOhPUWlLnh00Cll8pjrUcCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtU
# DVHRXdmncOOMA3CoB/iUSROUINDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5KqCv
# pSduSwhwUmotuQhcg9tw2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1
# Hf2JNMVL4Q1OpbybpMe46YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdoRORV
# bPR1VVnDuSeHVZlc4seAO+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUoHLWn
# qWU3dCCyFG1roSrgHjSHlq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7rlRyT
# laCCfw7aSUROwnu7zER6EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K096V1hE0
# yZIXe+giAwW00aHzrDchIc2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8+3mn
# AgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39/dfz
# kXFjGVBDz2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNV
# HQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEB
# BIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYI
# KwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNV
# HR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYD
# VR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4IC
# AQBlKq3xHCcEua5gQezRCESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fN
# aNmFj6Eh8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim
# 8/9yJmZSe2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUqW4da
# IqToXFE/JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMnxYOX
# 8VBRKe1uNnzQVTeLni2nHkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1
# d0IbX6Wq8/gVutDojBIFeRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AWcIQf
# VjnzrvwiCZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJgddJ3
# 5XTxfUlQ+8Hggt8l2Yv7roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV1S3C
# rWqZzBt1R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVccAvlK
# V9jEnstrniLvUxxVZE/rptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8atufk
# +EMF/cWuiC7POGT75qaL6vdCvHlshtjdNXOCIUjsarfNZzGCBRUwggURAgEBMDkw
# JTEjMCEGA1UEAwwaSWRlbnRpdHlGaXJzdCBDb2RlIFNpZ25pbmcCEF/6Ks8KfxqH
# R6Aj6Rcz87wwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAA
# oQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4w
# DAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgYfszWus6YTT2fb5fWm2+qIsZ
# gGFaQ5UydTr0z7DJ0SUwDQYJKoZIhvcNAQEBBQAEggEAKFtNwNJCtfmXP4kAouiS
# zVh+jfFLywcVNr5NK4HOdni27y+pJH8rr37v/SuB2Lont8z0zncFzAT5F6zl0Kz0
# Xg4MzBQhuB3IyUoiF3Z19tgIKXkYb969nfo+IIqNXgv87fCG3J8lRHfppCTbW5Bs
# BS94sKs5K0ZVtzIl2PWV2k7KLjTqUg3BPf/PRJPLKUXAwOaum8UAhGY27cebxCZd
# fjDRf6MHfBIF/1KV9jD//E7/ZlZjtiLWj/VJsNpuDPY3rCEd9XgGbwr6Iyg8PWTx
# OlPXQ8F08sXK4sQF/TYzXreRvr7SJXvCYXWrp3hUiKCRZ62+bJNAG9inNaTT60qg
# AqGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVT
# MRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1
# c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA
# 7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJ
# KoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAyMDYxMzQ0NTZaMC8GCSqGSIb3
# DQEJBDEiBCD9ndzGojEyJkFVckI9OKb+larfpoGFt8HOSPVtJ59teDANBgkqhkiG
# 9w0BAQEFAASCAgBrM9/eK+3PHy1XlmCo3s3vjZPoUZjLrK51WtYtM2vDa56lvkW6
# Nz+TWKQh9jprQKsK1OvL/XNGZvEZ4DS6i/E2W7B1eXy8j5BDUcZuHNt35Y9EaXzz
# eOyVgYlIpwJ+R4U9k4qL7nFPNeJz8yl2v7lrQCrvTDviOdphMIxr5k25ds8zt9s1
# sTYhqQjyBv034x4pPxilTm1FOBnTvY9bmmoih5XpCA5g20YiTcWuXMbPTfFfRjwr
# VibU1+6keneta4RoG7fzJMrZldoE0uXGNMn2X0EvczRxbW5M3P+NtfZNROlF6wZx
# 2dJpyvalrVPmotnsRRB7mVoI60DMA3WkWuJUKsdpJQYXkXGziSospaLAcM1zvXFP
# KtlNkxoT5OX/xgfBeZ17Wb99xO6YVwwjXH/P/GwVsc/c76s56qc/C6+skb7cy8Ui
# h1UPlowX811zdaUTF2P/J5RbBH+K4YbZQm0fYLlErbznm9ILKi3currjhy+CPxST
# oHmixfyVxIoYNn5bjOTO7+hC+pa0bEDR+57T3+RN+wCFTrc1b3t6rxMUZAUVKNik
# vQ9ULODKLUV6chSuWR3F/xnXvPO88BAf5KAs2ehXWYvfinq92Ws1SoBuRWVn3s0B
# z/wl1RRCcLlSyzqI3yB8ZPS7F0kJvzGNlacRmWZBvdAMHay3KjS5dxTDKg==
# SIG # End signature block
