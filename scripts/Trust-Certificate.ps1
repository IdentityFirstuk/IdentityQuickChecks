# Trust-Certificate.ps1
# Adds the self-signed certificate to Trusted People store

$certPath = ".\cert.pfx"
$password = ConvertTo-SecureString -String "password" -AsPlainText -Force

# Load the certificate
$cert = Get-PfxCertificate -FilePath $certPath -Password $password

# Add to Trusted People store (Local Machine)
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
    [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPeople,
    [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
)
$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$store.Add($cert)
$store.Close()

Write-Host "Certificate added to Local Machine Trusted People store" -ForegroundColor Green

# Also add to Current User store for current session
$userStore = New-Object System.Security.Cryptography.X509Certificates.X509Store(
    [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPeople,
    [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
)
$userStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$userStore.Add($cert)
$userStore.Close()

Write-Host "Certificate added to Current User Trusted People store" -ForegroundColor Green

Write-Host ""
Write-Host "Certificate details:" -ForegroundColor Yellow
Write-Host "  Subject: $($cert.Subject)" -ForegroundColor Gray
Write-Host "  Issuer: $($cert.Issuer)" -ForegroundColor Gray
Write-Host "  Thumbprint: $($cert.Thumbprint)" -ForegroundColor Gray
Write-Host "  Valid from: $($cert.NotBefore)" -ForegroundColor Gray
Write-Host "  Valid to: $($cert.NotAfter)" -ForegroundColor Gray
Write-Host ""
Write-Host "Run .\Sign-Scripts.ps1 -CheckOnly to verify signatures" -ForegroundColor Cyan
