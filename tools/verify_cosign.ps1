param(
    [Parameter(Mandatory=$true)][string]$ArtifactPath,
    [string]$RekorUrl = 'https://rekor.sigstore.dev'
)

if (-not (Test-Path $ArtifactPath)) { Write-Error "Artifact not found: $ArtifactPath"; exit 2 }

$cosignExe = Join-Path $env:TEMP 'cosign.exe'
if (-not (Test-Path $cosignExe)) {
    Write-Output "Downloading cosign to: $cosignExe"
    try {
        Invoke-WebRequest -Uri 'https://github.com/sigstore/cosign/releases/latest/download/cosign-windows-amd64.exe' -OutFile $cosignExe -UseBasicParsing -ErrorAction Stop
    } catch {
        Write-Error "Failed to download cosign: $($_.Exception.Message)"; exit 3
    }
}

Write-Output "Verifying artifact with cosign (keyless): $ArtifactPath"
try {
    & $cosignExe verify --keyless --rekor $RekorUrl $ArtifactPath 2>&1 | Write-Output
    if ($LASTEXITCODE -eq 0) { Write-Output "Verification succeeded." } else { Write-Error "Verification failed (exit $LASTEXITCODE)"; exit $LASTEXITCODE }
} catch {
    Write-Error "cosign verification failed: $($_.Exception.Message)"; exit 4
}
