param(
    [string]$ReleasePath = '.',
    [switch]$FailOnMismatch
)

Set-StrictMode -Version Latest

$releaseRoot = Resolve-Path $ReleasePath
Write-Output "Verifying release at: $releaseRoot"

$sumFile = Join-Path $releaseRoot 'SHA256SUMS.txt'
if (-not (Test-Path $sumFile)) { Write-Warning "No SHA256SUMS.txt found in $releaseRoot"; exit 2 }

$mismatches = @()
Get-Content $sumFile | ForEach-Object {
    if (-not ($_ -match '^([A-Fa-f0-9]{64})\s{2}(.+)$')) { return }
    $hash = $matches[1]
    $rel = $matches[2]
    $file = Join-Path $releaseRoot $rel
    if (-not (Test-Path $file)) { $mismatches += [PSCustomObject]@{File=$rel; Issue='Missing'}; return }
    $h = Get-FileHash -Path $file -Algorithm SHA256
    if ($h.Hash -ne $hash) { $mismatches += [PSCustomObject]@{File=$rel; Issue='HashMismatch'} }
}

if ($mismatches.Count -eq 0) {
    Write-Output "All checksums match. Release integrity OK."
    exit 0
} else {
    Write-Error "Checksum verification failed for $($mismatches.Count) file(s):"
    $mismatches | Format-Table -AutoSize
    if ($FailOnMismatch) { exit 3 } else { exit 1 }
}

# If cosign verification helper exists and there are zip artifacts, try to verify cosign signatures
$cosignHelper = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'verify_cosign.ps1'
if (Test-Path $cosignHelper) {
    $zips = Get-ChildItem -Path $releaseRoot -Filter '*.zip' -File -ErrorAction SilentlyContinue
    foreach ($z in $zips) {
        Write-Output "Running cosign verification for: $($z.FullName)"
        try {
            pwsh -NoProfile -ExecutionPolicy Bypass -File $cosignHelper -ArtifactPath $z.FullName
            if ($LASTEXITCODE -ne 0) { Write-Error "cosign verification failed for $($z.Name)"; exit 4 }
        } catch {
            Write-Warning "cosign verify error for $($z.Name): $($_.Exception.Message)"
        }
    }
}
