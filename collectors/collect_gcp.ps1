# GCP collector: emits normalized JSON array of `gcp.serviceAccount` or `gcp.user` evidence objects
try {
    $out = @()
    if (Get-Command "gcloud" -ErrorAction SilentlyContinue) {
        $saJson = gcloud iam service-accounts list --format=json 2>$null
        if ($saJson) {
            $sas = $saJson | ConvertFrom-Json
            foreach ($s in $sas) {
                $obj = [pscustomobject]@{
                    type = 'gcp.serviceAccount'
                    id = $s.email
                    displayName = $s.displayName
                    upn = $s.email
                    accountEnabled = $true
                    lastSignIn = $null
                    signals = @{ }
                    source = @{ collector = 'GCP'; collectedAt = (Get-Date).ToString('o') }
                }
                $out += $obj
            }
        }
    } else {
        # Try module-based collection (not implemented)
    }

    if ($out.Count -gt 0) { $out | ConvertTo-Json -Depth 6 } else { Write-Output "[]" }
} catch {
    Write-Output "[]"
}
