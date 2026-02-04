<#
.SYNOPSIS
Fetch a base64-encoded PFX blob from HashiCorp Vault (KV v1 or v2) and write it to disk.

.DESCRIPTION
This helper reads `VAULT_ADDR` and `VAULT_TOKEN` from environment variables (or accepts
`-VaultAddr`/`-VaultToken`) and fetches the secret at `-SecretPath`.

The secret should contain a field named `pfx` which is a base64-encoded representation
of the PFX file. For KV v2 the script will call `/v1/<mount>/data/<path>` and look
under `.data.data`. For KV v1 it will call `/v1/<path>` and inspect `.data`.

This is intended for CI. The script writes the PFX to the path specified by `-OutputPath`
and will exit non-zero on errors. It does not keep the PFX in persistent storage by default
— CI pipelines should delete the file after use.

USAGE
pwsh -NoProfile -File .\dev-tools\vault\get_pfx_from_vault.ps1 -SecretPath secret/ci/identityfirst/pfx -OutputPath C:\temp\identityfirst.pfx
# or rely on env vars: $env:VAULT_ADDR and $env:VAULT_TOKEN
# then call: pwsh -File .\dev-tools\vault\get_pfx_from_vault.ps1 -SecretPath secret/ci/identityfirst/pfx
#
# NOTE: the secret value should contain a property `pfx` with the base64 content.
# Example (KV v2 payload): { "data": { "data": { "pfx": "<base64>" } } }
#
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$SecretPath,

    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "identityfirst-codesign.pfx",

    [Parameter(Mandatory=$false)]
    [string]$VaultAddr = $env:VAULT_ADDR,

    [Parameter(Mandatory=$false)]
    [string]$VaultToken = $env:VAULT_TOKEN
)

if (-not $VaultAddr) {
    Write-Error "Vault address not provided. Set VAULT_ADDR or pass -VaultAddr."; exit 2
}
if (-not $VaultToken) {
    Write-Error "Vault token not provided. Set VAULT_TOKEN or pass -VaultToken."; exit 2
}

function Get-VaultSecret {
    param($addr, $token, $path)

    # Try KV v2 first: attempt to GET /v1/<mount>/data/<path>
    $v2url = "$addr/v1/$path"
    try {
        $r = Invoke-RestMethod -Method Get -Uri $v2url -Headers @{ 'X-Vault-Token' = $token } -ErrorAction Stop
        return $r
    } catch {
        # Try alternative v2 structure: if path omitted mount, try adding /data/
    }

    # If the path doesn't include 'data/', attempt to call with /data/
    if ($path -notmatch '/data/') {
        $v2url2 = "$addr/v1/$($path -replace '^/+','')/data"
        try {
            $r2 = Invoke-RestMethod -Method Get -Uri $v2url2 -Headers @{ 'X-Vault-Token' = $token } -ErrorAction Stop
            return $r2
        } catch {
            # Fall through to KV v1 attempt
        }
    }

    # KV v1 attempt
    $v1url = "$addr/v1/$path"
    try {
        $r3 = Invoke-RestMethod -Method Get -Uri $v1url -Headers @{ 'X-Vault-Token' = $token } -ErrorAction Stop
        return $r3
    } catch {
        throw "Unable to fetch secret from Vault. Tried: $v2url, $v2url2, $v1url. Error: $($_.Exception.Message)"
    }
}

Write-Output "Fetching secret from Vault: $SecretPath"
try {
    $resp = Get-VaultSecret -addr $VaultAddr -token $VaultToken -path $SecretPath
} catch {
    Write-Error $_; exit 3
}

# Extract base64 candidate from common payload shapes
$base64 = $null
if ($resp -and $resp.data -and $resp.data.data -and $resp.data.data.pfx) {
    $base64 = $resp.data.data.pfx
} elseif ($resp -and $resp.data -and $resp.data.pfx) {
    $base64 = $resp.data.pfx
} elseif ($resp -and $resp.pfx) {
    $base64 = $resp.pfx
} elseif ($resp -and $resp.data -and $resp.data.value) {
    $base64 = $resp.data.value
}

if (-not $base64) {
    Write-Error "No 'pfx' or compatible key found in Vault secret payload. Inspect the secret at path: $SecretPath"; exit 4
}

try {
    $bytes = [System.Convert]::FromBase64String($base64)
} catch {
    Write-Error "Failed to decode base64 PFX payload: $($_.Exception.Message)"; exit 5
}

try {
    [System.IO.File]::WriteAllBytes($OutputPath, $bytes)
    Write-Output "Wrote PFX to: $OutputPath"
} catch {
    Write-Error "Failed to write PFX to disk: $($_.Exception.Message)"; exit 6
}

exit 0
