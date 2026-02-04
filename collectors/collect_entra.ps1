# Entra collector: emits normalized JSON array of `entra.user` evidence objects
try {
    $out = @()
    if (Get-Module -ListAvailable -Name Microsoft.Graph.Identity.DirectoryManagement) {
        try {
            Import-Module Microsoft.Graph.Identity.DirectoryManagement -ErrorAction Stop
            Connect-MgGraph -Scopes "User.Read.All" -ErrorAction Stop | Out-Null
            $mgUsers = Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,AccountEnabled,LastSignInDateTime -ErrorAction SilentlyContinue
            foreach ($u in $mgUsers) {
                $obj = [pscustomobject]@{
                    type = 'entra.user'
                    id = $u.Id
                    displayName = $u.DisplayName
                    upn = $u.UserPrincipalName
                    accountEnabled = $u.AccountEnabled
                    lastSignIn = if ($u.LastSignInDateTime) { $u.LastSignInDateTime.ToString('o') } else { $null }
                    signals = @{ mfaRegistered = $false; isPrivileged = $false; pimEligible = $false }
                    source = @{ collector = 'EntraID'; collectedAt = (Get-Date).ToString('o') }
                }
                $out += $obj
            }
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        } catch {
            # Graph not connected/permissioned - emit nothing
        }
    }
    if ($out.Count -gt 0) { $out | ConvertTo-Json -Depth 6 } else { Write-Output "[]" }
} catch {
    Write-Output "[]"
}
