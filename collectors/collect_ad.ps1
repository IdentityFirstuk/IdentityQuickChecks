# AD collector: emits normalized JSON array of `ad.user` evidence objects
try {
    $out = @()
    $adModule = Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue
    if ($adModule) {
        Import-Module ActiveDirectory -ErrorAction Stop
        $users = Get-ADUser -Filter * -Properties DisplayName,mail,LastLogonDate,Enabled -ErrorAction SilentlyContinue
        foreach ($u in $users) {
            $obj = [pscustomobject]@{
                type = 'ad.user'
                id = $u.SamAccountName
                displayName = $u.DisplayName
                upn = $u.mail
                accountEnabled = $u.Enabled
                lastSignIn = if ($u.LastLogonDate) { $u.LastLogonDate.ToString('o') } else { $null }
                signals = @{ onPrem = $true }
                source = @{ collector = 'ActiveDirectory'; collectedAt = (Get-Date).ToString('o') }
            }
            $out += $obj
        }
    }
    if ($out.Count -gt 0) { $out | ConvertTo-Json -Depth 6 } else { Write-Output "[]" }
} catch {
    Write-Output "[]"
}
