# AWS collector: emits normalized JSON array of `aws.user` evidence objects
try {
    $out = @()
    $useCli = $false
    if (Get-Command "aws" -ErrorAction SilentlyContinue) { $useCli = $true }
    elseif (Get-Module -ListAvailable -Name AWS.Tools.IdentityManagement) { Import-Module AWS.Tools.IdentityManagement -ErrorAction SilentlyContinue }

    if ($useCli) {
        $userJson = aws iam list-users --output json 2>$null
        if ($userJson) {
            $users = $userJson | ConvertFrom-Json | Select-Object -ExpandProperty Users
            foreach ($u in $users) {
                $obj = [pscustomobject]@{
                    type = 'aws.user'
                    id = $u.UserName
                    displayName = $u.UserName
                    upn = $u.EmailAddress
                    accountEnabled = $true
                    lastSignIn = $null
                    signals = @{ mfaRegistered = $false }
                    source = @{ collector = 'AWS'; collectedAt = (Get-Date).ToString('o') }
                }
                $out += $obj
            }
        }
    } else {
        try {
            $users = Get-IAMUser -ErrorAction SilentlyContinue
            foreach ($u in $users) {
                $obj = [pscustomobject]@{
                    type = 'aws.user'
                    id = $u.UserName
                    displayName = $u.UserName
                    upn = $u.Arn
                    accountEnabled = $true
                    lastSignIn = $null
                    signals = @{ mfaRegistered = $false }
                    source = @{ collector = 'AWS'; collectedAt = (Get-Date).ToString('o') }
                }
                $out += $obj
            }
        } catch {
            # ignore
        }
    }

    if ($out.Count -gt 0) { $out | ConvertTo-Json -Depth 6 } else { Write-Output "[]" }
} catch {
    Write-Output "[]"
}
