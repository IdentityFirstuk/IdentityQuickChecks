function Invoke-NativeSampleCheck {
    <#
    .SYNOPSIS
      Runs the native prototype check implemented in the .NET assembly.
    .DESCRIPTION
      Loads the compiled assembly `IdentityFirst.QuickChecks.Core.dll` from the `dotnet` output folder
      and invokes `IdentityFirst.QuickChecks.Core.Checks.RunSampleCheck()` returning parsed JSON.
    #>
    Param(
        [string]$AssemblyPath = '.\\dotnet\\IdentityFirst.QuickChecks.Core\\bin\\Release\\net6.0\\IdentityFirst.QuickChecks.Core.dll'
    )

    if (-not (Test-Path $AssemblyPath)) {
        Throw "Assembly not found at $AssemblyPath. Build it with .\\.scripts\\build_dotnet.ps1"
    }

    try {
        $asm = [System.Reflection.Assembly]::LoadFrom((Resolve-Path $AssemblyPath).Path)
        $type = $asm.GetType('IdentityFirst.QuickChecks.Core.Checks')
        $method = $type.GetMethod('RunSampleCheck', [System.Reflection.BindingFlags] 'Public,Static')
        $json = $method.Invoke($null, @())
        return (ConvertFrom-Json -InputObject $json)
    } catch {
        Throw "Failed to invoke native check: $($_.Exception.Message)"
    }
}

Export-ModuleMember -Function Invoke-NativeSampleCheck
