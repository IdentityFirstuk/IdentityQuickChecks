param([string]$OutputPath = ".")

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================================================"
Write-Host "  External Trust Mapping"
Write-Host "========================================================================"

# Initialize tracking variables
$trustData = @()
$errors = @()
$processedCount = 0

Write-Host ""
Write-Host "  Mapping Active Directory trust relationships..." -ForegroundColor Gray

try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "  ActiveDirectory module loaded" -ForegroundColor Green
}
catch {
    Write-Host "  ERROR: ActiveDirectory module not available" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "  Enumerating trusts..." -ForegroundColor Gray

try {
    # Get all trusts from the current domain
    $currentDomain = Get-ADDomain -ErrorAction Stop
    Write-Host "  Current domain: $($currentDomain.Name)" -ForegroundColor Gray
    
    $incomingTrusts = Get-ADTrust -Filter * -ErrorAction Stop
    Write-Host "  Found $($incomingTrusts.Count) trust relationships" -ForegroundColor Gray
}
catch {
    Write-Host "  ERROR: Failed to enumerate trusts: $($_.Exception.Message)" -ForegroundColor Red
    $errors += $_.Exception.Message
}

# Categorize trusts
$externalTrusts = @()
$internalTrusts = @()
$forestTrusts = @()

foreach ($trust in $incomingTrusts) {
    try {
        $processedCount++
        
        # Determine trust direction
        $direction = $trust.TrustDirection
        $source = $trust.Source
        $target = $trust.Target
        $type = $trust.TrustType
        
        # Classify based on naming and type
        $isExternal = $false
        $classification = "UNKNOWN"
        
        if ($type -eq "External") {
            # External trust - always worth flagging
            $isExternal = $true
            $classification = "EXTERNAL"
            
            # Check if target is a known pattern
            if ($target -notmatch "\.$($currentDomain.DNSRoot)$" -and $target -notmatch "^$($currentDomain.NetBIOSName)") {
                # Likely external
                $classification = "EXTERNAL"
            }
        }
        elseif ($type -eq "Forest") {
            $classification = "FOREST"
            $forestTrusts += $trust
        }
        elseif ($type -eq "Realm") {
            $classification = "REALM"
            $isExternal = $true
        }
        elseif ($type -eq "MIT") {
            $classification = "MIT"
            $isExternal = $true
        }
        
        # Get trust attributes if available
        $tdo = $null
        try {
            $tdo = Get-ADObject -Identity $trust.DistinguishedName -Properties trustAttributes -ErrorAction Stop
            $trustAttributes = $tdo.trustAttributes
        }
        catch {
            $trustAttributes = "N/A"
        }
        
        # Build trust record
        $trustRecord = New-Object PSObject -Property @{
            SourceDomain = $source
            TargetDomain = $target
            TrustType = $type
            TrustDirection = $direction
            Classification = $classification
            IsExternal = $isExternal
            TrustAttributes = $trustAttributes
            SIDFiltering = if ($trustAttributes -band 0x00000020) { "Enabled" } else { "Disabled" }
            SelectiveAuthentication = if ($trustAttributes -band 0x00000010) { "Enabled" } else { "Disabled" }
        }
        
        $trustData += $trustRecord
        
        # Categorize for summary
        if ($isExternal) {
            $externalTrusts += $trustRecord
        }
        else {
            $internalTrusts += $trustRecord
        }
        
    }
    catch {
        $errorMsg = "Failed to process trust $($trust.Source): $($_.Exception.Message)"
        $errors += $errorMsg
        Write-Host "  WARNING: $errorMsg" -ForegroundColor Yellow
    }
}

# Output summary
Write-Host ""
Write-Host "  Trust Summary"
Write-Host "  ============="
Write-Host "  Total trusts found: $($trustData.Count)"
Write-Host "  External trusts: $($externalTrusts.Count)" -ForegroundColor $(if ($externalTrusts.Count -gt 0) { "Yellow" } else { "Green" })
Write-Host "  Forest trusts: $($forestTrusts.Count)"
Write-Host "  Internal trusts: $($internalTrusts.Count)"

if ($trustData) {
    Write-Host ""
    Write-Host "  Trust Details:"
    Write-Host "  ============="
    
    $trustData | Format-Table -AutoSize -Property `
        @{Name="Source"; Expression={$_.SourceDomain}; Width=25},
        @{Name="Target"; Expression={$_.TargetDomain}; Width=25},
        @{Name="Type"; Expression={$_.TrustType}; Width=10},
        @{Name="Direction"; Expression={$_.TrustDirection}; Width=12},
        @{Name="Class"; Expression={$_.Classification}; Width=10}
    
    # Highlight external trusts
    if ($externalTrusts) {
        Write-Host ""
        Write-Host "  EXTERNAL TRUSTS REQUIRING REVIEW:" -ForegroundColor Red
        foreach ($ext in $externalTrusts) {
            Write-Host "    $($ext.SourceDomain) -> $($ext.TargetDomain)" -ForegroundColor Gray
            Write-Host "      Type: $($ext.TrustType), SID Filtering: $($ext.SIDFiltering)" -ForegroundColor Gray
        }
    }
    
    # Forest trust details
    if ($forestTrusts) {
        Write-Host ""
        Write-Host "  FOREST TRUSTS:"
        foreach ($forest in $forestTrusts) {
            Write-Host "    $($forest.SourceDomain) -> $($forest.TargetDomain)" -ForegroundColor Gray
            Write-Host "      Selective Auth: $($forest.SelectiveAuthentication)" -ForegroundColor Gray
        }
    }
}
else {
    Write-Host ""
    Write-Host "  No trust relationships found." -ForegroundColor Green
    Write-Host "  This domain may be standalone or have no configured trusts." -ForegroundColor Gray
}

# Show errors
if ($errors) {
    Write-Host ""
    Write-Host "  Errors encountered:" -ForegroundColor Yellow
    foreach ($err in $errors) {
        Write-Host "    - $err" -ForegroundColor Gray
    }
}

# Generate report
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$reportPath = Join-Path $OutputPath "ExternalTrustMapping-$timestamp.json"

$report = @{
    CheckName = "External Trust Mapping"
    Timestamp = Get-Date -Format "o"
    Summary = @{
        TotalTrustsFound = $trustData.Count
        ExternalTrusts = $externalTrusts.Count
        ForestTrusts = $forestTrusts.Count
        InternalTrusts = $internalTrusts.Count
        Errors = $errors.Count
    }
    TrustDetails = $trustData
    ExternalTrusts = $externalTrusts
    ForestTrusts = $forestTrusts
    Errors = $errors
}

try {
    $jsonOutput = $report | ConvertTo-Json -Depth 10
    $jsonOutput | Set-Content -Path $reportPath -ErrorAction Stop
    Write-Host ""
    Write-Host "  Report saved: $reportPath" -ForegroundColor Cyan
}
catch {
    Write-Host ""
    Write-Host "  ERROR: Failed to save report" -ForegroundColor Red
}

exit 0
