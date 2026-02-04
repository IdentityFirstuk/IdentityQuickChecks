<#  
.SYNOPSIS
    IdentityFirst QuickChecks - Interactive HTML Dashboard Generator
    
.DESCRIPTION
    Generates an interactive HTML dashboard with:
    - Real-time gauge charts
    - Severity donut charts
    - Category breakdown
    - Finding details table
    - Search and filter functionality
    
.NOTES
    Self-contained HTML (no external dependencies for offline use)
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$JsonReport,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputDir = ".\Dashboard-Output",
    
    [Parameter(Mandatory=$false)]
    [string]$Title = "IdentityFirst QuickChecks Dashboard",
    
    [Parameter(Mandatory=$false)]
    [switch]$OpenBrowser
)

# Load JSON data
try {
    $data = Get-Content $JsonReport -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
}
catch {
    Write-Error "Failed to load JSON report: $($_.Exception.Message)"
    exit 1
}

# Calculate metrics
$totalFindings = ($data.Findings | Measure-Object).Count
$criticalCount = ($data.Findings | Where-Object { $_.Severity -eq 'Critical' } | Measure-Object).Count
$highCount = ($data.Findings | Where-Object { $_.Severity -eq 'High' } | Measure-Object).Count
$mediumCount = ($data.Findings | Where-Object { $_.Severity -eq 'Medium' } | Measure-Object).Count
$lowCount = ($data.Findings | Where-Object { $_.Severity -eq 'Low' } | Measure-Object).Count

$score = $data.OverallScore
if (-not $score) {
    $score = 100
    foreach ($f in $data.Findings) {
        switch ($f.Severity) {
            'Critical' { $score -= 25 }
            'High' { $score -= 10 }
            'Medium' { $score -= 5 }
            'Low' { $score -= 2 }
        }
    }
    $score = [Math]::Max(0, [Math]::Min(100, $score))
}

$healthStatus = $data.HealthStatus
if (-not $healthStatus) {
    $healthStatus = if ($score -ge 80) { 'Healthy' } elseif ($score -ge 60) { 'Warning' } else { 'Critical' }
}

$statusColor = switch ($healthStatus) {
    'Healthy' { '#28a745' }
    'Warning' { '#ffc107' }
    'Critical' { '#dc3545' }
    default { '#6c757d' }
}

# Generate findings table rows
$findingsRows = ""
foreach ($finding in $data.Findings) {
    $severityColor = switch ($finding.Severity) {
        'Critical' { '#dc3545' }
        'High' { '#fd7e14' }
        'Medium' { '#ffc107' }
        'Low' { '#17a2b8' }
        default { '#6c757d' }
    }
    
    $findingId = $finding.Id.Replace('-', '_').Replace('.', '_')
    
    $findingsRows += @"
        <tr class="finding-row" data-severity="$($finding.Severity)" data-category="$($finding.Category)">
            <td><span class="severity-badge" style="background: $severityColor">$($finding.Severity)</span></td>
            <td><strong>$($finding.Title)</strong></td>
            <td>$($finding.Category)</td>
            <td>$($finding.RuleId)</td>
            <td>$($finding.AffectedCount)</td>
            <td><button class="btn-details" onclick="showDetails('$findingId')">View</button></td>
        </tr>
"@
}

# Generate category breakdown
$categories = $data.Findings | Group-Object Category | Sort-Object Count -Descending
$categoryChart = ""
foreach ($cat in $categories) {
    $percent = [math]::Round(($cat.Count / $totalFindings) * 100, 1)
    $categoryChart += @"
        <div class="category-item">
            <div class="category-header">
                <span>$($cat.Name)</span>
                <span>$($cat.Count) ($percent%)</span>
            </div>
            <div class="category-bar">
                <div class="category-fill" style="width: $percent%"></div>
            </div>
        </div>
"@
}

# Generate critical findings section
$criticalSection = ""
if ($criticalCount -gt 0) {
    $criticalFindings = $data.Findings | Where-Object { $_.Severity -eq 'Critical' }
    foreach ($cf in $criticalFindings) {
        $criticalSection += @"
        <div class="critical-card">
            <div class="critical-header">
                <span class="critical-icon">ALERT</span>
                <span class="critical-title">$($cf.Title)</span>
            </div>
            <div class="critical-body">
                <p>$($cf.Description)</p>
                <div class="critical-meta">
                    <span>Category: $($cf.Category)</span>
                    <span>Rule: $($cf.RuleId)</span>
                </div>
                <div class="critical-remediation">
                    <strong>Remediation:</strong> $($cf.Remediation)
                </div>
            </div>
        </div>
"@
    }
}

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Generate findings data JS
$findingsDataJS = ""
foreach ($finding in $data.Findings) {
    $findingId = $finding.Id.Replace('-', '_').Replace('.', '_')
    $title = $finding.Title -replace "'", "\'" -replace '"', '\"'
    $desc = $finding.Description -replace "'", "\'" -replace '"', '\"'
    $rem = $finding.Remediation -replace "'", "\'" -replace '"', '\"'
    
    $findingsDataJS += @"
            $findingId: {
                title: '$title',
                description: '$desc',
                severity: '$($finding.Severity)',
                category: '$($finding.Category)',
                ruleId: '$($finding.RuleId)',
                remediation: '$rem',
                affected: '$($finding.AffectedCount) objects',
                confidence: '$($finding.Confidence)'
            },
"@
}

# Generate HTML
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$Title</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; color: #333; }
        
        .header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 30px; text-align: center; }
        .header h1 { font-size: 28px; margin-bottom: 10px; }
        .header .subtitle { opacity: 0.8; font-size: 14px; }
        
        .dashboard { padding: 20px; max-width: 1400px; margin: 0 auto; }
        
        .score-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .score-card { background: white; border-radius: 12px; padding: 25px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.05); transition: transform 0.2s; }
        .score-card:hover { transform: translateY(-2px); }
        .score-value { font-size: 56px; font-weight: bold; color: $statusColor; }
        .score-label { font-size: 14px; color: #666; margin-top: 5px; }
        .score-status { display: inline-block; padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; margin-top: 10px; background: $statusColor; }
        
        .gauge-container { display: flex; justify-content: center; margin: 30px 0; }
        .gauge { position: relative; width: 200px; height: 100px; overflow: hidden; }
        .gauge-bg { position: absolute; width: 200px; height: 200px; border-radius: 50%; background: #e9ecef; }
        .gauge-fill { position: absolute; width: 200px; height: 200px; border-radius: 50%; 
                      background: conic-gradient($statusColor 0deg, $statusColor $($score * 3.6)deg, transparent $($score * 3.6)deg, transparent 360deg);
                      transform: rotate(-90deg); }
        .gauge-center { position: absolute; width: 160px; height: 160px; background: white; border-radius: 50%;
                        top: 20px; left: 20px; display: flex; flex-direction: column; align-items: center; justify-content: center; }
        .gauge-text { font-size: 32px; font-weight: bold; color: $statusColor; }
        .gauge-label { font-size: 12px; color: #666; }
        
        .donut-container { display: flex; justify-content: center; margin: 20px 0; }
        .donut { position: relative; width: 200px; height: 200px; }
        .donut svg { transform: rotate(-90deg); }
        .donut-circle { fill: none; stroke-width: 30; }
        .donut-bg { stroke: #e9ecef; }
        .donut-fill-critical { stroke: #dc3545; }
        .donut-fill-high { stroke: #fd7e14; }
        .donut-fill-medium { stroke: #ffc107; }
        .donut-fill-low { stroke: #17a2b8; }
        .donut-center { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);
                        text-align: center; }
        .donut-total { font-size: 28px; font-weight: bold; }
        .donut-label { font-size: 12px; color: #666; }
        
        .legend { display: flex; justify-content: center; gap: 20px; margin: 20px 0; flex-wrap: wrap; }
        .legend-item { display: flex; align-items: center; gap: 8px; }
        .legend-color { width: 16px; height: 16px; border-radius: 4px; }
        
        .critical-section { margin: 30px 0; }
        .section-title { font-size: 20px; margin-bottom: 15px; color: #dc3545; display: flex; align-items: center; gap: 10px; }
        .critical-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; }
        .critical-card { background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.05); border-left: 4px solid #dc3545; }
        .critical-header { background: #fff5f5; padding: 15px; display: flex; align-items: center; gap: 10px; }
        .critical-icon { font-size: 14px; font-weight: bold; color: #dc3545; background: #fee; padding: 4px 8px; border-radius: 4px; }
        .critical-title { font-weight: bold; }
        .critical-body { padding: 15px; }
        .critical-body p { margin-bottom: 10px; color: #666; }
        .critical-meta { display: flex; gap: 20px; font-size: 12px; color: #999; margin-bottom: 10px; }
        .critical-remediation { background: #e7f3ff; padding: 10px; border-radius: 6px; font-size: 13px; }
        
        .category-section { margin: 30px 0; }
        .category-item { margin-bottom: 12px; }
        .category-header { display: flex; justify-content: space-between; margin-bottom: 5px; font-size: 14px; }
        .category-bar { background: #e9ecef; height: 8px; border-radius: 4px; overflow: hidden; }
        .category-fill { height: 100%; background: linear-gradient(90deg, #0078d4, #00a8e8); border-radius: 4px; transition: width 0.5s; }
        
        .findings-section { margin: 30px 0; }
        .findings-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        .search-box { display: flex; gap: 10px; }
        .search-input { padding: 10px 15px; border: 1px solid #ddd; border-radius: 6px; width: 300px; font-size: 14px; }
        .filter-select { padding: 10px 15px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; }
        .findings-table { background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
        .findings-table table { width: 100%; border-collapse: collapse; }
        .findings-table th { background: #0078d4; color: white; padding: 15px; text-align: left; font-weight: 500; }
        .findings-table td { padding: 15px; border-bottom: 1px solid #eee; }
        .finding-row:hover { background: #f8f9fa; }
        .severity-badge { padding: 4px 10px; border-radius: 12px; font-size: 12px; font-weight: bold; color: white; }
        .btn-details { padding: 6px 12px; background: #0078d4; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 12px; }
        .btn-details:hover { background: #005a9e; }
        
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; }
        .modal.active { display: flex; align-items: center; justify-content: center; }
        .modal-content { background: white; border-radius: 12px; max-width: 600px; width: 90%; max-height: 80vh; overflow-y: auto; }
        .modal-header { padding: 20px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }
        .modal-title { font-size: 18px; font-weight: bold; }
        .modal-close { background: none; border: none; font-size: 24px; cursor: pointer; color: #999; }
        .modal-body { padding: 20px; }
        .modal-section { margin-bottom: 15px; }
        .modal-label { font-weight: bold; color: #666; font-size: 12px; margin-bottom: 5px; }
        .modal-value { font-size: 14px; }
        
        .footer { text-align: center; padding: 30px; color: #999; font-size: 12px; }
        
        @media (max-width: 768px) {
            .score-cards { grid-template-columns: 1fr; }
            .critical-grid { grid-template-columns: 1fr; }
            .findings-header { flex-direction: column; gap: 10px; }
            .search-input { width: 100%; }
        }
        
        @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        .animate-in { animation: fadeIn 0.5s ease-out; }
    </style>
</head>
<body>
    <div class="header">
        <h1>IdentityFirst QuickChecks Dashboard</h1>
        <div class="subtitle">Generated: $($data.Timestamp)</div>
    </div>
    
    <div class="dashboard">
        <div class="score-cards animate-in">
            <div class="score-card">
                <div class="score-value">$score</div>
                <div class="score-label">Overall Score</div>
                <div class="score-status">$healthStatus</div>
            </div>
            <div class="score-card">
                <div class="score-value" style="color: #dc3545">$criticalCount</div>
                <div class="score-label">Critical Findings</div>
            </div>
            <div class="score-card">
                <div class="score-value" style="color: #fd7e14">$highCount</div>
                <div class="score-label">High Findings</div>
            </div>
            <div class="score-card">
                <div class="score-value" style="color: #6c757d">$totalFindings</div>
                <div class="score-label">Total Findings</div>
            </div>
        </div>
        
        <div class="animate-in" style="background: white; border-radius: 12px; padding: 30px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.05);">
            <h2 style="text-align: center; margin-bottom: 20px;">Security Health Score</h2>
            <div class="gauge-container">
                <div class="gauge">
                    <div class="gauge-bg"></div>
                    <div class="gauge-fill"></div>
                    <div class="gauge-center">
                        <div class="gauge-text">$score</div>
                        <div class="gauge-label">OUT OF 100</div>
                    </div>
                </div>
            </div>
            
            <div class="donut-container">
                <div class="donut">
                    <svg width="200" height="200" viewBox="0 0 200 200">
                        <circle class="donut-circle donut-bg" cx="100" cy="100" r="70"></circle>
                        <circle class="donut-circle donut-fill-critical" cx="100" cy="100" r="70"
                                stroke-dasharray="$($criticalCount * 4.4) 440" stroke-dashoffset="0"></circle>
                        <circle class="donut-circle donut-fill-high" cx="100" cy="100" r="70"
                                stroke-dasharray="$($highCount * 4.4) 440" 
                                stroke-dasharray="$($criticalCount * 4.4) 440" 
                                stroke-dashoffset="-$($criticalCount * 4.4)"></circle>
                        <circle class="donut-circle donut-fill-medium" cx="100" cy="100" r="70"
                                stroke-dasharray="$($mediumCount * 4.4) 440" 
                                stroke-dashoffset="-$((($criticalCount + $highCount) * 4.4))"></circle>
                        <circle class="donut-circle donut-fill-low" cx="100" cy="100" r="70"
                                stroke-dasharray="$($lowCount * 4.4) 440" 
                                stroke-dashoffset="-$((($criticalCount + $highCount + $mediumCount) * 4.4))"></circle>
                    </svg>
                    <div class="donut-center">
                        <div class="donut-total">$totalFindings</div>
                        <div class="donut-label">Total Findings</div>
                    </div>
                </div>
            </div>
            
            <div class="legend">
                <div class="legend-item">
                    <div class="legend-color" style="background: #dc3545"></div>
                    <span>Critical ($criticalCount)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #fd7e14"></div>
                    <span>High ($highCount)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #ffc107"></div>
                    <span>Medium ($mediumCount)</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #17a2b8"></div>
                    <span>Low ($lowCount)</span>
                </div>
            </div>
        </div>
        
        if ($criticalCount -gt 0) {
            @"
        <div class="critical-section">
            <h2 class="section-title">CRITICAL FINDINGS - Immediate Action Required</h2>
            <div class="critical-grid">
                $criticalSection
            </div>
        </div>
"@
        }
        
        <div class="category-section animate-in" style="background: white; border-radius: 12px; padding: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.05);">
            <h2 style="margin-bottom: 20px;">Findings by Category</h2>
            $categoryChart
        </div>
        
        <div class="findings-section animate-in">
            <div class="findings-header">
                <h2>All Findings</h2>
                <div class="search-box">
                    <input type="text" class="search-input" placeholder="Search findings..." id="searchInput">
                    <select class="filter-select" id="severityFilter">
                        <option value="">All Severities</option>
                        <option value="Critical">Critical</option>
                        <option value="High">High</option>
                        <option value="Medium">Medium</option>
                        <option value="Low">Low</option>
                    </select>
                </div>
            </div>
            <div class="findings-table">
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Title</th>
                            <th>Category</th>
                            <th>Rule</th>
                            <th>Affected</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody id="findingsTable">
                        $findingsRows
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    
    <div class="modal" id="detailsModal">
        <div class="modal-content">
            <div class="modal-header">
                <div class="modal-title" id="modalTitle">Finding Details</div>
                <button class="modal-close" onclick="closeModal()">X</button>
            </div>
            <div class="modal-body" id="modalBody"></div>
        </div>
    </div>
    
    <div class="footer">
        Generated by IdentityFirst QuickChecks
    </div>
    
    <script>
        const findingsData = {
$findingsDataJS        };
        
        document.getElementById('searchInput').addEventListener('input', filterFindings);
        document.getElementById('severityFilter').addEventListener('change', filterFindings);
        
        function filterFindings() {
            const search = document.getElementById('searchInput').value.toLowerCase();
            const severity = document.getElementById('severityFilter').value;
            const rows = document.querySelectorAll('.finding-row');
            
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                const rowSeverity = row.dataset.severity;
                const matchesSearch = text.includes(search);
                const matchesSeverity = !severity || rowSeverity === severity;
                row.style.display = (matchesSearch && matchesSeverity) ? '' : 'none';
            });
        }
        
        function showDetails(id) {
            const finding = findingsData[id];
            if (!finding) return;
            
            document.getElementById('modalTitle').textContent = finding.title;
            document.getElementById('modalBody').innerHTML = `
                <div class="modal-section">
                    <div class="modal-label">SEVERITY</div>
                    <div class="modal-value"><span class="severity-badge" style="background: ${finding.severity === 'Critical' ? '#dc3545' : finding.severity === 'High' ? '#fd7e14' : finding.severity === 'Medium' ? '#ffc107' : '#17a2b8'}">${finding.severity}</span></div>
                </div>
                <div class="modal-section">
                    <div class="modal-label">DESCRIPTION</div>
                    <div class="modal-value">${finding.description}</div>
                </div>
                <div class="modal-section">
                    <div class="modal-label">CATEGORY</div>
                    <div class="modal-value">${finding.category}</div>
                </div>
                <div class="modal-section">
                    <div class="modal-label">RULE ID</div>
                    <div class="modal-value">${finding.ruleId}</div>
                </div>
                <div class="modal-section">
                    <div class="modal-label">AFFECTED OBJECTS</div>
                    <div class="modal-value">${finding.affected}</div>
                </div>
                <div class="modal-section">
                    <div class="modal-label">CONFIDENCE</div>
                    <div class="modal-value">${finding.confidence}</div>
                </div>
                <div class="modal-section">
                    <div class="modal-label">REMEDIATION</div>
                    <div class="modal-value">${finding.remediation}</div>
                </div>
            `;
            document.getElementById('detailsModal').classList.add('active');
        }
        
        function closeModal() {
            document.getElementById('detailsModal').classList.remove('active');
        }
        
        document.getElementById('detailsModal').addEventListener('click', function(e) {
            if (e.target === this) closeModal();
        });
        
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') closeModal();
        });
    </script>
</body>
</html>
"@

# Save HTML
$outputPath = Join-Path $OutputDir "Dashboard-$((Get-Date).ToString('yyyyMMdd-HHmmss')).html"
$html | Set-Content -Path $outputPath -Encoding UTF8

Write-Host "Dashboard generated: $outputPath" -ForegroundColor Green

if ($OpenBrowser) {
    try {
        Start-Process $outputPath
    }
    catch {
        Write-Warning "Could not open browser: $($_.Exception.Message)"
    }
}

return $outputPath

# SIG # Begin signature block
# MIIcDgYJKoZIhvcNAQcCoIIb/zCCG/sCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBAuEQZSXg/WoQL
# kP1kVtAeWbWvLBnhIy9s37acJYahMaCCFlIwggMUMIIB/KADAgECAhBDR0HvMFNE
# lkJ70azsYRwnMA0GCSqGSIb3DQEBCwUAMCIxIDAeBgNVBAMMF0lkZW50aXR5Rmly
# c3QgQ29kZSBTaWduMB4XDTI2MDIwNDE2NDE0OFoXDTI3MDIwNDE3MDE0OFowIjEg
# MB4GA1UEAwwXSWRlbnRpdHlGaXJzdCBDb2RlIFNpZ24wggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQDWJrlUCUN9yoS4qyJUFIIrjVVnfoFqTXwze3ijNE5q
# wUAAiypU86tc6ct9/wQ9Q9qOn6gjKU3vDhq8XojyQhi/q0ffxG1pP8bHfCQtrMFc
# kTOKLZRgQO73caKFxunCuRdAGxdDxy94NNjwITySkaaLFb3gULH1wbfmu5l2v9ga
# CgpRJGoofRbYbjBS5B7TTNVXlyxl5I3toq9cYRwauWq0Fqj2h6gZ/8izDVU6nMGX
# k+ZfsQwTsVSxfiiWHozhjU7Rt8ckxfVt1YLyPamewESLxw4ijFgHYZUrxNtbm2DP
# QUUG4ekzdDQlBLBzjdIJh8hIz+gcqvyXIQpoFjF2xyoFAgMBAAGjRjBEMA4GA1Ud
# DwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQU0LvUry7V
# 3WlfTmidD6yCOpbcmSQwDQYJKoZIhvcNAQELBQADggEBAAWDzEqYgCCQHZwHCMlU
# ob2Jkqcbk6GYylmfTwW9EQ7iJjyKHFJlbUGuDJxClDwDteBCVpxhfbi0fJjkib8r
# b4Fbk9Rex5rJxEMidBYbnASWnLuJD7dsHbwf6N4SM/LsYhiEtllGb0UsKET6PyuO
# f1sYdDY+UcTssCzDAElCrlVIl4Z4/JBlXOhInMD7AnP6Xx2r4hCAVEWhHtJ+ahY/
# bFAJ7v+EsTET2Pa34kiymxJ7yYRNSxwxyb1umUx/Q6pui0lYjyNXt8AAg4A0ybyj
# ABLNYct6zilczJ6JqPCBJLL0ZbCDpg8SkmAn3G3Y+bSztlOIUo4eXpjXV1DE7oB/
# kuAwggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUA
# MGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsT
# EHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQg
# Um9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqcl
# LskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YF
# PFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceIt
# DBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZX
# V59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1
# ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2Tox
# RJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdp
# ekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF
# 30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9
# t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQ
# UOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXk
# aS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1Ud
# DgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEt
# UYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsG
# AQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0
# dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RD
# QS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAw
# DQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72arKGHLOyF
# XqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFIDyE7QKt76
# LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8L
# punyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2
# CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si
# /xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQwgga0MIIEnKADAgEC
# AhANx6xXBf8hmS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcw
# MDAwMDBaFw0zODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1l
# U3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZ
# loMsVO1DahGPNRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM
# 2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj
# 7GH8BLuxBG5AvftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQ
# Sku2Ws3IfDReb6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZ
# lDwFt+cVFBURJg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+
# 8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRx
# ykvq6gbylsXQskBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yG
# OP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqI
# MRvUBDx6z1ev+7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm
# 1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBj
# UwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729T
# SunkBnx6yuKQVvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4c
# D08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUF
# BwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEG
# CCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAX
# MAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaA
# HP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQ
# M2qEJPe36zwbSI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt
# 6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7
# bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmS
# Nq1UH410ANVko43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69
# M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnF
# RsjsYg39OlV8cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmM
# Thi0vw9vODRzW6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oa
# Qf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx
# 9yHbxtl5TPau1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3
# /BAPvIXKUjPSxyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN
# 8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQg
# VGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAw
# MDAwMFoXDTM2MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBU
# aW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx
# +wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvN
# Zh6wW2R6kSu9RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlL
# nh00Cll8pjrUcCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmn
# cOOMA3CoB/iUSROUINDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5KqCvpSduSwhw
# UmotuQhcg9tw2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL
# 4Q1OpbybpMe46YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdoRORVbPR1VVnD
# uSeHVZlc4seAO+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCy
# FG1roSrgHjSHlq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7rlRyTlaCCfw7a
# SUROwnu7zER6EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K096V1hE0yZIXe+gi
# AwW00aHzrDchIc2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGj
# ggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39/dfzkXFjGVBD
# z2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8E
# BAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGF
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUH
# MAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRH
# NFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBW
# MFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVk
# RzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkw
# FzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3x
# HCcEua5gQezRCESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh
# 8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim8/9yJmZS
# e2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUqW4daIqToXFE/
# JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMnxYOX8VBRKe1u
# NnzQVTeLni2nHkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq
# 8/gVutDojBIFeRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AWcIQfVjnzrvwi
# CZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJgddJ35XTxfUlQ
# +8Hggt8l2Yv7roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1
# R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVccAvlKV9jEnstr
# niLvUxxVZE/rptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8atufk+EMF/cWu
# iC7POGT75qaL6vdCvHlshtjdNXOCIUjsarfNZzGCBRIwggUOAgEBMDYwIjEgMB4G
# A1UEAwwXSWRlbnRpdHlGaXJzdCBDb2RlIFNpZ24CEENHQe8wU0SWQnvRrOxhHCcw
# DQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkq
# hkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGC
# NwIBFTAvBgkqhkiG9w0BCQQxIgQgMjlqowfqMg1YGKA07DU/ZenEJVANECWTbS+R
# GW/X148wDQYJKoZIhvcNAQEBBQAEggEAQhpleJN503b57P8ptsF0M9u864gebjEF
# eVJWyy7Uuc0U+hoz6C0nauBCHIwRfCgyZe4KdE+7I/vaEUUo3Z/JSbu+P9D2+77m
# Bjb1jGZneKnQ0OQu90AJpaX7sG5G1ctO98ZWfcjTH4W8KlZedxulnKbkelH9tg/V
# VQHMw4nWejbcd3O42n4PTc6GW2qDKDAiFrV0mTVIuXyPMjoWZz2jw3X93OdRfGxj
# rEyur6IB5cDb1Zzl8F38PIcimNLP4IEebmMG5Xz6UqXVWJNW6vOifUSTL+DDQVW4
# 3I9U71flXFsM1/SU4WW5h1TNJWB2lrv+sL7gys65RFDIToxOkQ/SbKGCAyYwggMi
# BgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAqA7xhLjfEFgtHE
# dqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcB
# MBwGCSqGSIb3DQEJBTEPFw0yNjAyMDQxNjUyMDlaMC8GCSqGSIb3DQEJBDEiBCDC
# UjTqxM+d6XlFhPb9gKKhUsKc0wvwy0xbfN0RRS5iUzANBgkqhkiG9w0BAQEFAASC
# AgBsESXIQ/7kvyLXZrCFJe+qldHKSuoiG7dpkgHPR89emm/QRId5qD+GHLFJoRSG
# 0M4j/j2HRDN4dowFEdr5PKY5ddOpQWhybpVNAddNooRD1NsGsGtsnLMMN4ZGWB7l
# 8hRhNVVFhr2Qa7eT9FBxayRgjkmr44JTHZHZx9FzFzCvBMEOrLgpe9CMK5a0mq8/
# rvI11Kl8yv4/HKYUyReKgJD9Rr9qNPzaQuIhahiLVU37VF4O2y79+6wEV6mac+RZ
# M/CQvc3aqBKdFDLdqHhyuLoY3Q2GSKgVk+p2hFmVqsirV2m0rhG1lpq/GOeJt4Oe
# AGBMI+i4U/OLXoUwshIfgS6BNoqEm2p9IpI10Ai9SvuLbJ/uC4UU9dIGx8v95g+m
# SYV04xr8Xq13JQ8sSvL64xeVka/wLCJfZ6BHf7ANdGlt966VgIafGvVyYbZBnMR9
# r7Xzwc88IS83ima9mM7INZJrQ8dGLGCqmGE+FPHGKQoRn/fgF/3wCfIO7RQxmDLB
# L8eWDHZqMxeSZEOUeoVv7yXUbEfr6xmHe160b9SQKKd7uuHYk6uDis5ZIeheTspa
# RnXPLTCUretqbHL0CvmG9Zy4l9/8GyATuzlFCi6zBbCSkq39XwqNmI+mKsvFmrQJ
# hC7yLOfG8PaSMy0POH8VaZ7J5oWlr1M/svLa0ehQixbP4Q==
# SIG # End signature block
