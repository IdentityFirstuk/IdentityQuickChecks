# ============================================================================
# ATTRIBUTION
# ============================================================================
# Author: Mark Ahearne
# Email: mark.ahearne@identityfirst.net
# Company: IdentityFirst Ltd
#
# This script is provided by IdentityFirst Ltd for identity security assessment.
# All rights reserved.
#
# License: See EULA.txt for license terms.
# ============================================================================
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
# MIIf3QYJKoZIhvcNAQcCoIIfzjCCH8oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBbR1d5tm/q6cSn
# MqY1AZOkM+pC5BIdw1T41a57Hu43YqCCGNwwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggWeMIIDhqADAgECAhAfb4XAeia2j0f08ahQbRKXMA0GCSqG
# SIb3DQEBCwUAMGcxCzAJBgNVBAYTAkdCMRcwFQYDVQQHDA5Ob3J0aHVtYmVybGFu
# ZDEaMBgGA1UECgwRSWRlbnRpdHlGaXJzdCBMdGQxIzAhBgNVBAMMGklkZW50aXR5
# Rmlyc3QgQ29kZSBTaWduaW5nMB4XDTI2MDEyOTIwNTAyM1oXDTI5MDEyOTIxMDAy
# M1owZzELMAkGA1UEBhMCR0IxFzAVBgNVBAcMDk5vcnRodW1iZXJsYW5kMRowGAYD
# VQQKDBFJZGVudGl0eUZpcnN0IEx0ZDEjMCEGA1UEAwwaSWRlbnRpdHlGaXJzdCBD
# b2RlIFNpZ25pbmcwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDV9YyY
# z49V2ipI5ePMgWVHs5h89pYHRk60XSkSOUrCXYH+83sOhTgzKnpvwo7Mzuchbf6f
# q4+85DpydvkLD1L/ZMAF3x1oP74iZ28JZYv/3PwrwLsUDAAiqFQlZk7YrDxgMhdO
# Z90dXpnK+xLTfbaRGLaqB40xnCMAozxHwIm1ClEOOlhC/I+BoPZqG6GRCcOXIdzU
# UQFWRGw8o33e2YyvDfCpwZlFHTgbD1Zmsx/SE7x9LiKi3UdnAyOMlrfHgSeJRIss
# omIVDKheB5MuAHlZQm//DMNBV7o+jO3prF4MJJygD+scND5ZImw+3L2BJEPYyBLZ
# Jum+fnKp4obGnMafQWyEk77bR+ebX3hIyglqcEwalVFdPQsIMeNQ7ervsFy7NOU0
# wBPIuEgLifGWwTVPHy70T2Ci+rz5+93qSljOWvOeT4LdQ/hpqH9JS4Eu4SpJrJ+U
# 6pwdbB3rZnFLax57w/Uh/ayZ74FZDvZhCg8KaV5sJo7XgbwZ44b3OPo6bXAWV7Jl
# yIWrO4h1q3QbgSXVWui3fWxfNmHgW3CEPTzKJlRM88wCvcPe/gQYx4aDFUKtEoiE
# JKmbuDFWoHyDAEuVo+ohUt03eRdEv73XZR/hwg9imN6NbaaR9aG1TV8C3/uMD5ET
# jBmdlUcGEztyHDLzVyIad+RQGh3nDmq2vhGLfQIDAQABo0YwRDAOBgNVHQ8BAf8E
# BAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFHZkS4haGPdZn+Um
# 4fJ/zeQU7kJzMA0GCSqGSIb3DQEBCwUAA4ICAQAnWa5k8D/hKdPn9IIZNY15hX6B
# NQylhSEPNRl4PT4vR1KKyX7Wl6c55c57z3egOC23wjOC6n0Nzt0JzZwgor9Do2V8
# 7R7APMQbXVMU2N1wDugVMNBsXbDbcS4AJz2IxRPmcW+CbMo32BoFeVbc6AODLhEr
# 1PEcAydxANk7E3rxXd1TD7pCLgp1XtRmZPx87SVJgYrRvr7J3VG0As/2KOO6Eu8n
# QTAwiyOZaRXh8MGmI/kd8SUZzFzwRpcafvSgjGqbQK6s4Tkvyxo9rkLKcS9xOww7
# hyEB6mmmV9Z0kPRBMk7llIKebFzN3exzhU8Jrdsnoas4dHl/O78VOl7nZEAbujhF
# l2IL+wFTicwrwCe9s4ZVtEhFZogUAxgGk6Ut00axJF5DgRuvc06YSRrrG7DvMKZw
# vSLWeeT9u+gbwmwEFLIjaEuF+PG0HQ2EgEaNxOKXP7xjJzLo58f5GWoFk+AKealG
# 8E1TuUfHLGJSl4m30vmenyjTlWtpcgbX5XBAb7BbYv3BrIsTiPwoqKY/X9orSDK8
# owFCw1x3Gy+K2DnaVR8JMtGv5KfC2hSobmjnc3nsryd0Bf0iEO/rcwtNbhAzjNEi
# rEKDng+bz5WEJ5HXVg3SXB7v73m+Q4xNVPfBT4WVV0YHxlbwtIk/Jpbsls43n5Uv
# 6aqzWFEZtlMMLRwTezCCBrQwggScoAMCAQICEA3HrFcF/yGZLkBDIgw6SYYwDQYJ
# KoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IElu
# YzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQg
# VHJ1c3RlZCBSb290IEc0MB4XDTI1MDUwNzAwMDAwMFoXDTM4MDExNDIzNTk1OVow
# aTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQD
# EzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1
# NiAyMDI1IENBMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALR4MdMK
# mEFyvjxGwBysddujRmh0tFEXnU2tjQ2UtZmWgyxU7UNqEY81FzJsQqr5G7A6c+Gh
# /qm8Xi4aPCOo2N8S9SLrC6Kbltqn7SWCWgzbNfiR+2fkHUiljNOqnIVD/gG3SYDE
# Ad4dg2dDGpeZGKe+42DFUF0mR/vtLa4+gKPsYfwEu7EEbkC9+0F2w4QJLVSTEG8y
# AR2CQWIM1iI5PHg62IVwxKSpO0XaF9DPfNBKS7Zazch8NF5vp7eaZ2CVNxpqumzT
# CNSOxm+SAWSuIr21Qomb+zzQWKhxKTVVgtmUPAW35xUUFREmDrMxSNlr/NsJyUXz
# dtFUUt4aS4CEeIY8y9IaaGBpPNXKFifinT7zL2gdFpBP9qh8SdLnEut/GcalNeJQ
# 55IuwnKCgs+nrpuQNfVmUB5KlCX3ZA4x5HHKS+rqBvKWxdCyQEEGcbLe1b8Aw4wJ
# khU1JrPsFfxW1gaou30yZ46t4Y9F20HHfIY4/6vHespYMQmUiote8ladjS/nJ0+k
# 6MvqzfpzPDOy5y6gqztiT96Fv/9bH7mQyogxG9QEPHrPV6/7umw052AkyiLA6tQb
# Zl1KhBtTasySkuJDpsZGKdlsjg4u70EwgWbVRSX1Wd4+zoFpp4Ra+MlKM2baoD6x
# 0VR4RjSpWM8o5a6D8bpfm4CLKczsG7ZrIGNTAgMBAAGjggFdMIIBWTASBgNVHRMB
# Af8ECDAGAQH/AgEAMB0GA1UdDgQWBBTvb1NK6eQGfHrK4pBW9i/USezLTjAfBgNV
# HSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYD
# VR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1Ud
# HwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRy
# dXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwH
# ATANBgkqhkiG9w0BAQsFAAOCAgEAF877FoAc/gc9EXZxML2+C8i1NKZ/zdCHxYga
# MH9Pw5tcBnPw6O6FTGNpoV2V4wzSUGvI9NAzaoQk97frPBtIj+ZLzdp+yXdhOP4h
# CFATuNT+ReOPK0mCefSG+tXqGpYZ3essBS3q8nL2UwM+NMvEuBd/2vmdYxDCvwzJ
# v2sRUoKEfJ+nN57mQfQXwcAEGCvRR2qKtntujB71WPYAgwPyWLKu6RnaID/B0ba2
# H3LUiwDRAXx1Neq9ydOal95CHfmTnM4I+ZI2rVQfjXQA1WSjjf4J2a7jLzWGNqNX
# +DF0SQzHU0pTi4dBwp9nEC8EAqoxW6q17r0z0noDjs6+BFo+z7bKSBwZXTRNivYu
# ve3L2oiKNqetRHdqfMTCW/NmKLJ9M+MtucVGyOxiDf06VXxyKkOirv6o02OoXN4b
# FzK0vlNMsvhlqgF2puE6FndlENSmE+9JGYxOGLS/D284NHNboDGcmWXfwXRy4kbu
# 4QFhOm0xJuF2EZAOk5eCkhSxZON3rGlHqhpB/8MluDezooIs8CVnrpHMiD2wL40m
# m53+/j7tFaxYKIqL0Q4ssd8xHZnIn/7GELH3IdvG2XlM9q7WP/UwgOkw/HQtyRN6
# 2JK4S1C8uw3PdBunvAZapsiI5YKdvlarEvf8EA+8hcpSM9LHJmyrxaFtoza2zNaQ
# 9k+5t1wwggbtMIIE1aADAgECAhAKgO8YS43xBYLRxHanlXRoMA0GCSqGSIb3DQEB
# CwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8G
# A1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBT
# SEEyNTYgMjAyNSBDQTEwHhcNMjUwNjA0MDAwMDAwWhcNMzYwOTAzMjM1OTU5WjBj
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMT
# MkRpZ2lDZXJ0IFNIQTI1NiBSU0E0MDk2IFRpbWVzdGFtcCBSZXNwb25kZXIgMjAy
# NSAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0EasLRLGntDqrmBW
# sytXum9R/4ZwCgHfyjfMGUIwYzKomd8U1nH7C8Dr0cVMF3BsfAFI54um8+dnxk36
# +jx0Tb+k+87H9WPxNyFPJIDZHhAqlUPt281mHrBbZHqRK71Em3/hCGC5KyyneqiZ
# 7syvFXJ9A72wzHpkBaMUNg7MOLxI6E9RaUueHTQKWXymOtRwJXcrcTTPPT2V1D/+
# cFllESviH8YjoPFvZSjKs3SKO1QNUdFd2adw44wDcKgH+JRJE5Qg0NP3yiSyi5Mx
# gU6cehGHr7zou1znOM8odbkqoK+lJ25LCHBSai25CFyD23DZgPfDrJJJK77epTwM
# P6eKA0kWa3osAe8fcpK40uhktzUd/Yk0xUvhDU6lvJukx7jphx40DQt82yepyekl
# 4i0r8OEps/FNO4ahfvAk12hE5FVs9HVVWcO5J4dVmVzix4A77p3awLbr89A90/nW
# GjXMGn7FQhmSlIUDy9Z2hSgctaepZTd0ILIUbWuhKuAeNIeWrzHKYueMJtItnj2Q
# +aTyLLKLM0MheP/9w6CtjuuVHJOVoIJ/DtpJRE7Ce7vMRHoRon4CWIvuiNN1Lk9Y
# +xZ66lazs2kKFSTnnkrT3pXWETTJkhd76CIDBbTRofOsNyEhzZtCGmnQigpFHti5
# 8CSmvEyJcAlDVcKacJ+A9/z7eacCAwEAAaOCAZUwggGRMAwGA1UdEwEB/wQCMAAw
# HQYDVR0OBBYEFOQ7/PIx7f391/ORcWMZUEPPYYzoMB8GA1UdIwQYMBaAFO9vU0rp
# 5AZ8esrikFb2L9RJ7MtOMA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggr
# BgEFBQcDCDCBlQYIKwYBBQUHAQEEgYgwgYUwJAYIKwYBBQUHMAGGGGh0dHA6Ly9v
# Y3NwLmRpZ2ljZXJ0LmNvbTBdBggrBgEFBQcwAoZRaHR0cDovL2NhY2VydHMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNI
# QTI1NjIwMjVDQTEuY3J0MF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly9jcmwzLmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZT
# SEEyNTYyMDI1Q0ExLmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1s
# BwEwDQYJKoZIhvcNAQELBQADggIBAGUqrfEcJwS5rmBB7NEIRJ5jQHIh+OT2Ik/b
# NYulCrVvhREafBYF0RkP2AGr181o2YWPoSHz9iZEN/FPsLSTwVQWo2H62yGBvg7o
# uCODwrx6ULj6hYKqdT8wv2UV+Kbz/3ImZlJ7YXwBD9R0oU62PtgxOao872bOySCI
# LdBghQ/ZLcdC8cbUUO75ZSpbh1oipOhcUT8lD8QAGB9lctZTTOJM3pHfKBAEcxQF
# oHlt2s9sXoxFizTeHihsQyfFg5fxUFEp7W42fNBVN4ueLaceRf9Cq9ec1v5iQMWT
# FQa0xNqItH3CPFTG7aEQJmmrJTV3Qhtfparz+BW60OiMEgV5GWoBy4RVPRwqxv7M
# k0Sy4QHs7v9y69NBqycz0BZwhB9WOfOu/CIJnzkQTwtSSpGGhLdjnQ4eBpjtP+XB
# 3pQCtv4E5UCSDag6+iX8MmB10nfldPF9SVD7weCC3yXZi/uuhqdwkgVxuiMFzGVF
# wYbQsiGnoa9F5AaAyBjFBtXVLcKtapnMG3VH3EmAp/jsJ3FVF3+d1SVDTmjFjLbN
# FZUWMXuZyvgLfgyPehwJVxwC+UpX2MSey2ueIu9THFVkT+um1vshETaWyQo8gmBt
# o/m3acaP9QsuLj3FNwFlTxq25+T4QwX9xa6ILs84ZPvmpovq90K8eWyG2N01c4Ih
# SOxqt81nMYIGVzCCBlMCAQEwezBnMQswCQYDVQQGEwJHQjEXMBUGA1UEBwwOTm9y
# dGh1bWJlcmxhbmQxGjAYBgNVBAoMEUlkZW50aXR5Rmlyc3QgTHRkMSMwIQYDVQQD
# DBpJZGVudGl0eUZpcnN0IENvZGUgU2lnbmluZwIQH2+FwHomto9H9PGoUG0SlzAN
# BglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqG
# SIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3
# AgEVMC8GCSqGSIb3DQEJBDEiBCAOZy9GoZ9/Uun5J8GfyJmaWK5zErVMW9tIoRqF
# DViXdzANBgkqhkiG9w0BAQEFAASCAgBHTDjsre5cCuDHlhShQ7hhAO4KhvOx2ElE
# niXFRtJQB6AFnqi4fZYSWvGcI/OpH8ngL4UKnMYIMXwDxvkSn28NchQd6xovgdoS
# 1D+EiH3v7sNjlIPTnEWVilH2chqKiFGZXtx6fNVHA80/VogiuTOoalM3jykPZRDL
# XAws00/hBX82YbShEsGOwNVri6CN+5UoOuEuAo4R0aXY5R6wE5K71jc8OfaDjr5s
# kYNYoqZDWLtgJOWBCqjAX79ngwfOWxv6NrjbIYbV9dg37d7yGh/8YUKQupS2m/d6
# FhQ3rz0xWS6nhh8UOcYrFvAuBZxRDlHm3xGC6pNAc+dCgQFHBYMe7+CEjHWMJndH
# DYwRFbreGzJWvdlvdkI+rUPLFwRCszCmgkh8B9cxr2wDC5S36RtKbJ1g5vZJuOW4
# DG/lfDqjX+4wSh8rRowxvkkM/mqamOOJO0gId0x/z6tSucp5YhwFZ74Lp3tHZATv
# rrt7qu/uHBeNMgw347UhPkV94ITBmeyIurzVe0e7IR0cB4geWVm9dmpnd0ciu83s
# e2sh9kya5Lg4jRwXcWBWkCVyKdayp0uz9tYTpaxjryY4bmdaI7vVJxGghKVaxjCq
# idhJSHCMkBQuqM1+mfcNpwUCn5mdBBMCEfk7qpWFvMFyvaPQPRrUpZKgCi8rjsHx
# jmaz+kvqeaGCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG9w0B
# CQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjAyMDUxNzEyNDlaMC8G
# CSqGSIb3DQEJBDEiBCCAUU1CKT8ijG0wSMvgU0KaR4xMTebWpIpSrdLmG/XrNjAN
# BgkqhkiG9w0BAQEFAASCAgBCEt6vACit4SycYRldH5l64UJhiVxUiaBeyc/7msYY
# WB59fH/TBT8sVtTvdd2PdHbjkgmZ8i7cHyXGZWksTgAXt7v65dLy3BZIY4jR9NuU
# giLFknnqHSSrVO9NvADwZnY/vYJ6HtreLnbGtiDx7dAcL55UX6EnnJ6VBSOYPylG
# TIOWE00A1zAkFqYAB4Xq5w3QqzWzpR0DckJ1ZE9dCk6utILsGeO6bFOEKMVaERJh
# rAXhfFNDdEiaMD0BfbNTz1LMKfW0HmzGbGS+Uov9UsvnpXRIskpiHp5ivX4cM1+E
# ROHYVAmLTkNSGbwOBc3+pS+WesoeMqUbPSMq/httEuGW+HW+lywUhxpm64olfde7
# rTVV6c3E3E+tG1r6nceiJhSEfp+1SjwFivE1VRL93snNmq6PBe3fNmrdWq/w21c1
# pfL7XcDpBuqo05iIAEY1ranIlDRBS6BYmwOZQUiZLHMCCWFKWXLJ0P78SruJA1u7
# zmXcUzsWPEEJXN6cqEJwINMS+HHs1iweBKreMfJuGb+ENY3l8xUXkqUJEbTmI1XW
# ykZyMwXaz5QgcyGhNZDZVRzZA2GlTcFASuRTtEFpdkkL3hn6UmzMJh5uIeMxw99/
# 7pdAO3gLUGO2J1h72Vbw/B3oku6hbpYb1acb3vjRpUkcLYRGVIOH9eqPmnfQ08Cx
# Jw==
# SIG # End signature block
