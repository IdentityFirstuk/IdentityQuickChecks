# ============================================================================
# IdentityFirst QuickChecks - Repository Initialization Script
# ============================================================================
# Initializes and pushes all files to GitHub repository
# ============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$RepoUrl = 'https://github.com/IdentityFirstuk/IdentityQuickChecks.git',
    
    [Parameter(Mandatory=$false)]
    [string]$Branch = 'main',
    
    [Parameter(Mandatory=$false)]
    [string]$CommitMessage = 'Initial commit: IdentityFirst QuickChecks v1.0.0',
    
    [Parameter(Mandatory=$false)]
    [switch]$WhatIf,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([string]$Text)
    Write-Host "-> $Text" -ForegroundColor Yellow
}

function Write-Success {
    param([string]$Text)
    Write-Host "[OK] $Text" -ForegroundColor Green
}

Write-Header 'IdentityFirst QuickChecks - Repository Initialization'

# ============================================================================
# Step 1: Check prerequisites
# ============================================================================

Write-Step 'Checking prerequisites...'

try {
    $gitVersion = git --version 2>&1
    Write-Success "Git found: $gitVersion"
}
catch {
    Write-Error "Git is not installed. Please install Git from https://git-scm.com/"
    exit 1
}

# ============================================================================
# Step 2: Get current directory and verify files
# ============================================================================

Write-Step 'Verifying project files...'

$projectRoot = (Get-Item -Path .).FullName
Write-Success "Project root: $projectRoot"

# Files to check (in root directory)
$requiredFiles = @(
    'README.md',
    'CHANGELOG.md',
    'VERSION.txt',
    'EULA.txt',
    'IdentityFirst.QuickChecks.psd1',
    'IdentityFirst.QuickChecks.psm1'
)

$allFound = $true
foreach ($file in $requiredFiles) {
    if (Test-Path $file) {
        Write-Success "Found: $file"
    }
    else {
        Write-Warning "Missing: $file"
        $allFound = $false
    }
}

# Check for module files
$moduleFiles = Get-ChildItem -Path . -Filter 'IdentityFirst.QuickChecks.*.psm1' | Select-Object -ExpandProperty Name
if ($moduleFiles.Count -gt 0) {
    Write-Success "Found $($moduleFiles.Count) module files"
    foreach ($f in $moduleFiles) {
        Write-Host "   - $f" -ForegroundColor Gray
    }
}
else {
    Write-Warning "No module files found!"
    $allFound = $false
}

# Check for scripts
$scriptFiles = Get-ChildItem -Path .\scripts -Filter '*.ps1' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
if ($scriptFiles.Count -gt 0) {
    Write-Success "Found $($scriptFiles.Count) scripts"
}

# Check for workflows
$workflowFiles = Get-ChildItem -Path .\.github\workflows -Filter '*.yml' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
if ($workflowFiles.Count -gt 0) {
    Write-Success "Found $($workflowFiles.Count) GitHub Actions workflows"
}

if (-not $allFound -and -not $Force) {
    Write-Error "Some required files are missing. Use -Force to continue anyway."
    exit 1
}

# ============================================================================
# Step 3: Initialize git repository
# ============================================================================

Write-Step 'Initializing Git repository...'

if (Test-Path '.git') {
    Write-Warning 'Git repository already exists!'
    if (-not $Force) {
        $continue = Read-Host 'Continue anyway? (y/n)'
        if ($continue -ne 'y') {
            exit 0
        }
    }
}
else {
    git init -b $Branch
    Write-Success "Git repository initialized on branch: $Branch"
}

# Configure git (suppress errors if already set)
    try {
        git config user.name 'IdentityFirst Bot' 2>&1 | Out-Null
    }
    catch {
        git config user.name 'GitHub Actions' 2>&1 | Out-Null
    }
    try {
        git config user.email 'github-actions[bot]@users.noreply.github.com' 2>&1 | Out-Null
    }
    catch {
        # Ignore - default will be used
    }

# ============================================================================
# Step 4: Create .gitignore
# ============================================================================

Write-Step 'Creating .gitignore...'

$gitignoreContent = @"
# ============================================================================
# IdentityFirst QuickChecks - .gitignore
# ============================================================================

# Ignore build outputs
bin/
obj/
*.user
*.suo
.dotnet/

# Ignore release files
*.zip
*.sha256
*.checksums.txt
*.sig

# Ignore test outputs
TestResults/
coverage/

# Ignore IDE files
.vs/
.vscode/
*.swp
*.swo
*~
.DS_Store
Thumbs.db

# Ignore PowerShell errors
error*.txt

# Ignore local configs
config/local.psd1
*.local.psd1

# Ignore modules installed locally
Modules/

# Ignore temporary files
*.tmp
*.temp
*.log

# Ignore PowerShell transcript files
*.transcript

# Ignore VS Code settings
.vscode/settings.json
.vscode/launch.json
.vscode/tasks.json

# Ignore macOS files
.DS_Store
.AppleDouble
.LSOverride

# Ignore Windows files
Thumbs.db
ehthumbs.db
Desktop.ini
"@

if (-not (Test-Path '.gitignore') -or $Force) {
    $gitignoreContent | Out-File -FilePath '.gitignore' -Encoding UTF8
    Write-Success '.gitignore created'
}
else {
    Write-Warning '.gitignore already exists - skipping'
}

# ============================================================================
# Step 5: Add files to git
# ============================================================================

Write-Step 'Adding files to Git...'

# Add all files
git add -A

# Show status
$status = git status --short
Write-Host ""
Write-Host "Files to commit:" -ForegroundColor Gray
Write-Host $status -ForegroundColor Gray
Write-Host ""

# ============================================================================
# Step 6: Create initial commit
# ============================================================================

Write-Step 'Creating initial commit...'

if ($WhatIf) {
    Write-Host "[WhatIf] Would commit with message: $CommitMessage" -ForegroundColor Yellow
}
else {
    git commit -m $CommitMessage
    Write-Success "Initial commit created"
}

# ============================================================================
# Step 7: Add remote and push
# ============================================================================

Write-Step 'Configuring remote repository...'

$remoteExists = git remote -v | Where-Object { $_ -match [regex]::Escape($RepoUrl) }
if (-not $remoteExists) {
    git remote add origin $RepoUrl
    Write-Success "Remote 'origin' added: $RepoUrl"
}
else {
    Write-Warning "Remote 'origin' already exists"
}

# ============================================================================
# Step 8: Push to GitHub
# ============================================================================

Write-Step 'Pushing to GitHub...'

if ($WhatIf) {
    Write-Host "[WhatIf] Would push to: $RepoUrl" -ForegroundColor Yellow
    Write-Host "[WhatIf] Would push branch: $Branch" -ForegroundColor Yellow
}
else {
    try {
        git push -u origin $Branch
        Write-Success "Successfully pushed to GitHub!"
        Write-Host ""
        Write-Host "Repository URL: $RepoUrl" -ForegroundColor Green
    }
    catch {
        Write-Warning "Push failed: $($_.Exception.Message)"
        Write-Host ""
        Write-Host "To push manually, run:" -ForegroundColor Yellow
        Write-Host "  git push -u origin $Branch" -ForegroundColor Gray
    }
}

# ============================================================================
# Summary
# ============================================================================

Write-Header 'Repository Initialization Complete'

Write-Host "Repository: $RepoUrl" -ForegroundColor White
Write-Host "Branch: $Branch" -ForegroundColor White
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  1. Review repository settings" -ForegroundColor Gray
Write-Host "  2. Enable GitHub Actions" -ForegroundColor Gray
Write-Host "  3. Create first release" -ForegroundColor Gray
Write-Host "  4. Add collaborators" -ForegroundColor Gray

Write-Host ""
Write-Host "Useful commands:" -ForegroundColor White
Write-Host "  git status                    # Check repository status" -ForegroundColor Gray
Write-Host "  git log --oneline            # View commit history" -ForegroundColor Gray
Write-Host "  git push                      # Push changes" -ForegroundColor Gray
Write-Host "  git pull                      # Pull changes" -ForegroundColor Gray
