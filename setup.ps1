$Green = "Green"
$Yellow = "Yellow"
$Red = "Red"

function Write-Success {
    param([string]$Message)
    Write-Host "✓ $Message" -ForegroundColor $Green
}

function Write-Info {
    param([string]$Message)
    Write-Host "ℹ $Message" -ForegroundColor Cyan
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠ $Message" -ForegroundColor $Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "✗ $Message" -ForegroundColor $Red
}

Write-Host "`n=====================================================" -ForegroundColor Cyan
Write-Host "  Digital Chain of Custody - Setup" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan

Write-Info "Checking Python installation..."
$pythonVersion = python --version 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Success "Python found: $pythonVersion"
} else {
    Write-Error "Python not found. Please install Python 3.11+"
    exit 1
}

$venvPath = ".\.venv"
if (Test-Path $venvPath) {
    Write-Warning "Virtual environment already exists"
} else {
    Write-Info "Creating virtual environment..."
    python -m venv .venv
    if ($LASTEXITCODE -eq 0) {
        Write-Success "Virtual environment created"
    } else {
        Write-Error "Failed to create virtual environment"
        exit 1
    }
}

Write-Info "Activating virtual environment..."
& "$venvPath\Scripts\Activate.ps1"
if ($LASTEXITCODE -eq 0) {
    Write-Success "Virtual environment activated"
} else {
    Write-Error "Failed to activate virtual environment"
    exit 1
}

Write-Info "Installing dependencies..."
pip install -r requirements.txt
if ($LASTEXITCODE -eq 0) {
    Write-Success "Dependencies installed"
} else {
    Write-Error "Failed to install dependencies"
    exit 1
}

Write-Info "Creating directories..."
if (-not (Test-Path "db")) { New-Item -ItemType Directory -Path "db" | Out-Null; Write-Success "Created db/" }
if (-not (Test-Path "evidence")) { New-Item -ItemType Directory -Path "evidence" | Out-Null; Write-Success "Created evidence/" }
if (-not (Test-Path "reports")) { New-Item -ItemType Directory -Path "reports" | Out-Null; Write-Success "Created reports/" }

if (-not (Test-Path ".gitignore")) {
    Write-Info "Creating .gitignore..."
    $gitignoreContent = @"
# Python
__pycache__/
*.py[cod]
*`$py.class
*.so
.Python
*.egg-info/
dist/
build/
.venv/
venv/

# Project specific
db/chain.db
db/*.db
evidence/
reports/

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db
"@
    $gitignoreContent | Out-File -FilePath ".gitignore" -Encoding utf8
    Write-Success "Created .gitignore"
}

Write-Host "`n=====================================================" -ForegroundColor Cyan
Write-Success "Setup completed successfully!"
Write-Host "`nNext steps:" -ForegroundColor Cyan
Write-Host "  1. Make sure virtual environment is activated:"
Write-Host "     .\.venv\Scripts\Activate.ps1" -ForegroundColor Yellow
Write-Host "  2. Start the application:"
Write-Host "     streamlit run app.py" -ForegroundColor Yellow
Write-Host "  3. Or run the demo:"
Write-Host "     python demo_alteration.py" -ForegroundColor Yellow
Write-Host "`n=====================================================" -ForegroundColor Cyan
