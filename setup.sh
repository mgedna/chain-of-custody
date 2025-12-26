echo "=================================================="
echo "  Digital Chain of Custody - Setup"
echo "=================================================="

echo "Checking Python installation..."
python3 --version || { echo "Python 3 not found. Please install Python 3.11+"; exit 1; }

if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
    echo "✓ Virtual environment created"
else
    echo "⚠ Virtual environment already exists"
fi

echo "Activating virtual environment..."
source .venv/bin/activate

echo "Installing dependencies..."
pip install -r requirements.txt
echo "✓ Dependencies installed"

echo "Creating directories..."
mkdir -p db evidence reports
echo "✓ Directories created"

if [ ! -f ".gitignore" ]; then
    echo "Creating .gitignore..."
    cat > .gitignore << 'EOF'
# Python
__pycache__/
*.py[cod]
*$py.class
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
EOF
    echo "✓ Created .gitignore"
fi

echo ""
echo "=================================================="
echo "✓ Setup completed successfully!"
echo ""
echo "Next steps:"
echo "  1. Activate virtual environment:"
echo "     source .venv/bin/activate"
echo "  2. Start the application:"
echo "     streamlit run app.py"
echo "  3. Or run the demo:"
echo "     python demo_alteration.py"
echo "=================================================="
