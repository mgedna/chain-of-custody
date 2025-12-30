# ⚡ Quick Start Guide

Get the Digital Chain of Custody system running in **5 minutes**.

## Prerequisites

* **Python 3.11 or higher** ([Download](https://www.python.org/downloads/))
* **Windows, macOS, or Linux**
* **Optional**: Hashcat ([Download](https://hashcat.net/hashcat/)) for credential analysis

## Installation Steps

### Step 1: Get the Code

```bash
# Download or clone the repository
cd chain_of_custody
```

### Step 2: Set Up Virtual Environment

**Windows (PowerShell)**:
```powershell
# Automated setup script
.\setup.ps1
```

Or manually:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**macOS/Linux**:
```bash
# Automated setup script
chmod +x setup.sh
./setup.sh
```

Or manually:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Step 3: Create Demo Accounts

```bash
python setup_accounts.py
```

This creates three demo accounts:

| Email | Password | Username | Role |
|-------|----------|----------|------|
| alice@forensics.lab | password123 | Alice | CUSTODIAN |
| bob@forensics.lab | password456 | Bob | CUSTODIAN |
| charlie@forensics.lab | password789 | Charlie | CUSTODIAN |

### Step 4: Start the Application

```bash
streamlit run app.py
```

The app will open automatically at: **http://localhost:8501**

## First Time Use

### 1. Login

1. Open http://localhost:8501
2. You'll see the **Login/Register** tab
3. **Login with demo account**:
   * Email: `alice@forensics.lab`
   * Password: `password123`
4. Click **Login**
5. You're now logged in as Alice (CUSTODIAN)

### 2. Add Evidence

1. Go to **Tab: Add Evidence**
2. Click **Browse files** and select a test file (any file works)
3. Click **Upload Evidence**
4. System will:
   * Calculate SHA-256 hash
   * Store file securely in `evidence/` directory
   * Set initial status to **RECEIVED**
   * Log action with your email
5. Note the **Probe ID** shown (e.g., "Probe ID: 1")

### 3. Transfer Custody

1. Go to **Tab: Custody Transfer**
2. **Select evidence**: Choose the probe you just added
3. **Current Custodian**: Auto-filled with "alice@forensics.lab"
4. **Transfer Reason**: Enter reason (e.g., "For initial analysis")
5. **Transfer To**: Select "bob@forensics.lab" from dropdown
6. Click **Perform Transfer**
7. System will:
   * Verify you're the current custodian
   * Check for valid chain (no reverse transfers)
   * Verify integrity (hash comparison)
   * Record transfer with reason
   * Always succeed (procedural requirement)
   * Show integrity status separately (VALID/ALTERED)

### 4. Check Integrity

1. Go to **Tab: Integrity Check**
2. **Select evidence** to verify
3. **Re-upload the original file**
4. Click **Verify Integrity**
5. System will:
   * Calculate hash of uploaded file
   * Compare with original hash
   * Show result:
     * ✓ **UNMODIFIED** - File intact
     * ❌ **MODIFIED** - File altered
   * Generate **VERIFY_INTEGRITY** event:
     * SUCCESS if hash matches
     * FAILURE if hash differs (permanently marks ALTERED)

### 5. Generate Report

1. Go to **Tab: Report**
2. Select report type:
   * **Per-Evidence Report**: Select specific probe
   * **Overall Report**: System-wide summary
3. Preview report in browser
4. Download as:
   * **TXT** - Plain text format
   * **PDF** - Professional formatted report with:
     * Evidence details
     * Transfer history
     * Integrity status
     * Timeline of compromise (if applicable)
     * Compromise interval (if applicable)
     * Credential analysis results (if performed)

### 6. View Audit Log

1. Go to **Tab: Audit Log**
2. Select limit: 10, 50, 100, or 500 entries
3. View recent actions:
   * PROBE_ADDED - Evidence registration
   * TRANSFER - Custody transfer (always SUCCESS)
   * VERIFY_INTEGRITY - Manual integrity check (SUCCESS/FAILURE)
   * AUTOMATED_VERIFY_INTEGRITY - System-wide check (FAILURE for altered)
   * ANALYSIS - Credential analysis (non-procedural)
   * STATUS_UPDATE - Evidence lifecycle change
4. Expand entries to see:
   * User email
   * Timestamp
   * Action details
   * Status (SUCCESS/WARNING/FAILURE)

### 7. Update Status & Run Automated Checks

1. Go to **Tab: Status & Automated Checks**
2. **Update Evidence Status**:
   * Select evidence
   * Choose new status: RECEIVED -> IN_ANALYSIS -> VERIFIED -> RELEASED/ARCHIVED
   * Enter reason for status change
   * Submit
3. **Run Automated Integrity Check**:
   * Click "Run Integrity Check"
   * System verifies ALL evidence
   * Uses authoritative integrity status (checks for ANY VERIFY_INTEGRITY FAILURE)
   * Creates AUTOMATED_VERIFY_INTEGRITY FAILURE events for altered probes
   * Shows summary:
     * Total probes checked
     * Altered probes detected
   * Lists altered evidence with details

### 8. Credential Analysis (Optional)

**Prerequisites**: Hashcat must be installed and in PATH

1. **Prepare Hash File**:
   ```
   # Example MD5 hashes (sample.hashes)
   5f4dcc3b5aa765d61d8327deb882cf99
   098f6bcd4621d373cade4e832627b4f6
   ```

2. **Upload as Evidence**:
   * Go to Tab: Add Evidence
   * Upload hash file
   * Note Probe ID

3. **Run Analysis**:
   * Go to **Tab: Credential Analysis**
   * Select probe containing hashes
   * Choose hash type (MD5, SHA256, BCRYPT, NTLM, etc.)
   * Upload custom wordlist (optional) or use default
   * Click "Run Analysis"

4. **View Results**:
   * Total hashes analyzed
   * Number cracked
   * Crack rate percentage
   * Security assessment:
     * 0%: Strong credential protection
     * <10%: Good credential protection
     * <50%: Moderate credential protection
     * ≥50%: Weak credential protection
   * Analysis logged as ANALYSIS event

5. **Include in Report**:
   * Per-Evidence reports automatically include credential analysis results

## Common Tasks

### Register New User

1. **In-App Registration**:
   * Go to Login/Register tab
   * Click "Register New Account"
   * Enter:
     * Email (must be unique)
     * Password (6+ characters)
     * Display Name (optional)
     * Role (ADMIN/INVESTIGATOR/CUSTODIAN)
   * Click "Create Account"

2. **Command Line**:
   ```python
   from core.auth import create_user_with_password
   create_user_with_password(
       "dave@forensics.lab",
       "password101",
       "Dave",
       "INVESTIGATOR"
   )
   ```

### Switch Users

1. **Logout**:
   * Current user shown at top of page
   * Click logout button (if available)
   * Or restart app

2. **Login as Different User**:
   * Email: `bob@forensics.lab`
   * Password: `password456`

### Test Tampering Detection

Run the demo script:

```bash
python demo_alteration.py
```

This script:
1. ✓ Adds evidence (hash: abc123...)
2. ✓ Performs Transfer 1 -> VALID (hash unchanged)
3. 🚨 Secretly modifies the stored file
4. ✗ Performs Transfer 2 -> ALTERED (hash mismatch detected!)
5. 📊 Generates report showing altered evidence
6. Shows how ALTERED status is irreversible

### Test Chain Validation

Run the demo script:

```bash
python demo_chain_validation.py
```

This script tests:
* ✓ Valid transfer (Alice -> Bob)
* ✗ Invalid: Not current custodian (Charlie tries to transfer)
* ✗ Invalid: Reverse transfer (Bob -> Alice - prohibited!)
* ✓ Valid: Linear chain (Bob -> Charlie)

### Clear All Data

**Warning**: This deletes everything!

```bash
# Stop the app first
rm -rf db/chain.db evidence/ reports/
python setup_accounts.py
streamlit run app.py
```

## Troubleshooting

### "Port 8501 already in use"

**Solution**: Use different port
```bash
streamlit run app.py --server.port 8502
```

### "Module not found" errors

**Solution**: Activate virtual environment and reinstall
```bash
# Windows
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# macOS/Linux
source .venv/bin/activate
pip install -r requirements.txt
```

### "Account creation failed"

**Causes**:
* Email already registered
* Password too short (<6 characters)
* Email format invalid

**Solution**: Use different email or check password

### "Login failed"

**Causes**:
* Wrong email or password
* Account doesn't exist

**Solution**: Try demo account:
* Email: `alice@forensics.lab`
* Password: `password123`

### Database locked

**Solution**: Close all app instances and restart
```bash
# Delete database (WARNING: loses all data)
rm db/chain.db
python setup_accounts.py
streamlit run app.py
```

### "Transfer validation failed"

**Causes**:
* Not current custodian
* Trying to transfer to yourself
* Reverse transfer (A->B->A prohibited)

**Solution**: Check current custodian in transfer tab

### Credential analysis fails

**Causes**:
* Hashcat not installed
* Hashcat not in PATH
* Wrong hash type selected
* Invalid hash format

**Solution**:
1. Install Hashcat: https://hashcat.net/hashcat/
2. Add to PATH
3. Verify: `hashcat --version`
4. Check hash type matches file content

### File upload issues

**Maximum file size**: 100 MB (configurable in `config.py`)

**Supported formats**: All file types

**Solution**: For files >100MB, update `config.py`:
```python
MAX_FILE_SIZE = 500 * 1024 * 1024  # 500 MB
```

## Configuration

### Default Settings (`config.py`)

```python
DATABASE_PATH = "db/chain.db"         # Database location
EVIDENCE_DIR = "evidence"              # Evidence storage
MAX_FILE_SIZE = 100 * 1024 * 1024     # Max file size (100 MB)
```

### Custom Configuration

Edit `config.py` before running:

```python
# Increase max file size
MAX_FILE_SIZE = 500 * 1024 * 1024

# Change database location
DATABASE_PATH = "/secure/storage/chain.db"

# Change evidence directory
EVIDENCE_DIR = "/secure/evidence"
```

## Command Reference

### Setup

```bash
# Windows setup
.\setup.ps1

# Linux/Mac setup
./setup.sh

# Create demo accounts
python setup_accounts.py
```

### Running

```bash
# Start app (default port 8501)
streamlit run app.py

# Start on different port
streamlit run app.py --server.port 8502

# Start with different config
streamlit run app.py --server.port 8501 --browser.serverAddress localhost
```

### Demo Scripts

```bash
# Test tampering detection
python demo_alteration.py

# Test chain validation
python demo_chain_validation.py
```

### Database Operations

```bash
# View database schema
sqlite3 db/chain.db ".schema"

# Query users
sqlite3 db/chain.db "SELECT email, username, role FROM users;"

# Query probes
sqlite3 db/chain.db "SELECT id, filename, status, uploaded_by FROM probes;"

# Query transfers
sqlite3 db/chain.db "SELECT * FROM transfers;"

# Query audit log
sqlite3 db/chain.db "SELECT timestamp, user_email, action, status FROM audit_log ORDER BY timestamp DESC LIMIT 10;"
```

## Next Steps

### Learn More

1. **README.md** - Complete feature documentation with updated workflows
2. **ARCHITECTURE.md** - System design and data flows with integrity status details
3. **SECURITY.md** - Security considerations and best practices

### Explore Features

1. **Try all tabs** - Navigate through all 7 tabs
2. **Test transfers** - Practice custody chain validation
3. **Verify integrity** - Upload files and check hashes
4. **Generate reports** - Download PDF reports with timeline
5. **View audit log** - Explore different event types
6. **Update status** - Test lifecycle management
7. **Run automated checks** - Verify all evidence
8. **Analyze credentials** - Test hash cracking (optional)

### Customize

1. **Add real users** - Register actual investigators
2. **Configure settings** - Edit `config.py` for your environment
3. **Integrate tools** - Connect to external systems (future)
4. **Deploy production** - See ARCHITECTURE.md for deployment guide

## Support

### Getting Help

1. Check this QUICKSTART.md
2. Review troubleshooting section
3. Check audit log for errors
4. Run demo scripts to verify installation

### Reporting Issues

Include:
* Python version: `python --version`
* OS: Windows/macOS/Linux
* Error message from terminal
* Steps to reproduce
* Screenshot (if UI issue)

---

**Quick Start Version**: 2.0.0  
**Last Updated**: December 30, 2025  
**Maintained By**: Edna Memedula

**🚀 You're ready to go! Start with Tab 1: Add Evidence**
