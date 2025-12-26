# 🔐 Digital Chain of Custody

A professional forensic evidence management system that tracks digital evidence through a secure custody chain, with **cryptographic integrity verification**, **chain validation**, **status lifecycle management**, and **comprehensive audit logging** with **user authentication**.

## Overview

This application implements a **digital chain of custody** system for forensic investigations compliant with **NIST SP 800-86**, **ISO/IEC 27037**, and **ACPO Guidelines**. It provides:

- **User Authentication**: Secure login with password-protected accounts
- **Evidence Registration**: Upload and securely store digital evidence files
- **Custody Transfer**: Track evidence movement with mandatory transfer reasons (NIST requirement)
- **Chain of Custody Validation**: Enforce proper custody chain rules
- **Evidence Status Lifecycle**: RECEIVED → IN_ANALYSIS → VERIFIED → RELEASED/ARCHIVED
- **Integrity Verification**: Detect evidence tampering through SHA-256 cryptographic hashing
- **Automated Integrity Checks**: NIST-compliant verification of all system evidence
- **Audit Trail**: Comprehensive logging of all system actions with user identification
- **Professional Reports**: Generate PDF/TXT reports with transfer history and integrity status

## 🆕 Key Features

### 🔑 User Authentication
- **Secure login system** with password hashing (PBKDF2 - 100,000 iterations)
- **Demo accounts** pre-configured for testing
- **Account registration** directly in app with validation
- **Session management** - Track authenticated user identity
- **User identification** in all audit logs and transfers

### 🔗 Chain of Custody Validation (NIST Compliant)
- **Custody Continuity** - Only current custodian can transfer
- **No Reverse Transfers** - Cannot go A → B → A (NIST standard)
- **Linear Chain Enforcement** - Proper sequence required
- **Smart UI** - Pre-fills from_user, filters to_user options
- **Mandatory Transfer Reason** - NIST requirement for transfer documentation

### 📋 Evidence Status Lifecycle (ISO/IEC 27037)
- **RECEIVED** - Initial status when evidence uploaded
- **IN_ANALYSIS** - Evidence under investigation
- **VERIFIED** - Integrity verified and complete
- **RELEASED** - Returned to owner
- **ARCHIVED** - Long-term storage
- **Status Management Tab** - Update evidence status with audit trail

### 🔒 Cryptographic Security
- **SHA-256 Hashing**: 256-bit collision-resistant cryptography
- **Hash Verification at Every Transfer**: Detect alterations between custody transfers
- **Tamper Detection**: STATUS labels (✓ VALID / ✗ ALTERED) show if evidence was modified
- **Secure File Storage**: Evidence stored in `evidence/` directory with cryptographic naming
- **Password Protection**: User accounts with PBKDF2 encryption

### 🔍 Automated Integrity Verification (NIST SP 800-86)
- **System-wide Integrity Checks**: Verify all evidence hasn't been tampered with
- **Automated Alerts**: Flag altered evidence immediately
- **Check Summary**: Total probes checked, altered count
- **Audit Integration**: Failed checks logged to audit trail

### 📊 Chain of Custody
- **User Management**: Create/register custodians with secure passwords
- **Transfer Recording**: Log evidence movement with:
  - Source and destination custodian
  - **Transfer reason** (e.g., "For analysis", "Verification", "Storage")
  - Cryptographic hash at transfer time
  - User identification
  - Timestamp
- **Status Indicators**: 
  - ✓ VALID - Hash matches original (evidence unmodified)
  - ✗ ALTERED - Hash differs from original (evidence tampered!)
  - ⚠️ NO_TRANSFERS - Evidence not yet transferred

### 📋 Audit & Reporting
- **Audit Log**: All actions logged with:
  - Timestamp (millisecond precision)
  - **Authenticated user**
  - Action type
  - Status (SUCCESS/WARNING/FAILURE)
  - Details and error messages
- **Professional Reports**: 
  - **Per-Evidence Reports** - Detailed chain history for specific evidence
  - **Overall Reports** - System-wide chain of custody summary
  - Text format for quick review
  - PDF format with styled tables and status indicators
  - Transfer history with integrity verification

### 💾 Database
- SQLite3 database with 4 tables:
  - `probes` - Digital evidence files with status lifecycle
  - `users` - Custodians with password hashes
  - `transfers` - Custody transfer history with **transfer reason** and user tracking
  - `audit_log` - System audit trail with user identification

## Application Tabs

### Tab 1: 📥 Add Evidence
- Upload digital evidence files
- Automatic SHA-256 hash calculation
- Secure storage in `evidence/` directory
- Associate with authenticated user

### Tab 2: 🔄 Custody Transfer
- Select evidence to transfer
- **Mandatory transfer reason** (NIST requirement)
- Current custodian auto-filled
- Valid recipients pre-filtered
- Hash verification at transfer time
- Auto-refresh after successful transfer

### Tab 3: 🔍 Integrity Check
- Verify evidence hasn't been tampered with
- Re-upload file and compare hash
- Shows VALID or ALTERED status
- Compare original vs current hash

### Tab 4: 📊 Report
- **Per-Evidence Reports** - Select specific evidence
  - Evidence details (ID, filename, hash, uploaded by)
  - Complete transfer history
  - Status for each transfer
  - Download as TXT or PDF
- **Overall Reports** - System-wide reports
  - All evidence with integrity status
  - Complete transfer history
  - Download as TXT or PDF

### Tab 5: 📋 Audit Log
- View all system actions in real-time
- Filter by limit (10/50/100/500 entries)
- Expandable entries showing:
  - Status (SUCCESS/WARNING/FAILURE)
  - Timestamp
  - Details of action
  - Error messages if any

### Tab 6: 📊 Status & Automated Checks
- **Status Management**
  - View current evidence status
  - Update status through lifecycle
  - RECEIVED → IN_ANALYSIS → VERIFIED → RELEASED/ARCHIVED
  - Changes logged to audit trail
- **Automated Integrity Verification** (NIST Compliance)
  - Run full system integrity check
  - Verify all evidence hashes
  - Detect altered evidence
  - Generate check summary
  - Alert on any tampering detected

## Installation

### Prerequisites
- Python 3.11+
- Windows/Linux/macOS

### Quick Setup

1. **Clone/Download the project**
   ```powershell
   cd chain_of_custody
   ```

2. **Run setup script** (Windows)
   ```powershell
   .\setup.ps1
   ```
   Or manually:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

3. **Create demo accounts**
   ```powershell
   python setup_accounts.py
   ```

4. **Start the application**
   ```powershell
   streamlit run app.py
   ```
   Opens at: `http://localhost:8501`

## Usage

### Login
1. Start app: `streamlit run app.py`
2. **Login with demo account:**
   - Username: `alice` / Password: `password123` (Officer Alice)
   - Username: `bob` / Password: `password456` (Officer Bob)
   - Username: `charlie` / Password: `password789` (Officer Charlie)

### Tab 1: Add Evidence 📁
1. Upload a digital file (text, image, document, etc.)
2. System automatically:
   - Creates a secure copy in `evidence/` directory
   - Calculates SHA-256 hash
   - Logs action to audit trail **with your username**
3. Note the **Probe ID** for future transfers

### Tab 2: Custody Transfer 🔄
1. Select evidence to transfer
2. System shows **Current Custodian** (who has it now)
3. **Only current custodian can transfer** (validated automatically)
4. Select recipient from valid options (pre-filtered)
5. System records transfer with:
   - Your username
   - Timestamp
   - Hash verification
   - Integrity status

### Tab 3: Integrity Check ✅
1. Re-upload the evidence file
2. System compares with original hash
3. Shows:
   - ✓ UNMODIFIED - File integrity intact
   - ❌ MODIFIED - File has been altered
   - ⚠️ UNKNOWN - File not in system

### Tab 4: Report 📊
1. Preview transfer history
2. Download as **TXT** (plain text) or **PDF** (professional format)
3. Report includes:
   - All registered evidence
   - Complete transfer chain with **custodian names**
   - Integrity status for each transfer
   - Timestamps

### Tab 5: Audit Log 📝
1. View all system actions
2. Filter by status (SUCCESS/WARNING/FAILURE)
3. Expandable entries showing:
   - **Username who performed action**
   - Timestamp
   - Action type
   - Details
   - Error messages (if any)

## Demo Scripts

### 1. Tampering Detection
```powershell
python demo_alteration.py
```
Shows evidence tampering detection between transfers.

### 2. Chain of Custody Validation
```powershell
python demo_chain_validation.py
```
Shows all custody chain validation rules in action.

## Project Structure

```
chain_of_custody/
├── 📖 README.md                 # This file
├── 📚 ARCHITECTURE.md           # System design
├── 🔐 SECURITY.md               # Security details
├── ⚡ QUICKSTART.md             # Fast setup
│
├── ⚙️ config.py                 # Configuration
├── 📦 requirements.txt           # Dependencies
├── 🔧 setup.ps1 / setup.sh      # Setup scripts
├── 🔐 setup_accounts.py         # Create demo accounts
│
├── 🎨 app.py                    # Streamlit UI (5 tabs)
├── 🧪 demo_alteration.py        # Tampering demo
├── 🧪 demo_chain_validation.py  # Validation demo
│
├── 📦 core/
│   ├── database.py              # SQLite operations
│   ├── auth.py                  # User authentication
│   ├── custody.py               # Business logic
│   ├── hashing.py               # SHA-256 cryptography
│   ├── storage.py               # File storage/retrieval
│   ├── audit.py                 # Audit logging
│   └── report.py                # Report generation
│
├── 🔐 db/
│   └── chain.db                 # Database (auto-created)
│
├── 📦 evidence/
│   └── probe_*.ext              # Evidence files
│
└── 📊 reports/
    └── *.pdf                    # Exported reports
```

## Database Schema

### users table (Updated)
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    password_hash TEXT
);
```

### probes table
```sql
CREATE TABLE probes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    stored_path TEXT NOT NULL,
    file_size INTEGER
);
```

### transfers table
```sql
CREATE TABLE transfers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    probe_id INTEGER NOT NULL,
    from_user TEXT NOT NULL,
    to_user TEXT NOT NULL,
    sha256_at_transfer TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(probe_id) REFERENCES probes(id)
);
```

### audit_log table
```sql
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    action TEXT NOT NULL,
    details TEXT,
    status TEXT,
    error_msg TEXT
);
```

## Configuration

Edit `config.py` to customize:

```python
DATABASE_PATH = "db/chain.db"         # Database location
EVIDENCE_DIR = "evidence"              # Evidence storage
MAX_FILE_SIZE = 100 * 1024 * 1024     # Max file size (100 MB)
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Login fails | Use demo account: alice / password123 |
| "Port already in use" | `streamlit run app.py --server.port 8502` |
| Database locked | Close app, delete `db/chain.db`, restart |
| Import errors | Run `pip install -r requirements.txt` |
| Setup script fails | Run `python setup_accounts.py` manually |

See **SECURITY.md** for security notes and limitations.

## Example Workflow

### 1. Crime Scene Investigation
```
Evidence collected → Add to system (Probe ID #1)
Alice receives → Transfer 1 (Alice → Bob) ✓ VALID
Bob receives → Transfer 2 (Bob → Charlie) ✓ VALID
Lab analysis → Transfer 3 (Charlie → Dave) ✓ VALID
Court presentation → Generate PDF report
Audit log shows: Alice → Bob → Charlie → Dave
```

### 2. Tampering Detection
```
Evidence added → Hash: abc123... (Alice uploads)
Transfer 1 → VALID (abc123...) Alice → Bob
[File secretly modified]
Transfer 2 → ALTERED (xyz789...) Bob → Charlie
Audit log shows: WARNING - Evidence altered at Transfer 2
Report shows: ✗ ALTERED - Evidence tampered!
```

## Features Summary

✅ **User Authentication** - Secure login with password hashing
✅ **Chain of Custody Validation** - Enforce proper transfer sequence
✅ **Integrity Verification** - SHA-256 tamper detection
✅ **Audit Logging** - All actions with user identification
✅ **Professional UI** - Smart dropdowns and pre-filled fields
✅ **PDF Reports** - Export custody chain with signatures
✅ **Demo Scripts** - Test all functionality
✅ **Complete Documentation** - README, ARCHITECTURE, SECURITY

## Security & Compliance

⚠️ **Not suitable for production without:**
- SSL/TLS encryption for network communication
- Database encryption at rest
- Multi-factor authentication (MFA)
- Role-based access control (RBAC)
- Regular security audits

✅ **Suitable for:**
- Educational demonstrations
- Forensic lab prototypes
- Classroom projects
- Controlled research environments

See **SECURITY.md** for detailed security analysis.

## Version Information

- **Project**: Digital Chain of Custody v1.0.0
- **Python**: 3.11+
- **Streamlit**: 1.40.0
- **ReportLab**: 4.0.9
- **Database**: SQLite3

## Next Steps

1. **Read QUICKSTART.md** for setup instructions
2. **Run setup_accounts.py** to create demo accounts
3. **Start app** with `streamlit run app.py`
4. **Try demo scripts** to see all functionality
5. **Read ARCHITECTURE.md** for system design
6. **Read SECURITY.md** for security details

## License

Educational project - 2025

## Support

For issues:
1. Check QUICKSTART.md troubleshooting
2. Review SECURITY.md for limitations
3. Check audit log in Tab 5
4. Run demo scripts to verify system works

---

**Made with 🔒 for forensic integrity and user authentication**

## Features

### 🔒 Security
- **Secure File Storage**: Evidence stored in `evidence/` directory with cryptographic naming
- **SHA-256 Hashing**: Cryptographic proof of evidence integrity
- **Hash Verification at Every Transfer**: Detect alterations between custody transfers
- **Tamper Detection**: STATUS labels (✓ VALID / ✗ ALTERED) show if evidence was modified

### 📊 Chain of Custody
- **User Management**: Add custodians to the system
- **Transfer Recording**: Log evidence movement with timestamps
- **Status Indicators**: 
  - ✓ VALID - Hash matches original (evidence unmodified)
  - ✗ ALTERED - Hash differs from original (evidence tampered!)
  - ⚠️ NO_TRANSFERS - Evidence not yet transferred

### 📋 Audit & Reporting
- **Audit Log**: All actions (Add Evidence, Transfers, Integrity Checks) logged with:
  - Timestamp
  - Action type
  - Status (SUCCESS/WARNING/FAILURE)
  - Details and error messages
- **Professional Reports**: 
  - Text format for quick review
  - PDF format with styled tables and status indicators
  - Transfer history with integrity verification

### 💾 Database
- SQLite3 database with 4 tables:
  - `probes` - Digital evidence files
  - `users` - Custodians
  - `transfers` - Custody transfer history
  - `audit_log` - System audit trail

## Installation

### Prerequisites
- Python 3.11+
- Windows/Linux/macOS

### Quick Setup

1. **Clone/Download the project**
   ```powershell
   cd chain_of_custody
   ```

2. **Run setup script** (Windows)
   ```powershell
   .\setup.ps1
   ```
   Or manually:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

3. **Start the application**
   ```powershell
   streamlit run app.py
   ```
   Opens at: `http://localhost:8501`

## Usage

### Tab 1: Add Evidence 📁
1. Upload a digital file (text, image, document, etc.)
2. System automatically:
   - Creates a secure copy in `evidence/` directory
   - Calculates SHA-256 hash
   - Logs action to audit trail
3. Note the **Probe ID** for future transfers

### Tab 2: Custody Transfer 🔄
1. Add custodians (e.g., "Officer Alice", "Officer Bob")
2. Select evidence to transfer
3. Choose FROM and TO custodians
4. Click "Perform Transfer"
5. System shows:
   - ✓ VALID - Evidence unchanged
   - ✗ ALTERED - Evidence was modified!

### Tab 3: Integrity Check ✅
1. Re-upload the evidence file
2. System compares with original hash
3. Shows:
   - ✓ UNMODIFIED - File integrity intact
   - ❌ MODIFIED - File has been altered
   - ⚠️ UNKNOWN - File not in system

### Tab 4: Report 📊
1. Preview transfer history
2. Download as **TXT** (plain text) or **PDF** (professional format)
3. Report includes:
   - All registered evidence
   - Complete transfer chain
   - Integrity status for each transfer
   - Timestamps

### Tab 5: Audit Log 📝
1. View all system actions
2. Filter by status (SUCCESS/WARNING/FAILURE)
3. Expandable entries showing:
   - Timestamp
   - Action type
   - Details
   - Error messages (if any)

## Demo: Tampering Detection

Run the automated demo to see evidence tampering detection:

```powershell
python demo_alteration.py
```

This script:
1. ✓ Adds evidence (hash: abc123...)
2. ✓ Performs Transfer 1 → VALID (hash unchanged)
3. 🚨 Secretly modifies the stored file
4. ✗ Performs Transfer 2 → ALTERED (hash mismatch detected!)
5. 📊 Generates report showing which transfer altered evidence

## Project Structure

```
chain_of_custody/
├── app.py                    # Streamlit UI (5 tabs)
├── demo_alteration.py        # Tampering detection demo
├── config.py                 # Configuration settings
├── requirements.txt          # Python dependencies
├── setup.ps1                 # Setup script
├── .gitignore               # Git ignore rules
├── README.md                # This file
│
├── core/                     # Core modules
│   ├── __init__.py
│   ├── database.py          # SQLite operations
│   ├── custody.py           # Business logic
│   ├── hashing.py           # SHA-256 cryptography
│   ├── storage.py           # File storage/retrieval
│   ├── audit.py             # Audit logging
│   └── report.py            # Report generation
│
├── db/                       # Database
│   └── chain.db             # SQLite database (auto-created)
│
├── evidence/                 # Evidence storage
│   ├── probe_1_20251226_101050.txt
│   ├── probe_2_20251226_102315.jpg
│   └── ...
│
└── .venv/                    # Virtual environment
    └── (auto-created by setup)
```

## Database Schema

### probes table
```sql
CREATE TABLE probes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    stored_path TEXT NOT NULL,
    file_size INTEGER
);
```

### transfers table
```sql
CREATE TABLE transfers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    probe_id INTEGER NOT NULL,
    from_user TEXT NOT NULL,
    to_user TEXT NOT NULL,
    sha256_at_transfer TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(probe_id) REFERENCES probes(id)
);
```

### audit_log table
```sql
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    action TEXT NOT NULL,
    details TEXT,
    status TEXT,
    error_msg TEXT
);
```

## API Reference

### Custody Module (`core/custody.py`)

#### `add_probe(filename, file_bytes) → (probe_id, sha256)`
Register new evidence in the system.

#### `add_transfer(probe_id, from_user, to_user) → (integrity_valid, original_hash, current_hash)`
Record custody transfer and verify integrity.

#### `verify_integrity(probe_id, file_bytes) → (is_valid, current_hash)`
Verify uploaded file against original.

#### `get_audit_log(limit) → list[audit_entries]`
Retrieve audit trail.

### Database Module (`core/database.py`)

#### `init_db()`
Initialize database with all tables.

#### `get_probe_details(probe_id) → (id, filename, sha256, created_at, stored_path, file_size)`
Get evidence details.

#### `get_report_data() → (probes, transfers)`
Get all data for report generation.

## Configuration

Edit `config.py` to customize:

```python
DATABASE_PATH = "db/chain.db"      # Database location
EVIDENCE_DIR = "evidence"          # Evidence storage directory
MAX_FILE_SIZE = 100 * 1024 * 1024  # Max file size (100 MB)
```

## Troubleshooting

### "Evidence folder not found"
- Folder is auto-created on first upload
- Check permissions on working directory

### Database locked error
- Close Streamlit app or demo script
- Delete `db/chain.db` and restart

### Encoding errors on Windows
- Set environment variable: `$PYTHONIOENCODING="utf-8"`
- Or use Python IDE instead of terminal

### Port already in use
- Streamlit uses port 8501 by default
- Change with: `streamlit run app.py --server.port 8502`

## Security Notes

⚠️ **Not for production without:**
- SSL/TLS for network communication
- User authentication & authorization
- Database encryption
- Access control lists (ACL)
- Regular security audits

✅ **Current implementation suitable for:**
- Educational demonstrations
- Forensic lab prototypes
- Evidence chain management in controlled environments
- Classroom projects

## Example Workflow

1. **Crime Scene Investigation**
   ```
   Evidence collected → Add to system (Probe ID #1)
   Officer Alice receives → Transfer 1 (VALID ✓)
   Officer Bob receives → Transfer 2 (VALID ✓)
   Lab analysis → Transfer 3 (VALID ✓)
   Court presentation → Generate PDF report
   ```

2. **Tampering Detection**
   ```
   Evidence added → Hash: abc123...
   Transfer 1 → VALID (abc123...)
   [File secretly modified]
   Transfer 2 → ALTERED (xyz789...)
   Report shows: ✗ ALTERED - Evidence tampered!
   ```

## License

Educational project - 2025

## Support

For issues or questions:
1. Check README.md troubleshooting section
2. Review audit log in Tab 5
3. Check terminal output for error messages
4. Run `demo_alteration.py` to verify system works

---

**Made with 🔒 for forensic integrity**

---

## 👤 Author

**Edna Memedula**  
📫 [LinkedIn](https://www.linkedin.com/in/edna-memedula-24b519245) • [GitHub](https://github.com/mgedna)