# 🔐 Digital Chain of Custody

A professional forensic evidence management system that tracks digital evidence through a secure custody chain, with **cryptographic integrity verification**, **chain validation**, **status lifecycle management**, **credential analysis capabilities**, and **comprehensive audit logging** with **user authentication**.

## Overview

This application implements a **digital chain of custody** system for forensic investigations compliant with **NIST SP 800-86**, **ISO/IEC 27037**, and **ACPO Guidelines**. It provides:

* **User Authentication**: Secure login with email-based accounts and role-based access (ADMIN, INVESTIGATOR, CUSTODIAN)
* **Evidence Registration**: Upload and securely store digital evidence files
* **Custody Transfer**: Track evidence movement with mandatory transfer reasons (NIST requirement)
* **Chain of Custody Validation**: Enforce proper custody chain rules
* **Evidence Status Lifecycle**: RECEIVED -> IN_ANALYSIS -> VERIFIED -> RELEASED/ARCHIVED
* **Integrity Verification**: Detect evidence tampering through SHA-256 cryptographic hashing with **irreversible ALTERED status**
* **Automated Integrity Checks**: NIST-compliant verification of all system evidence
* **Credential Analysis**: Optional hash cracking analysis using Hashcat (MD5, SHA1, SHA256, BCRYPT, NTLM, etc.)
* **Audit Trail**: Comprehensive logging of all system actions with user identification
* **Professional Reports**: Generate PDF/TXT reports with transfer history, integrity status, and analysis results

## 🆕 Key Features

### 🔑 User Authentication

* **Email-based login system** with password hashing (PBKDF2 - 100,000 iterations)
* **Role-based access control**: ADMIN, INVESTIGATOR, CUSTODIAN
* **Demo accounts** pre-configured for testing
* **Account registration** directly in app with validation
* **Session management** - Track authenticated user identity
* **User identification** in all audit logs and transfers

### 🔗 Chain of Custody Validation (NIST Compliant)

* **Custody Continuity** - Only current custodian can transfer
* **No Reverse Transfers** - Cannot go A -> B -> A (NIST standard)
* **Linear Chain Enforcement** - Proper sequence required
* **Smart UI** - Pre-fills from_user, filters to_user options
* **Mandatory Transfer Reason** - NIST requirement for transfer documentation

### 📋 Evidence Status Lifecycle (ISO/IEC 27037)

* **RECEIVED** - Initial status when evidence uploaded
* **IN_ANALYSIS** - Evidence under investigation
* **VERIFIED** - Integrity verified and complete
* **RELEASED** - Returned to owner
* **ARCHIVED** - Long-term storage
* **Status Management Tab** - Update evidence status with audit trail

### 🔒 Cryptographic Security

* **SHA-256 Hashing**: 256-bit collision-resistant cryptography
* **Hash Verification at Every Transfer**: Detect alterations between custody transfers
* **Irreversible ALTERED Status**: Once evidence is marked ALTERED through VERIFY_INTEGRITY failure, it remains ALTERED permanently (forensic integrity principle)
* **Authoritative Integrity Status**: System checks for ANY integrity failure in audit history - if found, evidence is permanently ALTERED
* **Transfer Independence**: Transfers always succeed and are logged as SUCCESS (procedural requirement), but integrity status (VALID/ALTERED) is tracked separately
* **Tamper Detection**: STATUS labels (✓ VALID / ✗ ALTERED) show if evidence was modified
* **Secure File Storage**: Evidence stored in `evidence/` directory with cryptographic naming
* **Password Protection**: User accounts with PBKDF2 encryption

### 🔍 Automated Integrity Verification (NIST SP 800-86)

* **System-wide Integrity Checks**: Verify all evidence hasn't been tampered with
* **Automated VERIFY_INTEGRITY Events**: Failed integrity checks generate VERIFY_INTEGRITY FAILURE events that permanently mark evidence as ALTERED
* **Forensic Principle**: Once compromised, always compromised - ALTERED status is irreversible
* **Automated Alerts**: Flag altered evidence immediately
* **Check Summary**: Total probes checked, altered count
* **Audit Integration**: All checks logged to audit trail with AUTOMATED_ prefix

### 🔐 Credential Analysis (Optional Module)

* **Hash Type Support**: MD5, MD5_SALTED, SHA1, SHA256, SHA256_SALTED, BCRYPT, SCRYPT, NTLM, LM, Windows, Linux, PDF
* **Hashcat Integration**: Industry-standard password cracking tool
* **Working Copy Protection**: Analysis performed on temporary copies - original evidence never touched
* **Dictionary Attack**: Configurable wordlist support
* **Statistics Only**: Returns crack rate and count, never plaintext passwords (ethical security)
* **Analysis Audit Trail**: All credential analysis logged as ANALYSIS events (non-procedural)
* **Report Integration**: Analysis results included in evidence reports

### 📊 Chain of Custody

* **User Management**: Create/register custodians with secure passwords and roles
* **Transfer Recording**: Log evidence movement with:
  + Source and destination custodian
  + **Transfer reason** (e.g., "For analysis", "Verification", "Storage")
  + Cryptographic hash at transfer time
  + User identification
  + Timestamp
* **Status Indicators**:
  + ✓ VALID - Hash matches original (evidence unmodified)
  + ✗ ALTERED - Hash differs from original OR integrity check failed (evidence tampered, irreversible!)
  + ⚠️ NO_TRANSFERS - Evidence not yet transferred

### 📋 Audit & Reporting

* **Audit Log**: All actions logged with:
  + Timestamp (millisecond precision)
  + **Authenticated user**
  + Action type (TRANSFER, VERIFY_INTEGRITY, ANALYSIS, etc.)
  + Status (SUCCESS/WARNING/FAILURE)
  + Details and error messages
* **Professional Reports**:
  + **Per-Evidence Reports** - Detailed chain history for specific evidence including credential analysis results
  + **Overall Reports** - System-wide chain of custody summary
  + **Integrity Timeline** - When evidence integrity was compromised
  + **Compromise Interval** - Narrowed window of when tampering occurred
  + Text format for quick review
  + PDF format with styled tables and status indicators
  + Transfer history with integrity verification
  + Analysis results summary

### 💾 Database

* SQLite3 database with 4 tables:
  + `probes` - Digital evidence files with status lifecycle
  + `users` - Custodians with email, password hashes, and roles
  + `transfers` - Custody transfer history with **transfer reason** and user tracking
  + `audit_log` - System audit trail with user identification and action types

## Application Tabs

### Tab 1: 📥 Add Evidence

* Upload digital evidence files
* Automatic SHA-256 hash calculation
* Secure storage in `evidence/` directory
* Initial status: RECEIVED
* Associate with authenticated user

### Tab 2: 🔄 Custody Transfer

* Select evidence to transfer
* **Mandatory transfer reason** (NIST requirement)
* Current custodian auto-filled
* Valid recipients pre-filtered (chain validation)
* Hash verification at transfer time
* **Transfer always succeeds** (procedural requirement)
* Integrity status tracked separately as VALID/ALTERED
* Auto-refresh after successful transfer

### Tab 3: 🔍 Integrity Check

* Verify evidence hasn't been tampered with
* Re-upload file and compare hash
* Shows VALID or ALTERED status
* Compare original vs current hash
* **Generates VERIFY_INTEGRITY event** (SUCCESS if valid, FAILURE if altered)
* **ALTERED status is permanent** - once integrity is compromised, it cannot be reversed

### Tab 4: 📊 Report

* **Per-Evidence Reports** - Select specific evidence
  + Evidence details (ID, filename, hash, uploaded by, status)
  + Complete transfer history
  + Status for each transfer
  + Integrity timeline showing when evidence was compromised
  + Compromise interval (narrowed window of tampering)
  + Credential analysis results if performed
  + Download as TXT or PDF
* **Overall Reports** - System-wide reports
  + All evidence with integrity status
  + Complete transfer history
  + Download as TXT or PDF

### Tab 5: 📋 Audit Log

* View all system actions in real-time
* Filter by limit (10/50/100/500 entries)
* Expandable entries showing:
  + Status (SUCCESS/WARNING/FAILURE)
  + Timestamp
  + Action type (TRANSFER, VERIFY_INTEGRITY, ANALYSIS, etc.)
  + Details of action
  + Error messages if any

### Tab 6: 📊 Status & Automated Checks

* **Status Management**
  + View current evidence status
  + Update status through lifecycle
  + RECEIVED -> IN_ANALYSIS -> VERIFIED -> RELEASED/ARCHIVED
  + Changes logged to audit trail
* **Automated Integrity Verification** (NIST Compliance)
  + Run full system integrity check
  + Verify all evidence hashes
  + Check authoritative integrity status (checks entire audit history for ANY failures)
  + Detect altered evidence based on VERIFY_INTEGRITY events
  + Generate check summary
  + Alert on any tampering detected
  + Creates AUTOMATED_VERIFY_INTEGRITY events for altered probes

### Tab 7: 🔐 Credential Analysis

* **Hash File Upload**: Upload files containing password hashes
* **Hash Type Selection**: Choose from supported formats (MD5, SHA256, BCRYPT, NTLM, etc.)
* **Wordlist Configuration**: Use default or upload custom wordlist
* **Analysis Execution**: Runs Hashcat on working copy (original untouched)
* **Results Display**:
  + Total hashes analyzed
  + Number cracked
  + Crack rate percentage
  + Security assessment (Strong/Good/Moderate/Weak)
* **Audit Integration**: All analysis logged as ANALYSIS events

## Installation

### Prerequisites

* Python 3.11+
* Windows/Linux/macOS
* **Optional**: Hashcat (for credential analysis module)

### Quick Setup

1. **Clone/Download the project**

   ```bash
   cd chain_of_custody
   ```

2. **Run setup script** (Windows)

   ```powershell
   .\setup.ps1
   ```

   Or manually:

   ```bash
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

3. **Create demo accounts**

   ```bash
   python setup_accounts.py
   ```

4. **Start the application**

   ```bash
   streamlit run app.py
   ```

   Opens at: `http://localhost:8501`

## Usage

### Login

1. Start app: `streamlit run app.py`
2. **Login with demo account:**
   * Email: `alice@forensics.lab` / Password: `password123` (Alice - CUSTODIAN)
   * Email: `bob@forensics.lab` / Password: `password456` (Bob - CUSTODIAN)
   * Email: `charlie@forensics.lab` / Password: `password789` (Charlie - CUSTODIAN)

### Tab 1: Add Evidence 📁

1. Upload a digital file (text, image, document, etc.)
2. System automatically:
   * Creates a secure copy in `evidence/` directory
   * Calculates SHA-256 hash
   * Sets initial status to RECEIVED
   * Logs action to audit trail **with your email**
3. Note the **Probe ID** for future transfers

### Tab 2: Custody Transfer 🔄

1. Select evidence to transfer
2. System shows **Current Custodian** (who has it now)
3. **Only current custodian can transfer** (validated automatically)
4. Enter **mandatory transfer reason**
5. Select recipient from valid options (pre-filtered, no reverse transfers)
6. System records transfer with:
   * Your email
   * Timestamp
   * Hash verification
   * Integrity status (VALID/ALTERED)
7. **Transfer always succeeds** regardless of integrity (procedural requirement)

### Tab 3: Integrity Check ✅

1. Re-upload the evidence file
2. System compares with original hash
3. Shows:
   * ✓ UNMODIFIED - File integrity intact
   * ❌ MODIFIED - File has been altered
   * ⚠️ UNKNOWN - File not in system
4. **Generates VERIFY_INTEGRITY event**:
   * SUCCESS if hash matches
   * **FAILURE if hash doesn't match** - permanently marks evidence as ALTERED

### Tab 4: Report 📊

1. Preview transfer history and integrity timeline
2. Download as **TXT** (plain text) or **PDF** (professional format)
3. Report includes:
   * All registered evidence
   * Complete transfer chain with **custodian names**
   * Integrity status for each transfer
   * Authoritative integrity status (checks full audit history)
   * Integrity timeline (when evidence was compromised)
   * Compromise interval (narrowed window of tampering)
   * Credential analysis results if performed
   * Timestamps

### Tab 5: Audit Log 📝

1. View all system actions
2. Filter by status (SUCCESS/WARNING/FAILURE)
3. Expandable entries showing:
   * **Email of user who performed action**
   * Timestamp
   * Action type (TRANSFER, VERIFY_INTEGRITY, ANALYSIS, etc.)
   * Details
   * Error messages (if any)

### Tab 6: Status & Automated Checks 📊

1. **Update Evidence Status**:
   * Select evidence
   * Choose new status from lifecycle
   * Submit with mandatory reason
   * View audit trail of status changes

2. **Run Automated Integrity Check**:
   * Click "Run Integrity Check"
   * System verifies ALL evidence
   * Uses authoritative integrity status (checks for ANY VERIFY_INTEGRITY FAILURE in history)
   * Creates AUTOMATED_VERIFY_INTEGRITY FAILURE events for altered probes
   * Shows summary: total checked, altered count
   * Lists altered evidence with probe ID, filename, and status

### Tab 7: Credential Analysis 🔐

1. **Select Evidence**: Choose probe containing password hashes
2. **Choose Hash Type**: Select format (MD5, SHA256, BCRYPT, NTLM, etc.)
3. **Configure Attack**: Use default wordlist or upload custom
4. **Run Analysis**: System creates working copy and runs Hashcat
5. **View Results**:
   * Total hashes analyzed
   * Cracked count
   * Crack rate %
   * Security assessment
6. **Analysis logged as ANALYSIS event** (non-procedural, does not affect chain of custody)

## Demo Scripts

### 1. Tampering Detection

```bash
python demo_alteration.py
```

Shows evidence tampering detection between transfers with ALTERED status propagation.

### 2. Chain of Custody Validation

```bash
python demo_chain_validation.py
```

Shows all custody chain validation rules in action including email-based authentication.

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
├── 🎨 app.py                    # Streamlit UI (7 tabs)
├── 🧪 demo_alteration.py        # Tampering demo
├── 🧪 demo_chain_validation.py  # Validation demo
│
├── 📦 core/
│   ├── database.py              # SQLite operations
│   ├── auth.py                  # User authentication (email-based)
│   ├── custody.py               # Business logic
│   ├── hashing.py               # SHA-256 cryptography
│   ├── storage.py               # File storage/retrieval
│   ├── audit.py                 # Audit logging (TRANSFER, VERIFY_INTEGRITY, ANALYSIS)
│   ├── report.py                # Report generation with integrity timeline
│   └── analysis.py              # Credential analysis (Hashcat integration)
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
    email TEXT NOT NULL UNIQUE,
    username TEXT,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'CUSTODIAN'
);
```

### probes table (Updated)

```sql
CREATE TABLE probes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    stored_path TEXT NOT NULL,
    file_size INTEGER,
    status TEXT DEFAULT 'RECEIVED',
    uploaded_by TEXT
);
```

### transfers table (Updated)

```sql
CREATE TABLE transfers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    probe_id INTEGER NOT NULL,
    from_user TEXT NOT NULL,
    to_user TEXT NOT NULL,
    sha256_at_transfer TEXT NOT NULL,
    transfer_reason TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(probe_id) REFERENCES probes(id)
);
```

### audit_log table (Updated)

```sql
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_email TEXT,
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

| Issue                     | Solution                                            |
| ------------------------- | --------------------------------------------------- |
| Login fails               | Use demo account: alice@forensics.lab / password123 |
| "Account creation failed" | Check email format and password strength (6+ chars) |
| "Port already in use"     | `streamlit run app.py --server.port 8502`           |
| Database locked           | Close app, delete `db/chain.db`, restart            |
| Import errors             | Run `pip install -r requirements.txt`               |
| Setup script fails        | Run `python setup_accounts.py` manually             |
| Credential analysis fails | Install Hashcat or skip optional analysis module    |

See **SECURITY.md** for security notes and limitations.

## Example Workflows

### 1. Crime Scene Investigation

```
Evidence collected -> Add to system (Probe ID #1, status: RECEIVED)
Alice receives -> Transfer 1 (Alice -> Bob, reason: "Initial analysis") ✓ VALID
Status updated -> IN_ANALYSIS
Bob receives -> Transfer 2 (Bob -> Charlie, reason: "Deep forensics") ✓ VALID
Lab analysis -> Transfer 3 (Charlie -> Dave, reason: "Report generation") ✓ VALID
Status updated -> VERIFIED
Court presentation -> Generate PDF report with full chain
Audit log shows: Alice -> Bob -> Charlie -> Dave (all emails tracked)
```

### 2. Tampering Detection with Irreversible ALTERED Status

```
Evidence added -> Hash: abc123... (Alice uploads)
Transfer 1 -> VALID (abc123...) Alice -> Bob
[File secretly modified on disk]
Transfer 2 -> ALTERED (xyz789...) Bob -> Charlie
  -> System detects hash mismatch
  -> Transfer SUCCEEDS (procedural requirement)
  -> Integrity marked ALTERED (separate from transfer)
Manual integrity check -> FAILURE
  -> Generates VERIFY_INTEGRITY FAILURE event
  -> Evidence permanently marked ALTERED
Transfer 3 -> Charlie -> Dave
  -> Transfer SUCCEEDS
  -> But authoritative status shows ALTERED (checks audit history)
  -> Once altered, always altered (forensic principle)
Report shows: 
  ✗ ALTERED - Evidence tampered at Transfer 2
  Integrity Timeline: Compromised between Transfer 1 and Transfer 2
  Compromise Interval: [Transfer 1 timestamp, Transfer 2 timestamp]
Audit log shows: 
  - WARNING at Transfer 2 (integrity: ALTERED)
  - VERIFY_INTEGRITY FAILURE event
  - AUTOMATED_VERIFY_INTEGRITY FAILURE event (if automated check ran)
```

### 3. Credential Analysis Workflow

```
Hash file collected -> Upload as evidence (Probe ID #5)
Analyst selects probe -> Tab 7: Credential Analysis
Choose hash type -> MD5
Run analysis -> Hashcat on working copy (original untouched)
Results show:
  - 150 hashes analyzed
  - 23 cracked (15.3%)
  - Assessment: Moderate credential protection
Analysis logged -> ANALYSIS event in audit trail
Report includes -> Credential analysis summary in evidence report
```

## Features Summary

✅ **Email-Based Authentication** - Secure login with role-based access
✅ **Chain of Custody Validation** - Enforce proper transfer sequence with no reverse transfers
✅ **Integrity Verification** - SHA-256 tamper detection with irreversible ALTERED status
✅ **Authoritative Integrity Status** - Checks entire audit history for ANY integrity failures
✅ **Transfer Independence** - Transfers always succeed (procedural) with separate integrity tracking
✅ **Credential Analysis** - Optional hash cracking with Hashcat integration
✅ **Audit Logging** - All actions with user email and action type (TRANSFER, VERIFY_INTEGRITY, ANALYSIS)
✅ **Professional UI** - Smart dropdowns and pre-filled fields with email-based users
✅ **PDF Reports** - Export custody chain with integrity timeline and analysis results
✅ **Demo Scripts** - Test all functionality including altered evidence workflows
✅ **Complete Documentation** - README, ARCHITECTURE, SECURITY

## Security & Compliance

⚠️ **Not suitable for production without:**

* SSL/TLS encryption for network communication
* Database encryption at rest
* Multi-factor authentication (MFA)
* Advanced role-based access control (RBAC)
* Regular security audits
* Secure Hashcat installation and wordlist management

✅ **Suitable for:**

* Educational demonstrations
* Forensic lab prototypes
* Classroom projects
* Controlled research environments
* Credential security analysis training

See **SECURITY.md** for detailed security analysis.

## Version Information

* **Project**: Digital Chain of Custody v2.0.0
* **Python**: 3.11+
* **Streamlit**: 1.40.0
* **ReportLab**: 4.0.9
* **Database**: SQLite3
* **Optional**: Hashcat 6.x+ (for credential analysis)

## Next Steps

1. **Read QUICKSTART.md** for setup instructions
2. **Run setup_accounts.py** to create demo accounts with emails
3. **Start app** with `streamlit run app.py`
4. **Try demo scripts** to see all functionality including altered evidence workflows
5. **Read ARCHITECTURE.md** for system design with integrity status details
6. **Read SECURITY.md** for security details including credential analysis risks

## License

Educational project - 2025

## Support

For issues:

1. Check QUICKSTART.md troubleshooting
2. Review SECURITY.md for limitations
3. Check audit log in Tab 5 for TRANSFER/VERIFY_INTEGRITY/ANALYSIS events
4. Run demo scripts to verify system works
5. Review integrity timeline in reports to understand when evidence was compromised

---

**Made with 🔒 for forensic integrity, irreversible tamper detection, and optional credential analysis**

## 👤 Author

**Edna Memedula**  
📫 [LinkedIn](https://www.linkedin.com/in/edna-memedula-24b519245) • [GitHub](https://github.com/mgedna)
