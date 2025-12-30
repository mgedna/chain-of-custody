# 🏗️ System Architecture

## Overview

The Digital Chain of Custody system is built with a modular architecture that separates concerns into distinct layers: presentation (Streamlit UI), business logic (core modules), data persistence (SQLite), and file storage.

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────────┐
│                     PRESENTATION LAYER                       │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │              Streamlit Web Interface (app.py)          │  │
│  │                                                        │  │
│  │  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐       │  │
│  │  │Login│ │Add  │ │Trans│ │Check│ │Reprt│ │Audit│       │  │
│  │  │     │ │Evid.│ │ fer │ │Integ│ │     │ │ Log │       │  │
│  │  └─────┘ └─────┘ └─────┘ └─────┘ └─────┘ └─────┘       │  │
│  │  ┌─────┐ ┌─────┐                                       │  │
│  │  │Statu│ │Cred.│                                       │  │
│  │  │ s   │ │Analy│                                       │  │
│  │  └─────┘ └─────┘                                       │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
                           │
                           │ Function Calls
                           ▼
┌──────────────────────────────────────────────────────────────┐
│                    BUSINESS LOGIC LAYER                      │
│                        (core/*.py)                           │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐      │
│  │   auth   │  │ custody  │  │ hashing  │  │ storage  │      │
│  │   .py    │  │   .py    │  │   .py    │  │   .py    │      │
│  │          │  │          │  │          │  │          │      │
│  │• Email   │  │• Add     │  │• SHA-256 │  │• Save    │      │
│  │  login   │  │  probe   │  │  hash    │  │  files   │      │
│  │• Role-   │  │• Transfer│  │• Verify  │  │• Load    │      │
│  │  based   │  │• Validate│  │  hash    │  │  files   │      │
│  │• PBKDF2  │  │  chain   │  │          │  │          │      │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘      │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                    │
│  │  audit   │  │  report  │  │ analysis │                    │
│  │   .py    │  │   .py    │  │   .py    │                    │
│  │          │  │          │  │          │                    │
│  │• TRANSFER│  │• TXT gen │  │• Hashcat │                    │
│  │• VERIFY_ │  │• PDF gen │  │  integr. │                    │
│  │  INTEGR. │  │• Timeline│  │• Working │                    │
│  │• ANALYSIS│  │• Interval│  │  copy    │                    │
│  └──────────┘  └──────────┘  └──────────┘                    │
└──────────────────────────────────────────────────────────────┘
                           │
                           │ SQL Queries
                           ▼
┌──────────────────────────────────────────────────────────────┐
│                     DATA LAYER                               │
│                    (core/database.py)                        │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐     │
│  │  users   │  │  probes  │  │transfers │  │audit_log  │     │
│  │          │  │          │  │          │  │           │     │
│  │• email   │  │• filename│  │• from_   │  │• timestamp│     │
│  │• username│  │• sha256  │  │  user    │  │• user_    │     │
│  │• pwd_hash│  │• status  │  │• to_user │  │  email    │     │
│  │• role    │  │• uploaded│  │• reason  │  │• action   │     │
│  │          │  │  _by     │  │• sha256  │  │• status   │     │
│  └──────────┘  └──────────┘  └──────────┘  └───────────┘     │
│                                                              │
│                    SQLite3 Database                          │
│                    (db/chain.db)                             │
└──────────────────────────────────────────────────────────────┘
                           │
                           │ File I/O
                           ▼
┌──────────────────────────────────────────────────────────────┐
│                    STORAGE LAYER                             │
│                                                              │
│  evidence/                                                   │
│  ├── probe_1_<timestamp>.<ext>                               │ 
│  ├── probe_2_<timestamp>.<ext>                               │
│  └── probe_N_<timestamp>.<ext>                               │
│                                                              │
│  /tmp/ (for credential analysis)                             │
│  ├── hashcat_work_<uuid>/                                    │
│  │   ├── hashes.txt                                          │
│  │   ├── wordlist.txt                                        │
│  │   └── potfile.pot                                         │
│  └── (cleaned up after analysis)                             │
└──────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Presentation Layer (app.py)

**Purpose**: User interface and workflow orchestration

**Key Features**:
* **Session Management**: Tracks authenticated user via `st.session_state`
* **7 Main Tabs**:
  1. **Login/Register** - Email-based authentication with role selection
  2. **Add Evidence** - File upload with automatic hashing
  3. **Custody Transfer** - Chain validation and transfer recording
  4. **Integrity Check** - Manual verification with VERIFY_INTEGRITY event generation
  5. **Report** - PDF/TXT generation with integrity timeline
  6. **Audit Log** - Real-time action viewing with event type filtering
  7. **Status Management** - Lifecycle updates and automated integrity checks
  8. **Credential Analysis** - Optional hash cracking module

**Technologies**:
* Streamlit 1.40.0 for reactive UI
* Session state for authentication persistence
* File uploader widgets for evidence/hash files
* Selectboxes with smart filtering (chain validation)

### 2. Authentication Layer (core/auth.py)

**Purpose**: User identity management with email-based authentication

**Key Functions**:

```python
def hash_password(password: str) -> str
    """PBKDF2 with SHA-256, 100,000 iterations"""

def verify_password(password: str, stored_hash: str) -> bool
    """Constant-time comparison"""

def create_user_with_password(email: str, password: str, username: str, role: str) -> bool
    """Create user with email, optional username, role (ADMIN/INVESTIGATOR/CUSTODIAN)"""

def authenticate_user(email: str, password: str) -> Optional[Tuple[int, str]]
    """Returns (user_id, username) or None"""
```

**Security Features**:
* PBKDF2-SHA256 with 100,000 iterations (NIST recommended)
* Email-based unique identification
* Role-based access control preparation (ADMIN/INVESTIGATOR/CUSTODIAN)
* Constant-time password comparison (timing attack prevention)

**Database Schema**:
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    username TEXT,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'CUSTODIAN'
);
```

### 3. Custody Management (core/custody.py)

**Purpose**: Business logic for evidence handling and chain validation

**Key Functions**:

```python
def add_probe(filename: str, file_bytes: bytes, uploaded_by: str) -> tuple
    """Register evidence with RECEIVED status"""

def add_transfer(probe_id: int, from_user: str, to_user: str, reason: str) -> tuple
    """
    Record custody transfer with:
    - Chain validation (custody continuity, no reverse transfers)
    - Hash verification at transfer time
    - Transfer ALWAYS succeeds (procedural requirement)
    - Integrity status tracked separately (VALID/ALTERED)
    """

def validate_custody_chain(probe_id: int, from_user: str, to_user: str) -> tuple
    """
    Validate transfer is allowed:
    - from_user must be current custodian
    - to_user cannot be same as from_user
    - No A→B→A reverse transfers (NIST standard)
    Returns: (is_valid, error_message)
    """

def verify_integrity(probe_id: int, file_bytes: bytes) -> tuple
    """
    Manual integrity verification with VERIFY_INTEGRITY event generation:
    - Compares uploaded file hash with original
    - Returns (is_valid, current_hash)
    - Generates VERIFY_INTEGRITY SUCCESS/FAILURE event
    - FAILURE events permanently mark evidence as ALTERED
    """

def get_authoritative_integrity_status(probe_id: int) -> Optional[str]
    """
    Get definitive integrity status:
    - Checks entire audit_log for ANY VERIFY_INTEGRITY FAILURE
    - If ANY failure found → ALTERED (irreversible)
    - Else if latest check SUCCESS → VALID
    - Else → None (no checks performed)
    """

def run_integrity_check_all() -> tuple
    """
    Automated system-wide integrity check:
    - Checks all probes using authoritative integrity status
    - Creates AUTOMATED_VERIFY_INTEGRITY FAILURE events for altered probes
    - Returns (total_checked, altered_count, altered_details)
    """

def update_probe_status(probe_id: int, new_status: str, reason: str, user_email: str) -> bool
    """Update evidence lifecycle status with audit trail"""

def get_current_custodian(probe_id: int) -> Optional[str]
    """Get current holder of evidence"""
```

**Chain Validation Rules**:
1. **Custody Continuity**: Only current custodian can transfer
2. **No Self-Transfer**: Cannot transfer to yourself
3. **No Reverse Transfers**: Cannot go A→B→A (NIST compliance)
4. **Linear Chain**: Must maintain proper sequence

**Integrity Status Logic**:
```
TRANSFER vs INTEGRITY STATUS:
├─ Transfer Action (Procedural)
│  ├─ Validates: custody chain rules
│  ├─ Records: from_user, to_user, reason, hash
│  └─ Always: SUCCESS (procedural documentation)
│
└─ Integrity Status (Forensic)
   ├─ Tracked: separately from transfer
   ├─ Calculated: at transfer time via hash comparison
   └─ Values:
      ├─ VALID: hash matches original
      └─ ALTERED: hash differs OR VERIFY_INTEGRITY FAILURE exists

VERIFY_INTEGRITY Event:
├─ Manual Check (Tab 3)
│  ├─ User uploads file
│  ├─ System compares hash
│  └─ Creates event: SUCCESS or FAILURE
│
├─ Automated Check (Tab 6)
│  ├─ System checks all probes
│  ├─ Uses authoritative status
│  └─ Creates AUTOMATED_VERIFY_INTEGRITY FAILURE for altered probes
│
└─ FAILURE Impact:
   ├─ Marks evidence ALTERED permanently
   ├─ Status is irreversible (forensic principle)
   └─ Future checks always return ALTERED
```

### 4. Cryptographic Operations (core/hashing.py)

**Purpose**: Evidence integrity verification

**Key Functions**:

```python
def hash_file(file_bytes: bytes) -> str
    """SHA-256 hash generation"""

def verify_hash(file_bytes: bytes, expected_hash: str) -> bool
    """Hash comparison"""
```

**Algorithm**: SHA-256 (NIST FIPS 180-4)
* 256-bit output
* Collision-resistant
* Pre-image resistant
* Second pre-image resistant

### 5. File Storage (core/storage.py)

**Purpose**: Secure evidence file management

**Key Functions**:

```python
def save_file(file_bytes: bytes, filename: str, probe_id: int) -> str
    """Store evidence with cryptographic naming"""

def load_file(stored_path: str) -> bytes
    """Retrieve evidence"""

def file_exists(stored_path: str) -> bool
    """Check existence"""
```

**Naming Convention**: `probe_{probe_id}_{timestamp}.{extension}`

**Storage Structure**:
```
evidence/
├── probe_1_20251230_101050.txt
├── probe_2_20251230_102315.jpg
├── probe_3_20251230_103422.pdf
└── probe_N_<timestamp>.<ext>
```

### 6. Audit Trail (core/audit.py)

**Purpose**: Comprehensive system logging with event types

**Key Functions**:

```python
def log_action(action: str, details: str, status: str, user_email: str = None)
    """
    Generic audit logging with user identification
    Status: SUCCESS, WARNING, FAILURE
    """

def log_probe_added(probe_id: int, filename: str, sha256: str, user_email: str)
    """Log evidence registration"""

def log_user_added(email: str, role: str)
    """Log account creation"""

def log_transfer(probe_id: int, from_user: str, to_user: str, integrity_valid: bool, current_hash: str)
    """
    Log custody transfer
    CRITICAL: Status is ALWAYS SUCCESS (procedural requirement)
    Integrity status (VALID/ALTERED) is separate and informational
    """

def log_integrity_check(probe_id: int, is_valid: Optional[bool], current_hash: str, source: str = "")
    """
    Log integrity verification
    Action: VERIFY_INTEGRITY or AUTOMATED_VERIFY_INTEGRITY
    Status: SUCCESS (valid) or FAILURE (altered)
    FAILURE permanently marks evidence as ALTERED
    """

def log_credential_analysis(probe_id: int, hash_type: str, total_hashes: int, cracked_hashes: int, crack_rate: float)
    """
    Log credential analysis
    Action: ANALYSIS
    Note: Non-procedural, does not affect chain of custody
    """

def log_error(action: str, error_msg: str)
    """Log system errors"""
```

**Event Types**:
* **PROBE_ADDED**: Evidence registration
* **TRANSFER**: Custody transfer (always SUCCESS, integrity separate)
* **VERIFY_INTEGRITY**: Manual integrity check (SUCCESS/FAILURE)
* **AUTOMATED_VERIFY_INTEGRITY**: System-wide check (FAILURE for altered probes)
* **ANALYSIS**: Credential analysis (non-procedural)
* **STATUS_UPDATE**: Evidence lifecycle change
* **USER_ADDED**: Account creation

**Audit Log Schema**:
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

### 7. Report Generation (core/report.py)

**Purpose**: Professional forensic reporting

**Key Functions**:

```python
def generate_overall_report_text() -> str
    """Plain text system-wide report"""

def generate_overall_report_pdf() -> bytes
    """PDF system-wide report"""

def generate_probe_report_text(probe_id: int) -> str
    """
    Per-evidence text report including:
    - Evidence details
    - Transfer history
    - Authoritative integrity status
    - Integrity timeline (when compromised)
    - Compromise interval (narrowed window)
    - Credential analysis results
    """

def generate_probe_pdf_report(probe_id: int) -> bytes
    """
    Professional PDF report with:
    - Styled tables
    - Integrity status indicators
    - Timeline of compromise
    - Interval of tampering
    - Analysis summary
    """

def get_probe_integrity_timeline(probe_id: int) -> List[dict]
    """
    Returns chronological integrity status changes:
    [
        {"timestamp": "...", "action": "TRANSFER", "status": "VALID"},
        {"timestamp": "...", "action": "VERIFY_INTEGRITY", "status": "FAILURE"},
        {"timestamp": "...", "action": "AUTOMATED_VERIFY_INTEGRITY", "status": "FAILURE"}
    ]
    """

def get_integrity_compromise_interval(probe_id: int) -> Optional[Tuple[str, str]]
    """
    Returns (start_time, end_time) of when tampering occurred:
    - start_time: Last known VALID timestamp
    - end_time: First ALTERED timestamp
    - Narrows window of when evidence was compromised
    """
```

**Report Features**:
* ReportLab PDF generation
* Professional styling with tables
* Status indicators (✓ VALID, ✗ ALTERED)
* Integrity timeline visualization
* Compromise interval calculation
* Credential analysis integration
* Chain of custody visualization

### 8. Credential Analysis (core/analysis.py)

**Purpose**: Optional password hash cracking for security assessment

**Key Functions**:

```python
def validate_hash_format(hashes: List[str], hash_type: str) -> Tuple[bool, str]
    """Validate hashes match expected format for type"""

def create_working_copy(hash_file_content: str) -> str
    """
    Create temporary copy for analysis
    PRINCIPLE: Original evidence never touched
    """

def cleanup_working_copy(temp_dir: str) -> None
    """Remove temporary analysis files"""

def run_hashcat_analysis(temp_dir: str, hash_type: str, wordlist_path: Optional[str]) -> Tuple[bool, int, int]
    """
    Execute Hashcat analysis on working copy
    Returns: (success, total_hashes, cracked_count)
    """

def parse_analysis_results(total_hashes: int, cracked_count: int) -> dict
    """
    Format analysis results
    SECURITY: Returns statistics only, never plaintext passwords
    """

def generate_findings_summary(total_hashes: int, cracked_count: int) -> str
    """
    Generate security assessment:
    - 0% cracked: Strong credential protection
    - <10%: Good credential protection
    - <50%: Moderate credential protection
    - ≥50%: Weak credential protection
    """

def perform_analysis(hash_file_content: str, hash_type: str, wordlist_path: Optional[str]) -> Tuple[bool, dict]
    """
    Complete analysis workflow:
    1. Validate hash format
    2. Create working copy
    3. Run Hashcat
    4. Parse results
    5. Clean up working copy
    6. Return statistics
    """
```

**Supported Hash Types**:
* MD5 (0)
* MD5_SALTED (10)
* SHA1 (100)
* SHA256 (1400)
* SHA256_SALTED (1710)
* BCRYPT (3200)
* SCRYPT (8900)
* NTLM (1000)
* LM (3000)
* Windows (1000)
* Linux (1800)
* PDF (10500)

**Analysis Workflow**:
```
User uploads hash file
    ↓
Validate hash format
    ↓
Create working copy in /tmp/
    ↓
Run Hashcat on working copy
    ↓
Parse potfile (cracked hashes)
    ↓
Calculate statistics:
  - Total hashes
  - Cracked count
  - Crack rate %
  - Security assessment
    ↓
Clean up working copy
    ↓
Log ANALYSIS event
    ↓
Return statistics (no plaintext)
```

**Security Principles**:
* **Original Evidence Untouched**: Analysis on temporary copies only
* **No Plaintext Storage**: Only statistics returned
* **Sandboxed Execution**: Working directory isolated
* **Cleanup Guaranteed**: `try/finally` ensures temp files removed
* **Non-Procedural**: Does not affect chain of custody
* **Audit Logged**: All analysis logged as ANALYSIS events

### 9. Database Layer (core/database.py)

**Purpose**: Data persistence and retrieval

**Key Functions**:

```python
def init_db()
    """Initialize database with schema including roles"""

def get_connection() -> sqlite3.Connection
    """Get thread-safe connection"""

def add_probe_to_db(filename: str, sha256: str, stored_path: str, file_size: int, uploaded_by: str) -> int
    """Insert evidence with RECEIVED status"""

def add_transfer_with_reason(probe_id: int, from_user: str, to_user: str, sha256_at_transfer: str, reason: str)
    """Record transfer with mandatory reason"""

def get_current_custodian(probe_id: int) -> Optional[str]
    """Get latest to_user from transfers"""

def get_previous_transfers(probe_id: int, current_user: str) -> List[str]
    """Get users in transfer chain (for reverse transfer validation)"""

def check_probe_integrity(probe_id: int) -> str
    """
    Check if probe integrity compromised
    Returns: VALID, ALTERED, or NO_TRANSFERS
    Note: This checks hash comparison at transfers, not VERIFY_INTEGRITY events
    """

def get_authoritative_integrity_status(probe_id: int) -> Optional[str]
    """
    Get definitive integrity status
    FORENSIC RULE:
    - If ANY VERIFY_INTEGRITY FAILURE exists → ALTERED (irreversible)
    - Else if latest check is SUCCESS → VALID
    - Else → None (no checks performed)
    
    This is the AUTHORITATIVE source of integrity status
    """

def get_probe_integrity_timeline(probe_id: int) -> List[dict]
    """Get chronological integrity status changes"""

def get_integrity_compromise_interval(probe_id: int) -> Optional[Tuple[str, str]]
    """Calculate window when tampering occurred"""

def update_probe_status(probe_id: int, new_status: str) -> bool
    """Update evidence lifecycle status"""

def verify_all_probes_integrity() -> List[Tuple]
    """
    Automated integrity check
    Checks both:
    1. VERIFY_INTEGRITY events in audit log
    2. Hash comparisons from transfers
    Returns altered probes
    """
```

**Database Schema**:

```sql
-- Users with email-based authentication
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    username TEXT,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'CUSTODIAN'
);

-- Evidence with lifecycle status
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

-- Transfers with reasons and validation
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

-- Comprehensive audit trail
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

## Data Flow Diagrams

### 1. Evidence Registration Flow

```
User uploads file
    ↓
app.py: Tab "Add Evidence"
    ↓
core/hashing.py: hash_file()
    ↓
core/storage.py: save_file()
    ↓
core/custody.py: add_probe()
    ↓
core/database.py: add_probe_to_db()
    ↓
core/audit.py: log_probe_added()
    ↓
Database: INSERT INTO probes + audit_log
    ↓
Response: (probe_id, sha256)
```

### 2. Custody Transfer Flow (with Chain Validation)

```
User selects evidence & recipient
    ↓
app.py: Tab "Custody Transfer"
    ↓
core/custody.py: validate_custody_chain()
    ├─ Check: Current custodian matches from_user
    ├─ Check: Not transferring to self
    └─ Check: No reverse transfer (A→B→A)
    ↓
Validation SUCCESS
    ↓
core/custody.py: add_transfer()
    ↓
core/hashing.py: verify_hash()
    ├─ Load file from storage
    ├─ Calculate current hash
    └─ Compare with original hash
    ↓
Integrity Check Result:
    ├─ VALID: Hash matches
    └─ ALTERED: Hash differs
    ↓
core/database.py: add_transfer_with_reason()
    ├─ INSERT transfer record
    ├─ Status: ALWAYS SUCCESS (procedural)
    └─ Integrity: VALID/ALTERED (separate)
    ↓
core/audit.py: log_transfer()
    ├─ Action: TRANSFER
    ├─ Status: SUCCESS
    └─ Integrity: VALID/ALTERED (informational)
    ↓
Response: (integrity_valid, original_hash, current_hash)
```

### 3. Integrity Verification Flow (VERIFY_INTEGRITY Event)

```
User uploads file for verification
    ↓
app.py: Tab "Integrity Check"
    ↓
core/custody.py: verify_integrity()
    ↓
core/hashing.py: hash_file()
    ↓
core/database.py: get_probe_details()
    ↓
Compare: uploaded_hash vs original_hash
    ↓
Result:
    ├─ Match: is_valid = True
    └─ Mismatch: is_valid = False
    ↓
core/audit.py: log_integrity_check()
    ├─ Action: VERIFY_INTEGRITY
    ├─ Status: SUCCESS (if valid) or FAILURE (if altered)
    └─ FAILURE Impact: Marks evidence ALTERED permanently
    ↓
Database: INSERT INTO audit_log
    ↓
Future Checks:
    └─ get_authoritative_integrity_status()
        ├─ Finds VERIFY_INTEGRITY FAILURE
        └─ Returns: ALTERED (irreversible)
```

### 4. Automated Integrity Check Flow

```
User clicks "Run Integrity Check"
    ↓
app.py: Tab "Status & Automated Checks"
    ↓
core/custody.py: run_integrity_check_all()
    ↓
core/database.py: get_probes()
    ├─ Get all evidence
    └─ For each probe:
        ↓
        get_authoritative_integrity_status(probe_id)
        ├─ Check audit_log for ANY VERIFY_INTEGRITY FAILURE
        │  ├─ If found: Return ALTERED
        │  └─ Else: Check latest verification
        └─ Result:
           ├─ ALTERED: Evidence compromised
           ├─ VALID: Evidence intact
           └─ None: No checks performed
    ↓
For each ALTERED probe:
    ├─ Add to altered list
    └─ log_integrity_check()
        ├─ Action: AUTOMATED_VERIFY_INTEGRITY
        ├─ Status: FAILURE
        ├─ Source: "AUTOMATED_"
        └─ Creates audit event marking tampering
    ↓
Response: (total_checked, altered_count, altered_details)
```

### 5. Credential Analysis Flow

```
User uploads hash file
    ↓
app.py: Tab "Credential Analysis"
    ↓
core/analysis.py: perform_analysis()
    ↓
validate_hash_format()
    ├─ Check hash length
    └─ Validate format for type
    ↓
create_working_copy()
    ├─ Create /tmp/hashcat_work_<uuid>/
    ├─ Write hashes.txt
    └─ Create wordlist.txt (if not provided)
    ↓
run_hashcat_analysis()
    ├─ Execute: hashcat -m <type> -a 0 hashes.txt wordlist.txt
    ├─ Output: potfile.pot
    └─ Count cracked hashes
    ↓
parse_analysis_results()
    ├─ Calculate crack rate %
    ├─ Generate security assessment
    └─ Format findings
    ↓
cleanup_working_copy()
    └─ Remove /tmp/hashcat_work_<uuid>/
    ↓
core/audit.py: log_credential_analysis()
    ├─ Action: ANALYSIS
    ├─ Status: SUCCESS/FAILURE
    └─ Details: hash_type, total, cracked, rate
    ↓
Response: (success, results_dict)
```

## Security Architecture

### Authentication Security

```
Password Storage:
├─ Algorithm: PBKDF2-SHA256
├─ Iterations: 100,000 (NIST recommended)
├─ Salt: Automatic per-password
└─ Storage: password_hash in users table

Login Flow:
├─ Email uniqueness enforced (UNIQUE constraint)
├─ Constant-time password comparison
├─ Session management via st.session_state
└─ Role-based access (ADMIN/INVESTIGATOR/CUSTODIAN)
```

### Integrity Security

```
Evidence Integrity:
├─ Hash Algorithm: SHA-256 (NIST FIPS 180-4)
├─ Hash Storage: In database + at each transfer
├─ Verification: On transfer + manual check
└─ Tamper Detection: Automatic comparison

Authoritative Integrity Status:
├─ Checks: Entire audit_log history
├─ Logic: ANY VERIFY_INTEGRITY FAILURE → ALTERED
├─ Irreversible: Once ALTERED, always ALTERED
└─ Forensic Principle: Contaminated evidence stays contaminated

Transfer vs Integrity:
├─ Transfer: Always SUCCESS (procedural)
├─ Integrity: VALID/ALTERED (separate tracking)
└─ Documentation: Both recorded in audit trail
