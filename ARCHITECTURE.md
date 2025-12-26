# 🏗️ System Architecture

## Overview

Digital Chain of Custody is built with a **layered architecture** separating concerns into distinct modules for maintainability, testability, and security.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                   STREAMLIT UI (app.py)                     │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  • Login Page (auth.py)                              │   │
│  │  • Tab 1: Add Evidence                               │   │
│  │  • Tab 2: Custody Transfer (with transfer reason)    │   │
│  │  • Tab 3: Integrity Check                            │   │
│  │  • Tab 4: Report Generation (per-evidence + overall) │   │
│  │  • Tab 5: Audit Log Display                          │   │
│  │  • Tab 6: Status Management & Auto Checks            │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│               ORCHESTRATION LAYER (custody.py)              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Business Logic:                                     │   │
│  │  • add_probe() - Register evidence with status       │   │
│  │  • add_transfer() - Transfer with reason & validation│   │
│  │  • verify_integrity() - Check tampering              │   │
│  │  • update_probe_status() - Lifecycle management      │   │
│  │  • run_integrity_check_all() - NIST auto checks      │   │
│  │  • get_audit_log() - Retrieve audit trail            │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
      ↙        ↓        ↓        ↓        ↓         ↓
┌───────────┐┌────────────┐┌──────────┐┌──────────┐┌────────┐┌──────────┐
│ auth.py   ││database.py ││storage.py││hashing.py││audit.py││report.py │
├───────────┤├────────────┤├──────────┤├──────────┤├────────┤├──────────┤
│•Login     ││•SQLite     ││•Files    ││•SHA256   ││•Log    ││•PDF/TXT  │
│•Passwords ││•Status     ││•Copy     ││•Verify   ││•Alert  ││•Per-probe│
│•Sessions  ││•Lifecycle  ││•Paths    ││•Utils    ││•Track  ││•Reports  │
└───────────┘└────────────┘└──────────┘└──────────┘└────────┘└──────────┘
```

## Layer Descriptions

### 1. **UI Layer** (`app.py`)
- **Purpose**: User interface and user interaction
- **Technology**: Streamlit with 6 tabs
- **Responsibilities**:
  - Display login page with registration
  - Render 6 tabs for different operations
  - Handle user input and form validation
  - Display results and messages
  - Session state management
  - Page refresh after critical actions

### 2. **Orchestration Layer** (`custody.py`)
- **Purpose**: Business logic and workflow coordination
- **Responsibilities**:
  - Validate custody chain rules
  - Coordinate between modules
  - Handle errors and logging
  - Return results to UI layer
  - **NEW**: Status lifecycle management
  - **NEW**: Automated integrity verification
- **Key Functions**:
  - `add_probe()` - Upload and register evidence with status RECEIVED
  - `add_transfer()` - Perform custody transfer with **transfer reason** and validation
  - `verify_integrity()` - Check evidence tampering
  - `update_probe_status()` - Update lifecycle status
  - `run_integrity_check_all()` - **NIST-compliant automated check**
  - `get_current_custodian()` - Get who has evidence now
  - `get_audit_log()` - Retrieve audit trail

### 3. **Service Layers** (Specific modules)

#### **auth.py** - User Authentication
- **Purpose**: Handle user authentication and session management
- **Functions**:
  - `authenticate_user(username, password)` - Login
  - `hash_password(password)` - Secure password storage
  - `verify_password(password, hash)` - Compare passwords
  - `create_user_with_password(username, password)` - Create account
  - `get_user_by_id(user_id)` - Get username

#### **database.py** - Data Persistence
- **Purpose**: All database operations
- **Technology**: SQLite3
- **Tables**:
  - `users` - Custodian accounts with password hashes
  - `probes` - Evidence files metadata
  - `transfers` - Custody transfer history
  - `audit_log` - System action logs
- **Key Functions**:
  - `add_probe()` - Insert evidence
  - `add_transfer()` - Record transfer
  - `get_probe_details()` - Retrieve evidence info
  - `check_custody_chain_valid()` - Validate transfer rules
  - `get_valid_next_custodian()` - Get current custodian

#### **storage.py** - File System Operations
- **Purpose**: Manage evidence file storage
- **Location**: `evidence/` directory
- **Functions**:
  - `store_evidence_file()` - Save copy with timestamp
  - `retrieve_evidence_file()` - Load file for verification
  - `get_evidence_file_size()` - Get file size
- **Naming**: `probe_{ID}_{TIMESTAMP}.{EXT}`

#### **hashing.py** - Cryptography
- **Purpose**: Cryptographic operations
- **Algorithm**: SHA-256
- **Functions**:
  - `calculate_sha256(file_bytes)` - Hash calculation
  - `verify_file_integrity()` - Compare hashes
  - `compare_hashes()` - Hash comparison with details

#### **audit.py** - Audit Logging
- **Purpose**: Track all system actions
- **Status Values**: SUCCESS, WARNING, FAILURE
- **Functions**:
  - `log_action()` - Core logging
  - `log_probe_added()` - Evidence added
  - `log_transfer()` - Custody transfer
  - `log_integrity_check()` - Verification
  - `get_audit_log()` - Retrieve logs

#### **report.py** - Report Generation
- **Purpose**: Generate professional reports
- **Formats**: TXT, PDF
- **Functions**:
  - `generate_text_report()` - Plain text output
  - `generate_pdf_report()` - Styled PDF with tables
  - `generate_pdf_report_bytes()` - Return PDF bytes

## Database Schema Details

### Table: `probes`
```
Column             | Type      | Details
-------------------|-----------|------------------------------------------
id                 | INTEGER   | PRIMARY KEY
filename           | TEXT      | Original file name
sha256             | TEXT      | Initial cryptographic hash
created_at         | TIMESTAMP | Evidence registration time
stored_path        | TEXT      | Path to stored copy on disk
file_size          | INTEGER   | File size in bytes
uploaded_by        | TEXT      | FK to users.name - who uploaded
status             | TEXT      | RECEIVED|IN_ANALYSIS|VERIFIED|RELEASED|ARCHIVED
status_updated_at  | TIMESTAMP | When status last changed
```

**Status Lifecycle** (ISO/IEC 27037 compliance):
- `RECEIVED` - Evidence intake, default status
- `IN_ANALYSIS` - Currently being examined
- `VERIFIED` - Integrity confirmed
- `RELEASED` - Released to stakeholders
- `ARCHIVED` - Case closed/long-term storage

### Table: `users`
```
Column        | Type | Details
--------------|------|------------------------------------------
id            | INT  | PRIMARY KEY
name          | TEXT | UNIQUE username
password_hash | TEXT | PBKDF2 hash (100,000 iterations)
```

### Table: `transfers`
```
Column             | Type      | Details
-------------------|-----------|------------------------------------------
id                 | INTEGER   | PRIMARY KEY
probe_id           | INTEGER   | FK to probes.id
from_user          | TEXT      | FK to users.name
to_user            | TEXT      | FK to users.name
sha256_at_transfer | TEXT      | Hash at transfer time (NIST requirement)
timestamp          | TIMESTAMP | Transfer execution time
transfer_reason    | TEXT      | **NEW - Mandatory reason for transfer (NIST)**
```

**Transfer Reason** (NIST SP 800-86 requirement):
- Documents PURPOSE of evidence transfer
- Examples: "Initial investigation", "Lab analysis", "Verification"
- Mandatory field - prevents unauthorized transfers
- Audit trail shows intent of each handoff

### Table: `audit_log`
```
Column   | Type      | Details
---------|-----------|------------------------------------------
id       | INTEGER   | PRIMARY KEY
timestamp| TIMESTAMP | Action time (ISO format)
action   | TEXT      | add_probe, transfer, verify_integrity, etc
details  | TEXT      | Detailed action information
status   | TEXT      | SUCCESS, WARNING, or FAILURE
error_msg| TEXT      | Error details if FAILURE
```

## Data Flow

### Evidence Upload Flow
```
User Upload
    ↓
add_probe() [custody.py]
    ├→ calculate_sha256() [hashing.py]
    ├→ db_add_probe() [database.py]
    ├→ store_evidence_file() [storage.py]
    ├→ update_probe_stored_path() [database.py]
    └→ log_probe_added() [audit.py]
```

### Custody Transfer Flow
```
User Selection
    ↓
add_transfer() [custody.py]
    ├→ check_custody_chain_valid() [database.py]
    │  ├→ get_last_transfer() [database.py]
    │  └→ Validate rules
    ├→ retrieve_evidence_file() [storage.py]
    ├→ calculate_sha256() [hashing.py]
    ├→ Compare hashes
    ├→ db_add_transfer() [database.py]
    └→ log_transfer() [audit.py]
```

### Integrity Check Flow
```
User Re-Upload
    ↓
verify_integrity() [custody.py]
    ├→ calculate_sha256() [hashing.py]
    ├→ get_probe_hash() [database.py]
    ├→ verify_file_integrity() [hashing.py]
    └→ log_integrity_check() [audit.py]
```

### Status Lifecycle Flow (NEW - NIST Compliance)
```
Evidence Registered
    ↓ (status: RECEIVED)
update_probe_status() [custody.py]
    ├→ db_update_probe_status() [database.py]
    ├→ Record status change timestamp
    ├→ Transition through states
    │  ├→ IN_ANALYSIS (examination)
    │  ├→ VERIFIED (integrity confirmed)
    │  ├→ RELEASED (to stakeholders)
    │  └→ ARCHIVED (case closed)
    └→ log_status_change() [audit.py]
```

### Automated Integrity Check Flow (NEW - NIST SP 800-86)
```
User Initiates Full Check
    ↓
run_integrity_check_all() [custody.py]
    ├→ get_all_probes() [database.py]
    ├→ For each probe:
    │  ├→ retrieve_evidence_file() [storage.py]
    │  ├→ calculate_sha256() [hashing.py]
    │  ├→ Compare with stored hash
    │  ├→ Mark as VALID or ALTERED
    │  └→ Log result [audit.py]
    ├→ Return altered_probes list
    ├→ Return summary messages
    └→ Alert user if tampering detected
```

## Validation Rules

### Chain of Custody Validation (`check_custody_chain_valid`)

1. **Custody Continuity**
   - Only current custodian can transfer
   - Extracted from `get_last_transfer()`
   - Error: "Only X can transfer this evidence"

2. **No Reverse Transfers** (NIST Standard)
   - Cannot transfer back to previous custodian
   - Prevents: A→B→A pattern
   - Error: "Cannot reverse transfer: evidence just came from X"
   - **NIST Compliance**: Prevents unauthorized return of evidence

3. **No Self-Transfers**
   - Cannot transfer to same person
   - Error: "Cannot transfer to the same person"

4. **Transfer Reason Required** (NIST SP 800-86)
   - **NEW**: Mandatory transfer_reason field
   - Documents PURPOSE of custody transfer
   - Examples: "Initial investigation", "Lab analysis", "Chain verification"
   - UI enforces non-empty field
   - Stored in transfers table for audit trail
   - Error: "Transfer reason is required"
   - **Forensic Value**: Creates record of intent for each handoff

## Standards Compliance

### NIST SP 800-86 (Digital Evidence) Implementation

**1. Evidence Status Lifecycle** (Section 3.4)
- Five-state model: RECEIVED → IN_ANALYSIS → VERIFIED → RELEASED/ARCHIVED
- Stored in `probes.status` with timestamp tracking
- UI Tab 6 provides status management interface
- Audit trail records all status transitions

**2. Transfer Documentation** (Section 3.3)
- Mandatory `transfer_reason` field in transfers table
- Documents PURPOSE of each custody transfer
- NIST requirement: "Document chain of custody with sufficient detail"
- Supports forensic investigation and legal requirements

**3. Automated Integrity Verification** (Section 3.2)
- `run_integrity_check_all()` performs system-wide verification
- SHA-256 hash comparison against stored values
- Detects tampering: VALID vs ALTERED status
- Audit logging of all check results
- Supports NIST requirement: "Preserve integrity of evidence"

### ISO/IEC 27037 (Digital Evidence Handling) Implementation

**Evidence Lifecycle**:
- Receipt: Status RECEIVED + timestamp
- Examination: Status IN_ANALYSIS
- Conclusion: Status VERIFIED
- Closure: Status RELEASED or ARCHIVED

**Continuity Documentation**:
- `transfers` table tracks all handoffs
- `audit_log` records user, timestamp, action
- `transfer_reason` documents purpose
- Supports ISO requirement: "Establish and maintain chain of custody"

### ACPO Guidelines (Digital Evidence) Implementation

**Record Keeping**:
- Comprehensive audit trail in `audit_log`
- All actions timestamped with ISO format
- User attribution for each action
- Status changes tracked with reasons

**Integrity Assurance**:
- SHA-256 hashing at receipt and transfer
- Automated verification prevents undetected tampering
- Hash comparison results logged
- VALID/ALTERED status visible in reports

## Security Architecture

### Authentication
- **Password Storage**: PBKDF2 hashing with salt (100,000 iterations)
- **Session Management**: Streamlit session_state
- **Login Flow**: Username/Password → Authenticate → Set session → Access app

### Data Integrity
- **File Hashing**: SHA-256 cryptographic hash at:
  - Evidence registration
  - Every transfer
  - Manual verification
- **Tamper Detection**: Hash comparison at each transfer shows:
  - ✓ VALID - No changes
  - ✗ ALTERED - Changes detected

### Audit Trail
- **Actions Logged**: Add probe, transfers, verifications, errors
- **User Tracking**: All actions attributed to authenticated user
- **Timestamps**: Millisecond precision ISO format
- **Status Tracking**: SUCCESS, WARNING, FAILURE

## Module Dependencies

```
app.py
├── config.py
├── core/database.py
├── core/auth.py
├── core/custody.py
│   ├── core/database.py
│   ├── core/hashing.py
│   ├── core/storage.py
│   ├── core/audit.py
│   └── core/report.py
│       ├── core/database.py
│       ├── core/hashing.py
│       └── reportlab

core/storage.py
├── config.py
└── datetime

core/audit.py
├── core/database.py
└── datetime

No circular dependencies ✓
```

## Configuration

### `config.py`
Centralized configuration for:
- `DATABASE_PATH` - SQLite database location
- `EVIDENCE_DIR` - Evidence file storage directory
- `MAX_FILE_SIZE` - Maximum uploadable file size
- `STREAMLIT_THEME` - UI theme
- `APP_VERSION` - Version string

## Performance Characteristics

| Operation | Complexity | Notes |
|-----------|-----------|-------|
| Hash calculation | O(n) | Depends on file size |
| Transfer validation | O(m) | m = number of previous transfers |
| Report generation | O(p+t) | p = probes, t = transfers |
| Audit log retrieval | O(1) | Limited by LIMIT clause |
| File storage | O(n) | n = file size |

## Extensibility Points

### Adding New Audit Actions
1. Create new function in `audit.py`: `log_new_action()`
2. Call from business logic in `custody.py`
3. Log automatically recorded in database

### Adding New Reports
1. Create new function in `report.py`: `generate_custom_report()`
2. Call from `app.py` report tab
3. Return text or PDF bytes

### Adding New Validation Rules
1. Extend `check_custody_chain_valid()` in `database.py`
2. Update error messages
3. UI automatically shows validation errors

## Testing

### Unit Tests Available
- `demo_alteration.py` - Tests tamper detection
- `demo_chain_validation.py` - Tests custody rules
- Manual testing via app.py

### Test Scenarios
1. **Authentication**: Login with correct/incorrect credentials
2. **Chain Validation**: Valid/invalid transfer sequences
3. **Integrity**: Tamper detection between transfers
4. **Audit**: Log all actions with correct user attribution

## Future Improvements

1. **Database Encryption** - Encrypt database at rest
2. **SSL/TLS** - Encrypted network communication
3. **Multi-Factor Authentication** - Additional security layer
4. **Role-Based Access** - Different user roles/permissions
5. **Export Formats** - Additional report formats (CSV, Excel)
6. **API Layer** - REST API for programmatic access
7. **Web Deployment** - Cloud-ready configuration

---

**Architecture designed for forensic integrity, auditability, and extensibility**
