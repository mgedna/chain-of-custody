import sqlite3
from datetime import datetime
from typing import List, Tuple, Optional
from config import DATABASE_PATH, DATABASE_DIR


def get_connection() -> sqlite3.Connection:
    """Get database connection."""
    DATABASE_DIR.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(str(DATABASE_PATH))


def init_db() -> None:
    """Initialize database tables."""
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS probes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        created_at TEXT NOT NULL,
        stored_path TEXT,
        file_size INTEGER,
        uploaded_by TEXT NOT NULL DEFAULT 'unknown',
        status TEXT DEFAULT 'RECEIVED' CHECK (status IN ('RECEIVED', 'IN_ANALYSIS', 'VERIFIED', 'RELEASED', 'ARCHIVED')),
        status_updated_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        username TEXT,
        password_hash TEXT,
        role TEXT DEFAULT 'CUSTODIAN' CHECK (role IN ('ADMIN', 'INVESTIGATOR', 'CUSTODIAN'))
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS transfers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        probe_id INTEGER NOT NULL,
        from_user TEXT NOT NULL,
        to_user TEXT NOT NULL,
        sha256_at_transfer TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        transfer_reason TEXT,
        transfer_notes TEXT,
        FOREIGN KEY (probe_id) REFERENCES probes(id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS credential_analysis (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        probe_id INTEGER NOT NULL,
        hash_type TEXT NOT NULL,
        total_hashes INTEGER NOT NULL,
        cracked_hashes INTEGER NOT NULL,
        crack_rate_percent REAL NOT NULL,
        findings TEXT,
        analysis_timestamp TEXT NOT NULL,
        analyzed_by TEXT DEFAULT 'unknown',
        FOREIGN KEY (probe_id) REFERENCES probes(id)
    )
    """)

    conn.commit()
    conn.close()

def add_probe(filename: str, sha256: str, uploaded_by: str, stored_path: str = None, file_size: int = None) -> int:
    """Insert a new probe into the database and return the probe ID."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO probes (filename, sha256, created_at, stored_path, file_size, uploaded_by)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (filename, sha256, datetime.now().isoformat(), stored_path, file_size, uploaded_by))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_probes() -> List[Tuple[int, str, str]]:
    """Retrieve all probes from the database."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, filename, sha256 FROM probes ORDER BY created_at DESC")
        return cur.fetchall()
    finally:
        conn.close()


def get_probes_for_user(username: str) -> List[Tuple[int, str, str]]:
    """
    Retrieve probes accessible to a user:
    - Probes uploaded by the user
    - Probes received through transfers to the user
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
        SELECT DISTINCT p.id, p.filename, p.sha256
        FROM probes p
        LEFT JOIN transfers t ON p.id = t.probe_id
        WHERE p.uploaded_by = ? OR t.to_user = ?
        ORDER BY p.created_at DESC
        """, (username, username))
        return cur.fetchall()
    finally:
        conn.close()


def get_probes_currently_held(username: str) -> List[Tuple[int, str, str]]:
    """
    Retrieve probes currently held by a user:
    - Probes uploaded by user that haven't been transferred yet
    - Probes received where user is the current custodian (last transfer recipient)
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
        SELECT DISTINCT p.id, p.filename, p.sha256
        FROM probes p
        WHERE p.uploaded_by = ? AND p.id NOT IN (
            SELECT DISTINCT probe_id FROM transfers
        )
        UNION
        SELECT DISTINCT p.id, p.filename, p.sha256
        FROM probes p
        INNER JOIN transfers t ON p.id = t.probe_id
        WHERE t.to_user = ? AND t.id = (
            SELECT MAX(id) FROM transfers WHERE probe_id = p.id
        )
        ORDER BY p.id DESC
        """, (username, username))
        return cur.fetchall()
    finally:
        conn.close()


def get_probe_details(probe_id: int) -> Optional[Tuple]:
    """Get complete probe details including stored path and original hash."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
        SELECT id, filename, sha256, created_at, stored_path, file_size
        FROM probes WHERE id = ?
        """, (probe_id,))
        return cur.fetchone()
    finally:
        conn.close()


def get_probe_hash(probe_id: int) -> Optional[str]:
    """Get the original hash of a probe by ID."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT sha256 FROM probes WHERE id = ?", (probe_id,))
        row = cur.fetchone()
        return row[0] if row else None
    finally:
        conn.close()

def check_if_hash_exists(sha256: str) -> Optional[int]:
    """Check if a hash already exists in the system. Returns probe_id if found, None otherwise."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM probes WHERE sha256 = ?", (sha256,))
        row = cur.fetchone()
        return row[0] if row else None
    finally:
        conn.close()

def update_probe_stored_path(probe_id: int, stored_path: str) -> None:
    """Update the stored path of a probe after file storage."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE probes SET stored_path = ? WHERE id = ?",
            (stored_path, probe_id)
        )
        conn.commit()
    finally:
        conn.close()


def check_probe_integrity(probe_id: int) -> str:
    """
    Check if a probe has been altered by comparing original hash with all transfer hashes.
    
    Returns:
        "VALID" - all transfer hashes match the original
        "ALTERED" - at least one transfer hash differs from the original
        "NO_TRANSFERS" - probe has no transfers yet
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        
        cur.execute("SELECT sha256 FROM probes WHERE id = ?", (probe_id,))
        row = cur.fetchone()
        if not row:
            return "NOT_FOUND"
        
        original_hash = row[0]
        
        cur.execute(
            "SELECT sha256_at_transfer FROM transfers WHERE probe_id = ? ORDER BY timestamp",
            (probe_id,)
        )
        transfers = cur.fetchall()
        
        if not transfers:
            return "NO_TRANSFERS"
        
        for transfer in transfers:
            if transfer[0] != original_hash:
                return "ALTERED"
        
        return "VALID"
    finally:
        conn.close()


def get_latest_integrity_verification(probe_id: int) -> Optional[str]:
    """
    Get the most recent VERIFY_INTEGRITY result from the audit log.
    
    CRITICAL: This returns the actual verification result (VALID/ALTERED) from the
    audit log, not a calculated status. This is the authoritative integrity status
    based on explicit verification checks.
    
    Returns:
        "VALID" - if latest VERIFY_INTEGRITY check showed valid
        "ALTERED" - if latest VERIFY_INTEGRITY check showed altered
        None - if no verification checks have been performed
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        
        cur.execute("""
            SELECT status
            FROM audit_log
            WHERE action = 'VERIFY_INTEGRITY' AND details LIKE ?
            ORDER BY timestamp DESC
            LIMIT 1
        """, (f'Probe ID: {probe_id}%',))
        
        result = cur.fetchone()
        if result:
            status = result[0]
            return "VALID" if status == "SUCCESS" else "ALTERED"
        
        return None
    finally:
        conn.close()

def add_user(name: str) -> None:
    """Insert a new user (custodian) into the database."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO users (name) VALUES (?)", (name,))
        conn.commit()
    finally:
        conn.close()


def get_users() -> List[Tuple[int, str]]:
    """Retrieve all users from the database."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, username FROM users ORDER BY username")
        return cur.fetchall()
    finally:
        conn.close()

def add_transfer(probe_id: int, from_user: str, to_user: str, sha256: str, reason: str = "", 
                 notes: str = "") -> None:
    """Record a proof custody transfer with reason and notes."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO transfers (probe_id, from_user, to_user, sha256_at_transfer, timestamp, 
                              transfer_reason, transfer_notes)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (probe_id, from_user, to_user, sha256, datetime.now().isoformat(), reason, notes))
        conn.commit()
    finally:
        conn.close()


def get_transfer_history() -> List[Tuple]:
    """Retrieve all transfers with probe information."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
        SELECT t.probe_id, t.from_user, t.to_user, t.sha256_at_transfer, t.timestamp, p.filename
        FROM transfers t
        JOIN probes p ON t.probe_id = p.id
        ORDER BY t.timestamp DESC
        """)
        return cur.fetchall()
    finally:
        conn.close()


def get_last_transfer(probe_id: int) -> Optional[Tuple]:
    """Get the last (most recent) transfer of a probe."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
        SELECT id, from_user, to_user, timestamp
        FROM transfers
        WHERE probe_id = ?
        ORDER BY timestamp DESC
        LIMIT 1
        """, (probe_id,))
        return cur.fetchone()
    finally:
        conn.close()


def get_valid_next_custodian(probe_id: int) -> Optional[str]:
    """
    Get the custodian who currently holds the evidence.
    Returns the 'to_user' of the last transfer, or None if no transfers yet.
    """
    last_transfer = get_last_transfer(probe_id)
    if not last_transfer:
        return None
    return last_transfer[2]


def check_custody_chain_valid(probe_id: int, from_user: str, to_user: str) -> Tuple[bool, str]:
    """
    Validate custody chain integrity.
    
    Returns:
        (is_valid, error_message)
        - is_valid: True if transfer is allowed
        - error_message: Description of any validation error
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM probes WHERE id = ?", (probe_id,))
        if not cur.fetchone():
            return False, f"Probe {probe_id} not found"
        
        cur.execute("""
        SELECT from_user, to_user, timestamp
        FROM transfers
        WHERE probe_id = ?
        ORDER BY timestamp ASC
        """, (probe_id,))
        transfers = cur.fetchall()
        
        if not transfers:
            return True, ""
        
        last_transfer = transfers[-1]
        last_to_user = last_transfer[1]
        last_from_user = last_transfer[0]
        
        if from_user != last_to_user:
            return False, f"Only {last_to_user} (current custodian) can transfer this evidence. {from_user} does not have it."
        
        if from_user == to_user:
            return False, f"Cannot transfer from {from_user} to the same person"
        
        if to_user == last_from_user:
            return False, f"Cannot reverse transfer: evidence cannot return to {to_user}. (NIST/Forensic standard: Chain must be linear and progressive)"
        
        return True, ""
    finally:
        conn.close()

def get_report_data() -> Tuple[List[Tuple], List[Tuple]]:
    """Get all probes and transfers for report generation."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, filename, sha256, created_at, status FROM probes ORDER BY created_at")
        probes = cur.fetchall()
        
        cur.execute("""
        SELECT t.probe_id, t.from_user, t.to_user, t.sha256_at_transfer, t.timestamp, p.filename, p.sha256
        FROM transfers t
        JOIN probes p ON t.probe_id = p.id
        ORDER BY t.timestamp
        """)
        transfers = cur.fetchall()
        
        return probes, transfers
    finally:
        conn.close()


def get_probe_report_data(probe_id: int) -> Tuple[Optional[Tuple], List[Tuple]]:
    """Get probe details and all its transfers for a report."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        
        cur.execute("""
        SELECT id, filename, sha256, created_at, uploaded_by, file_size, status
        FROM probes
        WHERE id = ?
        """, (probe_id,))
        probe = cur.fetchone()
        
        cur.execute("""
        SELECT from_user, to_user, sha256_at_transfer, timestamp, transfer_reason, transfer_notes
        FROM transfers
        WHERE probe_id = ?
        ORDER BY timestamp
        """, (probe_id,))
        transfers = cur.fetchall()
        
        return probe, transfers
    finally:
        conn.close()

def update_probe_status(probe_id: int, new_status: str) -> bool:
    """
    Update evidence status.
    Valid statuses: RECEIVED, IN_ANALYSIS, VERIFIED, RELEASED, ARCHIVED
    """
    valid_statuses = ['RECEIVED', 'IN_ANALYSIS', 'VERIFIED', 'RELEASED', 'ARCHIVED']
    if new_status not in valid_statuses:
        return False
    
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
        UPDATE probes 
        SET status = ?, status_updated_at = ?
        WHERE id = ?
        """, (new_status, datetime.now().isoformat(), probe_id))
        conn.commit()
        return True
    finally:
        conn.close()


def get_probe_status(probe_id: int) -> Optional[str]:
    """Get current status of a probe."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT status FROM probes WHERE id = ?", (probe_id,))
        row = cur.fetchone()
        return row[0] if row else None
    finally:
        conn.close()

def add_transfer_with_reason(probe_id: int, from_user: str, to_user: str, sha256: str, reason: str) -> None:
    """Record a custody transfer with reason/description."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO transfers (probe_id, from_user, to_user, sha256_at_transfer, timestamp, transfer_reason)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (probe_id, from_user, to_user, sha256, datetime.now().isoformat(), reason))
        conn.commit()
    finally:
        conn.close()

def verify_all_probes_integrity() -> List[Tuple[int, str, str, str]]:
    """
    Automated integrity check on all probes.
    Returns list of (probe_id, filename, status, last_transfer_hash) for ones that failed
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        
        cur.execute("""
        SELECT p.id, p.filename, p.sha256, MAX(t.sha256_at_transfer) as last_transfer_hash
        FROM probes p
        LEFT JOIN transfers t ON p.id = t.probe_id
        GROUP BY p.id
        """)
        
        results = []
        for row in cur.fetchall():
            probe_id, filename, original_hash, last_transfer_hash = row
            
            if last_transfer_hash is None:
                continue
            
            if last_transfer_hash != original_hash:
                results.append((probe_id, filename, "ALTERED", last_transfer_hash))
        
        return results
    finally:
        conn.close()

def get_probe_integrity_timeline(probe_id: int) -> List[Tuple[str, str, str, str, str, str]]:
    """
    Get a chronological timeline of integrity events for a probe.
    
    CRITICAL: Shows both Transfer Status (procedural: SUCCESS) and Integrity Status 
    (analytical: VALID/ALTERED). These are independent concepts. A transfer can succeed
    procedurally even if the evidence integrity is compromised (ALTERED).
    
    Includes VERIFY_INTEGRITY events from audit log to track all integrity checks.
    Transfers after the first ALTERED verification show "ALTERED (propagated)" to indicate
    that compromised evidence continues through the chain.
    
    Returns:
        List of tuples: (event_type, description, timestamp, hash_value, integrity_result, transfer_status)
        - event_type: 'ACQUISITION', 'TRANSFER', 'VERIFY_INTEGRITY'
        - integrity_result: 'VALID' or 'ALTERED' or 'ALTERED (propagated)'
        - transfer_status: 'SUCCESS' (procedural), only ACQUISITION/TRANSFER events
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        events = []
        
        cur.execute("""
            SELECT created_at, sha256, id, uploaded_by
            FROM probes
            WHERE id = ?
        """, (probe_id,))
        
        probe = cur.fetchone()
        if probe:
            events.append((
                'ACQUISITION',
                f"Digital evidence acquired by {probe[3]}",
                probe[0],
                probe[1],
                'VALID',
                'SUCCESS'
            ))
        
        cur.execute("""
            SELECT timestamp, from_user, to_user, sha256_at_transfer, transfer_reason
            FROM transfers
            WHERE probe_id = ?
            ORDER BY timestamp ASC
        """, (probe_id,))
        
        transfers = cur.fetchall()
        original_hash = probe[1] if probe else None
        
        for transfer in transfers:
            timestamp, from_user, to_user, hash_at_transfer, reason = transfer
            integrity_valid = (hash_at_transfer == original_hash)
            result = 'VALID' if integrity_valid else 'ALTERED'
            description = f"Custody transfer from {from_user} to {to_user}"
            if reason:
                description += f" (Reason: {reason})"
            
            events.append((
                'TRANSFER',
                description,
                timestamp,
                hash_at_transfer,
                result,
                'SUCCESS'
            ))
        
        cur.execute("""
            SELECT timestamp, details, status
            FROM audit_log
            WHERE action = 'VERIFY_INTEGRITY' AND details LIKE ?
            ORDER BY timestamp ASC
        """, (f'Probe ID: {probe_id}%',))
        
        integrity_checks = cur.fetchall()
        first_altered_timestamp = None
        
        for timestamp, details, status in integrity_checks:
            try:
                hash_part = details.split("Hash: ")[1].split("...")[0]
            except:
                hash_part = "unknown"
            
            integrity_result = 'VALID' if status == 'SUCCESS' else 'ALTERED'
            
            if integrity_result == 'ALTERED' and first_altered_timestamp is None:
                first_altered_timestamp = timestamp
            
            description = f"Integrity verification - {integrity_result.lower()}"
            
            events.append((
                'VERIFY_INTEGRITY',
                description,
                timestamp,
                hash_part,
                integrity_result,
                ''
            ))
        
        if first_altered_timestamp is not None:
            processed_events = []
            for event_type, description, timestamp, hash_value, integrity_result, transfer_status in events:
                if event_type == 'TRANSFER' and timestamp > first_altered_timestamp:
                    propagated_result = 'ALTERED (propagated)'
                    
                    processed_events.append((
                        event_type,
                        description,
                        timestamp,
                        hash_value,
                        propagated_result,
                        transfer_status
                    ))
                else:
                    processed_events.append((event_type, description, timestamp, hash_value, integrity_result, transfer_status))
            events = processed_events
        
        return sorted(events, key=lambda x: x[2])
    finally:
        conn.close()



def get_integrity_compromise_interval(probe_id: int) -> Optional[Tuple[str, str, str]]:
    """
    Determine the time interval when integrity was compromised.
    
    CRITICAL: The "last event with valid integrity" is the last event that occurred
    BEFORE the first ALTERED event, regardless of subsequent events. This correctly
    identifies when the compromise occurred.
    
    Returns:
        Tuple of (last_valid_event, first_altered_event, time_interval_description)
        or None if no compromise detected
    """
    timeline = get_probe_integrity_timeline(probe_id)
    
    if not timeline:
        return None
    
    first_altered = None
    first_altered_index = None
    
    for i, (event_type, description, timestamp, hash_val, result, transfer_status) in enumerate(timeline):
        if result == 'ALTERED' and first_altered is None:
            first_altered = (description, timestamp)
            first_altered_index = i
            break
    
    if first_altered is None:
        return None
    
    last_valid = None
    for i in range(first_altered_index - 1, -1, -1):
        event_type, description, timestamp, hash_val, result, transfer_status = timeline[i]
        if result == 'VALID':
            last_valid = (description, timestamp)
            break
    
    if last_valid is None:
        if timeline and timeline[0][4] == 'VALID':
            last_valid = (timeline[0][1], timeline[0][2])
        else:
            return None
    
    last_valid_desc, last_valid_time = last_valid
    first_altered_desc, first_altered_time = first_altered
    
    from datetime import datetime as dt
    try:
        last_dt = dt.fromisoformat(last_valid_time)
        first_dt = dt.fromisoformat(first_altered_time)
        duration = first_dt - last_dt
        total_seconds = duration.total_seconds()
        hours = int(total_seconds // 3600)
        minutes = int((total_seconds % 3600) // 60)
        seconds = int(total_seconds % 60)
        
        if total_seconds < 1:
            time_desc = "instantaneously (same timestamp)"
        elif total_seconds < 60:
            time_desc = f"within {seconds} second(s)" if seconds > 0 else "within seconds"
        elif minutes < 60:
            if minutes == 0:
                time_desc = "within the same minute"
            elif minutes == 1:
                time_desc = "within approximately one minute"
            else:
                time_desc = f"within approximately {minutes} minutes"
        elif hours < 24:
            if hours == 1:
                time_desc = "within approximately one hour"
            else:
                time_desc = f"within approximately {hours} hours" + (f" and {minutes} minute(s)" if minutes > 0 else "")
        else:
            days = int(total_seconds // 86400)
            time_desc = f"within approximately {days} day(s)" + (f" and {hours} hour(s)" if hours > 0 else "")
    except Exception:
        time_desc = "a period of time"
    
    interval_text = f"Between '{last_valid_desc}' and '{first_altered_desc}' ({time_desc})"
    
    return (last_valid_desc, first_altered_desc, interval_text)

def get_user_role(username: str) -> str:
    """Get user role (ADMIN, INVESTIGATOR, CUSTODIAN)."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT role FROM users WHERE username = ?", (username,))
        result = cur.fetchone()
        return result[0] if result else "CUSTODIAN"
    finally:
        conn.close()


def set_user_role(username: str, role: str) -> bool:
    """Set user role. Returns True if successful."""
    if role not in ['ADMIN', 'INVESTIGATOR', 'CUSTODIAN']:
        return False
    
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE users SET role = ? WHERE username = ?", (role, username))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def get_all_users_with_roles() -> List[Tuple[int, str, str]]:
    """Retrieve all users with their roles."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, username, COALESCE(role, 'CUSTODIAN') FROM users ORDER BY username")
        return cur.fetchall()
    finally:
        conn.close()

def save_analysis_results(
    probe_id: int,
    hash_type: str,
    total_hashes: int,
    cracked_hashes: int,
    crack_rate_percent: float,
    findings: str,
    analyzed_by: str = "unknown"
) -> int:
    """
    Save credential analysis results to database.
    
    NOTE: Only statistics are stored - no plaintext passwords.
    
    Args:
        probe_id: ID of analyzed probe
        hash_type: Type of hashes (MD5, SHA256, BCRYPT, etc.)
        total_hashes: Total hashes analyzed
        cracked_hashes: Number successfully cracked
        crack_rate_percent: Percentage cracked (0-100)
        findings: Summary findings text
        analyzed_by: Username of analyst
        
    Returns:
        Analysis record ID
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO credential_analysis 
        (probe_id, hash_type, total_hashes, cracked_hashes, crack_rate_percent, findings, analysis_timestamp, analyzed_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (probe_id, hash_type, total_hashes, cracked_hashes, crack_rate_percent, findings, 
              datetime.now().isoformat(), analyzed_by))
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_analysis_by_probe_id(probe_id: int) -> Optional[Tuple]:
    """
    Retrieve the most recent credential analysis for a probe.
    
    Returns:
        Tuple of (id, probe_id, hash_type, total_hashes, cracked_hashes, crack_rate_percent, findings, timestamp, analyzed_by)
        or None if no analysis exists
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
        SELECT id, probe_id, hash_type, total_hashes, cracked_hashes, crack_rate_percent, findings, analysis_timestamp, analyzed_by
        FROM credential_analysis
        WHERE probe_id = ?
        ORDER BY analysis_timestamp DESC
        LIMIT 1
        """, (probe_id,))
        return cur.fetchone()
    finally:
        conn.close()


def get_analysis_summary(probe_id: int) -> Optional[dict]:
    """
    Get formatted credential analysis summary for display.
    
    Returns:
        Dictionary with analysis details or None if no analysis
    """
    analysis = get_analysis_by_probe_id(probe_id)
    if not analysis:
        return None
    
    return {
        "id": analysis[0],
        "probe_id": analysis[1],
        "hash_type": analysis[2],
        "total_hashes": analysis[3],
        "cracked_hashes": analysis[4],
        "crack_rate": analysis[5],
        "findings": analysis[6],
        "timestamp": analysis[7],
        "analyzed_by": analysis[8]
    }