import sqlite3
import os
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
        name TEXT NOT NULL UNIQUE,
        password_hash TEXT
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
        cur.execute("SELECT id, name FROM users ORDER BY name")
        return cur.fetchall()
    finally:
        conn.close()

def add_transfer(probe_id: int, from_user: str, to_user: str, sha256: str, reason: str = "") -> None:
    """Record a proof custody transfer with optional reason."""
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
        cur.execute("SELECT id, filename, sha256, created_at FROM probes ORDER BY created_at")
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
        SELECT id, filename, sha256, created_at, uploaded_by, file_size
        FROM probes
        WHERE id = ?
        """, (probe_id,))
        probe = cur.fetchone()
        
        cur.execute("""
        SELECT from_user, to_user, sha256_at_transfer, timestamp
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

