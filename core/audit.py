from datetime import datetime
from typing import Optional
from core.database import get_connection


def log_action(action: str, details: str, status: str = "SUCCESS", error_msg: str = None) -> None:
    """
    Log an action to the audit trail.
    
    Args:
        action: Type of action (ADD_PROBE, ADD_USER, TRANSFER, VERIFY, etc.)
        details: Detailed description of the action
        status: SUCCESS or FAILURE
        error_msg: Error message if status is FAILURE
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT NOT NULL,
            status TEXT NOT NULL,
            error_msg TEXT
        )
        """)
        
        cur.execute("""
        INSERT INTO audit_log (timestamp, action, details, status, error_msg)
        VALUES (?, ?, ?, ?, ?)
        """, (datetime.now().isoformat(), action, details, status, error_msg))
        
        conn.commit()
    finally:
        conn.close()


def get_audit_log(limit: int = 100) -> list:
    """Retrieve audit log entries."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name='audit_log'
        """)
        if not cur.fetchone():
            return []
        
        cur.execute("""
        SELECT timestamp, action, details, status, error_msg
        FROM audit_log
        ORDER BY timestamp DESC
        LIMIT ?
        """, (limit,))
        return cur.fetchall()
    finally:
        conn.close()


def log_probe_added(filename: str, probe_id: int, sha256: str, file_size: int) -> None:
    """Log when a probe is added."""
    details = f"Probe ID: {probe_id}, File: {filename}, Size: {file_size} bytes, SHA-256: {sha256[:16]}..."
    log_action("ADD_PROBE", details, "SUCCESS")


def log_user_added(name: str) -> None:
    """Log when a user (custodian) is added."""
    details = f"Custodian: {name}"
    log_action("ADD_USER", details, "SUCCESS")


def log_transfer(probe_id: int, from_user: str, to_user: str, integrity_valid: bool, current_hash: str) -> None:
    """Log when a transfer is recorded."""
    status_text = "VALID" if integrity_valid else "ALTERED"
    details = f"Probe ID: {probe_id}, From: {from_user}, To: {to_user}, Status: {status_text}, Hash: {current_hash[:16]}..."
    status = "SUCCESS" if integrity_valid else "WARNING"
    log_action("TRANSFER", details, status)


def log_integrity_check(probe_id: int, is_valid: Optional[bool], current_hash: str) -> None:
    """Log when integrity is verified."""
    if is_valid is None:
        status_text = "NOT_FOUND"
        status = "FAILURE"
    elif is_valid:
        status_text = "VALID"
        status = "SUCCESS"
    else:
        status_text = "ALTERED"
        status = "FAILURE"
    
    details = f"Probe ID: {probe_id}, Status: {status_text}, Hash: {current_hash[:16]}..."
    log_action("VERIFY_INTEGRITY", details, status)


def log_error(action: str, error_msg: str) -> None:
    """Log an error."""
    log_action(action, error_msg, "FAILURE", error_msg)
