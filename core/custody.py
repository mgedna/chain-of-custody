from typing import Optional, Tuple, List
from datetime import datetime
from core.database import (
    add_probe as db_add_probe,
    get_probes as db_get_probes,
    get_probes_for_user,
    get_probes_currently_held,
    get_probe_hash,
    get_probe_details,
    add_user as db_add_user,
    get_users as db_get_users,
    add_transfer as db_add_transfer,
    update_probe_stored_path,
    check_if_hash_exists,
    check_custody_chain_valid,
    get_valid_next_custodian,
)
from core.hashing import calculate_sha256, verify_file_integrity
from core.report import generate_text_report, generate_pdf_report, generate_probe_text_report, generate_probe_pdf_report
from core.storage import store_evidence_file, retrieve_evidence_file, get_evidence_file_size
from core.audit import log_probe_added, log_user_added, log_transfer, log_integrity_check, log_error


def add_probe(filename: str, file_bytes: bytes, uploaded_by: str) -> Tuple[int, str]:
    """
    Add a new digital probe to the custody chain.
    Creates a copy of the file and stores it securely.
    Captures file metadata for ISO/IEC 27037 compliance.
    
    Args:
        filename: Original filename
        file_bytes: File content as bytes
        uploaded_by: Username who uploaded the evidence
        
    Returns:
        Tuple of (probe_id, sha256_hash)
    """
    try:
        sha256 = calculate_sha256(file_bytes)
        
        existing_probe = check_if_hash_exists(sha256)
        if existing_probe:
            print(f"Hash already exists in system - Probe ID: {existing_probe}")
            return existing_probe, sha256
        
        file_size = len(file_bytes)
        
        probe_id = db_add_probe(
            filename, sha256, uploaded_by, "temp_path", file_size
        )
        
        stored_path = store_evidence_file(filename, file_bytes, probe_id)
        update_probe_stored_path(probe_id, stored_path)
        
        log_probe_added(filename, probe_id, sha256, file_size)
        
        return probe_id, sha256
    except Exception as e:
        log_error("ADD_PROBE", str(e))
        raise


def get_probes():
    """Get all probes in the custody chain."""
    return db_get_probes()

def add_user(name: str) -> None:
    """Add a new custodian to the system."""
    try:
        db_add_user(name.strip())
        log_user_added(name.strip())
    except Exception as e:
        log_error("ADD_USER", str(e))
        raise


def get_users():
    """Get all registered custodians."""
    return db_get_users()


def get_current_custodian(probe_id: int) -> Optional[str]:
    """
    Get the custodian who currently holds the evidence.
    
    Returns:
        Custodian name or None if evidence hasn't been transferred yet
    """
    return get_valid_next_custodian(probe_id)

def add_transfer(probe_id: int, from_user: str, to_user: str, transfer_reason: str = "", 
                 transfer_notes: str = "") -> Tuple[str, bool, str, str]:
    """
    Record a custody transfer of a digital probe.
    
    CRITICAL: Transfers succeed regardless of integrity status. Integrity verification
    is ANALYTICAL (determines if evidence is trustworthy) while transfers are PROCEDURAL
    (documents responsibility change). Compromised evidence MUST be transferred and
    documented in the chain of custody.
    
    Args:
        probe_id: Evidence ID
        from_user: Source custodian
        to_user: Destination custodian
        transfer_reason: Mandatory reason for transfer
        transfer_notes: Optional investigator notes
    
    Returns:
        Tuple of (transfer_status, integrity_status, original_hash, current_hash)
        - transfer_status: 'SUCCESS' if transfer recorded (always success if chain valid)
        - integrity_status: True (VALID) or False (ALTERED)
        - original_hash: Original hash when probe was added
        - current_hash: Current hash from stored file
    
    Raises:
        ValueError: Only if custody chain is procedurally invalid
    """
    try:
        is_valid_chain, error_msg = check_custody_chain_valid(probe_id, from_user, to_user)
        if not is_valid_chain:
            raise ValueError(error_msg)
        
        probe_details = get_probe_details(probe_id)
        
        if not probe_details:
            raise ValueError(f"Probe {probe_id} not found")
        
        original_hash = probe_details[2]
        stored_path = probe_details[4]
        
        file_bytes = retrieve_evidence_file(stored_path)
        if file_bytes is None:
            raise ValueError(f"Stored file not found: {stored_path}")
        
        current_hash = calculate_sha256(file_bytes)
        integrity_valid = current_hash == original_hash
        
        db_add_transfer(probe_id, from_user, to_user, current_hash, transfer_reason, 
                       transfer_notes)
        
        log_transfer(probe_id, from_user, to_user, integrity_valid, current_hash)
        
        return 'SUCCESS', integrity_valid, original_hash, current_hash
    except Exception as e:
        log_error("TRANSFER", str(e))
        raise

def verify_integrity(probe_id: int, file_bytes: bytes) -> Tuple[Optional[bool], str]:
    """
    Verify the integrity of a probe by comparing its current hash
    with the original hash stored in the database.
    
    Returns:
        Tuple of (is_valid, current_hash) where:
        - is_valid: True if valid, False if altered, None if probe not found
        - current_hash: The SHA-256 hash of the current file
    """
    try:
        current_hash = calculate_sha256(file_bytes)
        original_hash = get_probe_hash(probe_id)
        
        if original_hash is None:
            log_integrity_check(probe_id, None, current_hash)
            return None, current_hash
        
        is_valid = verify_file_integrity(file_bytes, original_hash)
        log_integrity_check(probe_id, is_valid, current_hash)
        return is_valid, current_hash
    except Exception as e:
        log_error("VERIFY_INTEGRITY", str(e))
        raise

def generate_report() -> str:
    """
    Generate a comprehensive custody chain text report.
    
    Returns:
        Formatted text report containing all probes and transfer history.
    """
    return generate_text_report()


def generate_pdf_report_bytes() -> bytes:
    """
    Generate a professional PDF custody chain report.
    
    Returns:
        PDF file as bytes ready to be downloaded.
    """
    return generate_pdf_report()


def generate_probe_text_report_with_id(probe_id: int) -> str:
    """Generate a text report for a single probe."""
    return generate_probe_text_report(probe_id)


def generate_probe_pdf_report_with_id(probe_id: int) -> bytes:
    """Generate a PDF report for a single probe."""
    return generate_probe_pdf_report(probe_id)


def get_audit_log(limit: int = 100) -> list:
    """Get audit log entries."""
    from core.audit import get_audit_log as get_audit_log_db
    return get_audit_log_db(limit)

def update_probe_status(probe_id: int, new_status: str) -> bool:
    """
    Update evidence status.
    Valid statuses: RECEIVED, IN_ANALYSIS, VERIFIED, RELEASED, ARCHIVED
    """
    from core.database import update_probe_status as db_update_status
    return db_update_status(probe_id, new_status)


def get_probe_status(probe_id: int) -> Optional[str]:
    """Get current status of evidence."""
    from core.database import get_probe_status as db_get_status
    return db_get_status(probe_id)

def run_integrity_check_all():
    """
    Run automated integrity check on all probes.
    Logs VERIFY_INTEGRITY events for any altered probes (automatically propagates through chain).
    
    Returns:
        Tuple of (altered_probes, check_summary)
        - altered_probes: List of (probe_id, filename, status, last_hash)
        - check_summary: List of log messages
    """
    from core.database import get_probes, get_authoritative_integrity_status
    
    altered = []
    probes = get_probes()
    summary = []
    
    summary.append(f"Automated integrity check completed at {datetime.now().isoformat()}")
    summary.append(f"Total probes checked: {len(probes)}")

    for probe in probes:
        probe_id = probe[0]
        filename = probe[1]

        latest_verification = get_authoritative_integrity_status(probe_id)

        if latest_verification == "ALTERED":
            altered.append({
                "probe_id": probe_id,
                "filename": filename,
                "status": "ALTERED"
            })

            log_integrity_check(
                probe_id,
                is_valid=False,
                current_hash=probe[2],
                source="AUTOMATED_"
            )
    summary.append(f"Altered probes detected: {len(altered)}")
    
    return len(probes), len(altered), altered



def count_all_probes() -> int:
    """Count total number of probes."""
    from core.database import get_probes
    return len(get_probes())

def can_download_evidence(username: str, user_role: str) -> bool:
    """Check if user can download evidence files."""
    return user_role in ['ADMIN', 'INVESTIGATOR']


def can_download_reports(username: str, user_role: str) -> bool:
    """Check if user can download reports."""
    return True


def can_modify_status(username: str, user_role: str) -> bool:
    """Check if user can modify evidence status."""
    return user_role in ['ADMIN', 'INVESTIGATOR']


def can_sign_transfer(username: str, user_role: str) -> bool:
    """Check if user can digitally sign transfers."""
    return True


def can_view_all_probes(username: str, user_role: str) -> bool:
    """Check if user can view all system probes."""
    return user_role == 'ADMIN'


def get_accessible_probes(username: str, user_role: str) -> List:
    """Get list of probes accessible to user based on role."""
    if user_role == 'ADMIN':
        return db_get_probes()
    else:
        return get_probes_for_user(username)


def generate_user_with_role(username: str, role: str = 'CUSTODIAN') -> None:
    """
    Add a new user with a specific role.
    
    Args:
        username: Username
        role: 'ADMIN', 'INVESTIGATOR', or 'CUSTODIAN' (default)
    """
    from core.database import set_user_role
    
    db_add_user(username)
    if role in ['ADMIN', 'INVESTIGATOR', 'CUSTODIAN']:
        set_user_role(username, role)
