"""
File storage module for digital evidence.
Handles secure storage and retrieval of evidence files.
"""

import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional
from config import EVIDENCE_DIR


def ensure_evidence_directory() -> None:
    """Create evidence directory if it doesn't exist."""
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


def store_evidence_file(original_filename: str, file_bytes: bytes, probe_id: int) -> str:
    """
    Store a copy of the evidence file.
    
    Args:
        original_filename: Original name of the uploaded file
        file_bytes: File content as bytes
        probe_id: ID of the probe in the database
        
    Returns:
        Stored file path relative to project root
    """
    ensure_evidence_directory()
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    name, ext = os.path.splitext(original_filename)
    stored_filename = f"probe_{probe_id}_{timestamp}{ext}"
    stored_path = EVIDENCE_DIR / stored_filename
    
    with open(stored_path, 'wb') as f:
        f.write(file_bytes)
    
    return str(stored_path)


def retrieve_evidence_file(stored_path: str) -> Optional[bytes]:
    """
    Retrieve a stored evidence file.
    
    Args:
        stored_path: Path to the stored file
        
    Returns:
        File content as bytes, or None if not found
    """
    if not os.path.exists(stored_path):
        return None
    
    with open(stored_path, 'rb') as f:
        return f.read()


def get_evidence_file_size(stored_path: str) -> Optional[int]:
    """Get the size of a stored evidence file in bytes."""
    if not os.path.exists(stored_path):
        return None
    return os.path.getsize(stored_path)


def cleanup_old_evidence_files(probe_id: int, keep_latest: int = 1) -> None:
    """
    Clean up old versions of evidence files for a probe.
    Keeps only the latest versions.
    """
    ensure_evidence_directory()
    
    probe_files = []
    for filename in os.listdir(EVIDENCE_DIR):
        if filename.startswith(f"probe_{probe_id}_"):
            filepath = os.path.join(EVIDENCE_DIR, filename)
            probe_files.append((filepath, os.path.getmtime(filepath)))
    
    probe_files.sort(key=lambda x: x[1], reverse=True)
    
    for filepath, _ in probe_files[keep_latest:]:
        try:
            os.remove(filepath)
        except OSError:
            pass
