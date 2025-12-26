import hashlib
from typing import Tuple


def calculate_sha256(file_bytes: bytes) -> str:
    """Calculate SHA-256 hash of file bytes."""
    sha = hashlib.sha256()
    sha.update(file_bytes)
    return sha.hexdigest()


def verify_file_integrity(file_bytes: bytes, expected_hash: str) -> bool:
    """Verify that file bytes match the expected SHA-256 hash."""
    current_hash = calculate_sha256(file_bytes)
    return current_hash == expected_hash


def compare_hashes(current_hash: str, original_hash: str) -> Tuple[bool, str]:
    """
    Compare current hash with original hash.
    Returns: (is_valid, current_hash)
    """
    return current_hash == original_hash, current_hash
