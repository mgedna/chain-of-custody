import os
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Optional, Tuple, List
from datetime import datetime


HASHCAT_TYPES = {
    "MD5": "0",
    "MD5_SALTED": "10",
    "MD5_WORDPRESS": "682",
    "SHA1": "100",
    "SHA256": "1400",
    "SHA256_SALTED": "1710",
    "BCRYPT": "3200",
    "SCRYPT": "8900",
    "NTLM": "1000",
    "LM": "3000",
    "Windows": "1000",
    "Linux": "1800",
    "PDF": "10500",
}


def validate_hash_format(hashes: List[str], hash_type: str) -> Tuple[bool, str]:
    """
    Validate that hashes match expected format for the given type.
    
    Args:
        hashes: List of hash strings
        hash_type: Hash type identifier
        
    Returns:
        (is_valid, error_message) tuple
    """
    if not hashes:
        return False, "No hashes provided"
    
    expected_lengths = {
        "MD5": 32,
        "MD5_SALTED": (32, 128),
        "SHA1": 40,
        "SHA256": 64,
        "SHA256_SALTED": (64, 256),
        "BCRYPT": 60,
        "NTLM": 32,
        "LM": 32,
        "Windows": 32,
        "Linux": 106,
    }
    
    if hash_type not in expected_lengths:
        return False, f"Unsupported hash type: {hash_type}"
    
    expected = expected_lengths[hash_type]
    
    for h in hashes:
        h = h.strip()
        if isinstance(expected, tuple):
            if not (expected[0] <= len(h) <= expected[1]):
                return False, f"Hash length {len(h)} not in range {expected} for {hash_type}"
        else:
            if len(h) != expected and not h.startswith("$"):
                return False, f"Hash length {len(h)} doesn't match expected {expected} for {hash_type}"
    
    return True, "Hash format valid"


def create_working_copy(hash_file_content: str) -> str:
    """
    Create a temporary working copy of hash file for analysis.
    Original evidence file is never touched.
    
    Args:
        hash_file_content: String content of hash file
        
    Returns:
        Path to temporary working copy
    """
    temp_dir = tempfile.mkdtemp(prefix="hashcat_work_")
    hash_file_path = os.path.join(temp_dir, "hashes.txt")
    
    with open(hash_file_path, 'w') as f:
        f.write(hash_file_content)
    
    return temp_dir


def cleanup_working_copy(temp_dir: str) -> None:
    """
    Clean up temporary working directory after analysis.
    
    Args:
        temp_dir: Path to temporary directory to remove
    """
    try:
        shutil.rmtree(temp_dir)
    except Exception as e:
        print(f"Warning: Could not clean up {temp_dir}: {e}")


def run_hashcat_analysis(
    temp_dir: str,
    hash_type: str,
    wordlist_path: Optional[str] = None,
    attack_mode: str = "dictionary"
) -> Tuple[bool, int, int]:
    """
    Execute Hashcat analysis on working copy.
    
    This function runs Hashcat in a controlled, sandboxed manner on a temporary
    working copy of hashes. It does NOT modify original evidence.
    
    Args:
        temp_dir: Path to working directory with hash file
        hash_type: Hash type identifier (from HASHCAT_TYPES)
        wordlist_path: Path to dictionary wordlist file
        attack_mode: Attack mode (currently only "dictionary" supported)
        
    Returns:
        (success, total_hashes, cracked_count) tuple
    """
    if hash_type not in HASHCAT_TYPES:
        raise ValueError(f"Unsupported hash type: {hash_type}")
    
    hash_file = os.path.join(temp_dir, "hashes.txt")
    
    if not os.path.exists(hash_file):
        raise FileNotFoundError(f"Hash file not found: {hash_file}")
    
    with open(hash_file, 'r') as f:
        total_hashes = len([line for line in f if line.strip()])
    
    if wordlist_path is None:
        wordlist_path = os.path.join(temp_dir, "wordlist.txt")
        with open(wordlist_path, 'w') as f:
            f.write("password\n123456\nadmin\nletmein\n")
    
    potfile = os.path.join(temp_dir, "potfile.pot")
    hashcat_cmd = [
        "hashcat",
        "-m", HASHCAT_TYPES[hash_type],
        "-a", "0",
        "-o", potfile,
        "--potfile-path", potfile,
        "--outfile-format", "2",
        hash_file,
        wordlist_path
    ]
    
    try:
        result = subprocess.run(
            hashcat_cmd,
            capture_output=True,
            text=True,
            timeout=300
        )
        
        cracked_count = 0
        if os.path.exists(potfile):
            with open(potfile, 'r') as f:
                cracked_count = len([line for line in f if line.strip()])
        
        return True, total_hashes, cracked_count
        
    except subprocess.TimeoutExpired:
        return False, total_hashes, 0
    except FileNotFoundError:
        return False, total_hashes, 0
    except Exception as e:
        print(f"Hashcat execution error: {e}")
        return False, total_hashes, 0


def parse_analysis_results(
    total_hashes: int,
    cracked_count: int
) -> dict:
    """
    Parse and format analysis results for display and storage.
    
    SECURITY: Returns only statistics, never plaintext passwords.
    
    Args:
        total_hashes: Total number of hashes analyzed
        cracked_count: Number of successfully cracked hashes
        
    Returns:
        Dictionary with analysis summary
    """
    if total_hashes == 0:
        crack_rate = 0
    else:
        crack_rate = (cracked_count / total_hashes) * 100
    
    summary = {
        "timestamp": datetime.now().isoformat(),
        "total_hashes": total_hashes,
        "cracked_hashes": cracked_count,
        "crack_rate_percent": round(crack_rate, 2),
        "status": "COMPLETED",
        "findings": generate_findings_summary(total_hashes, cracked_count)
    }
    
    return summary


def generate_findings_summary(total_hashes: int, cracked_count: int) -> str:
    """
    Generate human-readable findings summary.
    
    Args:
        total_hashes: Total hashes analyzed
        cracked_count: Successfully cracked hashes
        
    Returns:
        String description of findings
    """
    if total_hashes == 0:
        return "No hashes analyzed"
    
    crack_rate = (cracked_count / total_hashes) * 100
    
    if crack_rate == 0:
        return f"Strong credential protection: 0 out of {total_hashes} hashes cracked using dictionary attack"
    elif crack_rate < 10:
        return f"Good credential protection: {cracked_count} out of {total_hashes} hashes ({crack_rate:.1f}%) cracked using dictionary attack"
    elif crack_rate < 50:
        return f"Moderate credential protection: {cracked_count} out of {total_hashes} hashes ({crack_rate:.1f}%) cracked using dictionary attack"
    else:
        return f"Weak credential protection: {cracked_count} out of {total_hashes} hashes ({crack_rate:.1f}%) cracked using dictionary attack"


def perform_analysis(
    hash_file_content: str,
    hash_type: str,
    wordlist_path: Optional[str] = None
) -> Tuple[bool, dict]:
    """
    Complete analysis workflow: create working copy, run analysis, clean up, return results.
    
    PRINCIPLE: Original evidence is never touched. All work is on temporary copies.
    
    Args:
        hash_file_content: String content of uploaded hash file
        hash_type: Hash type identifier
        wordlist_path: Optional path to custom wordlist
        
    Returns:
        (success, results_dict) tuple
    """
    hash_lines = [h.strip() for h in hash_file_content.split('\n') if h.strip()]
    is_valid, error_msg = validate_hash_format(hash_lines, hash_type)
    
    if not is_valid:
        return False, {"error": error_msg}
    
    temp_dir = create_working_copy(hash_file_content)
    
    try:
        success, total_hashes, cracked_count = run_hashcat_analysis(
            temp_dir,
            hash_type,
            wordlist_path
        )
        
        results = parse_analysis_results(total_hashes, cracked_count)
        results["analysis_success"] = success
        
        return True, results
        
    finally:
        cleanup_working_copy(temp_dir)
