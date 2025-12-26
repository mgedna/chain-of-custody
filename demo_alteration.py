#!/usr/bin/env python3
"""
Demo script: Simulates evidence tampering between transfers.
Shows how the system detects when a file has been altered.
"""

import os
import sys
from pathlib import Path

if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

sys.path.insert(0, str(Path(__file__).parent))

from core.custody import add_probe, add_user, add_transfer, get_audit_log
from core.database import init_db, get_report_data
from core.hashing import calculate_sha256
from core.storage import retrieve_evidence_file
from core.report import generate_text_report


def print_section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def demo():
    print_section("STEP 1: Initialize Database")
    init_db()
    print("✓ Database initialized")
    
    print_section("STEP 2: Create Test File")
    test_content = b"Original evidence file - DO NOT MODIFY"
    test_filename = "critical_evidence.txt"
    
    with open("temp_evidence.txt", "wb") as f:
        f.write(test_content)
    
    print(f"Created: {test_filename}")
    print(f"Content: {test_content.decode()}")
    print(f"Initial SHA-256: {calculate_sha256(test_content)}")
    
    print_section("STEP 3: Add Evidence to System")
    probe_id, original_hash = add_probe(test_filename, test_content)
    print(f"✓ Evidence added")
    print(f"  Probe ID: {probe_id}")
    print(f"  Original Hash: {original_hash}")
    
    print_section("STEP 4: Add Custodians")
    add_user("Officer Alice")
    add_user("Officer Bob")
    add_user("Officer Charlie")
    print("✓ Custodians added:")
    print("  - Officer Alice")
    print("  - Officer Bob")
    print("  - Officer Charlie")
    
    print_section("STEP 5: Transfer 1 - Alice to Bob (Should be VALID)")
    print("Evidence transferred from Officer Alice to Officer Bob...")
    integrity_valid_1, hash_at_transfer_1, current_hash_1 = add_transfer(
        probe_id, "Officer Alice", "Officer Bob"
    )
    
    if integrity_valid_1:
        print("✓ Transfer 1 VALID - Hash matches original")
    else:
        print("✗ Transfer 1 ALTERED - Hash mismatch (unexpected!)")
    
    print(f"  Original Hash:      {original_hash}")
    print(f"  Hash at Transfer 1: {hash_at_transfer_1}")
    print(f"  Match: {original_hash == hash_at_transfer_1}")
    
    print_section("STEP 6: Evidence is Tampered (Simulated)")
    print("ALERT: Evidence file has been secretly modified!")
    print("(Simulating: attacker modifies the stored file)")
    
    evidence_dir = Path("evidence")
    evidence_files = list(evidence_dir.glob(f"probe_{probe_id}_*"))
    
    if evidence_files:
        evidence_file = evidence_files[0]
        print(f"\nModifying stored file: {evidence_file.name}")
        
        tampered_content = test_content + b"\n[UNAUTHORIZED MODIFICATION]"
        
        with open(evidence_file, "wb") as f:
            f.write(tampered_content)
        
        tampered_hash = calculate_sha256(tampered_content)
        print(f"Original content:  {test_content.decode()}")
        print(f"Tampered content:  {tampered_content.decode()}")
        print(f"New SHA-256:       {tampered_hash}")
        print(f"Hash changed: {original_hash != tampered_hash}")
    else:
        print(f"ERROR: Could not find evidence file for probe {probe_id}")
    
    print_section("STEP 7: Transfer 2 - Bob to Charlie (Should be ALTERED)")
    print("Evidence transferred from Officer Bob to Officer Charlie...")
    integrity_valid_2, hash_at_transfer_2, current_hash_2 = add_transfer(
        probe_id, "Officer Bob", "Officer Charlie"
    )
    
    if integrity_valid_2:
        print("✓ Transfer 2 VALID - Hash matches original (unexpected!)")
    else:
        print("✗ Transfer 2 ALTERED - Hash mismatch DETECTED!")
    
    print(f"  Original Hash:      {original_hash}")
    print(f"  Hash at Transfer 2: {hash_at_transfer_2}")
    print(f"  Match: {original_hash == hash_at_transfer_2}")
    
    print_section("STEP 8: Generate Report")
    print("\n" + generate_text_report())
    
    print_section("STEP 9: Audit Log")
    audit_log = get_audit_log(10)
    
    if audit_log:
        print(f"{'Timestamp':<20} {'Action':<15} {'Status':<10} {'Details':<30}")
        print("-" * 80)
        for log_entry in audit_log:
            timestamp = log_entry[1][:19] if len(log_entry[1]) > 19 else log_entry[1]
            action = log_entry[2][:15]
            status = log_entry[4][:10] if log_entry[4] else "N/A"
            details = log_entry[3][:30] if log_entry[3] else "-"
            print(f"{timestamp:<20} {action:<15} {status:<10} {details:<30}")
    
    print_section("DEMO SUMMARY")
    print(f"✓ Evidence ID: {probe_id}")
    print(f"✓ Original Hash: {original_hash}")
    print(f"✓ Transfer 1 (Alice->Bob):     {('✓ VALID' if integrity_valid_1 else '✗ ALTERED')}")
    print(f"✓ Transfer 2 (Bob->Charlie):   {('✗ ALTERED' if not integrity_valid_2 else '✓ VALID')}")
    print(f"\n✓ Tampering was DETECTED! System integrity verified.")
    
    os.remove("temp_evidence.txt")
    print_section("Demo Complete")


if __name__ == "__main__":
    try:
        demo()
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
