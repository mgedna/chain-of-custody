"""
Demo: Custody chain validation
Shows how the system enforces proper custody chain
"""

import os
import sys
from pathlib import Path

if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

sys.path.insert(0, str(Path(__file__).parent))

from core.custody import add_probe, add_user, add_transfer
from core.database import init_db
from core.hashing import calculate_sha256

def print_section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")

def demo():
    print_section("CUSTODY CHAIN VALIDATION DEMO")
    
    init_db()
    print("Database initialized")
    
    test_content = b"Critical evidence file"
    probe_id, original_hash = add_probe("evidence.txt", test_content)
    print(f"Evidence added: ID={probe_id}, Hash={original_hash[:16]}...")
    
    add_user("Officer Alice")
    add_user("Officer Bob")
    add_user("Officer Charlie")
    add_user("Officer Dave")
    print("\nCustodians added: Alice, Bob, Charlie, Dave")
    
    print_section("TEST 1: Valid First Transfer (Alice -> Bob)")
    try:
        integrity, orig, curr = add_transfer(probe_id, "Officer Alice", "Officer Bob")
        print("✓ PASS: Transfer allowed (Alice -> Bob)")
    except ValueError as e:
        print(f"✗ FAIL: {e}")
    
    print_section("TEST 2: Invalid Transfer - Wrong Custodian (Charlie -> Dave)")
    try:
        integrity, orig, curr = add_transfer(probe_id, "Officer Charlie", "Officer Dave")
        print(f"✗ FAIL: Transfer should have been blocked!")
    except ValueError as e:
        print(f"✓ PASS: Transfer blocked - {e}")
    
    print_section("TEST 3: Valid Transfer - Correct Custodian (Bob -> Charlie)")
    try:
        integrity, orig, curr = add_transfer(probe_id, "Officer Bob", "Officer Charlie")
        print("✓ PASS: Transfer allowed (Bob -> Charlie)")
    except ValueError as e:
        print(f"✗ FAIL: {e}")
    
    print_section("TEST 4: Invalid Transfer - Reverse (Charlie -> Bob)")
    try:
        integrity, orig, curr = add_transfer(probe_id, "Officer Charlie", "Officer Bob")
        print(f"✗ FAIL: Reverse transfer should have been blocked!")
    except ValueError as e:
        print(f"✓ PASS: Reverse transfer blocked - {e}")
    
    print_section("TEST 5: Invalid Transfer - Same Person (Charlie -> Charlie)")
    try:
        integrity, orig, curr = add_transfer(probe_id, "Officer Charlie", "Officer Charlie")
        print(f"✗ FAIL: Self-transfer should have been blocked!")
    except ValueError as e:
        print(f"✓ PASS: Self-transfer blocked - {e}")
    
    print_section("TEST 6: Valid Transfer - Continue Chain (Charlie -> Dave)")
    try:
        integrity, orig, curr = add_transfer(probe_id, "Officer Charlie", "Officer Dave")
        print("✓ PASS: Transfer allowed (Charlie -> Dave)")
    except ValueError as e:
        print(f"✗ FAIL: {e}")
    
    print_section("TEST 7: Invalid Transfer - Wrong Person (Bob -> Alice)")
    try:
        integrity, orig, curr = add_transfer(probe_id, "Officer Bob", "Officer Alice")
        print(f"✗ FAIL: Transfer from wrong person should have been blocked!")
    except ValueError as e:
        print(f"✓ PASS: Transfer blocked - {e}")
    
    print_section("FINAL CUSTODY CHAIN")
    print("Alice -> Bob -> Charlie -> Dave")
    print("\n✓ Chain validation prevents:")
    print("  - Wrong custodian transferring evidence")
    print("  - Reverse transfers (going back)")
    print("  - Self-transfers")
    print("  - Skipping custodians")
    print("\n✓ Only current custodian can transfer to next person")

if __name__ == "__main__":
    try:
        if Path("db/chain.db").exists():
            import os
            os.remove("db/chain.db")
        demo()
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
