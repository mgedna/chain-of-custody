"""
Setup script to initialize demo accounts.
Run this once before starting the application.
"""

import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from config import DATABASE_PATH
from core.database import init_db
from core.auth import create_user_with_password

def setup_demo_accounts():
    """Create demo accounts for testing."""
    print("\n" + "="*60)
    print("  Creating Demo Accounts")
    print("="*60 + "\n")
    
    if DATABASE_PATH.exists():
        os.remove(DATABASE_PATH)
        print("✓ Old database removed")
    
    init_db()
    print("✓ Database initialized")
    
    demo_accounts = [
        ("alice", "password123", "Officer Alice"),
        ("bob", "password456", "Officer Bob"),
        ("charlie", "password789", "Officer Charlie"),
    ]
    
    for username, password, display_name in demo_accounts:
        if create_user_with_password(username, password):
            print(f"✓ Created account: {username} ({display_name})")
        else:
            print(f"⚠ Account may already exist: {username}")
    
    print("\n" + "="*60)
    print("  Demo Accounts Ready!")
    print("="*60)
    print("\nAccounts created:")
    for username, password, display_name in demo_accounts:
        print(f"  Username: {username}")
        print(f"  Password: {password}")
        print(f"  Display:  {display_name}")
        print()
    
    print("Start the app with: streamlit run app.py")

if __name__ == "__main__":
    setup_demo_accounts()
