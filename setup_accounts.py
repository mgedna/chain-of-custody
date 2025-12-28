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
        {
            "email": "alice@forensics.lab",
            "password": "password123",
            "username": "Alice",
            "role": "CUSTODIAN"
        },
        {
            "email": "bob@forensics.lab",
            "password": "password456",
            "username": "Bob",
            "role": "CUSTODIAN"
        },
        {
            "email": "charlie@forensics.lab",
            "password": "password789",
            "username": "Charlie",
            "role": "CUSTODIAN"
        }
    ]

    for account in demo_accounts:
        if create_user_with_password(account["email"], account["password"], account["username"], account["role"]):
            print(f"✓ Created account: {account['email']} ({account['username']})")
        else:
            print(f"⚠ Account may already exist: {account['email']}")
    
    print("\n" + "="*60)
    print("  Demo Accounts Ready!")
    print("="*60)
    print("\nAccounts created:")
    for account in demo_accounts:
        print(f"  Email:    {account['email']}")
        print(f"  Username: {account['username']}")
        print(f"  Password: {account['password']}")
        print(f"  Role:     {account['role']}")
        print()
    
    print("Start the app with: streamlit run app.py")

if __name__ == "__main__":
    setup_demo_accounts()
