import hashlib
import secrets
from typing import Optional, Tuple
from core.database import (
    get_connection,
    get_users as db_get_users,
)


def hash_password(password: str) -> str:
    """Hash a password with a secure algorithm."""
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt.encode(),
        100000
    )
    return f"{salt}${pwd_hash.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against its stored hash."""
    try:
        salt, pwd_hash = stored_hash.split('$')
        new_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt.encode(),
            100000
        ).hex()
        return new_hash == pwd_hash
    except:
        return False


def create_user_with_password(email: str, password: str, username: str = None, role: str = 'CUSTODIAN') -> bool:
    """Create a new user with email, password, optional username, and role."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        pwd_hash = hash_password(password)
        
        if role not in ['ADMIN', 'INVESTIGATOR', 'CUSTODIAN']:
            role = 'CUSTODIAN'
        
        display_name = username if username else email.split('@')[0]
        
        cur.execute("""
        INSERT INTO users (email, username, password_hash, role)
        VALUES (?, ?, ?, ?)
        """, (email, display_name, pwd_hash, role))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error creating user: {e}")
        return False
    finally:
        conn.close()


def authenticate_user(email: str, password: str) -> Optional[Tuple[int, str]]:
    """
    Authenticate a user with email and password.
    
    Returns:
        (user_id, username) if successful, None if failed
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
        SELECT id, username, password_hash FROM users WHERE email = ?
        """, (email,))
        result = cur.fetchone()
        
        if not result:
            return None
        
        user_id, username, pwd_hash = result
        
        if verify_password(password, pwd_hash):
            return (user_id, username)
        else:
            return None
    finally:
        conn.close()


def get_user_by_id(user_id: int) -> Optional[str]:
    """Get username by user ID."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        result = cur.fetchone()
        return result[0] if result else None
    finally:
        conn.close()
