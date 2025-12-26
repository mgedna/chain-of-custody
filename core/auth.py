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


def create_user_with_password(username: str, password: str) -> bool:
    """Create a new user with password (admin function)."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        pwd_hash = hash_password(password)
        cur.execute("""
        INSERT INTO users (name, password_hash)
        VALUES (?, ?)
        """, (username, pwd_hash))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error creating user: {e}")
        return False
    finally:
        conn.close()


def authenticate_user(username: str, password: str) -> Optional[Tuple[int, str]]:
    """
    Authenticate a user with username and password.
    
    Returns:
        (user_id, username) if successful, None if failed
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("""
        SELECT id, name, password_hash FROM users WHERE name = ?
        """, (username,))
        result = cur.fetchone()
        
        if not result:
            return None
        
        user_id, name, pwd_hash = result
        
        if verify_password(password, pwd_hash):
            return (user_id, name)
        else:
            return None
    finally:
        conn.close()


def get_user_by_id(user_id: int) -> Optional[str]:
    """Get username by user ID."""
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT name FROM users WHERE id = ?", (user_id,))
        result = cur.fetchone()
        return result[0] if result else None
    finally:
        conn.close()
