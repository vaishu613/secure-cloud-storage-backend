import os
import sqlite3
import hashlib
import hmac
import uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "users.db"


from contextlib import contextmanager

@contextmanager
def get_db_connection():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    """Initializes tables for users and file-owner relationships."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                full_name TEXT,
                created_at TEXT NOT NULL
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS files (
                file_id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                filename TEXT NOT NULL,
                size INTEGER NOT NULL,
                block_count INTEGER NOT NULL,
                s3_metadata_key TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (owner_id) REFERENCES users (id)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
        conn.commit()


# ==================================================
# PASSWORD HASHING AND VERIFICATION
# ==================================================

def hash_password(password: str) -> tuple[str, str]:
    """Hashes a password using PBKDF2-HMAC-SHA256 with 100,000 iterations and a unique salt."""
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        100_000
    )
    return salt.hex(), key.hex()


def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    """Verifies a password against the stored salt and hash using constant-time comparison."""
    try:
        salt = bytes.fromhex(salt_hex)
        key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            100_000
        )
        return hmac.compare_digest(key.hex(), hash_hex)
    except Exception:
        return False


# ==================================================
# USER OPERATIONS
# ==================================================

def create_user(email: str, password: str, full_name: str = "") -> Dict[str, Any]:
    """Creates a new user record with securely hashed password."""
    clean_email = email.strip().lower()
    salt_hex, hash_hex = hash_password(password)
    user_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO users (id, email, password_hash, salt, full_name, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, clean_email, hash_hex, salt_hex, full_name.strip(), created_at)
        )
        conn.commit()

    return {
        "id": user_id,
        "email": clean_email,
        "full_name": full_name.strip(),
        "created_at": created_at
    }


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Retrieves a user by email."""
    clean_email = email.strip().lower()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (clean_email,))
        row = cursor.fetchone()
        if row:
            return dict(row)
    return None


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a user by ID."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, full_name, created_at FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
    return None


# ==================================================
# FILE OPERATIONS (OWNER RECORD KEEPING)
# ==================================================

def register_user_file(
    file_id: str,
    owner_id: str,
    filename: str,
    size: int,
    block_count: int,
    s3_metadata_key: str,
    created_at: Optional[str] = None
) -> Dict[str, Any]:
    """Saves a file-to-owner mapping in the local database."""
    ts = created_at or datetime.now(timezone.utc).isoformat()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO files (file_id, owner_id, filename, size, block_count, s3_metadata_key, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (file_id, owner_id, filename, size, block_count, s3_metadata_key, ts)
        )
        conn.commit()

    return {
        "file_id": file_id,
        "owner_id": owner_id,
        "filename": filename,
        "size": size,
        "block_count": block_count,
        "s3_metadata_key": s3_metadata_key,
        "created_at": ts
    }


def get_files_by_owner(owner_id: str) -> List[Dict[str, Any]]:
    """Retrieves all files owned by a specific user."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM files WHERE owner_id = ? ORDER BY created_at DESC",
            (owner_id,)
        )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_file_record(file_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a single file record by file ID."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM files WHERE file_id = ?", (file_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
    return None


def delete_file_record(file_id: str, owner_id: str) -> bool:
    """Deletes a file record verifying that the caller is the owner."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM files WHERE file_id = ? AND owner_id = ?", (file_id, owner_id))
        conn.commit()
        return cursor.rowcount > 0


# Initialize on load
init_db()
