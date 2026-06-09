import sqlite3
import hashlib


DB_NAME = "secureguard.db"


def _hash_key(raw_key: str) -> str:
    """
    SHA-256 hash of the raw API key.
    We never store the plaintext key — only this hash.
    On validation we hash the incoming key and compare hashes.
    """
    return hashlib.sha256(raw_key.encode()).hexdigest()


def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT,
        findings TEXT,
        risk_score INTEGER,
        risk_level TEXT,
        report TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        label TEXT NOT NULL,
        key_hash TEXT NOT NULL UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Auto-seed API key from env var on startup if table is empty
    import os
    raw_key = os.getenv("API_KEY", "")
    if raw_key:
        cursor.execute("SELECT COUNT(*) FROM api_keys")
        count = cursor.fetchone()[0]
        if count == 0:
            cursor.execute(
                "INSERT INTO api_keys (label, key_hash) VALUES (?, ?)",
                ("default-key", _hash_key(raw_key))
            )

    conn.commit()
    conn.close()

def store_api_key(label: str, raw_key: str):
    """Store a new hashed API key with a human-readable label."""
    conn = sqlite3.connect(DB_NAME)
    conn.execute(
        "INSERT INTO api_keys (label, key_hash) VALUES (?, ?)",
        (label, _hash_key(raw_key))
    )
    conn.commit()
    conn.close()


def validate_api_key(raw_key: str) -> bool:
    """
    Returns True if the hash of raw_key exists in the api_keys table.
    This is the only function that should ever touch incoming key values.
    """
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT 1 FROM api_keys WHERE key_hash = ?",
        (_hash_key(raw_key),)
    )
    result = cursor.fetchone()
    conn.close()
    return result is not None


def save_scan(code, findings, risk_score, risk_level, report):

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO scans (code, findings, risk_score, risk_level, report)
        VALUES (?, ?, ?, ?, ?)
        """,
        (code, findings, risk_score, risk_level, report)
    )
    conn.commit()
    conn.close()


def get_scan_history():

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
    SELECT id, risk_score, risk_level, created_at
    FROM scans
    ORDER BY id DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows


def reset_scan_history():

    conn = sqlite3.connect(DB_NAME)
    conn.execute("DELETE FROM scans")
    conn.execute("DELETE FROM sqlite_sequence WHERE name = 'scans'")
    conn.commit()
    conn.close()


def get_full_scan_history():

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
    SELECT id, risk_score, risk_level, created_at
    FROM scans
    ORDER BY id DESC
    LIMIT 20
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows