import sqlite3


DB_NAME = "secureguard.db"


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

    conn.commit()
    conn.close()

def save_scan(
    code,
    findings,
    risk_score,
    risk_level,
    report
):

    conn = sqlite3.connect(DB_NAME)

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO scans
        (
            code,
            findings,
            risk_score,
            risk_level,
            report
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            code,
            findings,
            risk_score,
            risk_level,
            report
        )
    )

    conn.commit()
    conn.close()

def get_scan_history():

    conn = sqlite3.connect(DB_NAME)

    cursor = conn.cursor()

    cursor.execute("""
    SELECT
        id,
        risk_score,
        risk_level,
        created_at
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
    SELECT
        id,
        risk_score,
        risk_level,
        created_at
    FROM scans
    ORDER BY id DESC
    LIMIT 20
    """)

    rows = cursor.fetchall()

    conn.close()

    return rows