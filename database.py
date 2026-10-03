import sqlite3
import os

# Absolute path, anchored to this file's own folder (project root) — so it
# no longer matters which folder you were "cd"'d into when you ran a script.
# Every module (monitor.py, mitigation.py, app.py, reporter.py) now reads
# and writes the SAME database file.
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ransomware_logs.db")


def get_connection():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS detection_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            process_name TEXT,
            action_taken TEXT,
            threat_level TEXT,
            ioc TEXT
        )
    ''')
    # Backward-compatible migration for existing databases.
    try:
        cursor.execute("ALTER TABLE detection_logs ADD COLUMN ioc TEXT")
    except sqlite3.OperationalError:
        pass  # column already exists
    conn.commit()
    conn.close()


def log_incident(filename, pid, process_name, action_taken, threat_level="HIGH", ioc=None):
    """Called by mitigation.py (Layer 3) once a threat is confirmed.
    Writes into the SAME detection_logs table Layer 1 already uses, so
    the web dashboard and PDF report see every event in one place —
    this function was missing before, which would have crashed Layer 3
    the first time a CRITICAL event fired."""
    conn = get_connection()
    cursor = conn.cursor()
    display_process = f"{process_name} (PID {pid}) — {filename}" if pid else f"{process_name} — {filename}"
    cursor.execute('''
        INSERT INTO detection_logs (process_name, action_taken, threat_level, ioc)
        VALUES (?, ?, ?, ?)
    ''', (display_process, action_taken, threat_level, ioc))
    conn.commit()
    conn.close()


if __name__ == '__main__':
    init_db()
    print(f"Database initialised at: {DB_PATH}")
