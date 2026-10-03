"""Reset all demo history and temporary demo files before a fresh presentation.

Run from the project root:
    python3.10 reset_demo.py
"""
import os
import glob
import database

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "logs", "security_log.txt")
TARGET = os.path.join(BASE_DIR, "protected_folder")

if os.path.exists(database.DB_PATH):
    os.remove(database.DB_PATH)
    print(f"Deleted database: {database.DB_PATH}")

if os.path.exists(LOG_PATH):
    os.remove(LOG_PATH)
    print(f"Deleted log: {LOG_PATH}")

# Remove only files created by our demo simulators. The real canary files
# (DO_NOT_OPEN.txt, Backup.txt, Payroll_Canary.txt) are preserved.
demo_patterns = [
    "clean_demo_*.txt", "entropy_demo.txt", "extension_demo.txt",
    "extension_demo.txt.locked", "burst_demo_*.txt", "README_DECRYPT*.txt",
    "customer_records.txt", "*.locked", "canary_activity_note.txt",
    "client_document_*.txt", "client_document_*.txt.locked",
]
removed = 0
for pattern in demo_patterns:
    for path in glob.glob(os.path.join(TARGET, pattern)):
        if os.path.basename(path) in {"DO_NOT_OPEN.txt", "Backup.txt", "Payroll_Canary.txt"}:
            continue
        try:
            os.remove(path)
            removed += 1
        except FileNotFoundError:
            pass

# Ensure all configured canaries exist.
for name, content in {
    "DO_NOT_OPEN.txt": "CANARY FILE - DO NOT USE\n",
    "Backup.txt": "CANARY BACKUP FILE - DO NOT USE\n",
    "Payroll_Canary.txt": "CANARY FILE - DO NOT USE\n",
}.items():
    path = os.path.join(TARGET, name)
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
database.init_db()
print(f"Removed {removed} old demo file(s).")
print("Fresh ransomware_logs.db created. Demo history is now clean.")
print("Real canary files were preserved.")
