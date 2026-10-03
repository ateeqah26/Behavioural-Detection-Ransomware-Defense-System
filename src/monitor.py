# PollingObserver (not the default inotify Observer) — inotify only
# detects changes made by the SAME machine. On PythonAnywhere the Flask
# web app and this Always-on Task run on different backend servers that
# share files only via network filesystem, so inotify never sees writes
# made by app.py's /api/simulate route. PollingObserver re-scans the
# directory on an interval instead of relying on kernel-level inotify
# events, so it works correctly across NFS/network mounts.
from watchdog.observers.polling import PollingObserver as Observer
from watchdog.events import FileSystemEventHandler
import time
import os
import json
import sys
import sqlite3
from datetime import datetime
import logging
from collections import deque

def get_base_path():
    """Return the project root folder (next to the .exe if compiled, or
    one level up from src/ if running from source — this file lives in
    src/, so we go up one level to reach the same root that main.py,
    database.py and app.py all use)."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

RANSOMWARE_THRESHOLD = 5      # number of canary events...
RANSOMWARE_WINDOW = 10        # ...within this many seconds triggers an alert

# NEW: known ransomware-appended extensions — if a RENAMED event ends in
# one of these, severity is forced to CRITICAL regardless of burst count
RANSOMWARE_EXTENSIONS = {
    ".encrypted", ".locked", ".lockbit", ".crypt", ".enc",
    ".ransom", ".pay", ".aes", ".rsa", ".cry", ".ryk",
    ".revil", ".conti", ".hive", ".black", ".basta",
}

# NEW: filename patterns commonly used for ransom notes dropped by attackers
RANSOM_NOTE_PATTERNS = [
    "readme", "decrypt", "restore", "recover", "how_to",
    "ransom", "locked", "unlock", "pay", "instruction",
]

# Behaviour F: random/gibberish filename rename.
# This is deliberately conservative: the new filename must be long, mostly
# alphanumeric, and contain very few vowels. A normal human filename such as
# "project_report.txt" will not match.
def looks_like_random_rename(filename):
    stem = os.path.splitext(filename)[0]
    if len(stem) < 10:
        return False
    alnum = [c for c in stem if c.isalnum()]
    if len(alnum) < 10:
        return False
    alnum_ratio = len(alnum) / max(len(stem), 1)
    vowels = sum(c.lower() in "aeiou" for c in alnum)
    return alnum_ratio >= 0.90 and (vowels / len(alnum)) <= 0.20


# NEW: file formats that are naturally high-entropy BY DESIGN because
# they are already compressed internally — this has nothing to do with
# ransomware. A .zip, .docx (itself a zip container), .jpg, or .pdf
# will legitimately score 7.8-8.0 entropy even when completely normal,
# indistinguishable from encrypted content using entropy alone. Real
# EDR/anti-ransomware products maintain the same kind of exclusion list
# for exactly this reason — without it, ordinary use of compressed file
# types causes constant false CRITICAL alerts.
NATURALLY_HIGH_ENTROPY_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".gz", ".tar", ".bz2", ".xz",
    ".docx", ".xlsx", ".pptx", ".dotx", ".xltx", ".potx",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic",
    ".mp3", ".mp4", ".mov", ".avi", ".mkv", ".m4a",
    ".pdf",
}


def compute_entropy(filepath):
    """Calculate Shannon entropy (0-8) of a file's contents. Encrypted
    files look close to random data and score near 8; normal text/
    documents score much lower. This tells us whether a MODIFIED event
    actually looks like encryption, not just any edit."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except (FileNotFoundError, PermissionError, OSError):
        return 0.0
    if not data:
        return 0.0
    from collections import Counter
    import math
    byte_counts = Counter(data)
    length = len(data)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in byte_counts.values()
        if count > 0
    )
    return round(entropy, 4)

DESCRIPTIONS = {
    "CREATED":  "A new canary file was created. This can indicate an attacker "
                "dropping files (e.g. ransom notes) inside the protected folder.",
    "MODIFIED": "A canary file's contents were changed. This is the strongest "
                "signal of ransomware, which typically overwrites files with "
                "encrypted data.",
    "DELETED":  "A canary file was deleted. Some ransomware deletes the original "
                "after creating an encrypted copy.",
    "RENAMED":  "A canary file was renamed/moved. Ransomware often appends a new "
                "extension (e.g. '.locked') after encrypting a file.",
}

# ----------------------------------------------------------------------
# LOGGING SETUP
# ----------------------------------------------------------------------

log_path = os.path.join(get_base_path(), "logs", "security_log.txt")

os.makedirs(os.path.dirname(log_path), exist_ok=True)

logging.basicConfig(
    filename=log_path,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s"
)

# ----------------------------------------------------------------------
# HELPER UNTUK SIMPAN KE DATABASE (ransomware_logs.db)
# ----------------------------------------------------------------------

def log_to_database(process_name, action_taken, threat_level, ioc=None):
    """Memasukkan rekod insiden secara dinamik terus ke dalam SQLite database.
    Uses the shared database.py module (same absolute DB_PATH as every
    other file) instead of building its own path — this is what was
    causing Layer 1 events to sometimes land in a different .db file
    than the one app.py / reporter.py were reading from."""
    try:
        sys.path.insert(0, get_base_path())
        import database as shared_db
        conn = shared_db.get_connection()
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

        cursor.execute('''
            INSERT INTO detection_logs (process_name, action_taken, threat_level, ioc)
            VALUES (?, ?, ?, ?)
        ''', (process_name, action_taken, threat_level, ioc))

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB ERROR] Gagal menulis ke database: {e}")

# ----------------------------------------------------------------------
# HELPERS
# ----------------------------------------------------------------------

def load_config():
    config_path = os.path.join(get_base_path(), "config", "canary_files.json")

    with open(config_path, "r") as file:
        data = json.load(file)

    canary_files = {os.path.normcase(os.path.abspath(p)) for p in data["canary_files"]}

    protected_folders = [os.path.abspath(p) for p in data.get("protected_folders", [])]

    watch_folders = sorted({
        os.path.dirname(path) for path in canary_files
    })

    watch_folders_recursive = protected_folders
    return canary_files, watch_folders, watch_folders_recursive, protected_folders


def get_file_details(filepath):
    """Return extra forensic detail about a file, safely handling files
    that may no longer exist (e.g. after a DELETED event)."""
    details = {
        "full_path": filepath,
        "extension": os.path.splitext(filepath)[1] or "(none)",
        "exists": os.path.exists(filepath),
        "size_bytes": None,
        "last_modified": None,
    }

    if details["exists"]:
        try:
            stat = os.stat(filepath)
            details["size_bytes"] = stat.st_size
            details["last_modified"] = datetime.fromtimestamp(
                stat.st_mtime
            ).strftime("%Y-%m-%d %H:%M:%S")
        except OSError:
            pass

    return details


# ----------------------------------------------------------------------
# EVENT / BEHAVIOUR TRACKING
# ----------------------------------------------------------------------

# BUGFIX: stores (timestamp, filename) tuples now, not just timestamps —
# so burst detection can count DISTINCT FILES touched, not raw event
# count. A single Office/Excel save fires 4-6 raw filesystem events for
# ONE file (temp file create, write, delete original, rename) which used
# to trip this the exact same way 5 DIFFERENT files being encrypted
# would — causing a normal .xlsx save to be misclassified as CRITICAL.
event_history = deque()
canary_files = set()  # populated by start_layer1_monitor() once it runs
protected_folders = []

# NEW: dedup tracking — Windows/Office apps often fire several raw
# filesystem events (temp file write, rename, flush) for what is really
# ONE user-facing save action. We still count every raw event for burst
# detection (below), but we only LOG/REPORT once per file+event_type
# within this window, so the dashboard/PDF report doesn't fill up with
# near-identical rows.
_last_logged = {}
DEDUP_WINDOW_SECONDS = 3


def _is_duplicate(filename, event_type):
    key = (filename, event_type)
    now = time.time()
    last_time = _last_logged.get(key)
    _last_logged[key] = now
    if last_time is not None and (now - last_time) < DEDUP_WINDOW_SECONDS:
        return True
    return False


def analyse_behaviour(filename, event_type):
    """Track canary events over a rolling time window and flag rapid,
    ransomware-like bursts of activity across DISTINCT files. Returns
    True if an alert fired."""
    current_time = time.time()
    # Initial file creation is common and should not by itself contribute
    # to the ransomware burst counter. Burst detection focuses on rapid
    # changes to existing files: modify, rename, or delete.
    if event_type not in ("MODIFIED", "RENAMED", "DELETED"):
        return False

    event_history.append((current_time, filename))

    while event_history and current_time - event_history[0][0] > RANSOMWARE_WINDOW:
        event_history.popleft()

    distinct_files = {f for _, f in event_history}

    if len(distinct_files) >= RANSOMWARE_THRESHOLD:
        print(f"[ALERT] POSSIBLE RANSOMWARE DETECTED | {len(distinct_files)} distinct files changed in {RANSOMWARE_WINDOW}s")

        logging.critical(
            "\n"
            "############################################\n"
            "  POSSIBLE RANSOMWARE DETECTED\n"
            f"  Distinct Files Changed : {len(distinct_files)}\n"
            f"  Time Window            : {RANSOMWARE_WINDOW}s\n"
            f"  Threshold              : {RANSOMWARE_THRESHOLD}\n"
            "############################################\n"
        )
        return True

    return False


def create_security_event(filename, event_type, filepath, is_canary=False):
    # Burst detection MUST see every raw event, even duplicates — a real
    # ransomware attack really does touch files this rapidly, so this
    # counter needs the true frequency. But it counts DISTINCT FILES,
    # not raw events — see the bugfix note above analyse_behaviour().
    behaviour_alert = analyse_behaviour(filename, event_type)

    # NEW: suppress near-duplicate LOGGING (same file, same event type,
    # within a few seconds) — this is what was flooding the dashboard
    # and PDF report with 4-5 identical rows for a single Excel save
    if _is_duplicate(filename, event_type) and not behaviour_alert:
        print(f"[DEDUP] Skipped duplicate log for {event_type} | {filename}")
        return

    file_info = get_file_details(filepath)

    # NEW: entropy-based encryption detection — only meaningful for
    # MODIFIED events on files that still exist
    entropy = None  # stays None when not computed (e.g. RENAMED/CREATED events)
    encryption_suspected = False
    if event_type == "MODIFIED" and file_info["exists"]:
        entropy = compute_entropy(filepath)
        file_ext = file_info["extension"].lower()
        if file_ext in NATURALLY_HIGH_ENTROPY_EXTENSIONS:
            # Entropy is expected to be high for these formats regardless
            # of content — don't use it as an encryption signal here.
            # (ransomware renaming/extension checks below still apply)
            encryption_suspected = False
        else:
            encryption_suspected = entropy > 7.5

    # Check for known ransomware extensions — applies to RENAMED (file
    # renamed to add extension) AND CREATED (new file written directly
    # under an already-encrypted-looking name, which some ransomware/
    # simulators do instead of a true rename)
    ransomware_extension_detected = None
    if event_type in ("RENAMED", "CREATED"):
        ext = file_info["extension"].lower()
        if ext in RANSOMWARE_EXTENSIONS:
            ransomware_extension_detected = ext

    # NEW: check newly created files for ransom-note-style names
    is_ransom_note = False
    if event_type == "CREATED":
        stem = os.path.splitext(filename)[0].lower()
        is_ransom_note = any(pattern in stem for pattern in RANSOM_NOTE_PATTERNS)

    # Decide final severity using all available signals.
    #   CRITICAL — confirmed strong signal (entropy, known extension,
    #              ransom note, random rename, or burst pattern)
    #   HIGH     — a protected canary was touched: suspicious/anomalous,
    #              but not enough by itself to confirm ransomware
    #   MEDIUM   — ordinary file content changed, deleted, or renamed
    #   LOW      — ordinary file creation
    random_rename_suspected = (
        event_type == "RENAMED" and looks_like_random_rename(filename)
    )

    if (
        behaviour_alert
        or encryption_suspected
        or ransomware_extension_detected
        or is_ransom_note
        or random_rename_suspected
    ):
        severity = "CRITICAL"
    elif is_canary:
        # Touching a decoy/canary is a high-priority anomaly, but one canary
        # interaction alone does NOT confirm ransomware and therefore does
        # not trigger the CRITICAL alert path below.
        severity = "HIGH"
    elif event_type == "MODIFIED":
        # A normal edit is intentionally only MEDIUM. This is important for
        # the clean demo: editing an ordinary .txt in the watched folder
        # should be visible in the feed but must not trigger an alert.
        severity = "MEDIUM"
    elif event_type in ("DELETED", "RENAMED"):
        severity = "MEDIUM"
    else:  # CREATED
        severity = "LOW"

    event = {
        "filename": filename,
        "event_type": event_type,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "severity": severity,
        "layer": "Layer 1",
        "full_path": file_info["full_path"],
        "extension": file_info["extension"],
        "size_bytes": file_info["size_bytes"],
        "last_modified": file_info["last_modified"],
        "entropy": entropy,
        "encryption_suspected": encryption_suspected,
        "ransomware_extension_detected": ransomware_extension_detected,
        "is_ransom_note": is_ransom_note,
        "random_rename_suspected": random_rename_suspected,
        "description": DESCRIPTIONS.get(event_type, "Canary file event detected."),
    }

    print(f"[EVENT] {event['event_type']} | {event['filename']} | {event['severity']}"
          + (f" | entropy={entropy}" if event_type == "MODIFIED" else ""))

    # NEW: build a specific, human-readable reason instead of a bare
    # "FILE MODIFIED" — shows WHY this severity was assigned, using
    # only signals already computed above (no extra I/O, so this is
    # safe to add without slowing down event processing).
    detail_bits = []
    if event_type == "MODIFIED":
        if entropy is not None:
            file_ext_for_msg = file_info["extension"].lower()
            if file_ext_for_msg in NATURALLY_HIGH_ENTROPY_EXTENSIONS:
                detail_bits.append(
                    f"entropy {entropy} — expected for {file_ext_for_msg} files (compressed format), not treated as a signal"
                )
            else:
                detail_bits.append(
                    f"entropy {entropy}" + (" — looks encrypted" if encryption_suspected else " — looks like normal content")
                )
    elif event_type == "CREATED":
        if ransomware_extension_detected:
            detail_bits.append(f"extension '{ransomware_extension_detected}' is on the known ransomware list")
        if is_ransom_note:
            detail_bits.append("filename matches a common ransom-note pattern")
        if not detail_bits:
            detail_bits.append("new file appeared")
    elif event_type == "DELETED":
        detail_bits.append("original file removed")
    elif event_type == "RENAMED":
        if ransomware_extension_detected:
            detail_bits.append(f"renamed with extension '{ransomware_extension_detected}' — known ransomware extension")
        elif random_rename_suspected:
            detail_bits.append("new filename looks random/gibberish")
        else:
            detail_bits.append("file renamed or moved")
    if behaviour_alert:
        detail_bits.append("part of a rapid multi-file burst")

    source_tag = "[CANARY]" if is_canary else "[FOLDER]"
    action_taken = f"{source_tag} FILE {event_type} — " + "; ".join(detail_bits) if detail_bits else f"{source_tag} FILE {event_type}"

    # IOC / forensic evidence for this endpoint-focused project.
    # An IP address is intentionally not used: these are local file-system
    # behaviours, not network-origin events. The most useful IOC is the
    # affected file plus the strongest evidence observed for that event.
    ioc_bits = [f"FILE={filename}"]
    if event['extension'] and event['extension'] != '(none)':
        ioc_bits.append(f"EXT={event['extension']}")
    if entropy is not None:
        ioc_bits.append(f"ENTROPY={entropy}")
    if ransomware_extension_detected:
        ioc_bits.append(f"RANSOM_EXT={ransomware_extension_detected}")
    if is_ransom_note:
        ioc_bits.append("RANSOM_NOTE=YES")
    if random_rename_suspected:
        ioc_bits.append("RANDOM_NAME=YES")
    if behaviour_alert:
        ioc_bits.append(f"BURST_FILES>={RANSOMWARE_THRESHOLD}")
    ioc = " | ".join(ioc_bits)

    # 1. Simpan rekod ke fail security_log.txt
    logging.info(
        "\n"
        "---------------------------------------------------\n"
        f"  Event      : {event['event_type']}\n"
        f"  File       : {event['filename']}\n"
        f"  Path       : {event['full_path']}\n"
        f"  Extension  : {event['extension']}\n"
        f"  Size       : {event['size_bytes']} bytes\n"
        f"  Modified   : {event['last_modified']}\n"
        f"  Entropy    : {event['entropy'] if event['entropy'] is not None else 'N/A (not applicable for this event type)'}"
        + (" (HIGH - encryption suspected)" if event['encryption_suspected'] else "") + "\n"
        f"  Severity   : {event['severity']}\n"
        f"  Layer      : {event['layer']}\n"
        f"  IOC        : {ioc}\n"
        f"  Detail     : {event['description']}\n"
        "---------------------------------------------------\n"
    )

    # 2. SIMPAN REKOD SEBENAR KE DATABASE RANSOMWARE_LOGS.DB (Dinamik)
    log_to_database(
        process_name=event['filename'], 
        action_taken=action_taken, 
        threat_level=event['severity'],
        ioc=ioc
    )

    # 2b. NEW: real-time alert + immediate mitigation — ONLY for CRITICAL
    # events (confirmed by entropy, extension, ransom note, or burst
    # pattern). A single ordinary touch (MEDIUM severity) is logged and
    # watched, but does NOT trigger a kill — this avoids terminating
    # legitimate processes on accidental human edits, while still acting
    # immediately once a real ransomware indicator is confirmed.
    if event['severity'] == "CRITICAL":
        # NOTE: Windows popup removed — alerts now surface live on the
        # web dashboard instead (see app.py /api/alerts + templates/dashboard.html).
        try:
            from alerting import send_slack_alert
            send_slack_alert(event)     # optional, needs webhook configured
        except Exception as e:
            print(f"[ALERT ERROR] Failed to send real-time alert: {e}")

        try:
            from mitigation import find_process_touching_file, log_unidentified_process, trigger_layer3_mitigation

            pid, process_name = find_process_touching_file(filepath)
            if pid:
                trigger_layer3_mitigation(
                    pid=pid,
                    process_name=process_name,
                    severity=event["severity"],
                    behavior_score=100 if behaviour_alert else 70,
                    filename=filename
                )
            else:
                log_unidentified_process(filename, event["severity"])
        except Exception as e:
            print(f"[LAYER 1→3 ERROR] Mitigation step failed: {e}")
    else:
        print(f"[LAYER 1] {filename} touched (severity {event['severity']}) — logged, no kill triggered")

# ----------------------------------------------------------------------
# WATCHDOG HANDLER
# ----------------------------------------------------------------------

class CanaryMonitor(FileSystemEventHandler):

    def _handle(self, event, event_type):
        if event.is_directory:
            return

        if os.path.abspath(event.src_path) == os.path.abspath(log_path):
            return

        # BUGFIX: the database file (ransomware_logs.db) and its SQLite
        # sidecar files (-journal, -wal, -shm) live inside the same
        # protected_folders tree as the rest of the project. Without this
        # check, every write THIS system makes to its own database was
        # being detected as a new "security event", which triggered
        # another database write, which triggered another event —
        # an infinite self-detection feedback loop (visible as endless
        # ransomware_logs.db / ransomware_logs.db-journal rows flooding
        # the dashboard).
        if os.path.basename(event.src_path).startswith("ransomware_logs.db"):
            return

        # NEW: ignore Python's own bytecode cache. __pycache__/*.pyc files
        # are auto-regenerated every time main.py/app.py imports a module —
        # this happens on EVERY run, has nothing to do with the user's
        # actual data, and was flooding the dashboard whenever the
        # project's own folder is included in protected_folders.
        path_lower = event.src_path.lower()
        if "__pycache__" in path_lower or path_lower.endswith((".pyc", ".pyo")):
            return

        # For RENAMED events, the file now lives at dest_path — the
        # ransomware extension (e.g. ".locked") only shows up there,
        # not in the old src_path
        effective_path = event.src_path
        if event_type == "RENAMED" and hasattr(event, "dest_path"):
            effective_path = event.dest_path

        filename = os.path.basename(effective_path)
        # Canary matching still checks src_path — that's the original
        # decoy file's identity, even after it gets renamed away
        normalized_path = os.path.normcase(os.path.abspath(event.src_path))

        is_canary = normalized_path in canary_files

        is_in_protected_folder = any(
            normalized_path.startswith(os.path.normcase(folder))
            for folder in protected_folders
        )

        if is_canary or is_in_protected_folder:
            create_security_event(filename, event_type, effective_path, is_canary)
        else:
            print(f"[IGNORED] {effective_path}")

    def on_created(self, event):
        self._handle(event, "CREATED")

    def on_modified(self, event):
        self._handle(event, "MODIFIED")

    def on_deleted(self, event):
        self._handle(event, "DELETED")

    def on_moved(self, event):
        self._handle(event, "RENAMED")

# ----------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------

def start_layer1_monitor():
    """Entry point for Layer 1. Called by main.py on its own thread."""
    global canary_files, protected_folders

    canary_files, watch_folders, _, protected_folders = load_config()

    observer = Observer(timeout=0.5)

    for folder in watch_folders:
        if os.path.isdir(folder):
            observer.schedule(CanaryMonitor(), folder, recursive=False)
            print(f"Watching: {folder}")

    for folder in protected_folders:
        if os.path.isdir(folder):
            observer.schedule(CanaryMonitor(), folder, recursive=True)
            print(f"Watching (protected): {folder}")
        else:
            print(f"[WARNING] Protected folder not found: {folder}")

    observer.start()

    print("Layer 1 Monitoring Started...")
    logging.info("Layer 1 Monitoring Started")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        logging.info("Layer 1 Monitoring Stopped")

    observer.join()


if __name__ == "__main__":
    start_layer1_monitor()