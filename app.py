"""
app.py — Combined Explanation + Live Dashboard
(Early-Warning Ransomware Detection System Using Canary Files)

ONE page: scroll from "what this system does" straight into the live
detection feed — no separate blank-table page, no typing an IP into
an empty screen. Reads directly from the same ransomware_logs.db that
monitor.py / mitigation.py write to (via database.py's shared connection,
so there's no path-mismatch risk).

Run with:  python app.py
Laptop 1 (running main.py): http://localhost:5000
Laptop 2 (same WiFi/hotspot): http://<Laptop 1's IP>:5000
"""

import os
import sys
import sqlite3
import json
import random
import string
import time
from flask import Flask, render_template, jsonify, send_file, request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import database

app = Flask(__name__)


@app.route('/')
def home():
    return render_template('dashboard.html')


@app.route('/api/alerts')
def api_alerts():
    """Polled by the page's JavaScript every 2 seconds."""
    if not os.path.exists(database.DB_PATH):
        return jsonify([])
    try:
        conn = database.get_connection()
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM detection_logs ORDER BY id DESC LIMIT 50"
        ).fetchall()
        conn.close()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500



def _write_text(path, content, mode="w"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, mode, encoding="utf-8") as f:
        f.write(content)


def _sim_attack_flow(target_folder, canary_files, actions):
    """Narrated, safe ransomware-like attack sequence for an industry demo.
    It only creates/changes demo files; it never encrypts real data or kills processes.
    """
    actions.append("STEP 1 — Initial file drop: attacker-like process creates target documents")
    docs = []
    for i in range(6):
        path = os.path.join(target_folder, f"client_document_{i}.txt")
        _write_text(path, f"Confidential demo document {i}.\n")
        docs.append(path)
        actions.append(f"STEP 1: CREATED {os.path.basename(path)}")
        time.sleep(0.45)

    actions.append("STEP 2 — Early warning: protected canary files are touched")
    for path, text in zip(canary_files[:2], [
        "[ATTACK FLOW] canary interaction 1.\n",
        "[ATTACK FLOW] canary interaction 2.\n",
    ]):
        if not os.path.exists(path):
            _write_text(path, "Canary placeholder\n")
        _write_text(path, text, mode="a")
        actions.append(f"STEP 2: MODIFIED CANARY {os.path.basename(path)}")
        time.sleep(0.8)

    actions.append("STEP 3 — Mass file activity: rapid modifications begin")
    for path in docs:
        _write_text(path, "Rapid simulated encryption write.\n", mode="a")
    actions.append("STEP 3: MODIFIED 6 distinct documents rapidly — burst evidence")
    time.sleep(1.2)

    actions.append("STEP 4 — Encryption-like content appears in one document")
    entropy_path = os.path.join(target_folder, "client_document_0.txt")
    data = bytes(random.getrandbits(8) for _ in range(4096))
    with open(entropy_path, "wb") as f:
        f.write(data)
    actions.append("STEP 4: HIGH-ENTROPY WRITE to client_document_0.txt")
    time.sleep(1.0)

    actions.append("STEP 5 — Files receive a ransomware-style extension")
    locked_src = os.path.join(target_folder, "client_document_1.txt")
    locked_dst = locked_src + ".locked"
    if os.path.exists(locked_src):
        os.replace(locked_src, locked_dst)
        actions.append("STEP 5: RENAMED client_document_1.txt -> client_document_1.txt.locked")
    time.sleep(1.0)

    actions.append("STEP 6 — Ransom note is dropped")
    note = os.path.join(target_folder, "README_DECRYPT_FILES.txt")
    _write_text(note, "SIMULATION ONLY — no real files were encrypted.\n")
    actions.append("STEP 6: CREATED README_DECRYPT_FILES.txt")
    actions.append("ATTACK FLOW COMPLETE — dashboard should show the sequence from LOW/MEDIUM to CRITICAL evidence")

def _sim_clean(target_folder, actions):
    """Safe normal-user activity: exactly 3 events on ONE ordinary file.
    Create -> modify -> delete. No canary is touched and no CRITICAL alert
    should be generated."""
    path = os.path.join(target_folder, "clean_demo_notes.txt")
    try:
        _write_text(path, "Normal business document created for demo.\n")
        actions.append("CLEAN: CREATED clean_demo_notes.txt")
        time.sleep(0.8)

        _write_text(path, "Normal business document updated by a user.\n", mode="a")
        actions.append("CLEAN: MODIFIED clean_demo_notes.txt")
        time.sleep(0.8)

        os.remove(path)
        actions.append("CLEAN: DELETED clean_demo_notes.txt")
    except OSError as e:
        actions.append(f"Clean activity failed: {e}")


def _sim_a_canary(target_folder, canary_files, actions):
    """A — several harmless canary/protected-file interactions.
    Keeps the scenario below the burst threshold so it remains LOW/MEDIUM.
    """
    if not canary_files:
        raise OSError("No canary file configured")

    # Ensure all configured canaries exist before touching them.
    for idx, path in enumerate(canary_files[:3], start=1):
        if not os.path.exists(path):
            _write_text(path, f"Canary placeholder {idx}\n")

    # Three distinct canary modifications = MEDIUM.
    for path, text in zip(canary_files[:3], [
        "[DEMO A] canary viewed/updated by normal process.\n",
        "[DEMO A] canary metadata/content update.\n",
        "[DEMO A] third canary update.\n",
    ]):
        _write_text(path, text, mode="a")
        actions.append(f"A: MODIFIED canary {os.path.basename(path)}")
        time.sleep(0.6)

    # One ordinary create/edit/delete sequence = LOW then MEDIUM/MEDIUM.
    demo = os.path.join(target_folder, "canary_activity_note.txt")
    _write_text(demo, "Normal protected-folder note for canary demonstration.\n")
    actions.append("A: CREATED canary_activity_note.txt")
    time.sleep(0.5)
    _write_text(demo, "User added a normal note.\n", mode="a")
    actions.append("A: MODIFIED canary_activity_note.txt")
    time.sleep(0.5)
    try:
        os.remove(demo)
        actions.append("A: DELETED canary_activity_note.txt")
    except FileNotFoundError:
        pass

    actions.append("A: 3 canary modifications + 3 normal file actions; expected LOW/MEDIUM only")

def _sim_b_entropy(target_folder, actions):
    """B — High entropy rewrite using TXT so entropy is actually analysed."""
    path = os.path.join(target_folder, "entropy_demo.txt")
    _write_text(path, "Normal readable text before simulated encryption.\n")
    time.sleep(1.5)
    data = bytes(random.getrandbits(8) for _ in range(4096))
    with open(path, "wb") as f:
        f.write(data)
    actions.append("B: MODIFIED entropy_demo.txt with high-entropy random bytes (>7.5)")


def _sim_c_extension(target_folder, actions):
    """C — Rename a file with a known ransomware extension."""
    src = os.path.join(target_folder, "extension_demo.txt")
    dst = src + ".locked"
    _write_text(src, "Demo document before simulated encryption.\n")
    time.sleep(1.5)
    os.replace(src, dst)
    actions.append("C: RENAMED extension_demo.txt -> extension_demo.txt.locked")


def _sim_d_burst(target_folder, actions):
    """D — create files first, then rapidly modify six distinct files.
    The burst detector counts modifications/renames/deletes, not initial creates.
    """
    paths = []
    for i in range(6):
        path = os.path.join(target_folder, f"burst_demo_{i}.txt")
        _write_text(path, f"Initial document content {i}.\n")
        paths.append(path)
        time.sleep(0.25)
    actions.append("D: CREATED 6 files as initial setup")
    time.sleep(0.8)
    for path in paths:
        _write_text(path, "Rapid simulated encryption activity.\n", mode="a")
    actions.append("D: MODIFIED 6 different files rapidly (burst pattern)")
    actions.append("D: Expected CRITICAL once 5+ distinct files are changed within 10 seconds")

def _sim_e_ransom_note(target_folder, actions):
    """E — Create a ransom-note-style filename."""
    path = os.path.join(target_folder, "README_DECRYPT.txt")
    _write_text(path, "SIMULATION ONLY - Your files are not encrypted.\n")
    actions.append("E: CREATED README_DECRYPT.txt (ransom-note filename pattern)")


def _sim_f_random_rename(target_folder, actions):
    """F — Rename to a gibberish-looking filename."""
    src = os.path.join(target_folder, "customer_records.txt")
    random_name = "".join(random.choices("bcdfghjklmnpqrstvwxyz0123456789", k=14)) + ".txt"
    dst = os.path.join(target_folder, random_name)
    _write_text(src, "Customer record demo content.\n")
    time.sleep(1.5)
    os.replace(src, dst)
    actions.append(f"F: RENAMED customer_records.txt -> {random_name}")


@app.route('/api/simulate', methods=['POST'])
def simulate_attack():
    """Safe server-side behaviour simulator for the dashboard.
    Each A-F button runs one isolated behaviour; combined runs A-F."""
    scenario = (request.get_json(silent=True) or {}).get("scenario", "combined")
    valid_scenarios = {"clean", "A", "B", "C", "D", "E", "F", "combined", "attack_flow"}
    if scenario not in valid_scenarios:
        return jsonify({"error": f"Unknown scenario '{scenario}'"}), 400

    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config", "canary_files.json")
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        return jsonify({"error": f"Could not read canary_files.json: {e}"}), 500

    protected_folders = config.get("protected_folders", [])
    canary_files = config.get("canary_files", [])
    if not protected_folders and not canary_files:
        return jsonify({"error": "No protected folder/canary configured"}), 400

    target_folder = protected_folders[0] if protected_folders else os.path.dirname(canary_files[0])
    try:
        os.makedirs(target_folder, exist_ok=True)
    except OSError as e:
        return jsonify({"error": f"Could not access target folder: {e}"}), 500

    actions = []
    try:
        if scenario == "clean":
            _sim_clean(target_folder, actions)
        elif scenario == "A":
            _sim_a_canary(target_folder, canary_files, actions)
        elif scenario == "B":
            _sim_b_entropy(target_folder, actions)
        elif scenario == "C":
            _sim_c_extension(target_folder, actions)
        elif scenario == "D":
            _sim_d_burst(target_folder, actions)
        elif scenario == "E":
            _sim_e_ransom_note(target_folder, actions)
        elif scenario == "F":
            _sim_f_random_rename(target_folder, actions)
        elif scenario == "attack_flow":
            _sim_attack_flow(target_folder, canary_files, actions)
        elif scenario == "combined":
            _sim_a_canary(target_folder, canary_files, actions)
            time.sleep(1.5)
            _sim_b_entropy(target_folder, actions)
            time.sleep(1.5)
            _sim_c_extension(target_folder, actions)
            time.sleep(1.5)
            _sim_d_burst(target_folder, actions)
            time.sleep(1.5)
            _sim_e_ransom_note(target_folder, actions)
            time.sleep(1.5)
            _sim_f_random_rename(target_folder, actions)
    except OSError as e:
        return jsonify({"error": str(e), "actions": actions}), 500

    return jsonify({
        "status": "ok",
        "scenario": scenario,
        "target_folder": target_folder,
        "actions": actions
    })


@app.route('/generate-pdf')
def download_report():
    try:
        from reporter import generate_pdf_report
        pdf_file = generate_pdf_report()
        if os.path.exists(pdf_file):
            return send_file(pdf_file, as_attachment=True, download_name="Monitor_Security_Report.pdf")
        return "Error generating PDF", 500
    except ImportError:
        return "reporter.py not available", 501


if __name__ == '__main__':
    database.init_db()
    print(f"Reading alerts from: {database.DB_PATH}")
    print("Open http://localhost:5000")
    print("For Laptop 2 (panel viewing): http://<this-laptop-IP>:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
