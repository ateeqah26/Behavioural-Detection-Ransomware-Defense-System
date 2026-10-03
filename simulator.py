"""
simulator.py — Safe A-F ransomware behaviour demo simulator.

Each scenario is isolated so the panel can see one behaviour at a time.
"COMBINED" runs A-F in sequence. No real ransomware, no shadow-copy deletion,
and no process killing are performed.
"""

import json
import math
import os
import random
import string
import sys
import time


BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def load_demo_target():
    config_path = os.path.join(BASE_DIR, "config", "canary_files.json")
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        protected = config.get("protected_folders", [])
        canaries = config.get("canary_files", [])
        if protected:
            return protected[0], canaries
        if canaries:
            return os.path.dirname(canaries[0]), canaries
    except Exception:
        pass
    return os.path.join(BASE_DIR, "protected_folder"), []


TARGET_FOLDER, CANARY_PATHS = load_demo_target()
os.makedirs(TARGET_FOLDER, exist_ok=True)


def calculate_shannon_entropy(data):
    if not data:
        return 0.0
    counts = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def high_entropy_data(size=4096):
    # Deterministic enough for a reliable demo: keep generating until > 7.5.
    while True:
        data = os.urandom(size)
        if calculate_shannon_entropy(data) > 7.5:
            return data


def write_text(path, content, mode="w"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, mode, encoding="utf-8") as f:
        f.write(content)


def pause(seconds=1.0):
    time.sleep(seconds)


def scenario_a():
    print("\n=== A — CANARY / PROTECTED-FOLDER TOUCH ===")
    if not CANARY_PATHS:
        print("No canary files configured.")
        return
    for idx, path in enumerate(CANARY_PATHS[:3], start=1):
        if not os.path.exists(path):
            write_text(path, f"Canary placeholder {idx}\n")
    for path, text in zip(CANARY_PATHS[:3], [
        "[DEMO A] canary update 1\n",
        "[DEMO A] canary update 2\n",
        "[DEMO A] canary update 3\n",
    ]):
        write_text(path, text, "a")
        print(f"-> Modified canary: {os.path.basename(path)}")
        pause(0.6)
    demo = os.path.join(TARGET_FOLDER, "canary_activity_note.txt")
    write_text(demo, "Normal protected-folder note.\n")
    print("-> Created canary_activity_note.txt")
    pause(0.5)
    write_text(demo, "Normal user edit.\n", "a")
    print("-> Modified canary_activity_note.txt")
    pause(0.5)
    os.remove(demo)
    print("-> Deleted canary_activity_note.txt")
    print("Expected: LOW/MEDIUM only — no critical alert.")

def scenario_b():
    print("\n=== B — HIGH-ENTROPY WRITE ===")
    path = os.path.join(TARGET_FOLDER, "entropy_demo.txt")
    write_text(path, "Readable text before simulated encryption.\n")
    pause(1.5)
    data = high_entropy_data()
    with open(path, "wb") as f:
        f.write(data)
    print(f"-> Wrote random bytes to: {path}")
    print(f"-> Entropy: {calculate_shannon_entropy(data):.4f}")
    print("Expected: CRITICAL alert.")


def scenario_c():
    print("\n=== C — KNOWN RANSOMWARE EXTENSION ===")
    src = os.path.join(TARGET_FOLDER, "extension_demo.txt")
    dst = src + ".locked"
    write_text(src, "Demo document.\n")
    pause(1.5)
    os.replace(src, dst)
    print(f"-> Renamed: {os.path.basename(src)} -> {os.path.basename(dst)}")
    print("Expected: CRITICAL alert.")


def scenario_d():
    print("\n=== D — BURST MODIFICATION RATE ===")
    paths = []
    for i in range(6):
        path = os.path.join(TARGET_FOLDER, f"burst_demo_{i}.txt")
        write_text(path, f"Initial activity file {i}\n")
        paths.append(path)
        pause(0.25)
    print("-> Created 6 initial files.")
    pause(0.8)
    for path in paths:
        write_text(path, "Rapid simulated encryption activity.\n", "a")
    print("-> Modified 6 different files rapidly.")
    print("Expected: CRITICAL alert from the 5+ distinct-file modification rule.")

def scenario_e():
    print("\n=== E — RANSOM NOTE FILENAME ===")
    path = os.path.join(TARGET_FOLDER, "README_DECRYPT.txt")
    write_text(path, "SIMULATION ONLY - files are not encrypted.\n")
    print(f"-> Created: {path}")
    print("Expected: CRITICAL alert.")


def scenario_f():
    print("\n=== F — RANDOM FILENAME RENAME ===")
    src = os.path.join(TARGET_FOLDER, "customer_records.txt")
    consonants = "bcdfghjklmnpqrstvwxyz0123456789"
    random_name = "".join(random.choices(consonants, k=14)) + ".txt"
    dst = os.path.join(TARGET_FOLDER, random_name)
    write_text(src, "Customer record demo content.\n")
    pause(1.5)
    os.replace(src, dst)
    print(f"-> Renamed: customer_records.txt -> {random_name}")
    print("Expected: CRITICAL alert from the random/gibberish filename signal.")


def scenario_attack_flow():
    print("\n=== RANSOMWARE-LIKE ATTACK FLOW — SAFE DEMO ===")
    docs = []
    print("STEP 1: Initial file creation")
    for i in range(6):
        path = os.path.join(TARGET_FOLDER, f"client_document_{i}.txt")
        write_text(path, f"Confidential demo document {i}.\n")
        docs.append(path)
        print(f"-> Created {os.path.basename(path)}")
        pause(0.45)

    print("STEP 2: Canary interaction")
    for path in CANARY_PATHS[:2]:
        if not os.path.exists(path):
            write_text(path, "Canary placeholder\n")
        write_text(path, "[ATTACK FLOW] canary interaction\n", "a")
        print(f"-> Modified CANARY {os.path.basename(path)}")
        pause(0.8)

    print("STEP 3: Burst modification")
    for path in docs:
        write_text(path, "Rapid simulated encryption write.\n", "a")
    print("-> Modified 6 distinct documents rapidly")
    pause(1.2)

    print("STEP 4: High entropy")
    data = high_entropy_data()
    with open(docs[0], "wb") as f:
        f.write(data)
    print(f"-> High entropy write: {os.path.basename(docs[0])} ({calculate_shannon_entropy(data):.4f})")
    pause(1.0)

    print("STEP 5: Ransomware-style extension")
    src = docs[1]
    dst = src + ".locked"
    if os.path.exists(src):
        os.replace(src, dst)
    print(f"-> Renamed {os.path.basename(src)} -> {os.path.basename(dst)}")
    pause(1.0)

    print("STEP 6: Ransom note")
    note = os.path.join(TARGET_FOLDER, "README_DECRYPT_FILES.txt")
    write_text(note, "SIMULATION ONLY — no real files were encrypted.\n")
    print(f"-> Created {os.path.basename(note)}")
    print("✔ Attack flow completed — observe the Live Feed from LOW/MEDIUM to CRITICAL.")

def scenario_clean():
    print("\n=== CLEAN — NORMAL USER ACTIVITY ===")
    paths = [
        os.path.join(TARGET_FOLDER, "clean_demo_notes.txt"),
        os.path.join(TARGET_FOLDER, "clean_demo_report.txt"),
        os.path.join(TARGET_FOLDER, "clean_demo_todo.txt"),
    ]
    for path in paths:
        write_text(path, "Normal business document.\n")
        print(f"-> Created {os.path.basename(path)}")
        pause(1.5)
    for path in paths[:2]:
        write_text(path, "Normal user edit.\n", "a")
        print(f"-> Edited {os.path.basename(path)}")
        pause(1.5)
    os.remove(paths[2])
    print(f"-> Deleted {os.path.basename(paths[2])}")
    print("Expected: LOW/MEDIUM only — no alert.")


SCENARIOS = {
    "clean": ("Clean activity — LOW/MEDIUM only", scenario_clean),
    "A": ("A — Canary / protected-folder touch", scenario_a),
    "B": ("B — High-entropy write", scenario_b),
    "C": ("C — Known ransomware extension", scenario_c),
    "D": ("D — Burst modification rate", scenario_d),
    "E": ("E — Ransom note filename", scenario_e),
    "F": ("F — Random filename rename", scenario_f),
    "combined": ("A-F Combined — all behaviours", None),
    "attack_flow": ("Ransomware-like attack flow — step-by-step", scenario_attack_flow),
}


def run_combined():
    print("\n=== A-F COMBINED BEHAVIOUR SIMULATION ===")
    for key in ("A", "B", "C", "D", "E", "F"):
        SCENARIOS[key][1]()
        pause(1)
    print("\n✔ Combined A-F simulation completed.")


def print_menu():
    print("\n" + "=" * 64)
    print("        RANSOMWARE BEHAVIOUR SIMULATOR — DEMO MODE")
    print("=" * 64)
    print(f"Watched folder: {TARGET_FOLDER}\n")
    for key, (label, _) in SCENARIOS.items():
        print(f"{key:8} {label}")
    print("attack_flow  Ransomware-like attack flow — step-by-step")
    print("0        Exit")


if __name__ == "__main__":
    while True:
        print_menu()
        try:
            choice = input("\nSelect behaviour: ").strip()
        except KeyboardInterrupt:
            print("\nSimulator stopped.")
            break

        if choice == "0":
            break
        if choice == "combined":
            run_combined()
        elif choice in SCENARIOS:
            SCENARIOS[choice][1]()
        else:
            print("Invalid choice. Choose clean, A-F, combined, or 0.")
