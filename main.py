"""
main.py — Entry point that starts all 3 layers together.

Layer 1 (src/monitor.py)   — watches canary files, runs on its own thread
Layer 2 (src/behavior.py)  — scans running processes, runs on its own thread
Layer 3 (mitigation.py)    — NOT run on a thread; it's called directly by
                              Layer 2 the moment a threat is confirmed
                              (see trigger_layer3_mitigation inside behavior.py)
"""

import os
import sys
import threading
import time

# Make src/ importable, so "import monitor" and "import behavior" work
# from here even though they live in a subfolder
sys.path.append(os.path.join(os.path.dirname(__file__), "src"))

import database
import monitor
import behavior


def main():
    # Create the SQLite table if it doesn't exist yet — must happen once,
    # before either layer tries to log an incident to it
    database.init_db()

    print("=" * 54)
    print("   BEHAVIORAL RANSOMWARE DEFENSE SYSTEM — STARTING")
    print("=" * 54)

    layer1_thread = threading.Thread(
        target=monitor.start_layer1_monitor,
        daemon=True,
        name="Layer1-Monitor"
    )
    layer2_thread = threading.Thread(
        target=behavior.start_layer2_detection,
        daemon=True,
        name="Layer2-Detection"
    )

    layer1_thread.start()
    layer2_thread.start()

    print("\nAll layers running. Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down all layers...")


if __name__ == "__main__":
    main()
