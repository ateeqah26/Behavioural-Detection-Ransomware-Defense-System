"""
mitigation.py — Layer 3: Identify & Log (DETECTION-ONLY)

This system follows a honeytoken / early-warning strategy: the goal is
to detect and record ransomware-like behaviour with high confidence,
not to actively kill processes. Auto-termination was removed because:
  1. By the time a process is killed, the file it touched is already
     encrypted — killing it does not undo the damage.
  2. Ransomware often runs through trusted system processes; killing
     the wrong one can break the user's system.
  3. A Python user-mode script cannot safely terminate elevated
     processes anyway, without the kernel-level drivers real EDR
     products use.

Instead, Layer 3 identifies which process touched the canary/protected
file (or matched the blacklist) and logs it with full detail so it
shows up immediately on the live dashboard for a human to review.
"""

import psutil
import database
import os


def find_process_touching_file(filepath):
    """Identify which running process currently has an open handle on filepath."""
    target = os.path.normcase(os.path.abspath(filepath))
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            for f in proc.open_files():
                if os.path.normcase(os.path.abspath(f.path)) == target:
                    return proc.pid, proc.name()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
    return None, None


def log_unidentified_process(filename, severity):
    """Fallback used when the exact process touching the canary can't be
    identified (it may have already exited by the time we checked).
    NOTE: monitor.py's create_security_event() already wrote a database
    row for this exact detection — we only print here, we don't insert
    a second row, otherwise every CRITICAL event with an unidentified
    process ends up duplicated in the dashboard/report."""
    print(f"[LAYER 3] {filename}: source process could not be identified — logged anyway")


def trigger_layer3_mitigation(pid, process_name, severity, behavior_score, filename="canary_file"):
    """
    Called by Layer 1 (canary/entropy detection) or Layer 2 (blacklist
    process scan) when a threat is flagged. Identifies and logs the
    responsible process for the dashboard — does NOT terminate it.
    """
    print(f"\n[LAYER 3] Threat identified — logging for review (no termination)")
    print(f"Process        : {process_name} (PID: {pid})")
    print(f"Threat Severity: {severity} | Score: {behavior_score}/100")

    action_taken = f"DETECTED — flagged for review (behaviour score {behavior_score}/100)"

    database.log_incident(
        filename=filename,
        pid=pid if pid else 0,
        process_name=process_name,
        action_taken=action_taken,
        threat_level=severity
    )


if __name__ == "__main__":
    database.init_db()
