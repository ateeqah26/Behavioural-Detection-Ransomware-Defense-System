import os
import psutil
import time
import sys

def get_base_path():
    """Return the project root folder — this file lives in src/, so we
    go up one level (matches the same fix applied in monitor.py)."""
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
# Function to read a file containing blocked/ransomware names and store them in a set
def load_blacklist() -> set:
    """Dynamically reads the ransomware list from config/blacklist.txt."""

    # Find the current folder where this script is saved
    base_dir = get_base_path()

    # Build the full path to the 'config/blacklist.txt' file
    txt_path = os.path.join(base_dir, 'config', 'blacklist.txt')

    # Create an empty set to hold unique blacklisted items
    blacklist_set = set()
    try:
        # Open and read the blacklist file safely
        with open(txt_path, 'r') as f:
            for line in f:
                # Remove extra spaces/newlines and convert text to lowercase
                clean_line = line.strip().lower()

                # Skip empty lines and lines starting with '#' (which are comments)
                if clean_line and not clean_line.startswith('#'):
                    blacklist_set.add(clean_line)
        return blacklist_set
    
    # If the file does not exist, handle the error gracefully
    except FileNotFoundError:
        print(f"[Error] Blacklist file not found at: {txt_path}.")
        return blacklist_set
    
# Tracks PIDs already logged this run, so a blacklisted process that
# stays alive doesn't flood the dashboard with a duplicate row every
# single scan cycle (this loop runs once per second).
already_logged_pids = set()


# Function to turn a number score into a text danger level
def calculate_severity(score: int) -> str:
    """Maps numerical behavior scores to qualitative severity levels."""
    if score >= 80:
        return "CRITICAL"
    elif score >= 50:
        return "HIGH"
    elif score >= 25:
        return "MEDIUM"
    return "LOW"

def id_generation_sweep(pid: int, blacklist: set) -> tuple[int, str, bool]:
    """Scans active system processes against the blacklist and calculates a behavioral score."""
    try:
        p = psutil.Process(pid)
        name = p.name().lower()  # Get the lowercased name of the running process

        # Check if the process name exists inside your loaded blacklist set
        is_blacklisted = name in blacklist

        # If the process name matches an item on the blacklist AND we have not
        # already logged this exact PID this run (avoids flooding the dashboard
        # with a duplicate row every single 1-second scan cycle)
        if is_blacklisted and pid not in already_logged_pids:
            already_logged_pids.add(pid)
            # Baseline behavior metrics calculation
            backup_sabotage = False  # defined BEFORE the try, so it always exists
                                      # even if AccessDenied/NoSuchProcess fires early
            try:
                # If the process name matches an item on the blacklist
                cpu = p.cpu_percent(interval=0.01)

                # Get the RAM usage (Resident Set Size) and convert bytes to Megabytes (MB)
                memory = p.memory_info().rss / (1024 * 1024)

                # 🟢 Check for backup destruction (vssadmin delete)
                cmd_line = p.cmdline()
                cmd_string = " ".join(cmd_line).lower()
                if "vssadmin" in cmd_string and "delete" in cmd_string:
                 backup_sabotage = True

            # If the process closes or blocks access during scanning, catch the error
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                cpu, memory = 0.0, 0.0

            # Dynamic Behavioral Scoring Logic
            behavior_score = 65    # Base signature match score
            if cpu > 20.0:      # If the process is using more than 20% CPU
                behavior_score += 20   # Add 20 more points to the danger score
            if memory > 100.0:     # If the process is taking up more than 100 MB of RAM
                behavior_score += 15    # Add 15 more points to the danger score

            # 🟢 ADD PENALTY HERE: Apply the backup destruction score jump
            if backup_sabotage:
                behavior_score += 40

            # Cap the final score at a maximum of 100 using the min() function
            behavior_score = min(behavior_score, 100)

            # Use earlier function to translate this number score into "CRITICAL", "HIGH", etc.
            severity = calculate_severity(behavior_score)
            
            print("\n" + "=" * 40)
            print("Layer 2 Threat Intercept Confirmed")
            print("=" * 40)
            print(f"PID            : {pid}")
            print(f"Process Name : {p.name()}")
            print(f"CPU Usage      : {cpu:.1f}%")
            print(f"Memory Usage   : {memory:.1f} MB")
            print(f"Behavior Score : {behavior_score}/100")
            print(f"Severity Level : {severity}")
            print(f"Status         : BLACKLISTED")
            print("=" * 40)

            # Pass data directly to Layer 3
            from mitigation import trigger_layer3_mitigation
            trigger_layer3_mitigation(pid, p.name(), severity, behavior_score, filename="blacklisted process (Layer 2 scan)")

            return behavior_score, severity, True

        return 0, "LOW", False

    except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
        return 0, "LOW", False

# =====================================================================
# HYBRID AUTOMATED SYSTEM MONITORING SCANNER
# =====================================================================
def start_layer2_detection():
    """Entry point for Layer 2. Called by main.py on its own thread."""
    print("\n" + "#" * 54)
    print("  PRODUCTION ACTIVE MONITOR: LAYER 2 ENGINE DEPLOYED  ")
    print("#" * 54)

    scan_count = 0
    try:
        while True:
            scan_count += 1
            current_blacklist = load_blacklist()
            all_processes = list(psutil.process_iter())

            # Temporary tracking set to eliminate duplicate prints in a single cycle
            flagged_pids = set()

            print(f"[Cycle #{scan_count}] Screening active memory tracks...", end="\r")

            for proc in all_processes:
                try:
                    process_pid = proc.pid
                    if process_pid == os.getpid() or process_pid in flagged_pids:
                        continue

                    # Scan the process
                    score, severity, is_blacklisted = id_generation_sweep(process_pid, current_blacklist)

                    # If it's a match, add to flagged set so it doesn't print again this cycle
                    if is_blacklisted:
                        flagged_pids.add(process_pid)

                except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
                    continue

            # Rest pause before running the next system scanning sweep
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nLayer 2 monitoring engine offline.")


if __name__ == "__main__":
    start_layer2_detection()
