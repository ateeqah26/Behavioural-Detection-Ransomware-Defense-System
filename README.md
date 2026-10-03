# Behavioural Detection Ransomware Defense System

A lightweight early-warning system that watches decoy (canary) files and process behaviour — not signatures — and surfaces the alert live on this dashboard the moment something starts encrypting.

## Project Overview

The system monitors protected folders using canary files and behavioural
indicators to detect suspicious ransomware-like activity.

The system analyses:

- Canary / Protected-Folder Touch
- High-Entropy Write
- Known Extension Append
- Burst Modification Rate
- Ransom Note Filename
- Shadow Copy Deletion
- Random Filename Rename
- Security Process Kill Attempt

## System Architecture

The system consists of three main layers:

1. Monitoring Layer
2. Verify Layer
3. Alert Layer

Detected activities are displayed through a live web dashboard.

## Behaviour Simulation

The project includes safe simulation scenarios for demonstration:

- A - Canary / Protected Folder Touch
- B - High Entropy
- C - Ransomware Extension
- D - Rapid File Burst
- E - Ransom Note
- F - Random Filename
- A-F Combined
- Ransomware Attack Flow
- Clean User Activity

The simulator does not perform real ransomware encryption or destructive
system operations.

## Technologies

- Python
- Flask
- SQLite
- HTML/CSS/JavaScript
- Watchdog / filesystem monitoring
- Shannon entropy analysis

## Installation

```bash
pip install -r requirements.txt