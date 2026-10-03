"""
alerting.py — Real-time notification channel for CRITICAL security events.

Uses a Slack Incoming Webhook, since it's the fastest channel to set up
for a demo (no SMTP server/credentials needed — just one URL).

To enable:
1. In Slack, create an Incoming Webhook: api.slack.com/messaging/webhooks
2. Copy the webhook URL it gives you
3. Paste it into config/alert_config.json as "slack_webhook"

If no webhook is configured, alerts are simply skipped (not an error) —
so the system still works fully without Slack set up.
"""

import os
import sys
import json
import urllib.request


def get_base_path():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(os.path.abspath(__file__))


def load_alert_config():
    config_path = os.path.join(get_base_path(), "config", "alert_config.json")
    if not os.path.exists(config_path):
        return {}
    try:
        with open(config_path, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def send_windows_alert(event):
    """Show a native Windows popup for a CRITICAL event. Uses ctypes
    (built into Python — no pip install needed, so it always survives
    PyInstaller compilation). Runs on its own thread so it never blocks
    Layer 1 from processing further file events while the popup is open."""
    if sys.platform != "win32":
        return False  # Not on Windows (e.g. testing on Linux) — skip silently

    import threading
    import ctypes

    def _show_popup():
        entropy_display = event.get('entropy')
        entropy_display = entropy_display if entropy_display is not None else "N/A (not applicable for this event type)"
        message = (
            f"Event: {event['event_type']}\n"
            f"File: {event['filename']}\n"
            f"Severity: {event['severity']}\n"
            f"Time: {event['timestamp']}\n"
            f"Entropy: {entropy_display}\n\n"
            f"{event['description']}"
        )
        title = "🚨 RANSOMWARE ALERT — Behavioral Defense System"
        # MB_ICONWARNING (0x30) + MB_TOPMOST (0x40000) + MB_SETFOREGROUND (0x10000)
        ctypes.windll.user32.MessageBoxW(0, message, title, 0x30 | 0x40000 | 0x10000)

    threading.Thread(target=_show_popup, daemon=True).start()
    return True


def send_slack_alert(event):
    """Send a CRITICAL security event to Slack via an Incoming Webhook.
    Silently does nothing if no webhook is configured."""
    config = load_alert_config()
    webhook_url = config.get("slack_webhook")

    if not webhook_url:
        return False  # Not configured — this is expected, not an error

    payload = {
        "text": ":rotating_light: RANSOMWARE ALERT",
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🚨 Ransomware Defense Alert"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Event:*\n{event['event_type']}"},
                    {"type": "mrkdwn", "text": f"*File:*\n`{event['filename']}`"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n{event['severity']}"},
                    {"type": "mrkdwn", "text": f"*Time:*\n{event['timestamp']}"},
                    {"type": "mrkdwn", "text": f"*Entropy:*\n{event.get('entropy', 'N/A')}"},
                    {"type": "mrkdwn", "text": f"*Path:*\n`{event['full_path']}`"},
                ]
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Detail:* {event['description']}"}
            }
        ]
    }

    try:
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                print(f"[ALERT] Slack notification sent for {event['filename']}")
                return True
            print(f"[ALERT] Slack webhook returned status {resp.status}")
            return False
    except Exception as e:
        print(f"[ALERT] Slack notification failed: {e}")
        return False
