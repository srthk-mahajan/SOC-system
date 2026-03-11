import os
import json
from datetime import datetime
from collections import deque

LOG_FILE = "logs/alerts.log"

# Store last 10 alerts for dashboard
recent_alerts = deque(maxlen=10)

# Color codes
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
MAGENTA = "\033[95m"
RESET = "\033[0m"


def severity_color(severity):
    if severity == "CRITICAL":
        return MAGENTA
    if severity == "HIGH":
        return RED
    if severity == "MEDIUM":
        return YELLOW
    return GREEN


def create_alert(alert_type, source_ip, severity="MEDIUM", module="SYSTEM", details=""):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    event = {
        "timestamp": timestamp,
        "type": alert_type,
        "source_ip": source_ip,
        "severity": severity,
        "module": module,
        "details": details
    }

    # Store for dashboard
    recent_alerts.appendleft(event)

    # Console output
    message = (
        f"[{timestamp}] "
        f"{alert_type} | "
        f"IP: {source_ip} | "
        f"SEVERITY: {severity} | "
        f"MODULE: {module}"
    )

    if details:
        message += f" | DETAILS: {details}"

    color = severity_color(severity)
    print(color + message + RESET)

    # Ensure log directory exists
    os.makedirs("logs", exist_ok=True)

    # Write structured JSON event
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")


def get_recent_alerts():
    return list(recent_alerts)