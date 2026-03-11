import subprocess
import re
from detection_engine import process_ssh_failure


def extract_ip(line):
    # Match IPv4 OR IPv6
    match = re.search(r'from ([0-9a-fA-F:.]+)', line)
    if match:
        return match.group(1)
    return None


def start_log_monitor():
    print("[+] Authentication log monitoring started")

    process = subprocess.Popen(
    ["journalctl", "-f", "-n", "0", "-u", "ssh"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    for line in process.stdout:
        if "Failed password" in line:
            ip = extract_ip(line)
            if ip:
                if ip == "::1":
                    ip = "127.0.0.1"
                process_ssh_failure(ip)