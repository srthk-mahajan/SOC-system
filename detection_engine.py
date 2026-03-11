import time
import ipaddress
import requests
import subprocess
from collections import defaultdict, Counter
from alert_manager import create_alert


# ----------------------------
# Detection Configuration
# ----------------------------

CONFIG = {
    "PORT_SCAN_THRESHOLD": 10,
    "SCAN_TIME_WINDOW": 5,
    "PACKET_RATE_THRESHOLD": 40,
    "SENSITIVE_PORT_THRESHOLD": 5,
    "SSH_WINDOW": 30,
    "SSH_THRESHOLDS": {
        "MEDIUM": 3,
        "HIGH": 6,
        "CRITICAL": 10
    }
}

# ----------------------------
# SOC Statistics
# ----------------------------

packet_counter = 0
alert_counter = 0
suspicious_ips = Counter()

packet_rate = 0
last_rate_time = time.time()

attack_timeline = []

# ----------------------------
# Tracking Structures
# ----------------------------

port_scan_tracker = defaultdict(list)
packet_rate_tracker = defaultdict(list)
sensitive_tracker = defaultdict(int)
ssh_fail_tracker = defaultdict(list)

# Event correlation
attack_patterns = defaultdict(list)
CORRELATION_WINDOW = 60

# Alert cooldown
alert_cooldown = {}
COOLDOWN_TIME = 10

# Sensitive ports
SENSITIVE_PORTS = {22, 3389, 3306}

# Geo cache
geo_cache = {}


# ----------------------------
# GeoIP Enrichment
# ----------------------------

def enrich_ip(ip):

    if ip in geo_cache:
        return geo_cache[ip]

    try:
        addr = ipaddress.ip_address(ip)

        if addr.is_private or addr.is_loopback:
            geo_cache[ip] = "Local/Private"
            return geo_cache[ip]

        try:
            r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=2)
            data = r.json()
            geo_cache[ip] = f"{data.get('city','?')}, {data.get('country','?')}"
        except:
            geo_cache[ip] = "Unknown"

    except:
        geo_cache[ip] = "Unknown"

    return geo_cache[ip]


# ----------------------------
# Automated Response
# ----------------------------

def block_ip(ip):

    if ip.startswith("127."):
        return

    try:
        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        create_alert(
            "IP Automatically Blocked",
            ip,
            "CRITICAL",
            "RESPONSE_ENGINE",
            "Firewall rule applied"
        )

    except:
        pass


# ----------------------------
# Register Alert + Correlation
# ----------------------------

def register_alert(ip):

    now = time.time()

    if ip in alert_cooldown and now - alert_cooldown[ip] < COOLDOWN_TIME:
        return False

    alert_cooldown[ip] = now

    global alert_counter
    alert_counter += 1
    suspicious_ips[ip] += 1

    attack_timeline.append((time.strftime("%H:%M:%S"), ip))

    # Event correlation
    attack_patterns[ip].append(now)

    attack_patterns[ip] = [
        t for t in attack_patterns[ip]
        if now - t < CORRELATION_WINDOW
    ]

    if len(attack_patterns[ip]) >= 3:

        create_alert(
            "Multi-Stage Attack Detected",
            ip,
            "CRITICAL",
            "CORRELATION_ENGINE",
            "Multiple attack indicators detected"
        )

        block_ip(ip)

        attack_patterns[ip].clear()

    return True


# ----------------------------
# Packet Processing
# ----------------------------

def process_packet(src_ip, dst_port, flags):

    global packet_counter, packet_rate

    packet_counter += 1
    packet_rate += 1

    now = time.time()
    location = enrich_ip(src_ip)

    # ----------------------------
    # Port Scan Detection
    # ----------------------------

    port_scan_tracker[src_ip].append((dst_port, now))

    port_scan_tracker[src_ip] = [
        (port, t)
        for port, t in port_scan_tracker[src_ip]
        if now - t < CONFIG["SCAN_TIME_WINDOW"]
    ]

    unique_ports = {p for p, _ in port_scan_tracker[src_ip]}

    if len(unique_ports) >= CONFIG["PORT_SCAN_THRESHOLD"]:

        if register_alert(src_ip):

            create_alert(
                "Port Scan Detected",
                src_ip,
                "HIGH",
                "NETWORK_MONITOR",
                f"{len(unique_ports)} ports scanned in {CONFIG['SCAN_TIME_WINDOW']}s | Geo: {location}"
            )

        port_scan_tracker[src_ip].clear()

    # ----------------------------
    # Sensitive Port Detection
    # ----------------------------

    if dst_port in SENSITIVE_PORTS:

        sensitive_tracker[src_ip] += 1

        if sensitive_tracker[src_ip] == 1:

            create_alert(
                "Sensitive Port Access",
                src_ip,
                "LOW",
                "NETWORK_MONITOR",
                f"Connection to port {dst_port} | Geo: {location}"
            )

        if sensitive_tracker[src_ip] >= CONFIG["SENSITIVE_PORT_THRESHOLD"]:

            if register_alert(src_ip):

                create_alert(
                    "Sensitive Service Enumeration",
                    src_ip,
                    "MEDIUM",
                    "NETWORK_MONITOR",
                    f"Multiple probes on sensitive services | Geo: {location}"
                )

            sensitive_tracker[src_ip] = 0

    # ----------------------------
    # Traffic Burst Detection
    # ----------------------------

    packet_rate_tracker[src_ip].append(now)

    packet_rate_tracker[src_ip] = [
        t for t in packet_rate_tracker[src_ip]
        if now - t < 5
    ]

    if len(packet_rate_tracker[src_ip]) >= CONFIG["PACKET_RATE_THRESHOLD"]:

        if register_alert(src_ip):

            create_alert(
                "Traffic Burst Detected",
                src_ip,
                "HIGH",
                "NETWORK_MONITOR",
                f"{len(packet_rate_tracker[src_ip])} packets in 5s | Geo: {location}"
            )

        packet_rate_tracker[src_ip].clear()


# ----------------------------
# SSH Brute Force Detection
# ----------------------------

def process_ssh_failure(src_ip):

    now = time.time()
    location = enrich_ip(src_ip)

    ssh_fail_tracker[src_ip].append(now)

    ssh_fail_tracker[src_ip] = [
        t for t in ssh_fail_tracker[src_ip]
        if now - t < CONFIG["SSH_WINDOW"]
    ]

    failures = len(ssh_fail_tracker[src_ip])
    thresholds = CONFIG["SSH_THRESHOLDS"]

    severity = None

    if failures >= thresholds["CRITICAL"]:
        severity = "CRITICAL"
    elif failures >= thresholds["HIGH"]:
        severity = "HIGH"
    elif failures >= thresholds["MEDIUM"]:
        severity = "MEDIUM"

    if severity:

        if register_alert(src_ip):

            create_alert(
                "SSH Authentication Failures",
                src_ip,
                severity,
                "AUTH_LOG",
                f"{failures} failures in {CONFIG['SSH_WINDOW']}s | Geo: {location}"
            )


# ----------------------------
# Telemetry Helpers
# ----------------------------

def get_packet_rate():

    global packet_rate, last_rate_time

    now = time.time()
    elapsed = now - last_rate_time

    rate = packet_rate / elapsed if elapsed > 0 else 0

    packet_rate = 0
    last_rate_time = now

    return int(rate)


# ----------------------------
# Dashboard Stats
# ----------------------------

def get_stats():

    top_offenders = suspicious_ips.most_common(3)

    return {
        "packets": packet_counter,
        "alerts": alert_counter,
        "ips": len(suspicious_ips),
        "top": top_offenders,
        "rate": get_packet_rate()
    }