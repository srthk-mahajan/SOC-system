import threading
import time
import os   
from alert_manager import get_recent_alerts
from network_monitor import start_network_monitor
from log_monitor import start_log_monitor
from detection_engine import get_stats


def banner():
    print("""
SOC Threat Monitoring System
----------------------------
Monitoring network telemetry and authentication logs
""")


def rules():
    print("""
Detection Rules
---------------
Port Scan > 10 ports → HIGH
Sensitive Port Access → LOW
Sensitive Service Enumeration → MEDIUM
Traffic Burst → HIGH
""")


def dashboard():

    while True:

        stats = get_stats()
        alerts = get_recent_alerts()

        os.system("clear")

        banner()
        rules()

        print("\nSOC Threat Monitor\n------------------\n")

        print(f"Packets analyzed : {stats['packets']}")
        print(f"Alerts triggered : {stats['alerts']}")
        print(f"Suspicious IPs   : {stats['ips']}\n")

        print("Top Offenders")
        print("-------------")

        if stats["top"]:
            for ip, count in stats["top"]:
                print(f"{ip} → {count} alerts")
        else:
            print("None")

        print("\nRecent Alerts")
        print("-------------")

        if alerts:

            for a in alerts[:5]:

                timestamp = a.get("timestamp", "unknown")
                alert_type = a.get("type", "unknown")
                ip = a.get("source_ip", "unknown")
                severity = a.get("severity", "unknown")

                print(
                    f"[{timestamp}] {alert_type} "
                    f"(IP: {ip} | Severity: {severity})"
                )

        else:
            print("No alerts yet")

        time.sleep(2)


def main():

    net_thread = threading.Thread(target=start_network_monitor, daemon=True)
    log_thread = threading.Thread(target=start_log_monitor, daemon=True)

    net_thread.start()
    log_thread.start()

    dashboard()


if __name__ == "__main__":
    main()