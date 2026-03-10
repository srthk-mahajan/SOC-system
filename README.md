# SOC-system

A lightweight **Security Operations Center (SOC) style monitoring prototype** that analyzes **network traffic and Linux authentication logs** to detect suspicious activity such as **port scans and potential SSH brute-force attempts**.

---

# Overview

Modern SOC platforms monitor multiple telemetry sources to detect malicious activity. This project implements a simplified monitoring pipeline that collects:

* **Network telemetry** via packet inspection
* **System authentication logs** from Linux
* **Rule-based threat detection**
* **Security alert logging**

The system continuously monitors activity and generates alerts when suspicious patterns are detected.

---

# Architecture

```
                 +----------------------+
                 |       main.py        |
                 |  System Orchestrator |
                 +----------+-----------+
                            |
        +-------------------+-------------------+
        |                                       |
        v                                       v
+-------------------+               +-------------------+
|  Network Monitor  |               |    Log Monitor    |
|  (Scapy Sniffer)  |               |  Linux auth logs  |
+---------+---------+               +---------+---------+
          |                                   |
          +---------------+-------------------+
                          |
                          v
                +--------------------+
                |  Detection Engine  |
                | Rule-based threat  |
                |      analysis      |
                +----------+---------+
                           |
                           v
                  +----------------+
                  | Alert Manager  |
                  | Generate alert |
                  | & log events   |
                  +--------+-------+
                           |
                           v
                      logs/alerts.log
```

---

# Features

### Network Traffic Monitoring

Captures TCP/IP packets using **Scapy** and analyzes connection behavior.

### Port Scan Detection

Detects suspicious scanning activity when a single source IP attempts connections to multiple ports in a short time window.

### Authentication Log Monitoring

Monitors Linux authentication logs (`/var/log/auth.log`) for suspicious login activity.

### SSH Brute Force Detection

Detects repeated failed SSH login attempts from the same IP address.

### Alert Logging

Detected threats are recorded in a structured alert log for investigation.

---

# Detection Rules

| Rule                      | Description                                                                     |
| ------------------------- | ------------------------------------------------------------------------------- |
| Port Scan Detection       | Detects multiple connection attempts to different ports from the same source IP |
| SSH Brute Force Detection | Detects repeated failed SSH login attempts from a single IP                     |

---

# Example Alert

```
[2026-03-10 14:22:11]

ALERT TYPE: Port Scan
SOURCE IP: 127.0.0.1
SEVERITY: HIGH
```

---

# Project Structure

```
soc-threat-monitor/
│
├── src/
│   ├── main.py
│   ├── network_monitor.py
│   ├── log_monitor.py
│   ├── detection_engine.py
│   └── alert_manager.py
│
├── logs/
│   └── alerts.log
│
├── config/
│   └── config.yaml
│
├── screenshots/
│   ├── system_start.png
│   ├── port_scan_alert.png
│   └── dashboard_output.png
│
├── tests/
│   └── attack_simulation.md
│
├── requirements.txt
├── README.md
└── LICENSE
```

---

# Installation

### Requirements

* Python 3
* Linux (tested on Ubuntu/Kali)
* Root privileges (for packet capture)

Install dependencies:

```
pip install scapy
```

---

# Usage

Run the monitoring system:

```
sudo python main.py
```

The system will start monitoring:

* network traffic
* authentication logs

Detected threats will be displayed in the terminal and recorded in:

```
logs/alerts.log
```

---

# Attack Simulation (Testing)

You can simulate attacks to test the detection system.

### Port Scan Simulation

```
nmap -sS localhost
```

This should trigger a **Port Scan Alert**.

---

### SSH Brute Force Simulation

Attempt multiple failed SSH logins:

```
ssh root@localhost
```

Repeated failed attempts should trigger a **Brute Force Alert**.

---

# Example Output

```
SOC Threat Monitoring System
----------------------------

[+] Packet monitoring started
[+] Authentication log monitoring started
[+] Detection engine initialized

Monitoring activity...

[ALERT] Port scan detected
Source IP: 127.0.0.1
```

---

# Security Concepts Demonstrated

This project demonstrates several core **cybersecurity monitoring concepts**:

* Network packet inspection
* Intrusion detection systems (IDS)
* Security telemetry collection
* Rule-based threat detection
* Security alert logging
* SOC monitoring workflows

---

# Future Improvements

Potential enhancements include:

* Threat intelligence integration
* Web-based monitoring dashboard
* Additional detection rules
* Containerized deployment
* SIEM integration
* AI integration for anomaly detection

---

# Disclaimer

This project is intended for **educational and research purposes only**. It is a simplified prototype designed to demonstrate **security monitoring concepts**, not a production-grade SOC platform.

---

# License

MIT License
