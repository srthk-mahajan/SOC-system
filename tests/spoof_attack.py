from scapy.all import IP, TCP, send
import random
import time
import socket


# ----------------------------
# Detect local machine IP
# ----------------------------

def get_local_ip():

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()

    return ip


target = get_local_ip()

print("Detected interface IP:", target)


# ----------------------------
# Fake attacker IP
# ----------------------------

spoof_ip = f"45.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

print("Starting simulated attack from:", spoof_ip)


# ----------------------------
# Phase 1: Port Scan
# ----------------------------

print("\n[Phase 1] Port scanning...")

for port in range(1,120):

    pkt = IP(src=spoof_ip, dst=target)/TCP(dport=port, flags="S")
    send(pkt, verbose=False)

    time.sleep(0.01)


# ----------------------------
# Phase 2: Sensitive Services
# ----------------------------

print("\n[Phase 2] Sensitive service probing...")

for _ in range(10):

    for port in [22, 3306, 3389]:

        pkt = IP(src=spoof_ip, dst=target)/TCP(dport=port, flags="S")
        send(pkt, verbose=False)

        time.sleep(0.02)


# ----------------------------
# Phase 3: Traffic Burst
# ----------------------------

print("\n[Phase 3] Traffic burst...")

for _ in range(300):

    port = random.randint(1, 65535)

    pkt = IP(src=spoof_ip, dst=target)/TCP(dport=port, flags="S")
    send(pkt, verbose=False)

print("\nAttack simulation complete.")