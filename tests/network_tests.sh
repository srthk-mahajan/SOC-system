#!/bin/bash

echo "SOC Network Attack Simulation"
echo "-----------------------------"

# ----------------------------
# Port Scan
# ----------------------------

echo "[1] Port Scan Test"

nmap -p 1-1000 -T4 localhost

sleep 2

# ----------------------------
# Sensitive Port Enumeration
# ----------------------------

echo "[2] Sensitive Port Access Test"

for i in {1..10}
do
    nc -z localhost 22
    nc -z localhost 3306
    nc -z localhost 3389
done

sleep 2

# ----------------------------
# Traffic Burst
# ----------------------------

echo "[3] Suspicious Connection Rate Test"

for i in {1..200}
do
    nc -z localhost $((RANDOM%65535))
done

echo "Network simulation complete."