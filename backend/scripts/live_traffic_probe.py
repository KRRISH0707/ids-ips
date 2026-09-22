#!/usr/bin/env python3
"""
Enterprise IDS/IPS Real-Time Live Traffic & Continuous Threat Probe
Continuously generates real network telemetry, benign host heartbeats, and 
adversarial intrusion vectors against the IDS/IPS backend, proving that all
dashboard telemetry, KPI counters, Radar, Kill Chain, and Topology update in real time.
"""

import os
import sys
import time
import json
import random
import urllib.request
import urllib.parse
from datetime import datetime

API_BASE = os.getenv("API_BASE", "http://localhost:8000")
ADMIN_USER = os.getenv("ADMIN_USER", "krrish183224@gmail.com")
ADMIN_PASS = os.getenv("ADMIN_PASS", "183@Krrish")

ATTACK_VECTORS = [
    {
        "name": "External Reconnaissance Sweep",
        "src_ip": "185.220.101.5",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "TCP",
        "signature": "ET SCAN Nmap Scripting Engine SYN Stealth Port Sweep",
        "category": "network",
        "severity": "LOW",
        "risk_score": 38,
        "stage": "Reconnaissance",
    },
    {
        "name": "Apache Log4j JNDI RCE Exploit",
        "src_ip": "194.26.29.112",
        "dst_ip": "10.240.10.12",
        "dst_port": 8080,
        "protocol": "HTTP",
        "signature": "ET EXPLOIT Apache Log4j JNDI RCE Ingress (CVE-2021-44228)",
        "category": "exploitation",
        "severity": "CRITICAL",
        "risk_score": 98,
        "stage": "Exploitation",
    },
    {
        "name": "SQL Injection Auth Bypass",
        "src_ip": "45.33.32.156",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET WEB_SPECIFIC_APPS SQL Injection Union Select (Auth Bypass)",
        "category": "web_api",
        "severity": "HIGH",
        "risk_score": 88,
        "stage": "Exploitation",
    },
    {
        "name": "Active Directory Kerberoasting",
        "src_ip": "10.240.15.44",
        "dst_ip": "10.240.10.4",
        "dst_port": 88,
        "protocol": "Kerberos",
        "signature": "Kerberoasting AD Ticket Request (RC4-HMAC downgrade)",
        "category": "credential",
        "severity": "HIGH",
        "risk_score": 92,
        "stage": "Lateral Pivot",
    },
    {
        "name": "Cobalt Strike HTTPS Beaconing",
        "src_ip": "45.154.255.89",
        "dst_ip": "10.240.15.12",
        "dst_port": 8443,
        "protocol": "TLS",
        "signature": "ET TROJAN Cobalt Strike Malleable C2 HTTPS Beacon",
        "category": "malware",
        "severity": "CRITICAL",
        "risk_score": 96,
        "stage": "C2 Beaconing",
    },
    {
        "name": "Sensitive Database Exfiltration Over DNS Tunnel",
        "src_ip": "10.240.20.88",
        "dst_ip": "198.51.100.42",
        "dst_port": 53,
        "protocol": "DNS",
        "signature": "ET POST_COMPROMISE High-Volume DNS Tunnel Exfiltration",
        "category": "post_compromise",
        "severity": "CRITICAL",
        "risk_score": 97,
        "stage": "Exfiltration",
    },
    {
        "name": "LockBit Ransomware Shadow Copy Deletion",
        "src_ip": "89.248.165.11",
        "dst_ip": "10.240.20.88",
        "dst_port": 445,
        "protocol": "SMB",
        "signature": "Win32.Ransomware.LockBit3.0 Volume Shadow Deletion via vssadmin",
        "category": "malware",
        "severity": "CRITICAL",
        "risk_score": 99,
        "stage": "C2 Beaconing",
    },
]

BENIGN_TELEMETRY = [
    {
        "signature": "Sensor Heartbeat: Edge Bastion Ingress Flow",
        "src_ip": "10.240.10.1",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "TLS",
        "category": "system_telemetry",
        "severity": "LOW",
        "risk_score": 12,
    },
    {
        "signature": "Internal Database Replication Sync Bus",
        "src_ip": "10.240.20.88",
        "dst_ip": "10.240.20.89",
        "dst_port": 5432,
        "protocol": "PostgreSQL",
        "category": "system_telemetry",
        "severity": "LOW",
        "risk_score": 8,
    },
    {
        "signature": "OAuth2 API Token Verification Keep-Alive",
        "src_ip": "10.240.15.10",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "category": "system_telemetry",
        "severity": "LOW",
        "risk_score": 14,
    },
]

def login():
    data = urllib.parse.urlencode({
        "username": ADMIN_USER,
        "password": ADMIN_PASS
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{API_BASE}/api/auth/login",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    with urllib.request.urlopen(req) as resp:
        res = json.loads(resp.read().decode())
        return res["access_token"]

def send_telemetry_event(token, event):
    payload = {
        "src_ip": event["src_ip"],
        "src_port": random.randint(1024, 65535),
        "dst_ip": event["dst_ip"],
        "dst_port": event["dst_port"],
        "protocol": event["protocol"],
        "signature": event["signature"],
        "category": event["category"],
        "severity": event["severity"],
        "risk_score": event["risk_score"],
        "status": "OPEN",
        "raw_event": {
            "source": "live_traffic_probe",
            "timestamp": datetime.utcnow().isoformat(),
            "packet_length": random.randint(64, 1518)
        }
    }
    req = urllib.request.Request(
        f"{API_BASE}/api/alerts",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        }
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())

def main():
    print("=" * 65)
    print("APEX IDS/IPS REAL-TIME TELEMETRY & ATTACK STREAM GENERATOR")
    print(f"Connecting to Backend API: {API_BASE} as {ADMIN_USER}...")
    print("=" * 65)

    try:
        token = login()
        print("[AUTH] Successfully authenticated with backend API.")
    except Exception as e:
        print(f"[AUTH ERROR] Failed to authenticate: {e}")
        sys.exit(1)

    print("\nStarting live real-time event generator.")
    print("Open http://localhost:3000 to watch all live metrics, Radar,")
    print("Kill Chain, and charts update in real time after every event!\n")

    count = 0
    try:
        while True:
            count += 1
            # 70% benign telemetry, 30% realistic attack vector
            is_attack = (random.random() < 0.4) or (count % 3 == 0)
            if is_attack:
                event = random.choice(ATTACK_VECTORS)
                icon = "🔥 [ATTACK]"
            else:
                event = random.choice(BENIGN_TELEMETRY)
                icon = "🟢 [BENIGN]"

            try:
                res = send_telemetry_event(token, event)
                alert = res.get("alert", {})
                mit = res.get("autonomous_mitigation", {})
                blocked = " [IPS QUARANTINED]" if mit.get("prevented") else ""
                print(f"#{count} {icon} {event['severity']} | {event['signature'][:42]}... | {event['src_ip']} -> {event['dst_ip']}{blocked}")
            except urllib.error.HTTPError as he:
                if he.code == 401:
                    token = login()
                print(f"#{count} [WARN] HTTP {he.code}: {he}")
            except Exception as ex:
                print(f"#{count} [ERR] Ingestion error: {ex}")

            # Sleep between 2 to 4 seconds
            time.sleep(random.uniform(2.0, 4.0))

    except KeyboardInterrupt:
        print("\n[STOP] Live traffic probe stopped by user.")

if __name__ == "__main__":
    main()
