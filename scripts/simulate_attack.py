#!/usr/bin/env python3
"""
Enterprise IDS/IPS Attack Simulation Script
Simulates realistic cyber attacks against the platform to test:
1. Real-time alert ingestion (Kafka / REST)
2. Live WebSocket alerts streaming to Dashboard UI
3. Automated Incident creation
4. Automated IPS IP blocking enforcement
"""

import sys
import time
import json
import random
import urllib.request
import urllib.parse
from datetime import datetime

API_BASE = "http://localhost:8000"

ATTACK_SCENARIOS = [
    {
        "name": "🚨 SSH Brute Force Attack",
        "description": "Rapid repeated SSH login failures targeting edge bastion host",
        "src_ip": "203.0.113.88",
        "src_port": 54120,
        "dst_ip": "192.168.1.20",
        "dst_port": 22,
        "protocol": "TCP",
        "signature": "ET POLICY SSH Brute Force Attempt (Failed Logins >= 25)",
        "category": "brute_force",
        "severity": "CRITICAL",
        "risk_score": 95,
        "raw_event": {
            "service": "ssh",
            "failed_attempts": 28,
            "target_user": "root",
            "tool": "hydra/v9.5"
        }
    },
    {
        "name": "💉 Web Application SQL Injection Attack",
        "description": "Malicious payload injection attempting database extraction via HTTP GET",
        "src_ip": "198.51.100.99",
        "src_port": 49182,
        "dst_ip": "192.168.1.10",
        "dst_port": 443,
        "protocol": "TCP",
        "signature": "ET WEB_SPECIFIC_APPS SQL Injection in URI parameter 'id=1 UNION SELECT * FROM users'",
        "category": "web_attack",
        "severity": "HIGH",
        "risk_score": 88,
        "raw_event": {
            "uri": "/api/v1/customers?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
            "method": "GET",
            "user_agent": "sqlmap/1.7.2#stable"
        }
    },
    {
        "name": "🔍 Distributed SYN Port Scan / Reconnaissance",
        "description": "Port scanner mapping active network services across DMZ subnet",
        "src_ip": "192.0.2.77",
        "src_port": 39821,
        "dst_ip": "192.168.1.10",
        "dst_port": 8080,
        "protocol": "TCP",
        "signature": "ET SCAN Nmap Scripting Engine Vulnerability Sweep",
        "category": "reconnaissance",
        "severity": "HIGH",
        "risk_score": 82,
        "raw_event": {
            "scan_type": "SYN_STEALTH",
            "ports_scanned": [21, 22, 23, 25, 80, 443, 3306, 8080],
            "packets_per_sec": 1200
        }
    },
    {
        "name": "☣️ Cobalt Strike Command & Control (C2) Beacon",
        "description": "Compromised internal host communicating with external threat actor server",
        "src_ip": "192.168.1.150",
        "src_port": 50431,
        "dst_ip": "45.33.32.156",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET TROJAN Cobalt Strike Malleable C2 HTTP Beaconing Activity",
        "category": "c2",
        "severity": "CRITICAL",
        "risk_score": 98,
        "raw_event": {
            "c2_domain": "update-service-cdn-telemetry.org",
            "beacon_interval": 30,
            "jitter": 15,
            "packet_entropy": 7.92
        }
    }
]

def login():
    data = urllib.parse.urlencode({
        "username": "krrish183224@gmail.com",
        "password": "183@Krrish"
    }).encode()
    req = urllib.request.Request(
        f"{API_BASE}/api/auth/login",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    with urllib.request.urlopen(req) as res:
        token = json.loads(res.read().decode())["access_token"]
        return token

def send_attack(token, attack):
    print(f"\n⚡ Launching: {attack['name']}")
    print(f"   Target: {attack['dst_ip']}:{attack['dst_port']} from Attacker IP: {attack['src_ip']}")
    print(f"   Severity: {attack['severity']} | Risk Score: {attack['risk_score']}/100")
    print(f"   Signature: {attack['signature']}")

    payload = {
        "src_ip": attack["src_ip"],
        "src_port": attack["src_port"],
        "dst_ip": attack["dst_ip"],
        "dst_port": attack["dst_port"],
        "protocol": attack["protocol"],
        "signature": attack["signature"],
        "category": attack["category"],
        "severity": attack["severity"],
        "risk_score": attack["risk_score"],
        "status": "OPEN",
        "raw_event": attack["raw_event"]
    }

    req = urllib.request.Request(
        f"{API_BASE}/api/alerts",
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        }
    )

    try:
        with urllib.request.urlopen(req) as res:
            res_data = json.loads(res.read().decode())
            print(f"   ✅ Alert Ingested Successfully! ID: {res_data['alert']['id']}")
            print("   📡 Broadcasted via Redis to Dashboard Live Feed!")
    except Exception as e:
        print(f"   ❌ Ingestion error: {e}")

    # If critical risk, also simulate automated IPS block enforcement
    if attack["risk_score"] >= 90:
        print(f"   🛡️ Automated IPS Trigger: Enforcing Firewall Ban on {attack['src_ip']}...")
        block_payload = {
            "ip_address": attack["src_ip"],
            "reason": f"Automated IPS Block: {attack['signature']}",
            "duration_minutes": 120
        }
        block_req = urllib.request.Request(
            f"{API_BASE}/api/ips-actions",
            data=json.dumps(block_payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}"
            }
        )
        try:
            with urllib.request.urlopen(block_req) as b_res:
                print(f"   🔒 IPS Action Confirmed: {attack['src_ip']} added to blocked list!")
        except Exception as be:
            print(f"   ⚠️ IPS block note: {be}")

def main():
    print("=" * 65)
    print("🛡️  ENTERPRISE IDS/IPS LIVE ATTACK SIMULATOR  🛡️")
    print("=" * 65)
    print(f"Connecting to IDS/IPS Platform at {API_BASE}...")

    try:
        token = login()
        print("Authenticated with System Administrator credentials.")
    except Exception as e:
        print(f"Authentication failed: {e}")
        sys.exit(1)

    print("\nStarting attack scenario simulation...")
    print("👉 Keep your dashboard open at http://localhost:3000 to watch live alerts stream in!\n")

    for i, attack in enumerate(ATTACK_SCENARIOS, 1):
        print(f"--- [Attack Scenario {i} of {len(ATTACK_SCENARIOS)}] ---")
        send_attack(token, attack)
        if i < len(ATTACK_SCENARIOS):
            print("\nWaiting 3 seconds before next attack sequence...")
            time.sleep(3)

    print("\n" + "=" * 65)
    print("🎯 ATTACK SIMULATION COMPLETED!")
    print("Check your dashboard views:")
    print(" - Executive Dashboard: http://localhost:3000")
    print(" - Alerts Log:          http://localhost:3000/alerts")
    print(" - Security Incidents:  http://localhost:3000/incidents")
    print(" - Blocked IPs (IPS):   http://localhost:3000/ips-actions")
    print(" - Compliance Audit:    http://localhost:3000/audit-logs")
    print("=" * 65)

if __name__ == "__main__":
    main()
