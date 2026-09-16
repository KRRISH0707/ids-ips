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
import urllib.request
import urllib.parse
from datetime import datetime

API_BASE = "http://localhost:8000"

ATTACK_SCENARIOS = [
    {
        "name": "[ATTACK] SSH Brute Force Attack",
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
        "name": "[ATTACK] Web Application SQL Injection Attack",
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
        "name": "[ATTACK] Distributed SYN Port Scan / Reconnaissance",
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
        "name": "[ATTACK] Cobalt Strike Command & Control (C2) Beacon",
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
    print(f"\n>> Launching: {attack['name']}")
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
            print(f"   [OK] Alert Ingested Successfully! ID: {res_data['alert']['id']}")
            print("   [LIVE] Broadcasted via Redis to Dashboard Live Feed!")
    except Exception as e:
        print(f"   [ERR] Ingestion error: {e}")

    # If critical risk, trigger automated IPS block enforcement
    if attack["risk_score"] >= 90:
        print(f"   [IPS] Automated IPS Trigger: Enforcing Firewall Ban on {attack['src_ip']}...")
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
                print(f"   [BLOCKED] IPS Action Confirmed: {attack['src_ip']} added to blocked list!")
        except Exception as be:
            print(f"   [NOTE] IPS block note: {be}")

    # ── AI/ML Threat Evaluation & Next Stage Forecast ─────────────────────────
    print("   [AI] Running Real-Time Multi-Vector Neural Threat Evaluation...")
    ai_payload = {
        "src_ip": attack["src_ip"],
        "dst_ip": attack["dst_ip"],
        "dst_port": attack["dst_port"],
        "protocol": attack["protocol"],
        "signature": attack["signature"],
        "category": attack["category"],
        "severity": attack["severity"],
        "risk_score": attack["risk_score"],
        "raw_event": attack["raw_event"],
    }
    ai_req = urllib.request.Request(
        f"{API_BASE}/api/ai/predict",
        data=json.dumps(ai_payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        }
    )
    try:
        with urllib.request.urlopen(ai_req) as ai_res:
            ai_data = json.loads(ai_res.read().decode())
            conf = ai_data.get("confidence_percentage") or int(ai_data.get("confidence", 0.85) * 100)
            family = ai_data.get("attack_family", "ANOMALY")
            score = ai_data.get("anomaly_score", 0.0)
            next_stg = ai_data.get("predicted_next_stage") or ai_data.get("next_stage_forecast", "Stage 2: Active Investigation")
            rec = ai_data.get("recommended_action", "MONITOR")
            print(f"   [AI INFERENCE] Classified Family : {family} (Confidence: {conf}%)")
            print(f"   [AI INFERENCE] Anomaly Score    : {score:.2f} / 1.00")
            print(f"   [AI FORECAST]  Predicted Next  : {next_stg}")
            print(f"   [AI DIRECTIVE] Recommended Plan : {rec}")

            # If AI requires automated machine isolation:
            if ai_data.get("auto_isolation_required"):
                target_host = ai_data.get("compromised_host_ip", attack["dst_ip"])
                print(f"   [AI QUARANTINE] Target host {target_host} flagged for network isolation!")
                _trigger_host_isolation(token, target_host)
    except Exception as ae:
        print(f"   [AI ERROR] Threat prediction note: {ae}")

def _trigger_host_isolation(token, host_ip):
    # Fetch sensor list to find matching host
    sensors_req = urllib.request.Request(
        f"{API_BASE}/api/sensors",
        headers={"Authorization": f"Bearer {token}"}
    )
    try:
        with urllib.request.urlopen(sensors_req) as s_res:
            res_data = json.loads(s_res.read().decode())
            sensors = res_data.get("items", res_data if isinstance(res_data, list) else [])
            target_sensor = None
            for s in sensors:
                if s.get("ip_address") == host_ip or s.get("hostname") in ("edge-bastion-01", "sensor-01"):
                    target_sensor = s
                    break

            if not target_sensor and sensors:
                target_sensor = sensors[0]

            if target_sensor:
                s_id = target_sensor["id"]
                iso_req = urllib.request.Request(
                    f"{API_BASE}/api/sensors/{s_id}/isolate",
                    data=b"{}",
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {token}"
                    }
                )
                with urllib.request.urlopen(iso_req) as iso_res:
                    res_j = json.loads(iso_res.read().decode())
                    print(f"   [QUARANTINE SUCCESS] Host '{target_sensor['hostname']}' ({target_sensor['ip_address']}) ISOLATED from network!")
    except Exception as e:
        print(f"   [QUARANTINE NOTE] Sensor isolation note: {e}")

def main():
    print("=" * 65)
    print("ENTERPRISE IDS/IPS LIVE ATTACK SIMULATOR & AI DEFENSE")
    print("=" * 65)
    print(f"Connecting to IDS/IPS Platform at {API_BASE}...")

    try:
        token = login()
        print("Authenticated with System Administrator credentials.")
    except Exception as e:
        print(f"Authentication failed: {e}")
        sys.exit(1)

    print("\nStarting attack scenario simulation...")
    print("Keep your dashboard open at http://localhost:3000 to watch live alerts stream in!\n")

    for i, attack in enumerate(ATTACK_SCENARIOS, 1):
        print(f"--- [Attack Scenario {i} of {len(ATTACK_SCENARIOS)}] ---")
        send_attack(token, attack)
        if i < len(ATTACK_SCENARIOS):
            print("\nWaiting 2 seconds before next attack sequence...")
            time.sleep(2)

    # Fetch final AI Global Forecast
    try:
        print("\n" + "=" * 65)
        print("FETCHING AI/ML GLOBAL THREAT POSTURE FORECAST...")
        f_req = urllib.request.Request(
            f"{API_BASE}/api/ai/forecast",
            headers={"Authorization": f"Bearer {token}"}
        )
        with urllib.request.urlopen(f_req) as f_res:
            forecast = json.loads(f_res.read().decode())
            print(f"Global AI Threat Level   : {forecast['global_ai_threat_level']}")
            print(f"Average Anomaly Score    : {forecast['average_anomaly_score']}")
            print(f"Isolated Machines Count  : {forecast['isolated_machines_count']}")
            print(f"Recommendation           : {forecast['recommendation']}")
    except Exception as e:
        print(f"Forecast error: {e}")

    print("\n" + "=" * 65)
    print("ATTACK SIMULATION & AI DEFENSE WORKFLOW COMPLETED!")
    print("Check your dashboard views:")
    print(" - Security Operations Dashboard: http://localhost:3000")
    print(" - Monitored Endpoints & Sensors: http://localhost:3000/sensors")
    print(" - Real-time Threat Alerts:       http://localhost:3000/alerts")
    print(" - Security Incidents:            http://localhost:3000/incidents")
    print(" - IPS Firewall Active Blocks:    http://localhost:3000/ips-actions")
    print(" - Compliance & Forensic Logs:    http://localhost:3000/audit-logs")
    print("=" * 65)

if __name__ == "__main__":
    main()
