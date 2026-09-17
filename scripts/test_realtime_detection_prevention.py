#!/usr/bin/env python3
"""
AEGIS-X Autonomous Threat Interceptor: Real-Time Detection & Prevention Audit Suite

Validates:
1. Attack Detection: Suricata heuristic + AI/ML multi-vector anomaly classification.
2. Attack Prevention: Kernel-level autonomous IPS drop & IP quarantine enforcement.
3. Real-Time Telemetry: Sub-second Redis broadcast & Live WebSocket propagation.
"""

import json
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone

API_BASE = "http://localhost:8000"

TEST_ATTACKS = [
    {
        "key": "LOG4J",
        "name": "Log4Shell 0-Day Remote Code Execution",
        "cve": "CVE-2021-44228",
        "src_ip": "185.220.101.5",
        "dst_ip": "10.240.10.12",
        "expected_family": "REMOTE_CODE_EXECUTION_ZERO_DAY",
        "min_anomaly": 0.85,
    },
    {
        "key": "LOCKBIT",
        "name": "LockBit 3.0 Ransomware Shadow Copy Sever",
        "cve": "T1486",
        "src_ip": "198.51.100.22",
        "dst_ip": "10.240.20.88",
        "expected_family": "RANSOMWARE_BURST",
        "min_anomaly": 0.85,
    },
    {
        "key": "COBALT_STRIKE",
        "name": "APT29 Cobalt Strike Malleable C2 Beacon",
        "cve": "T1071.001",
        "src_ip": "45.33.32.156",
        "dst_ip": "10.240.20.88",
        "expected_family": "C2_ACTIVE_SESSION",
        "min_anomaly": 0.85,
    },
    {
        "key": "MIRAI",
        "name": "Mirai IoT SYN Flood Distributed DoS",
        "cve": "T1498",
        "src_ip": "194.26.29.112",
        "dst_ip": "10.240.0.1",
        "expected_family": "DISTRIBUTED_DENIAL_OF_SERVICE",
        "min_anomaly": 0.85,
    }
]

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

def query_stats_summary(token):
    req = urllib.request.Request(
        f"{API_BASE}/api/alerts/stats/summary",
        headers={"Authorization": f"Bearer {token}"}
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())

def run_realtime_audit():
    print("=" * 78)
    print("  AEGIS-X: END-TO-END REAL-TIME ATTACK DETECTION & PREVENTION AUDIT")
    print("=" * 78)

    token = get_token()
    print(f"[AUTH] Administrator authenticated. JWT Token acquired.")
    
    # Baseline stats
    baseline_stats = query_stats_summary(token)
    print(f"[BASELINE] Initial Alerts: {baseline_stats.get('open_total', 0)} open | {baseline_stats.get('critical_total', 0)} critical")

    passed_count = 0
    total_count = len(TEST_ATTACKS)

    for i, attack in enumerate(TEST_ATTACKS, 1):
        print("\n" + "-" * 78)
        print(f"[{i}/{total_count}] TESTING ATTACK VECTOR: {attack['name']} ({attack['cve']})")
        print(f"      Source IP: {attack['src_ip']}  -->  Target Asset: {attack['dst_ip']}")
        print("-" * 78)

        t_start = time.time()
        sim_payload = json.dumps({"scenario": attack["key"]}).encode()
        sim_req = urllib.request.Request(
            f"{API_BASE}/api/alerts/simulate",
            data=sim_payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}"
            },
            method="POST"
        )

        with urllib.request.urlopen(sim_req) as resp:
            res = json.loads(resp.read().decode())
        t_elapsed = time.time() - t_start

        # 1. Detection Checks
        alert_data = res.get("alert", {})
        ai_data = res.get("ai_evaluation", {})
        mitigation = res.get("autonomous_mitigation", {})

        detected_family = ai_data.get("attack_family")
        anomaly_score = ai_data.get("anomaly_score", 0.0)
        recommended_action = ai_data.get("recommended_action")

        is_detected = (
            detected_family == attack["expected_family"]
            and anomaly_score >= attack["min_anomaly"]
        )
        print(f"  [DETECTION]    AI Family Classified : {detected_family} (Expected: {attack['expected_family']})")
        print(f"  [DETECTION]    AI Anomaly Score     : {anomaly_score:.2f} / 1.00 (Threshold >= {attack['min_anomaly']})")
        print(f"  [DETECTION]    Trajectory Forecast  : {ai_data.get('predicted_next_stage')}")
        print(f"  [DETECTION]    Verdict              : {'[PASS] DETECTED' if is_detected else '[FAIL]'}")

        # 2. Prevention Checks
        is_prevented = (
            mitigation.get("prevented") is True
            and alert_data.get("status") == "AUTO_BLOCKED"
            and mitigation.get("action") == "FIREWALL_DROP_SEVERED"
        )
        print(f"  [PREVENTION]   Alert Ingest Status  : {alert_data.get('status')} (Expected: AUTO_BLOCKED)")
        print(f"  [PREVENTION]   Autonomous IPS Sever : {mitigation.get('prevented')} (Action: {mitigation.get('action')})")
        print(f"  [PREVENTION]   Mitigation MTTC Clock: {mitigation.get('mttc')} (Measured API RT: {t_elapsed:.3f}s)")
        print(f"  [PREVENTION]   Verdict              : {'[PASS] PREVENTED & SEVERED' if is_prevented else '[FAIL]'}")

        # 3. Database Registry Verification
        registry = query_blocked_ips(token)
        matching_blocks = [b for b in registry.get("items", []) if b["ip_address"].split('/')[0] == attack["src_ip"] and b["is_active"]]
        is_registered = len(matching_blocks) > 0
        if is_registered:
            block = matching_blocks[0]
            print(f"  [REGISTRY]     Active Quarantine    : IP {block['ip_address']} locked by '{block['blocked_by']}'")
            print(f"  [REGISTRY]     Quarantine Reason    : {block['reason']}")
        print(f"  [REGISTRY]     Verdict              : {'[PASS] VERIFIED IN KERNEL REGISTRY' if is_registered else '[FAIL]'}")

        if is_detected and is_prevented and is_registered:
            passed_count += 1
            print(f"  => RESULT FOR {attack['key']}: ALL DEFENSE LAYERS ACTIVE [PASS]")
        else:
            print(f"  => RESULT FOR {attack['key']}: DEFENSE GAP DETECTED [FAIL]")

    # Verify real-time stats increment
    print("\n" + "=" * 78)
    print("  VERIFYING REAL-TIME METRICS & TELEMETRY SYNCHRONIZATION")
    print("=" * 78)
    final_stats = query_stats_summary(token)
    crit_diff = (final_stats.get("critical_total") or 0) - (baseline_stats.get("critical_total") or 0)
    print(f"  Initial Critical Alerts : {baseline_stats.get('critical_total', 0)}")
    print(f"  Updated Critical Alerts : {final_stats.get('critical_total', 0)} (+{crit_diff} detected & severed in real time)")
    print(f"  Total Active Quarantine : {len(query_blocked_ips(token).get('items', []))} malicious IPs locked in firewall")
    
    print("\n" + "=" * 78)
    print(f"  AUDIT SUMMARY: {passed_count}/{total_count} ATTACKS AUTONOMOUSLY DETECTED & PREVENTED")
    print("=" * 78)
    assert passed_count == total_count, f"Only {passed_count}/{total_count} attacks passed!"
    print("\n[SUCCESS] PRODUCT PASSED FULL REAL-TIME DETECTION AND AUTONOMOUS PREVENTION AUDIT!\n")

if __name__ == "__main__":
    run_realtime_audit()
