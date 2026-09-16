#!/usr/bin/env python3
"""
Enterprise IDS/IPS Comprehensive Edge-Case & Finalization Test Suite.

Tests:
1. Security & Authentication boundary conditions (bad pass, non-existent user, SQLi, bad JWT).
2. Input sanitization & protected IP defense (blocking 127.0.0.1, 0.0.0.0, malformed IPs).
3. State machine validation (duplicate IP blocks, invalid incident statuses, 404 handling).
4. AI/ML engine boundary conditions (zero-event state, clean vs malicious IP lookups).
5. SOAR playbook execution & MITRE ATT&CK coverage integrity.
6. Frontend route availability for all 13 client views.
"""

import sys
import json
import urllib.request
import urllib.parse
import urllib.error
import uuid

# Ensure clean UTF-8 console output on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

API_BASE = "http://localhost:8000"
FRONTEND_BASE = "http://localhost:3000"

PASSED = 0
FAILED = 0

def log_test(category: str, name: str, success: bool, detail: str = ""):
    global PASSED, FAILED
    if success:
        PASSED += 1
        print(f"  [PASS] [{category}] {name} {f'({detail})' if detail else ''}")
    else:
        FAILED += 1
        print(f"  [FAIL] [{category}] {name} {f'--> {detail}' if detail else ''}")

def http_request(url: str, method: str = "GET", data: dict = None, headers: dict = None):
    """Utility to make HTTP request and return (status_code, response_dict_or_text)."""
    hdrs = headers.copy() if headers else {}
    body = None
    if data is not None:
        if "Content-Type" in hdrs and hdrs["Content-Type"] == "application/x-www-form-urlencoded":
            body = urllib.parse.urlencode(data).encode()
        else:
            hdrs["Content-Type"] = "application/json"
            body = json.dumps(data).encode()
            
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as res:
            raw = res.read().decode()
            try:
                parsed = json.loads(raw)
            except Exception:
                parsed = raw
            return res.status, parsed
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = raw
        return e.code, parsed
    except Exception as e:
        return 0, str(e)


def run_tests():
    print("=" * 70)
    print(" ENTERPRISE IDS/IPS COMPREHENSIVE EDGE-CASE AUDIT & VALIDATION")
    print("=" * 70)

    # ──────────────────────────────────────────────────────────────────────────
    # 1. AUTHENTICATION & SECURITY EDGE CASES
    # ──────────────────────────────────────────────────────────────────────────
    print("\n[CATEGORY 1: AUTHENTICATION & SECURITY BOUNDARIES]")

    # 1.1 Bad password
    status, res = http_request(
        f"{API_BASE}/api/auth/login",
        method="POST",
        data={"username": "krrish183224@gmail.com", "password": "WRONG_PASSWORD_XYZ"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    log_test("AUTH", "Reject wrong password", status == 401, f"HTTP {status}")

    # 1.2 Non-existent user
    status, res = http_request(
        f"{API_BASE}/api/auth/login",
        method="POST",
        data={"username": "nobody_exists_12345@domain.com", "password": "AnyPassword"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    log_test("AUTH", "Reject non-existent user", status == 401, f"HTTP {status}")

    # 1.3 SQL Injection in Login field
    status, res = http_request(
        f"{API_BASE}/api/auth/login",
        method="POST",
        data={"username": "' OR '1'='1' --", "password": "' OR '1'='1' --"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    log_test("AUTH", "Defend against SQL injection login bypass", status == 401, f"HTTP {status}")

    # 1.4 Unauthenticated access to protected routes
    protected_routes = [
        "/api/alerts",
        "/api/incidents",
        "/api/sensors",
        "/api/rules",
        "/api/ips-actions",
        "/api/soar/playbooks",
        "/api/mitre/matrix",
        "/api/network/topology"
    ]
    unauth_all_401 = True
    for route in protected_routes:
        st, _ = http_request(f"{API_BASE}{route}", method="GET")
        if st != 401:
            unauth_all_401 = False
            break
    log_test("AUTH", "Protected routes require valid Bearer token", unauth_all_401, f"Tested {len(protected_routes)} endpoints")

    # 1.5 Malformed / Tampered JWT Token
    st, _ = http_request(
        f"{API_BASE}/api/alerts",
        method="GET",
        headers={"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.INVALID_TAMPERED.SIGNATURE"}
    )
    log_test("AUTH", "Reject tampered JWT token", st == 401, f"HTTP {st}")

    # Obtain valid admin token for subsequent tests
    status, res = http_request(
        f"{API_BASE}/api/auth/login",
        method="POST",
        data={"username": "krrish183224@gmail.com", "password": "183@Krrish"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    if status != 200 or "access_token" not in res:
        print("  \033[91mFATAL: Failed to obtain admin token for testing!\033[0m")
        return
    token = res["access_token"]
    auth_headers = {"Authorization": f"Bearer {token}"}
    log_test("AUTH", "Admin login & valid JWT issuance", True, "Bearer token active")


    # ──────────────────────────────────────────────────────────────────────────
    # 2. DATA VALIDATION & PROTECTED IP SAFEGUARDS
    # ──────────────────────────────────────────────────────────────────────────
    print("\n[CATEGORY 2: DATA VALIDATION & PROTECTED IP SAFEGUARDS]")

    # 2.1 Malformed IP string blocking
    st, res = http_request(
        f"{API_BASE}/api/ips-actions",
        method="POST",
        data={"ip_address": "999.999.999.999", "reason": "Test malformed"},
        headers=auth_headers
    )
    log_test("IPS", "Reject malformed IP address '999.999.999.999'", st in [400, 422], f"HTTP {st}")

    st, res = http_request(
        f"{API_BASE}/api/ips-actions",
        method="POST",
        data={"ip_address": "not_an_ip_string", "reason": "Test string"},
        headers=auth_headers
    )
    log_test("IPS", "Reject non-IP string 'not_an_ip_string'", st in [400, 422], f"HTTP {st}")

    # 2.2 Protect loopback / local system IP from self-lockout
    st, res = http_request(
        f"{API_BASE}/api/ips-actions",
        method="POST",
        data={"ip_address": "127.0.0.1", "reason": "Accidental loopback block"},
        headers=auth_headers
    )
    log_test("IPS", "Safeguard loopback IP '127.0.0.1' from self-lockout", st == 400, f"HTTP {st} - Protected")

    st, res = http_request(
        f"{API_BASE}/api/ips-actions",
        method="POST",
        data={"ip_address": "0.0.0.0", "reason": "Accidental wildcard block"},
        headers=auth_headers
    )
    log_test("IPS", "Safeguard unspecified IP '0.0.0.0' from blocking", st == 400, f"HTTP {st} - Protected")

    # 2.3 Idempotency & Duplicate IP handling
    test_attacker_ip = f"198.51.100.{uuid.uuid4().int % 200 + 10}"
    st1, block_res1 = http_request(
        f"{API_BASE}/api/ips-actions",
        method="POST",
        data={"ip_address": test_attacker_ip, "reason": "Edge case test block"},
        headers=auth_headers
    )
    log_test("IPS", f"Block valid external attacker IP ({test_attacker_ip})", st1 == 201, f"HTTP {st1}")

    st2, block_res2 = http_request(
        f"{API_BASE}/api/ips-actions",
        method="POST",
        data={"ip_address": test_attacker_ip, "reason": "Duplicate block attempt"},
        headers=auth_headers
    )
    log_test("IPS", "Handle duplicate IP block with 409 Conflict", st2 == 409, f"HTTP {st2}")

    # Clean up test block
    if st1 == 201 and "id" in block_res1:
        st_del, _ = http_request(
            f"{API_BASE}/api/ips-actions/{block_res1['id']}",
            method="DELETE",
            data={"reason": "Edge case cleanup"},
            headers=auth_headers
        )
        log_test("IPS", "Unblock and restore IP successfully", st_del == 200, f"HTTP {st_del}")

    # 2.4 Unblock non-existent block ID
    fake_uuid = str(uuid.uuid4())
    st, _ = http_request(
        f"{API_BASE}/api/ips-actions/{fake_uuid}",
        method="DELETE",
        data={"reason": "Delete non-existent"},
        headers=auth_headers
    )
    log_test("IPS", "Handle unblock on non-existent UUID cleanly (404)", st == 404, f"HTTP {st}")


    # ──────────────────────────────────────────────────────────────────────────
    # 3. STATE MACHINE VALIDATION & 404 HANDLING
    # ──────────────────────────────────────────────────────────────────────────
    print("\n[CATEGORY 3: STATE MACHINE & LIFECYCLE TRANSITIONS]")

    # 3.1 Create test incident
    st, inc = http_request(
        f"{API_BASE}/api/incidents",
        method="POST",
        data={"title": "Edge Case Test Incident", "description": "Testing lifecycle transitions", "severity": "HIGH"},
        headers=auth_headers
    )
    log_test("INCIDENT", "Create incident record", st == 201, f"HTTP {st}")

    if st == 201 and "id" in inc:
        inc_id = inc["id"]
        # 3.2 Update to valid status
        st_up, _ = http_request(
            f"{API_BASE}/api/incidents/{inc_id}/status",
            method="PATCH",
            data={"status": "INVESTIGATING"},
            headers=auth_headers
        )
        log_test("INCIDENT", "Transition status to INVESTIGATING", st_up == 200, f"HTTP {st_up}")

        # 3.3 Reject invalid status string
        st_bad, _ = http_request(
            f"{API_BASE}/api/incidents/{inc_id}/status",
            method="PATCH",
            data={"status": "INVALID_UNKNOWN_STATUS"},
            headers=auth_headers
        )
        log_test("INCIDENT", "Reject invalid status 'INVALID_UNKNOWN_STATUS'", st_bad in [400, 422], f"HTTP {st_bad}")

        # 3.4 Resolve incident
        st_res, _ = http_request(
            f"{API_BASE}/api/incidents/{inc_id}/status",
            method="PATCH",
            data={"status": "RESOLVED"},
            headers=auth_headers
        )
        log_test("INCIDENT", "Transition status to RESOLVED", st_res == 200, f"HTTP {st_res}")

    # 3.5 Look up non-existent incident
    st, _ = http_request(f"{API_BASE}/api/incidents/{fake_uuid}", method="GET", headers=auth_headers)
    log_test("INCIDENT", "Look up non-existent incident returns 404", st == 404, f"HTTP {st}")

    # 3.6 Look up packet trace for non-existent alert
    st, _ = http_request(f"{API_BASE}/api/alerts/{fake_uuid}/packet-trace", method="GET", headers=auth_headers)
    log_test("DPI", "Packet trace for non-existent alert returns 404", st == 404, f"HTTP {st}")

    # 3.7 Execute non-existent playbook
    st, _ = http_request(
        f"{API_BASE}/api/soar/playbooks/{fake_uuid}/execute",
        method="POST",
        data={"target": "10.0.0.5"},
        headers=auth_headers
    )
    log_test("SOAR", "Execute non-existent playbook returns 404", st == 404, f"HTTP {st}")


    # ──────────────────────────────────────────────────────────────────────────
    # 4. AI/ML ENGINE & THREAT INTELLIGENCE EDGE CASES
    # ──────────────────────────────────────────────────────────────────────────
    print("\n[CATEGORY 4: AI/ML ENGINE & THREAT INTELLIGENCE EDGE CASES]")

    # 4.1 AI Forecast API
    st, forecast = http_request(f"{API_BASE}/api/ai/forecast", method="GET", headers=auth_headers)
    log_test("AI", "Query AI Threat Forecast", st == 200 and "global_ai_threat_level" in forecast, f"Threat Level: {forecast.get('global_ai_threat_level', 'N/A')}")

    # 4.2 AI Predict with empty/minimal telemetry
    st, pred_empty = http_request(
        f"{API_BASE}/api/ai/predict",
        method="POST",
        data={"src_ip": "10.0.0.5", "dst_ip": "10.0.0.1", "signature": "", "risk_score": 0},
        headers=auth_headers
    )
    log_test("AI", "AI evaluation on minimal telemetry (no crash)", st == 200 and "anomaly_score" in pred_empty, f"Anomaly score: {pred_empty.get('anomaly_score')}")

    # 4.3 AI Predict on active Ransomware telemetry
    st, pred_ransom = http_request(
        f"{API_BASE}/api/ai/predict",
        method="POST",
        data={
            "src_ip": "192.168.1.188",
            "dst_ip": "192.168.1.10",
            "signature": "Win.Ransomware.Locky Encrypt Vssadmin Shadowcopy deletion detected",
            "risk_score": 95,
            "category": "ransomware",
            "raw_event": {"packet_entropy": 7.2, "failed_attempts": 20}
        },
        headers=auth_headers
    )
    is_ransom_isolated = (
        st == 200 and
        pred_ransom.get("recommended_action") == "ISOLATE_HOST" and
        pred_ransom.get("auto_isolation_required") is True
    )
    log_test("AI", "AI detects Ransomware and demands IMMEDIATE Host Isolation", is_ransom_isolated, f"Action: {pred_ransom.get('recommended_action')}")

    # 4.4 Threat Intel Clean IP Lookup
    st, ti_clean = http_request(
        f"{API_BASE}/api/threat-intel/lookup",
        method="POST",
        data={"value": "8.8.8.8"},
        headers=auth_headers
    )
    log_test("INTEL", "Clean IP lookup ('8.8.8.8') returns NOT_FLAGGED", st == 200 and ti_clean.get("status") == "NOT_FLAGGED", f"Status: {ti_clean.get('status')}")

    # 4.5 Threat Intel Malicious IOC Lookup
    st, ti_mal = http_request(
        f"{API_BASE}/api/threat-intel/lookup",
        method="POST",
        data={"value": "45.33.32.156"},
        headers=auth_headers
    )
    log_test("INTEL", "Known Malicious IOC ('45.33.32.156') returns IDENTIFIED_THREAT", st == 200 and ti_mal.get("status") == "IDENTIFIED_THREAT", f"Reputation: {ti_mal.get('reputation_score')}%")


    # ──────────────────────────────────────────────────────────────────────────
    # 5. INTEGRITY OF MITRE & TOPOLOGY ENGINES
    # ──────────────────────────────────────────────────────────────────────────
    print("\n[CATEGORY 5: MITRE ATT&CK & NETWORK TOPOLOGY INTEGRITY]")

    # 5.1 MITRE ATT&CK Matrix integrity
    st, mitre = http_request(f"{API_BASE}/api/mitre/matrix", method="GET", headers=auth_headers)
    tactic_count = len(mitre.get("tactics", []))
    log_test("MITRE", "Full MITRE ATT&CK Enterprise Matrix loaded", st == 200 and tactic_count >= 10, f"{tactic_count} tactics active")

    # 5.2 Network Topology Graph integrity
    st, topo = http_request(f"{API_BASE}/api/network/topology", method="GET", headers=auth_headers)
    nodes_count = len(topo.get("nodes", []))
    edges_count = len(topo.get("edges", []))
    has_gateway = any(n.get("type") == "GATEWAY" for n in topo.get("nodes", []))
    log_test("TOPOLOGY", "Network Topology graph generated with Gateway hub", st == 200 and has_gateway, f"{nodes_count} nodes, {edges_count} edges")


    # ──────────────────────────────────────────────────────────────────────────
    # 6. FRONTEND PAGES AVAILABILITY (ALL CLIENT VIEWS)
    # ──────────────────────────────────────────────────────────────────────────
    print("\n[CATEGORY 6: FRONTEND ROUTE AVAILABILITY (ALL 13 PAGES)]")
    frontend_routes = [
        ("/", "Executive SOC Dashboard"),
        ("/landing", "Commercial Product Portal & Showcase"),
        ("/login", "Authentication Gateway"),
        ("/alerts", "Alerts & DPI Dissector"),
        ("/incidents", "Incident Response Center"),
        ("/sensors", "Distributed Sensor Fleet"),
        ("/rules", "Suricata / Snort Rule Manager"),
        ("/ips-actions", "Active IPS Quarantine Blocks"),
        ("/topology", "Interactive Network Topology"),
        ("/playbooks", "SOAR Automated Playbooks"),
        ("/mitre", "MITRE ATT&CK Matrix"),
        ("/threat-intel", "Threat Intelligence Hub"),
        ("/audit-logs", "Compliance Audit Logs")
    ]

    for route, label in frontend_routes:
        st, _ = http_request(f"{FRONTEND_BASE}{route}", method="GET")
        log_test("UI", f"{label} ({route})", st == 200, f"HTTP {st}")

    # ──────────────────────────────────────────────────────────────────────────
    # FINAL AUDIT SUMMARY
    # ──────────────────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print(f" AUDIT COMPLETE: \033[92m{PASSED} PASSED\033[0m | \033[91m{FAILED} FAILED\033[0m")
    print("=" * 70)

    if FAILED > 0:
        print("\n\033[91m[WARNING] Some edge cases failed! Review failures above.\033[0m")
        sys.exit(1)
    else:
        print("\n\033[92m[SUCCESS] PRODUCT FULLY FINALIZED & PASSED ALL EDGE-CASE AUDITS!\033[0m\n")
        sys.exit(0)

if __name__ == "__main__":
    run_tests()
