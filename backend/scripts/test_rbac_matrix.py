#!/usr/bin/env python3
"""
Enterprise IDS/IPS Role-Based Access Control (RBAC) Matrix Verification.

Validates the exact two-layer authorization matrix:
Role       Dashboard  Alerts  Incidents      IPS Controls  Users
Admin         ✅         ✅       ✅             ✅           ✅
Analyst       ✅         ✅       ✅             ✅           ❌
Viewer        ✅         ✅       👁️ (Read-only) ❌           ❌
"""

import sys
import json
import urllib.request
import urllib.parse
import urllib.error

# Ensure clean UTF-8 console output on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

API_BASE = "http://localhost:8000"

PASSED = 0
FAILED = 0

def log_test(role: str, action: str, success: bool, detail: str = ""):
    global PASSED, FAILED
    status_str = "[PASS]" if success else "[FAIL]"
    if success:
        PASSED += 1
    else:
        FAILED += 1
    print(f"  {status_str} [{role.upper():7s}] {action} {f'({detail})' if detail else ''}")

def login(email: str, password: str) -> str:
    data = urllib.parse.urlencode({"username": email, "password": password}).encode()
    req = urllib.request.Request(
        f"{API_BASE}/api/auth/login",
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as res:
            body = json.loads(res.read().decode())
            return body["access_token"]
    except Exception as e:
        print(f"Failed to log in as {email}: {e}")
        return ""

def api_call(path: str, token: str, method: str = "GET", data: dict = None):
    headers = {"Authorization": f"Bearer {token}"}
    body = None
    if data is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(data).encode()
    req = urllib.request.Request(f"{API_BASE}/api{path}", data=body, headers=headers, method=method)
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

def main():
    print("=" * 70)
    print(" ENTERPRISE IDS/IPS RBAC PERMISSIONS MATRIX AUDIT")
    print("=" * 70)

    # 1. Authenticate all 3 roles
    print("\n[PHASE 1: AUTHENTICATION & JWT ISSUANCE]")
    admin_token = login("krrish183224@gmail.com", "183@Krrish")
    log_test("ADMIN", "Authenticate & acquire JWT", bool(admin_token), "Role: ADMIN")

    analyst_token = login("analyst@ids-soc.com", "Analyst123!")
    log_test("ANALYST", "Authenticate & acquire JWT", bool(analyst_token), "Role: ANALYST")

    viewer_token = login("viewer@ids-soc.com", "Viewer123!")
    log_test("VIEWER", "Authenticate & acquire JWT", bool(viewer_token), "Role: VIEWER")

    tokens = {
        "ADMIN": admin_token,
        "ANALYST": analyst_token,
        "VIEWER": viewer_token,
    }

    # 2. Test Dashboard & Telemetry (All roles: ✅)
    print("\n[PHASE 2: DASHBOARD & TELEMETRY ACCESS (Admin: ✅ | Analyst: ✅ | Viewer: ✅)]")
    for role, tok in tokens.items():
        st, _ = api_call("/alerts/stats/summary", tok)
        log_test(role, "Access SOC Alerts Telemetry Summary", st == 200, f"HTTP {st}")
        st, _ = api_call("/incidents/stats/summary", tok)
        log_test(role, "Access Security Incidents Telemetry Summary", st == 200, f"HTTP {st}")
        st, _ = api_call("/ai/forecast", tok)
        log_test(role, "Access AI Threat Forecast & Insights", st == 200, f"HTTP {st}")

    # 3. Test Alerts & DPI Ingestion (All roles: ✅)
    print("\n[PHASE 3: ALERTS & PACKET TRACES (Admin: ✅ | Analyst: ✅ | Viewer: ✅)]")
    for role, tok in tokens.items():
        st, _ = api_call("/alerts?limit=5", tok)
        log_test(role, "List Ingested Security Alerts", st == 200, f"HTTP {st}")

    # 4. Test Incidents (Admin: ✅ | Analyst: ✅ | Viewer: 👁️ Read-only)
    print("\n[PHASE 4: INCIDENTS MANAGEMENT (Admin: ✅ | Analyst: ✅ | Viewer: 👁️ Read-Only)]")
    # All roles can list/read incidents
    for role, tok in tokens.items():
        st, _ = api_call("/incidents?limit=5", tok)
        log_test(role, "Read Security Incidents (👁️)", st == 200, f"HTTP {st}")

    # Admin creates incident -> 201 Created
    st, inc_admin = api_call("/incidents", tokens["ADMIN"], "POST", {
        "title": "RBAC Test Incident (Admin Created)",
        "description": "Created by Admin to verify RBAC matrix",
        "severity": "MEDIUM",
        "risk_score": 50
    })
    log_test("ADMIN", "Create Security Incident Record (✅)", st == 201, f"HTTP {st}")
    inc_id = inc_admin.get("id") if isinstance(inc_admin, dict) else None

    # Analyst creates incident -> 201 Created
    st, _ = api_call("/incidents", tokens["ANALYST"], "POST", {
        "title": "RBAC Test Incident (Analyst Created)",
        "description": "Created by Analyst to verify RBAC matrix",
        "severity": "LOW",
        "risk_score": 25
    })
    log_test("ANALYST", "Create Security Incident Record (✅)", st == 201, f"HTTP {st}")

    # Viewer attempts to create incident -> 403 Forbidden!
    st, _ = api_call("/incidents", tokens["VIEWER"], "POST", {
        "title": "Unauthorized Incident Creation",
        "description": "Viewer should be blocked",
        "severity": "CRITICAL",
        "risk_score": 99
    })
    log_test("VIEWER", "Block Incident Creation (❌ Restricted)", st == 403, f"HTTP {st} Forbidden")

    if inc_id:
        # Admin updates status -> 200 OK
        st, _ = api_call(f"/incidents/{inc_id}/status", tokens["ADMIN"], "PATCH", {"status": "INVESTIGATING"})
        log_test("ADMIN", "Update Incident Lifecycle Status (✅)", st == 200, f"HTTP {st}")

        # Analyst updates status -> 200 OK
        st, _ = api_call(f"/incidents/{inc_id}/status", tokens["ANALYST"], "PATCH", {"status": "CONTAINED"})
        log_test("ANALYST", "Update Incident Lifecycle Status (✅)", st == 200, f"HTTP {st}")

        # Viewer attempts status update -> 403 Forbidden!
        st, _ = api_call(f"/incidents/{inc_id}/status", tokens["VIEWER"], "PATCH", {"status": "RESOLVED"})
        log_test("VIEWER", "Block Incident Status Transition (❌ Restricted)", st == 403, f"HTTP {st} Forbidden")

    # 5. Test IPS Controls (Admin: ✅ | Analyst: ✅ | Viewer: ❌ Restricted)
    print("\n[PHASE 5: IPS ACTIVE MITIGATION CONTROLS (Admin: ✅ | Analyst: ✅ | Viewer: ❌)]")
    # Admin can list blocked IPs
    st, _ = api_call("/ips-actions", tokens["ADMIN"])
    log_test("ADMIN", "List IPS Blocklist Registry (✅)", st == 200, f"HTTP {st}")

    # Analyst can list blocked IPs
    st, _ = api_call("/ips-actions", tokens["ANALYST"])
    log_test("ANALYST", "List IPS Blocklist Registry (✅)", st == 200, f"HTTP {st}")

    # Viewer is forbidden from listing or managing IPS actions -> 403 Forbidden!
    st, _ = api_call("/ips-actions", tokens["VIEWER"])
    log_test("VIEWER", "Block Access to IPS Registry (❌ Restricted)", st == 403, f"HTTP {st} Forbidden")

    import time
    test_ip = f"198.51.100.{int(time.time() * 10) % 150 + 50}"
    st, blk_res = api_call("/ips-actions", tokens["ADMIN"], "POST", {
        "ip_address": test_ip,
        "reason": "RBAC verification block",
        "duration_minutes": 10
    })
    block_id = blk_res.get("id") if isinstance(blk_res, dict) else None
    log_test("ADMIN", f"Enforce Firewall Block on {test_ip} (✅)", st == 201, f"HTTP {st}")

    # Viewer attempts to block IP -> 403 Forbidden!
    st, _ = api_call("/ips-actions", tokens["VIEWER"], "POST", {
        "ip_address": "198.51.100.89",
        "reason": "Viewer unauthorized block"
    })
    log_test("VIEWER", "Block IP Firewall Enforcement (❌ Restricted)", st == 403, f"HTTP {st} Forbidden")

    # Analyst unblocks the test IP via DELETE -> 200 OK
    if block_id:
        st, _ = api_call(f"/ips-actions/{block_id}", tokens["ANALYST"], "DELETE", {
            "reason": "Analyst verified unblock"
        })
        log_test("ANALYST", f"Unblock Firewall Target {test_ip} (✅)", st == 200, f"HTTP {st}")

    # 6. Test User Management (Admin: ✅ | Analyst: ❌ | Viewer: ❌)
    print("\n[PHASE 6: USER FLEET & RBAC POLICIES (Admin: ✅ | Analyst: ❌ | Viewer: ❌)]")
    # Admin can list users
    st, _ = api_call("/users", tokens["ADMIN"])
    log_test("ADMIN", "Manage User Fleet & RBAC Directory (✅)", st == 200, f"HTTP {st}")

    # Analyst blocked from listing users -> 403 Forbidden!
    st, _ = api_call("/users", tokens["ANALYST"])
    log_test("ANALYST", "Block Access to Users Directory (❌ Restricted)", st == 403, f"HTTP {st} Forbidden")

    # Viewer blocked from listing users -> 403 Forbidden!
    st, _ = api_call("/users", tokens["VIEWER"])
    log_test("VIEWER", "Block Access to Users Directory (❌ Restricted)", st == 403, f"HTTP {st} Forbidden")

    print("\n" + "=" * 70)
    print(f" AUDIT COMPLETE: {PASSED} PASSED | {FAILED} FAILED")
    print("=" * 70)

    if FAILED == 0:
        print("\n[SUCCESS] TWO-LAYER ENTERPRISE RBAC MATRIX FULLY VERIFIED AND ENFORCED!")
        sys.exit(0)
    else:
        print(f"\n[FAIL] {FAILED} test cases violated the security boundary!")
        sys.exit(1)

if __name__ == "__main__":
    main()
