#!/usr/bin/env python3
"""
Seed 45 Days of Historical Telemetry:
Populates realistic, chronologically distributed enterprise security data spanning
the full 45-day window (August 7, 2026 - September 21, 2026):
  1. Alerts (~850+ alerts across all 45 days)
  2. Incidents (~130+ multi-stage cases with lifecycles)
  3. Blocked IPs (~50+ active & historical quarantines)
  4. Audit Logs (~350+ compliance audit records)
  5. Playbook Executions (~75+ SOAR execution logs)
"""

import os
import sys
import random
from datetime import datetime, timedelta, timezone
import ipaddress
import psycopg
from psycopg.types.json import Jsonb

def _sanitize_db_url(raw_url: str) -> str:
    url = raw_url.replace("postgresql+psycopg://", "postgresql://")
    try:
        from urllib.parse import quote_plus
        if "://" in url:
            prefix, rest = url.split("://", 1)
            if "@" in rest:
                user_info, host_part = rest.rsplit("@", 1)
                if ":" in user_info:
                    username, password = user_info.split(":", 1)
                    if "%" not in password:
                        password = quote_plus(password)
                    return f"{prefix}://{username}:{password}@{host_part}"
    except Exception:
        pass
    return url

DATABASE_URL = _sanitize_db_url(os.getenv(
    "DATABASE_URL",
    "postgresql://idsips:change-me-in-development@localhost:5432/idsips"
))

# Realistic Attack Catalog
ATTACK_SIGNATURES = [
    {
        "sig": "ET EXPLOIT Apache Log4j JNDI RCE (CVE-2021-44228)",
        "cat": "exploitation",
        "sev": "CRITICAL",
        "proto": "HTTPS",
        "dst_port": 443,
        "risk": 98,
        "technique": "T1190 - Exploit Public-Facing Application"
    },
    {
        "sig": "Win32.Ransomware.LockBit3.0 Volume Shadow Deletion via vssadmin",
        "cat": "malware",
        "sev": "CRITICAL",
        "proto": "TCP",
        "dst_port": 445,
        "risk": 99,
        "technique": "T1490 - Inhibit System Recovery"
    },
    {
        "sig": "ET TROJAN Cobalt Strike Malleable C2 HTTPS Beacon",
        "cat": "malware",
        "sev": "CRITICAL",
        "proto": "HTTPS",
        "dst_port": 443,
        "risk": 96,
        "technique": "T1071.001 - Application Layer Protocol: Web Protocols"
    },
    {
        "sig": "Mirai IoT SYN Flood Distributed Denial of Service (> 1.2M pps)",
        "cat": "network",
        "sev": "CRITICAL",
        "proto": "TCP",
        "dst_port": 80,
        "risk": 94,
        "technique": "T1498 - Network Denial of Service"
    },
    {
        "sig": "Kerberoasting Active Directory Ticket Request (RC4-HMAC downgrade)",
        "cat": "credential",
        "sev": "HIGH",
        "proto": "Kerberos",
        "dst_port": 88,
        "risk": 89,
        "technique": "T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting"
    },
    {
        "sig": "ET WEB_SPECIFIC_APPS SQL Injection in URI parameter UNION SELECT",
        "cat": "web_api",
        "sev": "CRITICAL",
        "proto": "HTTPS",
        "dst_port": 443,
        "risk": 95,
        "technique": "T1190 - Exploit Public-Facing Application"
    },
    {
        "sig": "ET POST_COMPROMISE Data Exfiltration Over DNS Tunnel (Base64 Chunked)",
        "cat": "post_compromise",
        "sev": "CRITICAL",
        "proto": "DNS",
        "dst_port": 53,
        "risk": 97,
        "technique": "T1048.003 - Exfiltration Over Alternative Protocol: DNS"
    },
    {
        "sig": "ET SCAN Nmap Scripting Engine OS Fingerprint & Service Sweep",
        "cat": "network",
        "sev": "MEDIUM",
        "proto": "TCP",
        "dst_port": 445,
        "risk": 65,
        "technique": "T1046 - Network Service Scanning"
    },
    {
        "sig": "ET EXPLOIT Spring4Shell Remote Code Execution (CVE-2022-22965)",
        "cat": "exploitation",
        "sev": "CRITICAL",
        "proto": "HTTPS",
        "dst_port": 8080,
        "risk": 97,
        "technique": "T1190 - Exploit Public-Facing Application"
    },
    {
        "sig": "SSH Brute Force Dictionary Attack (Multiple Rapid Auth Failures)",
        "cat": "credential",
        "sev": "HIGH",
        "proto": "SSH",
        "dst_port": 22,
        "risk": 82,
        "technique": "T1110.001 - Brute Force: Password Guessing"
    },
    {
        "sig": "ET TROJAN China Chopper Web Shell POST Command Execution (eval base64_decode)",
        "cat": "web_api",
        "sev": "CRITICAL",
        "proto": "HTTPS",
        "dst_port": 443,
        "risk": 99,
        "technique": "T1505.003 - Server Software Component: Web Shell"
    },
    {
        "sig": "ET EXPLOIT Linux SUID GTFOBin Privilege Escalation Root Shell Spawn",
        "cat": "exploitation",
        "sev": "CRITICAL",
        "proto": "TCP",
        "dst_port": 31337,
        "risk": 96,
        "technique": "T1548.001 - Abuse Elevation Control Mechanism: Setuid and Setgid"
    },
    {
        "sig": "BGP Hijack Anomaly / Unauthorized Autonomous System Path Announcement",
        "cat": "network",
        "sev": "HIGH",
        "proto": "BGP",
        "dst_port": 179,
        "risk": 88,
        "technique": "T1584.004 - Compromise Infrastructure: Server"
    },
    {
        "sig": "Cloud Metadata IMDSv1 Credential Exfiltration Probe (169.254.169.254)",
        "cat": "web_api",
        "sev": "HIGH",
        "proto": "HTTP",
        "dst_port": 80,
        "risk": 85,
        "technique": "T1552.005 - Cloud Instance Metadata API"
    },
    {
        "sig": "Suspicious Lateral SMB Named Pipe Impersonation \\\\pipe\\\\spoolss",
        "cat": "post_compromise",
        "sev": "MEDIUM",
        "proto": "SMB",
        "dst_port": 445,
        "risk": 72,
        "technique": "T1021.002 - Remote Services: SMB/Windows Admin Shares"
    },
    {
        "sig": "Anomalous Outbound TLS Beacon to Uncategorized High-Entropy FQDN",
        "cat": "malware",
        "sev": "MEDIUM",
        "proto": "HTTPS",
        "dst_port": 8443,
        "risk": 68,
        "technique": "T1568.002 - Dynamic Resolution: Domain Generation Algorithms"
    }
]

SOURCE_IPS = [
    "185.220.101.5", "198.51.100.22", "194.26.29.112", "91.108.4.100",
    "45.33.32.156", "203.0.113.88", "192.0.2.77", "185.191.171.34",
    "193.163.125.10", "45.154.255.89", "89.248.165.11", "103.145.13.20",
    "198.51.100.99", "185.244.25.188", "194.87.139.7", "77.247.110.15"
]

INTERNAL_TARGETS = [
    "10.240.10.12", "10.240.20.88", "10.240.0.1", "10.240.10.4",
    "10.240.15.44", "10.240.12.90", "10.240.30.5", "10.240.25.100"
]

INCIDENT_TITLES = [
    ("Active Directory Kerberos & Lateral Pivot Campaign", "CRITICAL", "T1558"),
    ("Volumetric Mirai Distributed Denial of Service", "CRITICAL", "T1498"),
    ("Targeted Cobalt Strike C2 Ingress via Web Ingestion", "CRITICAL", "T1071"),
    ("LockBit 3.0 Ransomware Staging on Database Core", "CRITICAL", "T1486"),
    ("Multi-Vector External Perimeter Port Sweep & Recon", "HIGH", "T1046"),
    ("Zero-Day Log4j RCE Ingress via Perimeter Gateway", "CRITICAL", "T1190"),
    ("Credential Stuffing & SSH Brute Force Surge", "HIGH", "T1110"),
    ("Covert Base64 DNS Exfiltration Channel Detected", "CRITICAL", "T1048"),
    ("Spring4Shell Web Application Exploit Attempt", "HIGH", "T1190"),
    ("Cloud IAM Metadata IMDSv1 Harvest Attempt", "HIGH", "T1552"),
    ("Internal Lateral Movement via PsExec Named Pipes", "HIGH", "T1021"),
    ("Automated SQL Injection Injection Probe on API Cluster", "MEDIUM", "T1190")
]

def seed_45_days(conn=None):
    should_close = False
    if conn is None:
        try:
            from app.core.database import get_sync_connection
            conn = get_sync_connection()
            should_close = True
        except Exception:
            pass

    if conn is None:
        print(f"Connecting to database: {DATABASE_URL}...")
        try:
            conn = psycopg.connect(DATABASE_URL)
            conn.autocommit = False
            should_close = True
        except Exception as e:
            print(f"Failed to connect to database: {e}")
            raise e

    with conn.cursor() as cur:
        # Check current date / anchor date (using Sept 21, 2026 as reference base)
        cur.execute("SELECT now()")
        row_now = cur.fetchone()
        db_now = (list(row_now.values())[0] if isinstance(row_now, dict) else row_now[0]) if row_now else datetime.now(timezone.utc)
        print(f"Database Current Time: {db_now}")

        # Fetch active admin user id & sensor id
        cur.execute("SELECT id, email FROM users WHERE role = 'ADMIN' LIMIT 1")
        admin_row = cur.fetchone()
        admin_id = None
        admin_email = "admin@ids-soc.com"
        if admin_row:
            if isinstance(admin_row, dict):
                admin_id = admin_row.get("id")
                admin_email = admin_row.get("email", admin_email)
            else:
                admin_id = admin_row[0]
                admin_email = admin_row[1] if len(admin_row) > 1 else admin_email

        cur.execute("SELECT id FROM sensors LIMIT 1")
        sensor_row = cur.fetchone()
        sensor_id = None
        if sensor_row:
            sensor_id = sensor_row.get("id") if isinstance(sensor_row, dict) else sensor_row[0]

        cur.execute("SELECT id, name, trigger_event FROM playbooks")
        raw_playbooks = cur.fetchall()
        playbooks = []
        for pb in raw_playbooks:
            if isinstance(pb, dict):
                playbooks.append((pb.get("id"), pb.get("name"), pb.get("trigger_event")))
            else:
                playbooks.append(pb)

        print("\n--- Generating 45-Day Historic Data (Day -45 to Day 0) ---")

        # Track created incidents to attach alerts
        created_incidents = []

        # 1. Generate Incidents across 45 days (approx 2-4 per day)
        for day_offset in range(45, -1, -1):
            day_date = db_now - timedelta(days=day_offset)
            num_incidents = random.randint(1, 4) if day_offset > 2 else random.randint(2, 5)

            for _ in range(num_incidents):
                title_template, sev, mitre_tag = random.choice(INCIDENT_TITLES)
                hour = random.randint(0, 23)
                minute = random.randint(0, 59)
                second = random.randint(0, 59)
                incident_time = day_date.replace(hour=hour, minute=minute, second=second)

                # Realistic status based on age:
                if day_offset > 14:
                    status = random.choices(["RESOLVED", "CONTAINED", "FALSE_POSITIVE"], weights=[75, 20, 5])[0]
                    resolved_at = incident_time + timedelta(hours=random.randint(2, 48))
                elif day_offset > 3:
                    status = random.choices(["RESOLVED", "CONTAINED", "INVESTIGATING"], weights=[50, 35, 15])[0]
                    resolved_at = incident_time + timedelta(hours=random.randint(1, 24)) if status == "RESOLVED" else None
                else:
                    status = random.choices(["INVESTIGATING", "NEW", "CONTAINED", "RESOLVED"], weights=[45, 30, 15, 10])[0]
                    resolved_at = incident_time + timedelta(hours=2) if status == "RESOLVED" else None

                cur.execute(
                    """
                    INSERT INTO incidents (title, description, severity, risk_score, status, assigned_to, created_at, updated_at, resolved_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id, created_at, status
                    """,
                    (
                        f"{title_template} [Cluster #{random.randint(100, 999)}]",
                        f"Automated incident correlation rule triggered for {mitre_tag}. Telemetry verified across edge DPI probes.",
                        sev,
                        random.randint(70, 99) if sev == "CRITICAL" else random.randint(50, 79),
                        status,
                        admin_id,
                        incident_time,
                        incident_time,
                        resolved_at
                    )
                )
                inc_row = cur.fetchone()
                inc_id = (inc_row.get("id") if isinstance(inc_row, dict) else inc_row[0]) if inc_row else None
                created_incidents.append((inc_id, incident_time, status))

        print(f"Created {len(created_incidents)} incidents distributed across 45 days.")

        # 2. Generate Alerts across 45 days (approx 15-30 alerts per day = ~900 alerts)
        total_alerts = 0
        for day_offset in range(45, -1, -1):
            day_date = db_now - timedelta(days=day_offset)
            # Higher alert volume on weekdays, realistic variance
            is_weekend = day_date.weekday() >= 5
            daily_alert_count = random.randint(12, 22) if is_weekend else random.randint(18, 35)

            # Find incidents from this day or adjacent days
            matching_incs = [inc[0] for inc in created_incidents if abs((inc[1] - day_date).days) <= 1]

            for _ in range(daily_alert_count):
                atk = random.choice(ATTACK_SIGNATURES)
                hour = random.randint(0, 23)
                minute = random.randint(0, 59)
                second = random.randint(0, 59)
                alert_time = day_date.replace(hour=hour, minute=minute, second=second)

                src_ip = random.choice(SOURCE_IPS)
                dst_ip = random.choice(INTERNAL_TARGETS)
                src_port = random.randint(1024, 65535)
                dst_port = atk["dst_port"]
                protocol = atk["proto"]
                signature = atk["sig"]
                category = atk["cat"]
                severity = atk["sev"]
                risk_score = atk["risk"]

                # Realistic status: older alerts are RESOLVED or AUTO_BLOCKED; recent can be OPEN or INVESTIGATING
                if day_offset > 7:
                    alert_status = random.choices(["RESOLVED", "AUTO_BLOCKED", "FALSE_POSITIVE"], weights=[60, 35, 5])[0]
                elif day_offset > 1:
                    alert_status = random.choices(["RESOLVED", "AUTO_BLOCKED", "INVESTIGATING", "OPEN"], weights=[40, 35, 15, 10])[0]
                else:
                    alert_status = random.choices(["AUTO_BLOCKED", "OPEN", "INVESTIGATING", "RESOLVED"], weights=[40, 30, 20, 10])[0]

                inc_id = random.choice(matching_incs) if matching_incs and random.random() < 0.65 else None

                raw_event = {
                    "technique": atk["technique"],
                    "sensor": "Primary Edge Probe",
                    "interface": "eth0",
                    "packet_length": random.randint(64, 1518),
                    "tcp_flags": "ACK,PSH" if protocol == "TCP" else "SYN",
                    "scenario_key": category.upper()
                }

                cur.execute(
                    """
                    INSERT INTO alerts (
                        sensor_id, incident_id, timestamp, src_ip, src_port,
                        dst_ip, dst_port, protocol, signature, category,
                        severity, risk_score, status, raw_event, created_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        sensor_id, inc_id, alert_time, src_ip, src_port,
                        dst_ip, dst_port, protocol, signature, category,
                        severity, risk_score, alert_status, Jsonb(raw_event), alert_time
                    )
                )
                total_alerts += 1

        print(f"Created {total_alerts} alerts distributed across 45 days.")

        # 3. Generate Blocked IPs / Quarantines across 45 days
        total_blocks = 0
        used_ips = set()
        # Generate varied external IPs
        quarantine_ips = [f"{random.randint(45, 198)}.{random.randint(10, 240)}.{random.randint(1, 250)}.{random.randint(2, 250)}" for _ in range(70)]

        for day_offset in range(45, -1, -1):
            if random.random() < 0.7:  # 70% chance of an IPS quarantine action on any given day
                num_blocks = random.randint(1, 2)
                for _ in range(num_blocks):
                    ip = random.choice(quarantine_ips)
                    if ip in used_ips:
                        continue
                    used_ips.add(ip)

                    day_date = db_now - timedelta(days=day_offset)
                    block_time = day_date.replace(hour=random.randint(0, 23), minute=random.randint(0, 59))

                    # Older blocks are usually lifted or expired; recent ones remain active
                    if day_offset > 10:
                        is_active = random.choices([False, True], weights=[80, 20])[0]
                    else:
                        is_active = random.choices([True, False], weights=[85, 15])[0]

                    reason = random.choice([
                        "Autonomous eBPF Mitigation: Critical Log4j RCE exploit attempt",
                        "High Volume SYN Flood (> 1.2M pps) Layer-4 drop rule",
                        "SSH Brute Force Dictionary threshold exceeded",
                        "Cobalt Strike Malleable C2 HTTP Beacon detected",
                        "Automated SQL Injection in URI parameter",
                        "Zero-Day Behavioral Anomaly Score > 95"
                    ])

                    expires_at = block_time + timedelta(hours=24) if not is_active else None

                    cur.execute(
                        """
                        INSERT INTO blocked_ips (ip_address, reason, blocked_by, is_active, blocked_at, expires_at)
                        VALUES (%s, %s, 'AI_AUTONOMOUS_IPS', %s, %s, %s)
                        ON CONFLICT (ip_address) DO NOTHING
                        """,
                        (ip, reason, is_active, block_time, expires_at)
                    )
                    total_blocks += 1

        print(f"Created {total_blocks} blocked IP quarantines across 45 days.")

        # 4. Generate Audit Logs across 45 days
        total_audits = 0
        audit_actions = [
            ("OPERATOR_LOGIN", "users", {"method": "password_mfa", "status": "SUCCESS"}),
            ("INCIDENT_STATUS_CHANGED", "incidents", {"new_status": "INVESTIGATING", "tier": "Tier-2"}),
            ("INCIDENT_STATUS_CHANGED", "incidents", {"new_status": "CONTAINED", "action": "HOST_ISOLATION"}),
            ("INCIDENT_STATUS_CHANGED", "incidents", {"new_status": "RESOLVED", "mttc": "4.2m"}),
            ("IPS_RULE_COMPILED", "rules", {"rule_type": "SURICATA", "action": "BLOCK"}),
            ("IP_QUARANTINE_ENFORCED", "blocked_ips", {"layer": "eBPF_XDP", "drop_mode": "KERNEL"}),
            ("THREAT_INDICATOR_SYNCED", "threat_intel", {"feed": "AbuseIPDB_OTX", "count": 14}),
            ("SOAR_PLAYBOOK_EXECUTED", "playbooks", {"trigger": "AUTONOMOUS_ML", "status": "SUCCESS"})
        ]

        for day_offset in range(45, -1, -1):
            day_date = db_now - timedelta(days=day_offset)
            num_logs = random.randint(5, 14)

            for _ in range(num_logs):
                hour = random.randint(0, 23)
                minute = random.randint(0, 59)
                log_time = day_date.replace(hour=hour, minute=minute)

                action, resource, details = random.choice(audit_actions)
                cur.execute(
                    """
                    INSERT INTO audit_logs (actor_id, actor, action, resource, details, source_ip, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        admin_id,
                        admin_email,
                        action,
                        resource,
                        Jsonb(details),
                        "10.240.0.105",
                        log_time
                    )
                )
                total_audits += 1

        print(f"Created {total_audits} compliance audit logs across 45 days.")

        # 5. Generate Playbook Executions across 45 days
        total_pb_execs = 0
        if playbooks:
            for day_offset in range(45, -1, -1):
                if random.random() < 0.65:
                    day_date = db_now - timedelta(days=day_offset)
                    num_execs = random.randint(1, 3)

                    for _ in range(num_execs):
                        pb_id, pb_name, pb_trigger = random.choice(playbooks)
                        exec_time = day_date.replace(hour=random.randint(0, 23), minute=random.randint(0, 59))
                        target_ip = random.choice(SOURCE_IPS)

                        cur.execute(
                            """
                            INSERT INTO playbook_executions (
                                playbook_id, playbook_name, status, target,
                                actions_taken, logs, triggered_by, executed_at
                            )
                            VALUES (%s, %s, 'SUCCESS', %s, %s, %s, 'AI_AUTONOMOUS_ENGINE', %s)
                            """,
                            (
                                pb_id,
                                pb_name,
                                target_ip,
                                Jsonb(["ISOLATE_HOST", "FIREWALL_DROP_EGRESS", "SOC_NOTIFICATION"]),
                                Jsonb([
                                    {"timestamp": exec_time.isoformat(), "msg": f"Trigger received: {pb_trigger}"},
                                    {"timestamp": (exec_time + timedelta(seconds=1)).isoformat(), "msg": f"eBPF rule enacted on target {target_ip}"},
                                    {"timestamp": (exec_time + timedelta(seconds=2)).isoformat(), "msg": "Execution finalized with exit code 0"}
                                ]),
                                exec_time
                            )
                        )
                        total_pb_execs += 1

            print(f"Created {total_pb_execs} SOAR playbook executions across 45 days.")

        conn.commit()
        print("\n✅ Successfully seeded 45-day historical telemetry database!")

    if should_close:
        try:
            conn.close()
        except Exception:
            pass

if __name__ == "__main__":
    seed_45_days()
