#!/usr/bin/env python3
"""
Seed Enterprise SOC Suite:
1. Playbooks (SOAR)
2. Threat Intelligence IOCs (IP, Domains, Hashes)
"""

import os
import sys
import psycopg
from psycopg.types.json import Jsonb

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://idsips:change-me-in-development@localhost:5432/idsips"
)

PLAYBOOKS = [
    {
        "name": "PB-01: Rapid Ransomware Containment",
        "description": "Instantly stops ransomware propagation by quarantining endpoint, killing lateral SMB ports, and locking shadow storage.",
        "trigger_event": "RANSOMWARE",
        "severity_threshold": "CRITICAL",
        "actions": ["ISOLATE_HOST", "LOCK_SHADOW_COPIES", "BLOCK_LATERAL_SMB", "DISPATCH_PAGERDUTY_ALERT"],
        "is_active": True
    },
    {
        "name": "PB-02: Cobalt Strike & C2 Neutralization",
        "description": "Sever active Command & Control communication, ban external C2 IP, and isolate infected beaconing host.",
        "trigger_event": "C2_BEACON",
        "severity_threshold": "CRITICAL",
        "actions": ["FIREWALL_DROP_EGRESS", "ISOLATE_COMPROMISED_HOST", "DUMP_PROCESS_MEMORY_ARTIFACTS", "SOC_HIGH_PRIORITY_INCIDENT"],
        "is_active": True
    },
    {
        "name": "PB-03: Credential Stuffing & SSH Brute Force Mitigation",
        "description": "Imposes 24-hour firewall ban on attacking botnet IP, invalidates active tokens, and prompts MFA challenge.",
        "trigger_event": "BRUTE_FORCE",
        "severity_threshold": "HIGH",
        "actions": ["BLOCK_SOURCE_IP_24H", "FORCE_USER_SESSION_TERMINATION", "ENABLE_MFA_STEPUP", "WRITE_FORENSIC_AUDIT_LOG"],
        "is_active": True
    },
    {
        "name": "PB-04: Automated Network Reconnaissance Countermeasure",
        "description": "Identifies malicious port scanners and blackholes scanning traffic before service exploits can occur.",
        "trigger_event": "PORT_SCAN",
        "severity_threshold": "HIGH",
        "actions": ["TARPIT_ATTACKER_TCP", "DYNAMIC_IPTABLES_DROP", "NOTIFY_NETWORK_ADMIN"],
        "is_active": True
    },
    {
        "name": "PB-05: High Anomaly Behavioral Isolation",
        "description": "Autonomously quarantines any internal machine showing acute behavioral deviations or high entropy anomalies.",
        "trigger_event": "HIGH_ANOMALY",
        "severity_threshold": "CRITICAL",
        "actions": ["ISOLATE_HOST", "START_PROMISCUOUS_PCAP_CAPTURE", "ESCALATE_TO_TIER2_ANALYST"],
        "is_active": True
    },
    {
        "name": "PB-06: Distributed Denial-of-Service (DDoS) Volumetric Shield",
        "description": "Mitigates multi-gigabit volumetric SYN, UDP, and ICMP saturation attacks by activating BGP Flowspec filtering and dynamic drop rules.",
        "trigger_event": "SYN_FLOOD",
        "severity_threshold": "CRITICAL",
        "actions": ["ACTIVATE_BGP_FLOWSPEC_SCRUBBING", "DYNAMIC_IPTABLES_DROP", "RATE_LIMIT_SYN_COOKIES", "BROADCAST_INCIDENT_WAR_ROOM"],
        "is_active": True
    },
    {
        "name": "PB-07: Remote Code Execution & Web Exploit Lockdown",
        "description": "Intercepts active Log4Shell, SQL injection, and zero-day web shell uploads, terminating worker threads and capturing forensic packet evidence.",
        "trigger_event": "RCE_EXPLOIT",
        "severity_threshold": "CRITICAL",
        "actions": ["TERMINATE_WEB_WORKER_PROCESS", "BLOCK_SOURCE_IP_24H", "INVALIDATE_SESSION_COOKIES", "CAPTURE_FORENSIC_PCAP_STREAM"],
        "is_active": True
    },
    {
        "name": "PB-08: Active Directory Domain Controller Breach Containment",
        "description": "Halts Active Directory domain credential harvesting, Kerberoasting ticket extraction, and unauthorized RPC replication across Domain Controllers.",
        "trigger_event": "KERBEROASTING",
        "severity_threshold": "CRITICAL",
        "actions": ["SUSPEND_COMPROMISED_AD_ACCOUNT", "SEVER_SMB_RPC_TUNNELS", "TRIGGER_KRBTGT_PASSWORD_RESET", "DISPATCH_SOC_URGENT_PAGE"],
        "is_active": True
    },
    {
        "name": "PB-09: Covert DNS Tunneling & Data Exfiltration Interception",
        "description": "Detects high-entropy outbound DNS tunneling and covert exfiltration channels, sinkholing attacker domains and severing socket connections.",
        "trigger_event": "DNS_TUNNELING",
        "severity_threshold": "HIGH",
        "actions": ["SINKHOLE_MALICIOUS_NAMESERVER", "INJECT_TCP_RESET_STREAM", "ISOLATE_EXFILTRATING_HOST", "DUMP_ENDPOINT_NETWORK_SOCKETS"],
        "is_active": True
    },
    {
        "name": "PB-10: Cloud Container Escape & Supply Chain Tamper Quarantine",
        "description": "Enforces kernel-level container cgroup freezing upon detecting namespace breakouts, revoking ephemeral cloud IAM metadata credentials immediately.",
        "trigger_event": "CONTAINER_ESCAPE",
        "severity_threshold": "CRITICAL",
        "actions": ["FREEZE_CONTAINER_RUNTIME_CGROUP", "REVOKE_CLOUD_IAM_ROLE_TOKENS", "TERMINATE_KUBERNETES_POD", "NOTIFY_DEVSECOPS_LEAD"],
        "is_active": True
    },
    {
        "name": "PB-11: Unauthorized Lateral Movement & Pass-The-Hash Quarantine",
        "description": "Contains internal lateral pivoting via Pass-The-Hash, WMI, or WinRM by enforcing microsegmentation boundaries around infected nodes.",
        "trigger_event": "LATERAL_MOVEMENT",
        "severity_threshold": "HIGH",
        "actions": ["ENFORCE_MICROSEGMENTATION_ISOLATION", "REVOKE_KERBEROS_TGT_TOKENS", "ENABLE_EXTENDED_SECURITY_AUDIT", "SOC_TIER2_ESCALATION"],
        "is_active": True
    },
    {
        "name": "PB-12: Zero-Day Protocol Anomaly & Packet Replay Neutralization",
        "description": "Autonomously synthesizes dynamic eBPF drop filters and Snort/Suricata bytecode rules upon identifying malformed packet payloads or zero-day zero-byte exploits.",
        "trigger_event": "PROTOCOL_VIOLATION",
        "severity_threshold": "CRITICAL",
        "actions": ["INJECT_KERNEL_EBPF_DISCARD", "BLOCK_SOURCE_IP_24H", "GENERATE_SURICATA_SNORT_SIGNATURE", "DISPATCH_PAGERDUTY_ALERT"],
        "is_active": True
    }
]

THREAT_INTEL = [
    {
        "ioc_type": "IP",
        "value": "203.0.113.88",
        "threat_type": "SSH_BRUTE_FORCE_BOTNET",
        "confidence": 98,
        "source": "AbuseIPDB Verified",
        "tags": ["brute_force", "hydra", "botnet"]
    },
    {
        "ioc_type": "IP",
        "value": "45.33.32.156",
        "threat_type": "COBALT_STRIKE_C2",
        "confidence": 99,
        "source": "AlienVault OTX Pulse",
        "tags": ["c2", "cobalt_strike", "malleable"]
    },
    {
        "ioc_type": "IP",
        "value": "198.51.100.99",
        "threat_type": "SQL_INJECTION_SCANNER",
        "confidence": 92,
        "source": "Emerging Threats Pro",
        "tags": ["sqlmap", "web_exploit", "cve_2024"]
    },
    {
        "ioc_type": "DOMAIN",
        "value": "update-service-cdn-telemetry.org",
        "threat_type": "MALICIOUS_C2_DOMAIN",
        "confidence": 95,
        "source": "ThreatConnect Intelligence",
        "tags": ["c2", "fast_flux", "beacon"]
    },
    {
        "ioc_type": "HASH",
        "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "threat_type": "LOCKBIT_RANSOMWARE_PAYLOAD",
        "confidence": 100,
        "source": "CISA Cybersecurity Advisory",
        "tags": ["ransomware", "lockbit3", "wiper"]
    },
    {
        "ioc_type": "IP",
        "value": "192.0.2.77",
        "threat_type": "PORT_SCANNER_MASS_SWEEP",
        "confidence": 88,
        "source": "Shadowserver Recon Sweep",
        "tags": ["nmap", "port_scanner", "recon"]
    }
]

def main():
    print(f"Connecting to {DATABASE_URL}...")
    try:
        with psycopg.connect(DATABASE_URL) as conn:
            with conn.cursor() as cur:
                # 1. Seed Playbooks
                print("Seeding SOAR Playbooks...")
                for pb in PLAYBOOKS:
                    cur.execute(
                        "SELECT id FROM playbooks WHERE name = %s",
                        (pb["name"],)
                    )
                    existing = cur.fetchone()
                    if existing:
                        cur.execute(
                            """
                            UPDATE playbooks
                            SET description = %s, trigger_event = %s, severity_threshold = %s, actions = %s, is_active = %s
                            WHERE id = %s
                            """,
                            (pb["description"], pb["trigger_event"], pb["severity_threshold"], Jsonb(pb["actions"]), pb["is_active"], existing[0])
                        )
                    else:
                        cur.execute(
                            """
                            INSERT INTO playbooks (name, description, trigger_event, severity_threshold, actions, is_active)
                            VALUES (%s, %s, %s, %s, %s, %s)
                            """,
                            (pb["name"], pb["description"], pb["trigger_event"], pb["severity_threshold"], Jsonb(pb["actions"]), pb["is_active"])
                        )

                # 2. Seed Threat Intel
                print("Seeding Threat Intelligence IOCs...")
                for ti in THREAT_INTEL:
                    cur.execute(
                        """
                        INSERT INTO threat_intel (ioc_type, value, threat_type, confidence, source, tags)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (ioc_type, value) DO UPDATE
                        SET confidence = EXCLUDED.confidence,
                            source = EXCLUDED.source,
                            tags = EXCLUDED.tags
                        """,
                        (ti["ioc_type"], ti["value"], ti["threat_type"], ti["confidence"], ti["source"], Jsonb(ti["tags"]))
                    )

                conn.commit()
                print("Successfully seeded SOAR Playbooks & Threat Intelligence IOCs!")
    except Exception as e:
        print(f"Error seeding database: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
