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

try:
    from .seed_55_playbooks import PLAYBOOKS_55 as PLAYBOOKS
except ImportError:
    from seed_55_playbooks import PLAYBOOKS_55 as PLAYBOOKS

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
