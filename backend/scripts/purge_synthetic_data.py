#!/usr/bin/env python3
"""
Purge Synthetic / Simulated Historical Data from Apex Sentinel.
Leaves system infrastructure (Users, Sensors, Rules, Playbooks, Threat Intel IOCs)
completely intact, and resets live operational tables (Alerts, Incidents, Blocked IPs,
Audit Logs, Playbook Executions) to a clean zero-state for authentic telemetry.
"""

import os
import sys
import psycopg

def get_db_url():
    url = os.getenv("DATABASE_URL", "postgresql://idsips:change-me-in-development@localhost:5432/idsips")
    url = url.replace("postgresql+psycopg://", "postgresql://")
    return url

def purge():
    url = get_db_url()
    print("[*] Connecting to database to purge synthetic data...")
    with psycopg.connect(url) as conn:
        with conn.cursor() as cur:
            # 1. Truncate operational tables (cascade handles foreign keys)
            print("[*] Purging synthetic alerts, incidents, quarantines, and logs...")
            cur.execute("""
                TRUNCATE TABLE 
                    alerts,
                    incidents,
                    blocked_ips,
                    audit_logs,
                    playbook_executions
                CASCADE;
            """)
            conn.commit()
            print("  ✓ Tables truncated: alerts, incidents, blocked_ips, audit_logs, playbook_executions.")

            # 2. Verify infrastructure tables are preserved
            cur.execute("SELECT COUNT(*) FROM users;")
            users_count = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM sensors;")
            sensors_count = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM rules;")
            rules_count = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM threat_intel;")
            iocs_count = cur.fetchone()[0]

            print("\n[+] Verification of Preserved Production Assets:")
            print(f"  • Users:                  {users_count}")
            print(f"  • Network Sensors:        {sensors_count}")
            print(f"  • Detection Rules:        {rules_count}")
            print(f"  • Threat Intel IOCs:      {iocs_count}")
            print("\n[+] All synthetic historical telemetry has been purged.")
            print("[+] Apex Sentinel is now operating exclusively on TRUE live traffic & detections.")

if __name__ == "__main__":
    purge()
