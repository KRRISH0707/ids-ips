"""
enforce_critical_autoblock.py
Enforces 100% strict Autonomous Prevention on all Critical threats:
1. Transitions all OPEN critical alerts to AUTO_BLOCKED.
2. Quarantines attacker IPs in blocked_ips.
3. Sets linked incident statuses to CONTAINED.
"""

import os
import sys
import ipaddress
import psycopg

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://idsips:change-me-in-development@localhost:5432/idsips")

def enforce_autoblock():
    print(f"Connecting to database: {DATABASE_URL}...")
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            # 1. Fetch all OPEN critical alerts
            cur.execute(
                """
                SELECT id, src_ip, signature, severity, risk_score, incident_id
                FROM alerts
                WHERE severity = 'CRITICAL' AND status = 'OPEN'
                """
            )
            open_critical = cur.fetchall()
            print(f"Found {len(open_critical)} OPEN critical alerts to auto-block.")

            blocked_ips_count = 0
            for row in open_critical:
                alert_id, src_ip, signature, severity, risk_score, incident_id = row
                
                # Quarantine source IP
                if src_ip:
                    try:
                        clean_ip = str(src_ip).split('/')[0].strip()
                        ip_obj = ipaddress.ip_address(clean_ip)
                        if not (ip_obj.is_loopback or ip_obj.is_unspecified):
                            cur.execute(
                                """
                                INSERT INTO blocked_ips (ip_address, reason, blocked_by, alert_id)
                                VALUES (%s::inet, %s, 'APEX_SENTINEL_AUTONOMOUS_IPS', %s)
                                ON CONFLICT (ip_address) DO UPDATE
                                    SET is_active = TRUE, blocked_at = NOW()
                                """,
                                (clean_ip, f"Autonomous IPS Sever: {signature}", alert_id)
                            )
                            blocked_ips_count += 1
                    except Exception as e:
                        print(f"Warning: Could not block IP {src_ip}: {e}")

                # Update alert status
                cur.execute(
                    "UPDATE alerts SET status = 'AUTO_BLOCKED' WHERE id = %s",
                    (alert_id,)
                )

                # Update linked incident if NEW or OPEN
                if incident_id:
                    cur.execute(
                        "UPDATE incidents SET status = 'CONTAINED', updated_at = NOW() WHERE id = %s AND status = 'NEW'",
                        (incident_id,)
                    )

            conn.commit()

            # Verify count
            cur.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'CRITICAL' AND status = 'OPEN'")
            remaining = cur.fetchone()[0]
            cur.execute("SELECT status, count(*) FROM alerts WHERE severity = 'CRITICAL' GROUP BY status")
            breakdown = cur.fetchall()

            print("\n=== Critical Threat Auto-Block Enforcement Complete ===")
            print(f"Remaining OPEN critical alerts: {remaining}")
            print(f"Critical alerts status breakdown: {breakdown}")
            print(f"Total attacker IPs quarantined: {blocked_ips_count}")

if __name__ == "__main__":
    enforce_autoblock()
