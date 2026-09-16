"""
Seed database with initial Admin user, default sensors, detection rules, and alerts using psycopg.
"""
import sys
import logging
from app.core.database import get_sync_connection
from app.core.security import hash_password

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("seed")

def seed():
    try:
        conn = get_sync_connection()
        with conn.cursor() as cur:
            # 1. Create Default Admin User
            admin_email = "admin@ids.local"
            cur.execute("SELECT id FROM users WHERE email = %s", (admin_email,))
            existing = cur.fetchone()
            
            if not existing:
                hashed_pw = hash_password("AdminPassword1!")
                cur.execute(
                    """
                    INSERT INTO users (email, hashed_password, full_name, role, is_active)
                    VALUES (%s, %s, 'Default Administrator', 'ADMIN', TRUE)
                    """,
                    (admin_email, hashed_pw)
                )
                logger.info(f"Created default admin user: {admin_email}")
            else:
                logger.info(f"Admin user {admin_email} already exists.")

            # 2. Create Default Sensor
            sensor_name = "Primary Edge Probe"
            cur.execute("SELECT id FROM sensors WHERE name = %s", (sensor_name,))
            if not cur.fetchone():
                cur.execute(
                    """
                    INSERT INTO sensors (name, hostname, ip_address, location, status)
                    VALUES (%s, 'sensor-edge-01.internal', '192.168.1.100', 'US-East Gateway', 'ONLINE')
                    """,
                    (sensor_name,)
                )
                logger.info("Created default sensor node.")

            # 3. Create Sample Detection Rules
            cur.execute("SELECT id FROM rules LIMIT 1")
            if not cur.fetchone():
                cur.execute(
                    """
                    INSERT INTO rules (name, description, condition, action, severity, category, enabled)
                    VALUES 
                    ('SSH Brute Force Attempt', 'Detects > 5 failed SSH logins in 60s', '{"type": "suricata", "sid": 1000001}', 'BLOCK', 'HIGH', 'Authentication', TRUE),
                    ('Malware C2 Beaconing', 'Detects DNS queries to known C2 domain', '{"type": "suricata", "sid": 1000002}', 'ALERT', 'CRITICAL', 'Command & Control', TRUE),
                    ('Port Scan Activity', 'Detects TCP SYN scan across > 20 ports', '{"type": "suricata", "sid": 1000003}', 'ALERT', 'MEDIUM', 'Reconnaissance', TRUE)
                    """
                )
                logger.info("Created default detection rules.")

            # 4. Create Sample Incident & Alerts
            cur.execute("SELECT id FROM alerts LIMIT 1")
            if not cur.fetchone():
                cur.execute(
                    """
                    INSERT INTO incidents (title, description, severity, risk_score, status)
                    VALUES ('Potential Reconnaissance Campaign', 'Multiple port scans detected targeting DMZ web servers', 'HIGH', 75, 'INVESTIGATING')
                    RETURNING id
                    """
                )
                inc_res = cur.fetchone()
                inc_id = inc_res["id"]

                cur.execute(
                    """
                    INSERT INTO alerts (src_ip, src_port, dst_ip, dst_port, protocol, signature, category, severity, risk_score, status, incident_id)
                    VALUES
                    ('198.51.100.42', 45210, '192.168.1.10', 443, 'TCP', 'ET SCAN Potential Nmap Scan', 'Reconnaissance', 'HIGH', 75, 'OPEN', %s),
                    ('198.51.100.42', 45212, '192.168.1.10', 80, 'TCP', 'ET SCAN Potential Nmap Scan', 'Reconnaissance', 'MEDIUM', 50, 'OPEN', %s),
                    ('203.0.113.15', 51102, '192.168.1.20', 22, 'TCP', 'ET POLICY SSH Brute Force Detection', 'Authentication', 'CRITICAL', 90, 'INVESTIGATING', NULL)
                    """,
                    (inc_id, inc_id)
                )
                logger.info("Created sample incidents and alerts.")

            conn.commit()
            logger.info("Database seeding completed successfully.")

    except Exception as e:
        logger.error(f"Seeding error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    seed()
