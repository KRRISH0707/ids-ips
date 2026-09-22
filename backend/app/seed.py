"""
Seed database with initial Admin user, default sensors, detection rules, and alerts using psycopg.
Reads admin credentials from settings (ADMIN_EMAIL and ADMIN_PASSWORD env vars).
"""
import sys
import logging
from app.core.config import get_settings
from app.core.database import get_sync_connection
from app.core.security import hash_password

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("seed")
settings = get_settings()

def seed():
    try:
        conn = get_sync_connection()
        with conn.cursor() as cur:
            admin_email = settings.admin_email
            admin_pw = settings.admin_password
            hashed_pw = hash_password(admin_pw)

            # 1. Create or Update Default Users (Admin, Analyst, Viewer)
            default_users = [
                {
                    "email": admin_email,
                    "password": admin_pw,
                    "full_name": "Default Administrator",
                    "role": "ADMIN",
                },
                {
                    "email": "analyst@ids-soc.com",
                    "password": "Analyst123!",
                    "full_name": "Tier-2 SOC Analyst",
                    "role": "ANALYST",
                },
                {
                    "email": "viewer@ids-soc.com",
                    "password": "Viewer123!",
                    "full_name": "Compliance & Security Viewer",
                    "role": "VIEWER",
                },
                {
                    "email": "demo@ids-soc.com",
                    "password": "DemoViewer123!",
                    "full_name": "Demo Evaluation User",
                    "role": "VIEWER",
                },
            ]

            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS managed_password TEXT;")

            for u in default_users:
                cur.execute("SELECT id FROM users WHERE email = %s", (u["email"],))
                existing = cur.fetchone()
                pw_hash = hash_password(u["password"])
                if not existing:
                    cur.execute(
                        """
                        INSERT INTO users (email, hashed_password, managed_password, full_name, role, is_active)
                        VALUES (%s, %s, %s, %s, %s, TRUE)
                        """,
                        (u["email"], pw_hash, u["password"], u["full_name"], u["role"]),
                    )
                    logger.info(f"Created default user: {u['email']} ({u['role']})")
                else:
                    cur.execute(
                        "UPDATE users SET hashed_password = %s, managed_password = %s, role = %s WHERE email = %s",
                        (pw_hash, u["password"], u["role"], u["email"]),
                    )
                    logger.info(f"Synchronized user credentials: {u['email']} ({u['role']})")

            conn.commit()
            logger.info("Successfully committed all system users.")

            # 2. Create Default Sensor
            try:
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
                conn.commit()
            except Exception as s_err:
                logger.warning(f"Sensor seed notice: {s_err}")
                conn.rollback()

            # 3. Create Sample Detection Rules across all 6 attack categories
            try:
                cur.execute("SELECT id FROM rules LIMIT 1")
                if not cur.fetchone():
                    cur.execute(
                        """
                        INSERT INTO rules (name, description, condition, action, severity, category, enabled)
                        VALUES 
                        ('Malware C2 & Trojan Beacon Detection', 'Intercepts Trojan & Cobalt Strike C2 beacon channels', '{"type": "suricata", "sid": 1000001}', 'BLOCK', 'CRITICAL', 'malware', TRUE),
                        ('Ransomware Shadow Copy Deletion Prevention', 'Intercepts vssadmin & mass encryption commands', '{"type": "suricata", "sid": 1000002}', 'BLOCK', 'CRITICAL', 'malware', TRUE),
                        ('Volumetric DDoS & SYN Flood Protection', 'Rate limits TCP SYN bursts and UDP reflection floods', '{"type": "suricata", "sid": 1000003}', 'BLOCK', 'CRITICAL', 'network', TRUE),
                        ('ARP & DNS Spoofing Poisoning Guard', 'Detects gratuitous ARP claims and forged DNS A-records', '{"type": "suricata", "sid": 1000004}', 'BLOCK', 'HIGH', 'network', TRUE),
                        ('Authentication Brute Force & Password Spraying', 'Detects rapid login failures & multi-user password sprays', '{"type": "suricata", "sid": 1000005}', 'BLOCK', 'HIGH', 'credential', TRUE),
                        ('Active Directory Kerberoasting Protection', 'Intercepts RC4-HMAC downgraded TGS ticket requests', '{"type": "suricata", "sid": 1000006}', 'BLOCK', 'HIGH', 'credential', TRUE),
                        ('SQL Injection & Web Exploit Interception', 'Inspects HTTP URI & payload for SQLi & XSS patterns', '{"type": "suricata", "sid": 1000007}', 'BLOCK', 'CRITICAL', 'web_api', TRUE),
                        ('Server-Side Request Forgery (SSRF) Guard', 'Blocks cloud metadata (169.254.169.254) extraction', '{"type": "suricata", "sid": 1000008}', 'BLOCK', 'CRITICAL', 'web_api', TRUE),
                        ('Zero-Day & Remote Code Execution (RCE) Interceptor', 'Unsupervised mathematical ML anomaly & Log4j/Spring4Shell drop', '{"type": "suricata", "sid": 1000009}', 'BLOCK', 'CRITICAL', 'exploitation', TRUE),
                        ('Buffer Overflow & Memory Corruption Shield', 'Detects NOP sleds & stack pointer overwrites', '{"type": "suricata", "sid": 1000010}', 'BLOCK', 'CRITICAL', 'exploitation', TRUE),
                        ('Lateral Movement & PsExec Sweep Sever', 'Blocks unauthorized SMB/WMI remote execution sweeps', '{"type": "suricata", "sid": 1000011}', 'BLOCK', 'HIGH', 'post_compromise', TRUE),
                        ('Data Exfiltration DNS Tunneling Guard', 'Blocks Base64 chunked DNS exfiltration tunnels', '{"type": "suricata", "sid": 1000012}', 'BLOCK', 'CRITICAL', 'post_compromise', TRUE)
                        """
                    )
                    logger.info("Created default enterprise detection rules across all attack categories.")
                conn.commit()
            except Exception as r_err:
                logger.warning(f"Rules seed notice: {r_err}")
                conn.rollback()

            # 4. Create Sample Incident & Alerts
            try:
                cur.execute("ALTER TABLE alerts DROP CONSTRAINT IF EXISTS alerts_status_check;")
                cur.execute("ALTER TABLE alerts ADD CONSTRAINT alerts_status_check CHECK (status IN ('OPEN','INVESTIGATING','RESOLVED','FALSE_POSITIVE','AUTO_BLOCKED'));")
                cur.execute("SELECT id FROM alerts LIMIT 1")
                if not cur.fetchone():
                    cur.execute(
                        """
                        INSERT INTO incidents (title, description, severity, risk_score, status)
                        VALUES ('Multi-Vector Advanced Adversary Campaign', 'Correlated multi-stage attack detected across network perimeter and AD domain', 'CRITICAL', 95, 'INVESTIGATING')
                        RETURNING id
                        """
                    )
                    inc_res = cur.fetchone()
                    inc_id = inc_res["id"]

                    cur.execute(
                        """
                        INSERT INTO alerts (src_ip, src_port, dst_ip, dst_port, protocol, signature, category, severity, risk_score, status, incident_id)
                        VALUES
                        ('185.220.101.5', 49152, '10.240.10.12', 443, 'HTTPS', 'ET EXPLOIT Apache Log4j JNDI RCE (CVE-2021-44228)', 'exploitation', 'CRITICAL', 98, 'OPEN', %s),
                        ('198.51.100.22', 54100, '10.240.20.88', 445, 'TCP', 'Win32.Ransomware.LockBit3.0 Volume Shadow Deletion via vssadmin', 'malware', 'CRITICAL', 99, 'OPEN', %s),
                        ('194.26.29.112', 38910, '10.240.0.1', 80, 'TCP', 'Mirai IoT SYN Flood Distributed Denial of Service (> 1.2M pps)', 'network', 'CRITICAL', 94, 'OPEN', %s),
                        ('10.240.15.44', 51102, '10.240.10.4', 88, 'Kerberos', 'Kerberoasting Active Directory Ticket Request (RC4-HMAC downgrade)', 'credential', 'HIGH', 94, 'OPEN', %s),
                        ('198.51.100.99', 49182, '10.240.10.12', 443, 'HTTPS', 'ET WEB_SPECIFIC_APPS SQL Injection in URI parameter UNION SELECT', 'web_api', 'CRITICAL', 98, 'OPEN', %s),
                        ('10.240.20.88', 53000, '45.33.32.10', 53, 'DNS', 'ET POST_COMPROMISE Data Exfiltration Over DNS Tunnel (Base64 Chunked)', 'post_compromise', 'CRITICAL', 97, 'OPEN', %s)
                        """,
                        (inc_id, inc_id, inc_id, inc_id, inc_id, inc_id)
                    )
                    logger.info("Created sample incidents and alerts across all categories.")
                conn.commit()
            except Exception as a_err:
                logger.warning(f"Alerts seed notice: {a_err}")
                conn.rollback()

            logger.info("Database seeding completed successfully.")

    except Exception as e:
        logger.error(f"Seeding error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    seed()
