#!/usr/bin/env python3
"""
Emergency unblock script — removes ALL active blocks for the operator's
own management IP from the blocked_ips table so the dashboard can fetch data again.

Usage (from the project root):
    python scripts/unblock_my_ip.py [<ip_address>]

If no IP is given, it reads IPS_MANAGEMENT_ALLOWLIST from the .env file.
"""
import os
import sys
import re

# ---------------------------------------------------------------------------
# Load .env from the project root (two levels up from scripts/)
# ---------------------------------------------------------------------------
_here = os.path.dirname(os.path.abspath(__file__))
_env_path = os.path.join(_here, "..", ".env")

def load_dotenv(path):
    env = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)=(.*)$', line)
                if m:
                    env[m.group(1)] = m.group(2).strip('"').strip("'")
    except FileNotFoundError:
        pass
    return env

_dotenv = load_dotenv(_env_path)
for k, v in _dotenv.items():
    os.environ.setdefault(k, v)

# ---------------------------------------------------------------------------
# Determine which IP to unblock
# ---------------------------------------------------------------------------
if len(sys.argv) > 1:
    target_ips = [ip.strip() for ip in sys.argv[1:] if ip.strip()]
else:
    raw = os.environ.get("IPS_MANAGEMENT_ALLOWLIST", "")
    target_ips = [ip.strip() for ip in raw.split(",") if ip.strip()]

if not target_ips:
    print("ERROR: No IP address specified and IPS_MANAGEMENT_ALLOWLIST is empty.")
    print("Usage: python scripts/unblock_my_ip.py <ip_address>")
    sys.exit(1)

print(f"Unblocking IP(s): {', '.join(target_ips)}")

# ---------------------------------------------------------------------------
# Connect to Postgres and deactivate blocks
# ---------------------------------------------------------------------------
try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    print("ERROR: psycopg not installed. Run: pip install psycopg[binary]")
    sys.exit(1)

db_url = os.environ.get("DATABASE_URL", "")
if not db_url:
    host = os.environ.get("POSTGRES_HOST", "localhost")
    port = os.environ.get("POSTGRES_PORT", "5432")
    user = os.environ.get("POSTGRES_USER", "idsips")
    pw   = os.environ.get("POSTGRES_PASSWORD", "")
    db   = os.environ.get("POSTGRES_DB", "idsips")
    db_url = f"postgresql://{user}:{pw}@{host}:{port}/{db}"

try:
    with psycopg.connect(db_url, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            for ip in target_ips:
                # Strip CIDR suffix if present (e.g. /32)
                clean_ip = ip.split("/")[0]

                cur.execute(
                    """
                    UPDATE blocked_ips
                    SET is_active = false
                    WHERE ip_address::text LIKE %s AND is_active = true
                    RETURNING id, ip_address::text AS ip_address, reason, blocked_at
                    """,
                    (f"{clean_ip}%",),
                )
                rows = cur.fetchall()
                if rows:
                    for r in rows:
                        print(f"  [UNBLOCKED] {r['ip_address']} (id={r['id']}, reason={r['reason']!r})")
                else:
                    print(f"  [OK] No active block found for {clean_ip} -- already unblocked or never blocked.")

            cur.execute("SELECT COUNT(*) AS n FROM blocked_ips WHERE is_active = true")
            remaining = cur.fetchone()["n"]
            print(f"\nActive blocks remaining in DB: {remaining}")

        conn.commit()

    print("\nDone. Reload the dashboard (backend cache clears in 2s automatically).")

except Exception as exc:
    print(f"ERROR: Could not connect to database: {exc}")
    sys.exit(1)
