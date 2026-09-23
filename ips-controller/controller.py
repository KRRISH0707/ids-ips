"""
IPS Controller – Autonomous Edge & Host Intrusion Prevention Controller.
Listens on Redis channels (`ids.ips.actions`, `ips:host_isolation`) and
enforces hardware/kernel-level DROP rules via:
  * Linux: iptables (with nftables fallback)
  * Windows: netsh advfirewall
  * Simulation Mode: Logging only when IPS_SIMULATION_MODE=true is explicitly set.

Guaranteed Safeguards:
  * Never drops localhost, loopback, or addresses in IPS_MANAGEMENT_ALLOWLIST.
  * Hydrates existing active blocks from PostgreSQL on startup.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import platform
import subprocess
import sys
import time
from typing import Set

import redis

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("ips.controller")

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
DATABASE_URL = os.getenv("DATABASE_URL", "")
CHANNEL = "ids.ips.actions"

# Only enable simulation mode if explicitly requested by environment variable
SIMULATION_MODE = os.getenv("IPS_SIMULATION_MODE", "false").lower() in ("true", "1", "yes")

# Management allowlist parsed into IPNetwork objects
ALLOWLIST_RAW = os.getenv("IPS_MANAGEMENT_ALLOWLIST", "").strip()
ALLOWLIST_NETS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

for entry in ALLOWLIST_RAW.split(","):
    entry = entry.strip()
    if entry:
        try:
            ALLOWLIST_NETS.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            pass

# Cache of currently active blocked IPs to prevent redundant OS commands
_active_blocked_ips: Set[str] = set()

if SIMULATION_MODE:
    logger.warning("⚠️  IPS controller running in SIMULATION MODE – no real firewall drops will be executed.")
else:
    logger.info("🛡️  IPS controller running in ACTIVE ENFORCEMENT MODE (%s kernel)", platform.system())


# ── Allowlist & Safety Checks ────────────────────────────────────────────────

def is_allowlisted(ip_str: str) -> bool:
    """Check if an IP address is a protected management address or loopback."""
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        if addr.is_loopback or addr.is_unspecified:
            return True
        for net in ALLOWLIST_NETS:
            if addr in net:
                return True
    except ValueError:
        pass
    return False


# ── Subprocess Runner ─────────────────────────────────────────────────────────

def _run(cmd: list[str]) -> tuple[int, str]:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode, result.stdout + result.stderr
    except Exception as exc:
        return 1, str(exc)


# ── Firewall Enforcement Handlers ────────────────────────────────────────────

def _apply_linux_block(ip: str) -> bool:
    # Check if already present in INPUT chain
    code, _ = _run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"])
    if code == 0:
        return True

    # Prepend DROP rule to both INPUT and FORWARD chains for complete perimeter denial
    c1, out1 = _run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
    c2, out2 = _run(["iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"])
    if c1 == 0 or c2 == 0:
        return True

    # Fallback to modern nftables if legacy iptables is not present in container/host
    c3, out3 = _run(["nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", ip, "drop"])
    if c3 == 0:
        return True

    logger.error("Failed to inject Linux firewall rule for %s: %s", ip, out1 + out2 + out3)
    return False


def _remove_linux_block(ip: str) -> bool:
    _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
    _run(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"])
    return True


def _apply_windows_block(ip: str) -> bool:
    rule_name = f"APEX_IPS_BLOCK_{ip.replace(':', '_')}"
    _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])
    code, out = _run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"
    ])
    if code != 0:
        logger.error("Failed to inject Windows firewall rule for %s: %s", ip, out)
        return False
    return True


def _remove_windows_block(ip: str) -> bool:
    rule_name = f"APEX_IPS_BLOCK_{ip.replace(':', '_')}"
    code, _ = _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])
    return code == 0


def block_ip(ip: str, reason: str = "") -> bool:
    ip = ip.strip()
    if not ip:
        return False

    if is_allowlisted(ip):
        logger.warning("🛡️ [SAFETY NET] Refusing to block protected management/loopback IP: %s (reason=%r)", ip, reason)
        return False

    if ip in _active_blocked_ips:
        logger.debug("IP %s already in active blocked cache", ip)
        return True

    if SIMULATION_MODE:
        logger.info("[SIMULATED BLOCK] %s  reason=%r", ip, reason)
        _active_blocked_ips.add(ip)
        return True

    success = False
    system = platform.system()
    if system == "Windows":
        success = _apply_windows_block(ip)
    else:
        success = _apply_linux_block(ip)

    if success:
        _active_blocked_ips.add(ip)
        logger.warning("🚨 [ACTIVE KERNEL IPS] Successfully DROPPED IP %s  reason=%r", ip, reason)
    return success


def unblock_ip(ip: str, reason: str = "") -> bool:
    ip = ip.strip()
    if not ip:
        return False

    if SIMULATION_MODE:
        logger.info("[SIMULATED UNBLOCK] %s  reason=%r", ip, reason)
        _active_blocked_ips.discard(ip)
        return True

    system = platform.system()
    if system == "Windows":
        _remove_windows_block(ip)
    else:
        _remove_linux_block(ip)

    _active_blocked_ips.discard(ip)
    logger.info("✅ [ACTIVE KERNEL IPS] Successfully UNBLOCKED IP %s  reason=%r", ip, reason)
    return True


# ── Host Isolation & Quarantine ──────────────────────────────────────────────

def isolate_host(hostname: str, ip: str, reason: str = "") -> bool:
    """Isolate an internal compromised host from lateral and outbound communications."""
    if is_allowlisted(ip):
        logger.warning("[SAFETY NET] Refusing to isolate allowlisted host %s (%s)", hostname, ip)
        return False

    if SIMULATION_MODE:
        logger.warning("[SIMULATED QUARANTINE] Host: %s (%s)  reason=%r", hostname, ip, reason)
        return True

    system = platform.system()
    if system == "Linux":
        _run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
        _run(["iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"])
        _run(["iptables", "-I", "FORWARD", "-d", ip, "-j", "DROP"])
    logger.warning("🛡️  HOST QUARANTINED: %s (%s)  reason=%r", hostname, ip, reason)
    return True


def unisolate_host(hostname: str, ip: str, reason: str = "") -> bool:
    """Restore network communications for a remediated host."""
    if SIMULATION_MODE:
        logger.info("[SIMULATED RESTORE] Host: %s (%s)  reason=%r", hostname, ip, reason)
        return True

    system = platform.system()
    if system == "Linux":
        _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
        _run(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"])
        _run(["iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP"])
    logger.info("✅  HOST RESTORED: %s (%s)", hostname, ip)
    return True


# ── Database State Hydration ─────────────────────────────────────────────────

def hydrate_active_blocks() -> None:
    """Hydrate all active blocked IPs from PostgreSQL on container startup."""
    if not DATABASE_URL:
        return
    try:
        import psycopg
        db_url = DATABASE_URL.replace("postgresql+psycopg://", "postgresql://")
        logger.info("Connecting to database for active firewall state hydration...")
        with psycopg.connect(db_url, connect_timeout=5) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT ip_address::text, reason FROM blocked_ips WHERE is_active = TRUE")
                rows = cur.fetchall()
                logger.info("Hydrated %d active blocked IPs from database.", len(rows))
                for ip_str, reason in rows:
                    block_ip(ip_str, reason=f"Boot Hydration: {reason or 'Persisted Quarantine'}")
    except Exception as exc:
        logger.warning("Database hydration skipped or failed (%s). Controller will proceed on Redis events.", exc)


# ── Redis Subscriber Loop ────────────────────────────────────────────────────

def connect_redis() -> redis.Redis:
    """Connect to Redis with resilient retry backoff."""
    while True:
        try:
            client = redis.from_url(REDIS_URL, decode_responses=True, socket_connect_timeout=3)
            client.ping()
            logger.info("Connected to Redis event bus at %s", REDIS_URL.split("@")[-1])
            return client
        except Exception as exc:
            logger.warning("Redis unavailable (%s), retrying in 5s…", exc)
            time.sleep(5)


def handle_ips_message(data: str) -> None:
    try:
        payload = json.loads(data)
    except json.JSONDecodeError:
        logger.warning("Received malformed JSON on ips.actions: %r", data)
        return

    action = payload.get("action", "").upper()
    ip = payload.get("ip_address", "")

    if not ip:
        logger.warning("IPS action missing ip_address: %s", payload)
        return

    if action == "BLOCK":
        block_ip(ip, reason=payload.get("reason", "Autonomous IPS Quarantine"))
    elif action == "UNBLOCK":
        unblock_ip(ip, reason=payload.get("reason", "Operator Unblock"))
    else:
        logger.warning("Unknown IPS action received: %r", action)


def handle_isolation_message(data: str) -> None:
    try:
        payload = json.loads(data)
    except json.JSONDecodeError:
        logger.warning("Received malformed JSON on host_isolation: %r", data)
        return

    action = payload.get("action", "").upper()
    hostname = payload.get("hostname", "unknown")
    ip = payload.get("ip_address", "")

    if action == "ISOLATE":
        isolate_host(hostname, ip, reason=payload.get("reason", "Autonomous Host Quarantine"))
    elif action == "UNISOLATE":
        unisolate_host(hostname, ip, reason=payload.get("reason", "Admin Restoration"))


def run() -> None:
    hydrate_active_blocks()

    client = connect_redis()
    pubsub = client.pubsub()
    channels = [CHANNEL, "ips:host_isolation"]
    pubsub.subscribe(*channels)
    logger.info("Subscribed to Redis event bus channels: %s", channels)
    logger.info("IPS Controller active and armed. Ready to process attack drop events.")

    for message in pubsub.listen():
        if message["type"] != "message":
            continue
        channel = message["channel"]
        if channel == CHANNEL:
            handle_ips_message(message["data"])
        elif channel == "ips:host_isolation":
            handle_isolation_message(message["data"])


if __name__ == "__main__":
    run()
