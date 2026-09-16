"""
IPS Controller – listens on the Redis `ids.ips.actions` channel and
enforces block / unblock decisions via iptables (Linux) or in
"simulation mode" on Windows / development machines.

Simulation mode is automatically activated when:
  * Running on Windows, or
  * The environment variable IPS_SIMULATION_MODE=true is set.

In simulation mode every action is logged but no OS-level firewall
rule is created.  This makes the controller safe to run inside Docker
Desktop on Windows without CAP_NET_ADMIN.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import subprocess
import sys
import time

import redis

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("ips.controller")

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
CHANNEL = "ids.ips.actions"
SIMULATION_MODE = (
    os.getenv("IPS_SIMULATION_MODE", "").lower() in ("true", "1", "yes")
    or platform.system() == "Windows"
)

if SIMULATION_MODE:
    logger.warning("⚠️  IPS controller running in SIMULATION MODE – no firewall rules will be applied")


# ── iptables helpers ──────────────────────────────────────────────────────────

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


def block_ip(ip: str, reason: str = "") -> bool:
    if SIMULATION_MODE:
        logger.info("[SIM] BLOCK  %s  reason=%r", ip, reason)
        return True

    code, out = _run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"])
    if code == 0:
        logger.info("IP %s already blocked (iptables rule exists)", ip)
        return True

    code, out = _run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    if code != 0:
        logger.error("Failed to block %s: %s", ip, out)
        return False

    logger.info("BLOCKED  %s  reason=%r", ip, reason)
    return True


def unblock_ip(ip: str, reason: str = "") -> bool:
    if SIMULATION_MODE:
        logger.info("[SIM] UNBLOCK  %s  reason=%r", ip, reason)
        return True

    code, out = _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
    if code != 0:
        logger.warning("iptables rule for %s not found or already removed: %s", ip, out)
        return False

    logger.info("UNBLOCKED  %s  reason=%r", ip, reason)
    return True


# ── Host Isolation & Quarantine Helpers ──────────────────────────────────────

def isolate_host(hostname: str, ip: str, reason: str = "") -> bool:
    """Quarantine a compromised endpoint from the network."""
    if SIMULATION_MODE:
        logger.warning("[SIM] 🛡️  HOST ISOLATED / QUARANTINED: %s (%s)  reason=%r", hostname, ip, reason)
        return True

    # Cut off inbound and outbound network traffic on Linux
    _run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
    _run(["iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"])
    _run(["iptables", "-I", "FORWARD", "-d", ip, "-j", "DROP"])
    logger.warning("🛡️  HOST ISOLATED / QUARANTINED: %s (%s) via iptables", hostname, ip)
    return True


def unisolate_host(hostname: str, ip: str, reason: str = "") -> bool:
    """Lift quarantine and restore network access."""
    if SIMULATION_MODE:
        logger.info("[SIM] ✅  HOST RESTORED / UNISOLATED: %s (%s)  reason=%r", hostname, ip, reason)
        return True

    _run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
    _run(["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"])
    _run(["iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP"])
    logger.info("✅  HOST RESTORED / UNISOLATED: %s (%s)", hostname, ip)
    return True


# ── Redis subscriber loop ─────────────────────────────────────────────────────

def connect_redis() -> redis.Redis:
    """Retry loop until Redis is reachable."""
    while True:
        try:
            client = redis.from_url(REDIS_URL, decode_responses=True, socket_connect_timeout=3)
            client.ping()
            logger.info("Connected to Redis at %s", REDIS_URL)
            return client
        except Exception as exc:
            logger.warning("Redis not available (%s), retrying in 5 s…", exc)
            time.sleep(5)


def handle_ips_message(data: str) -> None:
    try:
        payload = json.loads(data)
    except json.JSONDecodeError:
        logger.warning("Received non-JSON message on ips.actions: %r", data)
        return

    action = payload.get("action", "").upper()
    ip = payload.get("ip_address", "")

    if not ip:
        logger.warning("Message missing ip_address: %s", payload)
        return

    if action == "BLOCK":
        block_ip(ip, reason=payload.get("reason", ""))
    elif action == "UNBLOCK":
        unblock_ip(ip, reason=payload.get("reason", ""))
    else:
        logger.warning("Unknown IPS action: %r", action)


def handle_isolation_message(data: str) -> None:
    try:
        payload = json.loads(data)
    except json.JSONDecodeError:
        logger.warning("Received non-JSON message on host_isolation: %r", data)
        return

    action = payload.get("action", "").upper()
    hostname = payload.get("hostname", "unknown")
    ip = payload.get("ip_address", "")

    if action == "ISOLATE":
        isolate_host(hostname, ip, reason="AI/Admin Triggered Machine Quarantine")
    elif action == "UNISOLATE":
        unisolate_host(hostname, ip, reason="Admin Approved Machine Restoration")
    else:
        logger.warning("Unknown isolation action: %r", action)


def run() -> None:
    client = connect_redis()
    pubsub = client.pubsub()
    channels = [CHANNEL, "ips:host_isolation"]
    pubsub.subscribe(*channels)
    logger.info("Subscribed to Redis channels: %s", channels)

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
