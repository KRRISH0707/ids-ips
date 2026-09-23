"""
Multi-Channel SOC Webhook Dispatcher.

Dispatches real-time security alerts to Slack, Discord, Microsoft Teams,
or custom SIEM/SOAR webhooks asynchronously without blocking detection ingestion.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from typing import Any
import urllib.request

logger = logging.getLogger("ids.alert_dispatcher")


def _send_http_post(url: str, payload: dict[str, Any], timeout: float = 3.0) -> None:
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "Apex-Sentinel-SOC-Dispatcher/1.0",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status not in (200, 204):
                logger.warning("Webhook endpoint %s returned HTTP %s", url[:30], resp.status)
    except Exception as exc:
        logger.debug("Failed to deliver webhook notification to %s: %s", url[:30], exc)


def _format_discord_embed(alert: dict[str, Any]) -> dict[str, Any]:
    severity = str(alert.get("severity", "HIGH")).upper()
    color_map = {
        "CRITICAL": 15158332,  # Red
        "HIGH": 15105570,      # Orange
        "MEDIUM": 15844367,    # Gold
        "LOW": 3447003,        # Blue
    }
    color = color_map.get(severity, 15158332)

    src_ip = alert.get("src_ip", "Unknown")
    sig = alert.get("signature", "Suspicious Activity")
    category = alert.get("category", "threat").upper()
    risk = alert.get("risk_score", 90)
    raw = alert.get("raw_event", {}) or {}
    path = raw.get("path", "N/A")

    return {
        "username": "Apex Sentinel Autonomous IPS",
        "avatar_url": "https://img.icons8.com/color/96/shield.png",
        "embeds": [
            {
                "title": f"🚨 Autonomous IPS Quarantine: {severity}",
                "description": f"**Exploit Vector**: `{sig}`\n**Category**: `{category}`",
                "color": color,
                "fields": [
                    {"name": "Attacker IP", "value": f"`{src_ip}`", "inline": True},
                    {"name": "Risk Score", "value": f"**{risk}/100**", "inline": True},
                    {"name": "Target Path", "value": f"`{path}`", "inline": True},
                    {"name": "Mitigation Action", "value": "🛡️ **FIREWALL_DROP_ACTIVE (iptables drop)**", "inline": False},
                ],
                "footer": {"text": "Apex Sentinel Autonomous Cyber Defense"},
                "timestamp": alert.get("timestamp", ""),
            }
        ],
    }


def _format_slack_blocks(alert: dict[str, Any]) -> dict[str, Any]:
    severity = str(alert.get("severity", "HIGH")).upper()
    src_ip = alert.get("src_ip", "Unknown")
    sig = alert.get("signature", "Suspicious Activity")
    category = alert.get("category", "threat").upper()
    risk = alert.get("risk_score", 90)

    return {
        "text": f"🚨 [IPS AUTO-BLOCK] {severity} Exploit Intercepted from {src_ip}",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 Apex Sentinel Alert: {severity}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Attacker IP:*\n`{src_ip}`"},
                    {"type": "mrkdwn", "text": f"*Risk Score:*\n*{risk}/100*"},
                    {"type": "mrkdwn", "text": f"*Category:*\n`{category}`"},
                    {"type": "mrkdwn", "text": f"*Defense Action:*\n*Linux Kernel DROP*"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Signature Matched:*\n`{sig}`",
                },
            },
        ],
    }


def dispatch_soc_alert(alert: dict[str, Any]) -> None:
    """Dispatches real-time security alerts to configured webhook endpoints in a background thread."""
    discord_url = os.getenv("DISCORD_WEBHOOK_URL", "").strip()
    slack_url = os.getenv("SLACK_WEBHOOK_URL", "").strip()
    generic_url = os.getenv("ALERT_WEBHOOK_URL", "").strip()

    if not (discord_url or slack_url or generic_url):
        return

    def _worker():
        if discord_url:
            _send_http_post(discord_url, _format_discord_embed(alert))
        if slack_url:
            _send_http_post(slack_url, _format_slack_blocks(alert))
        if generic_url:
            _send_http_post(generic_url, {
                "event": "IPS_AUTONOMOUS_QUARANTINE",
                "alert": alert,
            })

    # Fire-and-forget in background daemon thread
    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()
