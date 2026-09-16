"""
Redis pub/sub helpers.

Publish functions are intentionally synchronous so they can be called from
regular FastAPI route handlers without an event loop in scope.  The async
subscriber is used by the WebSocket endpoint.
"""

from __future__ import annotations

import json
from typing import Any

import redis as sync_redis

from ..core.config import get_settings

settings = get_settings()

# Lazy singleton – created on first call to avoid import-time failures when
# Redis is not yet reachable (important during Docker Compose start-up).
_sync_client: sync_redis.Redis | None = None


def _get_sync_client() -> sync_redis.Redis:
    global _sync_client
    if _sync_client is None:
        _sync_client = sync_redis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=3,
        )
    return _sync_client


# ── Channel names ─────────────────────────────────────────────────────────────

LIVE_ALERTS_CHANNEL = "ids.live.alerts"
LIVE_INCIDENTS_CHANNEL = "ids.live.incidents"
IPS_ACTIONS_CHANNEL = "ids.ips.actions"


# ── Publishers ────────────────────────────────────────────────────────────────

def publish_live_alert(alert: dict[str, Any]) -> None:
    """Publish a serialised alert to the live-alerts Redis channel."""
    _get_sync_client().publish(
        LIVE_ALERTS_CHANNEL,
        json.dumps(alert, default=str),
    )


def publish_live_incident(incident: dict[str, Any]) -> None:
    """Publish a serialised incident update to the live-incidents channel."""
    _get_sync_client().publish(
        LIVE_INCIDENTS_CHANNEL,
        json.dumps(incident, default=str),
    )


def publish_ips_action(action: dict[str, Any]) -> None:
    """Notify the IPS controller of a block / unblock request."""
    _get_sync_client().publish(
        IPS_ACTIONS_CHANNEL,
        json.dumps(action, default=str),
    )
