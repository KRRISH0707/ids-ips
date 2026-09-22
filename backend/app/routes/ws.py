"""
WebSocket live-feed endpoint.

Clients connect to /api/ws/live to receive real-time JSON messages for:
  * new alerts  (channel: ids.live.alerts)
  * incident updates (channel: ids.live.incidents)

The endpoint subscribes to both Redis channels and forwards every
message to the connected WebSocket client.  Each socket gets its own
Redis subscription so that multiple dashboards can connect
simultaneously.

Authentication: The JWT must be supplied as a query parameter
  ?token=<access_token>   (WebSocket clients cannot set custom headers).
"""

from __future__ import annotations

import asyncio
import json
import logging

import redis.asyncio as aioredis
from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect
from jose import JWTError

from ..core.config import get_settings
from ..core.security import decode_token

logger = logging.getLogger(__name__)
settings = get_settings()

router = APIRouter(prefix="/ws", tags=["websocket"])

CHANNELS = ["ids.live.alerts", "ids.live.incidents", "ids.ips.actions", "ids.audit.logs"]


async def _authenticate(token: str) -> dict | None:
    """Validate the JWT; return the payload or None on failure."""
    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            return None
        return payload
    except Exception:
        return None


@router.websocket("/live")
async def websocket_live_feed(
    websocket: WebSocket,
    token: str = Query(..., description="JWT access token"),
):
    payload = await _authenticate(token)
    if payload is None:
        await websocket.close(code=4001, reason="Unauthorized")
        return

    await websocket.accept()
    logger.info("WS client connected (user=%s)", payload.get("sub"))

    # Each connection gets its own async Redis client + pubsub object
    redis_client = aioredis.from_url(
        settings.redis_url,
        decode_responses=True,
        socket_connect_timeout=3,
    )
    pubsub = redis_client.pubsub()
    await pubsub.subscribe(*CHANNELS)

    try:
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            try:
                await websocket.send_text(message["data"])
            except WebSocketDisconnect:
                break
            except Exception as exc:
                logger.warning("WS send error: %s", exc)
                break
    except WebSocketDisconnect:
        pass
    except asyncio.CancelledError:
        pass
    finally:
        await pubsub.unsubscribe(*CHANNELS)
        await redis_client.aclose()
        logger.info("WS client disconnected (user=%s)", payload.get("sub"))
