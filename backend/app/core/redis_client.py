import redis.asyncio as aioredis
import redis as syncredis

from .config import get_settings

settings = get_settings()

# ── Async client (for WebSocket pub/sub and FastAPI endpoints) ────────────────
_async_pool: aioredis.Redis | None = None


def get_async_redis() -> aioredis.Redis:
    global _async_pool
    if _async_pool is None:
        _async_pool = aioredis.from_url(
            settings.redis_url,
            decode_responses=True,
        )
    return _async_pool


# ── Sync client (for background workers, seed scripts) ───────────────────────
_sync_client: syncredis.Redis | None = None


def get_sync_redis() -> syncredis.Redis:
    global _sync_client
    if _sync_client is None:
        _sync_client = syncredis.from_url(
            settings.redis_url,
            decode_responses=True,
        )
    return _sync_client


# ── Channel names ─────────────────────────────────────────────────────────────
LIVE_ALERTS_CHANNEL = "ids.live.alerts"
LIVE_INCIDENTS_CHANNEL = "ids.live.incidents"
