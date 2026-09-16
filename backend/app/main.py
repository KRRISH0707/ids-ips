"""
FastAPI application entry-point for the Enterprise IDS/IPS platform.

Startup lifecycle:
  1. Verify PostgreSQL connectivity (fail fast if DB unreachable).
  2. Verify Redis connectivity.
  3. Register all API routers.

All configuration is read from environment variables via
`app.core.config.Settings` (Pydantic BaseSettings).
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .core.config import get_settings
from .core.database import get_sync_connection
from .core.redis_client import get_sync_redis
from .routes import (
    ai_insights,
    alerts,
    audit_logs,
    auth,
    health,
    incidents,
    ips_actions,
    metrics,
    mitre,
    network_topology,
    playbooks,
    rules,
    sensors,
    threat_intel,
    users,
    ws,
)

settings = get_settings()
logger = logging.getLogger("ids.main")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup checks and graceful shutdown."""

    # PostgreSQL
    try:
        with get_sync_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
        logger.info("✅  PostgreSQL connection OK")
    except Exception as exc:
        logger.critical("❌  PostgreSQL unreachable: %s", exc)
        raise

    # Redis
    try:
        r = get_sync_redis()
        r.ping()
        logger.info("✅  Redis connection OK")
    except Exception as exc:
        logger.warning("⚠️   Redis unreachable (live feed disabled): %s", exc)

    logger.info("🚀  IDS/IPS API started  [env=%s]", os.getenv("APP_ENV", "development"))

    yield

    logger.info("🛑  IDS/IPS API shutting down")


# ── Application ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="Enterprise IDS/IPS API",
    version="1.0.0",
    description=(
        "Production-grade Intrusion Detection & Prevention System REST API. "
        "Provides real-time alert ingestion, incident management, IPS enforcement, "
        "detection rule management, and a live WebSocket feed."
    ),
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)


# ── CORS ──────────────────────────────────────────────────────────────────────

_origins = [
    o.strip()
    for o in settings.cors_origins.split(",")
    if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=".*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Global exception handler ──────────────────────────────────────────────────

@app.exception_handler(Exception)
async def generic_exception_handler(request, exc):
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


# ── Routers ───────────────────────────────────────────────────────────────────

PREFIX = "/api"

app.include_router(health.router,       prefix=PREFIX)
app.include_router(auth.router,         prefix=PREFIX)
app.include_router(users.router,        prefix=PREFIX)
app.include_router(alerts.router,       prefix=PREFIX)
app.include_router(incidents.router,    prefix=PREFIX)
app.include_router(sensors.router,      prefix=PREFIX)
app.include_router(rules.router,        prefix=PREFIX)
app.include_router(ips_actions.router,  prefix=PREFIX)
app.include_router(audit_logs.router,   prefix=PREFIX)
app.include_router(metrics.router,      prefix=PREFIX)
app.include_router(ai_insights.router,  prefix=PREFIX)
app.include_router(playbooks.router,         prefix=PREFIX)
app.include_router(mitre.router,             prefix=PREFIX)
app.include_router(network_topology.router,  prefix=PREFIX)
app.include_router(threat_intel.router,      prefix=PREFIX)
app.include_router(ws.router,                prefix=PREFIX)