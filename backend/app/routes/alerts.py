import json
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID

# pyrefly: ignore [missing-import]
import psycopg
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
# pyrefly: ignore [missing-import]
from psycopg.types.json import Jsonb

from ..core.database import get_sync_connection
from ..core.security import get_current_user, write_audit_log
from ..core.metrics import alerts_ingested_total, open_alerts_gauge
from ..services.kafka import publish_alert
from ..services.redis_pubsub import publish_live_alert

router = APIRouter(prefix="/alerts", tags=["alerts"])


class AlertCreate(BaseModel):
    sensor_id: Optional[UUID] = None
    incident_id: Optional[UUID] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = Field(default=None, ge=1, le=65535)
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = Field(default=None, ge=1, le=65535)
    protocol: Optional[str] = Field(default=None, max_length=50)
    signature: str = Field(..., min_length=1, max_length=500)
    category: str = Field(default="unknown", max_length=100)
    severity: str = Field(default="MEDIUM", max_length=20)
    risk_score: int = Field(default=0, ge=0, le=100)
    status: str = Field(default="OPEN", max_length=30)
    raw_event: Optional[dict[str, Any]] = None


class AlertStatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(OPEN|INVESTIGATING|RESOLVED|FALSE_POSITIVE)$")


ALLOWED_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
ALLOWED_STATUSES = {"OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"}

_SELECT_COLS = """
    id, sensor_id, incident_id, rule_id,
    timestamp, src_ip::text AS src_ip, src_port,
    dst_ip::text AS dst_ip, dst_port, protocol,
    signature, category, severity, risk_score, status,
    raw_event, created_at
"""


@router.get("")
def list_alerts(
    severity: Optional[str] = Query(None),
    alert_status: Optional[str] = Query(None, alias="status"),
    src_ip: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    current_user: dict = Depends(get_current_user),
):
    """Return alerts with optional filtering and pagination."""
    conditions = []
    params: list[Any] = []

    if severity:
        conditions.append("severity = %s")
        params.append(severity.upper())
    if alert_status:
        conditions.append("status = %s")
        params.append(alert_status.upper())
    if src_ip:
        conditions.append("src_ip::text = %s")
        params.append(src_ip)

    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params += [limit, skip]

    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT {_SELECT_COLS}
                FROM alerts
                {where_clause}
                ORDER BY timestamp DESC
                LIMIT %s OFFSET %s
                """,
                params,
            )
            items = cur.fetchall()

            cur.execute(f"SELECT COUNT(*) AS cnt FROM alerts {where_clause}", params[:-2])
            total = cur.fetchone()["cnt"]

    return {"items": items, "total": total, "skip": skip, "limit": limit}


@router.get("/{alert_id}")
def get_alert(alert_id: UUID, current_user: dict = Depends(get_current_user)):
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT {_SELECT_COLS} FROM alerts WHERE id = %s",
                (str(alert_id),),
            )
            alert = cur.fetchone()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.post("", status_code=status.HTTP_201_CREATED)
def ingest_alert(
    body: AlertCreate,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    """Ingest a new alert, publish to Kafka, push live via Redis."""
    severity = body.severity.upper()
    if severity not in ALLOWED_SEVERITIES:
        raise HTTPException(
            status_code=400,
            detail=f"severity must be one of {sorted(ALLOWED_SEVERITIES)}",
        )
    alert_status = body.status.upper()
    if alert_status not in ALLOWED_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"status must be one of {sorted(ALLOWED_STATUSES)}",
        )

    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute(
                    f"""
                    INSERT INTO alerts (
                        sensor_id, incident_id, timestamp,
                        src_ip, src_port, dst_ip, dst_port, protocol,
                        signature, category, severity, risk_score, status, raw_event
                    )
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    RETURNING {_SELECT_COLS}
                    """,
                    (
                        body.sensor_id,
                        body.incident_id,
                        datetime.now(timezone.utc),
                        body.src_ip,
                        body.src_port,
                        body.dst_ip,
                        body.dst_port,
                        body.protocol,
                        body.signature,
                        body.category,
                        severity,
                        body.risk_score,
                        alert_status,
                        Jsonb(body.raw_event) if body.raw_event else None,
                    ),
                )
                created = cur.fetchone()
                conn.commit()
            except psycopg.Error as exc:
                conn.rollback()
                raise HTTPException(status_code=400, detail=f"DB error: {exc}")

    # Fire-and-forget: Kafka + Redis pub/sub
    try:
        publish_alert(created)
    except Exception:
        pass  # Don't fail the request if Kafka is unavailable

    try:
        publish_live_alert(created)
    except Exception:
        pass

    alerts_ingested_total.labels(severity=severity).inc()

    return {"accepted": True, "alert": created}


@router.patch("/{alert_id}/status")
def update_alert_status(
    alert_id: UUID,
    body: AlertStatusUpdate,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE alerts SET status = %s
                WHERE id = %s
                RETURNING {_SELECT_COLS}
                """,
                (body.status, str(alert_id)),
            )
            updated = cur.fetchone()
            conn.commit()

    if not updated:
        raise HTTPException(status_code=404, detail="Alert not found")

    write_audit_log(
        actor_id=current_user["id"],
        actor=current_user["email"],
        action="ALERT_STATUS_CHANGED",
        resource="alerts",
        resource_id=str(alert_id),
        details={"new_status": body.status},
        source_ip=request.client.host if request.client else None,
    )
    return updated


@router.get("/stats/summary")
def alerts_summary(current_user: dict = Depends(get_current_user)):
    """Quick stats for the dashboard KPIs."""
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    COUNT(*) FILTER (WHERE status = 'OPEN')           AS open_total,
                    COUNT(*) FILTER (WHERE severity = 'CRITICAL')     AS critical_total,
                    COUNT(*) FILTER (WHERE severity = 'HIGH')         AS high_total,
                    COUNT(*) FILTER (WHERE severity = 'MEDIUM')       AS medium_total,
                    COUNT(*) FILTER (WHERE severity = 'LOW')          AS low_total,
                    COUNT(*) FILTER (WHERE timestamp > now() - interval '1 hour') AS last_hour,
                    COUNT(*) FILTER (WHERE timestamp > now() - interval '24 hours') AS last_24h
                FROM alerts
                """
            )
            return cur.fetchone()
