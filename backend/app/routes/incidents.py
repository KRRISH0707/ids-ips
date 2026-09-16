from typing import Optional
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from ..core.database import get_sync_connection
from ..core.security import get_current_user, require_role, write_audit_log
from ..core.metrics import incidents_created_total

router = APIRouter(prefix="/incidents", tags=["incidents"])

_SELECT_COLS = """
    id, title, description, severity, risk_score, status,
    assigned_to, created_at, updated_at, resolved_at
"""


class IncidentCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=300)
    description: str = ""
    severity: str = Field(default="MEDIUM", pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    risk_score: int = Field(default=0, ge=0, le=100)
    assigned_to: Optional[UUID] = None


class IncidentStatusUpdate(BaseModel):
    status: str = Field(
        ...,
        pattern="^(NEW|INVESTIGATING|CONTAINED|RESOLVED|FALSE_POSITIVE)$",
    )
    assigned_to: Optional[UUID] = None


@router.get("")
def list_incidents(
    inc_status: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    current_user: dict = Depends(get_current_user),
):
    conditions, params = [], []
    if inc_status:
        conditions.append("status = %s")
        params.append(inc_status.upper())
    if severity:
        conditions.append("severity = %s")
        params.append(severity.upper())

    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params += [limit, skip]

    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT {_SELECT_COLS} FROM incidents {where_clause} ORDER BY created_at DESC LIMIT %s OFFSET %s",
                params,
            )
            items = cur.fetchall()
            cur.execute(f"SELECT COUNT(*) AS cnt FROM incidents {where_clause}", params[:-2])
            total = cur.fetchone()["cnt"]

    return {"items": items, "total": total}


@router.get("/{incident_id}")
def get_incident(incident_id: UUID, current_user: dict = Depends(get_current_user)):
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT {_SELECT_COLS} FROM incidents WHERE id = %s",
                (str(incident_id),),
            )
            incident = cur.fetchone()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.get("/{incident_id}/alerts")
def incident_alerts(incident_id: UUID, current_user: dict = Depends(get_current_user)):
    """All alerts linked to this incident."""
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, timestamp, src_ip::text, dst_ip::text, dst_port,
                       signature, severity, risk_score, status
                FROM alerts WHERE incident_id = %s ORDER BY timestamp DESC
                """,
                (str(incident_id),),
            )
            return {"items": cur.fetchall()}


@router.post("", status_code=status.HTTP_201_CREATED)
def create_incident(
    body: IncidentCreate,
    request: Request,
    current_user: dict = Depends(require_role("ADMIN", "ANALYST")),
):
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                INSERT INTO incidents (title, description, severity, risk_score, assigned_to)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING {_SELECT_COLS}
                """,
                (body.title, body.description, body.severity, body.risk_score, body.assigned_to),
            )
            incident = cur.fetchone()
            conn.commit()

    incidents_created_total.labels(severity=body.severity).inc()
    write_audit_log(
        actor_id=current_user["id"],
        actor=current_user["email"],
        action="INCIDENT_CREATED",
        resource="incidents",
        resource_id=str(incident["id"]),
        details={"title": body.title, "severity": body.severity},
        source_ip=request.client.host if request.client else None,
    )
    return incident


@router.patch("/{incident_id}/status")
def update_incident_status(
    incident_id: UUID,
    body: IncidentStatusUpdate,
    request: Request,
    current_user: dict = Depends(require_role("ADMIN", "ANALYST")),
):
    extra_set = ""
    extra_vals = []
    if body.status == "RESOLVED":
        extra_set = ", resolved_at = now()"
    if body.assigned_to:
        extra_set += ", assigned_to = %s"
        extra_vals.append(str(body.assigned_to))

    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE incidents
                SET status = %s, updated_at = now() {extra_set}
                WHERE id = %s
                RETURNING {_SELECT_COLS}
                """,
                [body.status, *extra_vals, str(incident_id)],
            )
            updated = cur.fetchone()
            conn.commit()

    if not updated:
        raise HTTPException(status_code=404, detail="Incident not found")

    write_audit_log(
        actor_id=current_user["id"],
        actor=current_user["email"],
        action="INCIDENT_STATUS_CHANGED",
        resource="incidents",
        resource_id=str(incident_id),
        details={"new_status": body.status},
        source_ip=request.client.host if request.client else None,
    )
    return updated


@router.get("/stats/summary")
def incidents_summary(current_user: dict = Depends(get_current_user)):
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    COUNT(*) FILTER (WHERE status = 'NEW')             AS new_count,
                    COUNT(*) FILTER (WHERE status = 'INVESTIGATING')   AS investigating_count,
                    COUNT(*) FILTER (WHERE status = 'RESOLVED')        AS resolved_count,
                    COUNT(*) FILTER (WHERE severity = 'CRITICAL')      AS critical_count,
                    COUNT(*) FILTER (WHERE created_at > now() - interval '24 hours') AS last_24h
                FROM incidents
                """
            )
            return cur.fetchone()
