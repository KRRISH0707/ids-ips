from datetime import datetime, timezone, timedelta
from typing import Optional
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from ..core.database import get_sync_connection
from ..core.security import get_current_user, require_role, write_audit_log
from ..core.metrics import active_sensors_gauge

router = APIRouter(prefix="/sensors", tags=["sensors"])

_SELECT_COLS = """
    id, name, hostname, ip_address::text AS ip_address,
    location, sensor_type, status, version, last_seen, metadata, created_at
"""


class SensorCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    location: Optional[str] = None
    sensor_type: str = Field(default="NETWORK", pattern="^(NETWORK|HOST|HYBRID)$")
    version: Optional[str] = None
    metadata: Optional[dict] = None


class SensorUpdate(BaseModel):
    name: Optional[str] = None
    hostname: Optional[str] = None
    location: Optional[str] = None
    version: Optional[str] = None
    status: Optional[str] = Field(default=None, pattern="^(ONLINE|OFFLINE|DEGRADED|UNKNOWN)$")
    metadata: Optional[dict] = None


@router.get("")
def list_sensors(current_user: dict = Depends(get_current_user)):
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            # Auto-mark sensors as OFFLINE if last_seen > 5 min ago
            cur.execute(
                """
                UPDATE sensors SET status = 'OFFLINE'
                WHERE status = 'ONLINE'
                  AND last_seen < now() - interval '5 minutes'
                """
            )
            conn.commit()

            cur.execute(
                f"SELECT {_SELECT_COLS} FROM sensors ORDER BY created_at DESC"
            )
            sensors = cur.fetchall()

    online = sum(1 for s in sensors if s["status"] == "ONLINE")
    active_sensors_gauge.set(online)
    return {"items": sensors, "total": len(sensors)}


@router.get("/{sensor_id}")
def get_sensor(sensor_id: UUID, current_user: dict = Depends(get_current_user)):
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT {_SELECT_COLS} FROM sensors WHERE id = %s", (str(sensor_id),)
            )
            sensor = cur.fetchone()
    if not sensor:
        raise HTTPException(status_code=404, detail="Sensor not found")
    return sensor


@router.post("", status_code=status.HTTP_201_CREATED)
def register_sensor(
    body: SensorCreate,
    request: Request,
    current_user: dict = Depends(require_role("ADMIN", "ANALYST")),
):
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute(
                    f"""
                    INSERT INTO sensors (name, hostname, ip_address, location, sensor_type, version, metadata)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING {_SELECT_COLS}
                    """,
                    (
                        body.name, body.hostname, body.ip_address,
                        body.location, body.sensor_type, body.version,
                        body.metadata,
                    ),
                )
                sensor = cur.fetchone()
                conn.commit()
            except psycopg.Error as exc:
                conn.rollback()
                raise HTTPException(status_code=400, detail=str(exc))

    write_audit_log(
        actor_id=current_user["id"],
        actor=current_user["email"],
        action="SENSOR_REGISTERED",
        resource="sensors",
        resource_id=str(sensor["id"]),
        details={"name": body.name, "type": body.sensor_type},
        source_ip=request.client.host if request.client else None,
    )
    return sensor


@router.put("/{sensor_id}/heartbeat")
def sensor_heartbeat(sensor_id: UUID, request: Request):
    """Called by sensors to check in and mark themselves ONLINE."""
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE sensors SET status = 'ONLINE', last_seen = now()
                WHERE id = %s RETURNING id, name, status, last_seen
                """,
                (str(sensor_id),),
            )
            sensor = cur.fetchone()
            conn.commit()
    if not sensor:
        raise HTTPException(status_code=404, detail="Sensor not found")
    return sensor


@router.patch("/{sensor_id}")
def update_sensor(
    sensor_id: UUID,
    body: SensorUpdate,
    current_user: dict = Depends(require_role("ADMIN")),
):
    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    set_clauses = ", ".join(f"{k} = %s" for k in updates)
    values = list(updates.values()) + [str(sensor_id)]

    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE sensors SET {set_clauses}
                WHERE id = %s RETURNING {_SELECT_COLS}
                """,
                values,
            )
            updated = cur.fetchone()
            conn.commit()

    if not updated:
        raise HTTPException(status_code=404, detail="Sensor not found")
    return updated


@router.delete("/{sensor_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_sensor(
    sensor_id: UUID,
    current_user: dict = Depends(require_role("ADMIN")),
):
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM sensors WHERE id = %s RETURNING id",
                (str(sensor_id),),
            )
            deleted = cur.fetchone()
            conn.commit()
    if not deleted:
        raise HTTPException(status_code=404, detail="Sensor not found")

    write_audit_log(
        actor_id=current_user["id"],
        actor=current_user["email"],
        action="SENSOR_DELETED",
        resource="sensors",
        resource_id=str(sensor_id),
    )
