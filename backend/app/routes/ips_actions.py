"""
IPS actions – block / unblock IP addresses.

Writes to the `blocked_ips` table and publishes a Redis event so the
IPS controller picks it up immediately.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

import ipaddress
import psycopg
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from ..core.database import get_sync_connection
from ..core.metrics import blocked_ips_total
from ..core.security import get_current_user, require_role, write_audit_log
from ..services.redis_pubsub import publish_ips_action

router = APIRouter(prefix="/ips-actions", tags=["ips-actions"])

_SELECT_COLS = """
    id, ip_address::text AS ip_address, reason, blocked_by,
    blocked_at, expires_at, is_active, alert_id
"""


# ── Schemas ───────────────────────────────────────────────────────────────────

class BlockRequest(BaseModel):
    ip_address: str = Field(..., min_length=7, max_length=45)
    reason: str = Field(..., min_length=1, max_length=500)
    alert_id: Optional[UUID] = None
    expires_at: Optional[datetime] = None  # None = permanent


class UnblockRequest(BaseModel):
    reason: str = Field(default="Manually unblocked", max_length=500)


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("")
def list_blocked_ips(
    is_active: Optional[bool] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    current_user: dict = Depends(get_current_user),
):
    conditions, params = [], []
    if is_active is not None:
        conditions.append("is_active = %s")
        params.append(is_active)
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params += [limit, skip]

    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT {_SELECT_COLS}
                FROM blocked_ips {where}
                ORDER BY blocked_at DESC
                LIMIT %s OFFSET %s
                """,
                params,
            )
            items = cur.fetchall()
            cur.execute(
                f"SELECT COUNT(*) AS cnt FROM blocked_ips {where}", params[:-2]
            )
            total = cur.fetchone()["cnt"]

    return {"items": items, "total": total}


@router.get("/{block_id}")
def get_blocked_ip(block_id: UUID, current_user: dict = Depends(get_current_user)):
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT {_SELECT_COLS} FROM blocked_ips WHERE id = %s",
                (str(block_id),),
            )
            record = cur.fetchone()
    if not record:
        raise HTTPException(status_code=404, detail="Block record not found")
    return record


@router.post("", status_code=status.HTTP_201_CREATED)
def block_ip(
    body: BlockRequest,
    request: Request,
    current_user: dict = Depends(require_role("ADMIN", "ANALYST")),
):
    # Edge case protection: validate IP address & prevent blocking loopback/system addresses
    try:
        ip_obj = ipaddress.ip_address(body.ip_address.strip())
        if ip_obj.is_loopback or ip_obj.is_unspecified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot block protected system/loopback address: {body.ip_address}",
            )
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid IP address format: {body.ip_address}",
        )

    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute(
                    f"""
                    INSERT INTO blocked_ips
                        (ip_address, reason, blocked_by, expires_at, alert_id)
                    VALUES (%s::inet, %s, %s, %s, %s)
                    RETURNING {_SELECT_COLS}
                    """,
                    (
                        body.ip_address,
                        body.reason,
                        current_user["email"],
                        body.expires_at,
                        body.alert_id,
                    ),
                )
                record = cur.fetchone()
                conn.commit()
            except psycopg.errors.UniqueViolation:
                conn.rollback()
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"IP {body.ip_address} is already blocked",
                )
            except psycopg.Error as exc:
                conn.rollback()
                raise HTTPException(status_code=400, detail=f"Invalid IP address: {exc}")

    blocked_ips_total.inc()

    action_payload = {
        "action": "BLOCK",
        "ip_address": body.ip_address,
        "reason": body.reason,
        "block_id": str(record["id"]),
        "expires_at": body.expires_at.isoformat() if body.expires_at else None,
    }
    try:
        publish_ips_action(action_payload)
    except Exception:
        pass  # Controller will reconcile on next poll

    write_audit_log(
        actor_id=current_user["id"],
        actor=current_user["email"],
        action="IP_BLOCKED",
        resource="blocked_ips",
        resource_id=str(record["id"]),
        details={"ip": body.ip_address, "reason": body.reason},
        source_ip=request.client.host if request.client else None,
    )
    return record


@router.delete("/{block_id}", status_code=status.HTTP_200_OK)
def unblock_ip(
    block_id: UUID,
    body: UnblockRequest,
    request: Request,
    current_user: dict = Depends(require_role("ADMIN", "ANALYST")),
):
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE blocked_ips
                SET is_active = false
                WHERE id = %s AND is_active = true
                RETURNING {_SELECT_COLS}
                """,
                (str(block_id),),
            )
            record = cur.fetchone()
            conn.commit()

    if not record:
        raise HTTPException(
            status_code=404,
            detail="Block record not found or already inactive",
        )

    action_payload = {
        "action": "UNBLOCK",
        "ip_address": record["ip_address"],
        "reason": body.reason,
        "block_id": str(block_id),
    }
    try:
        publish_ips_action(action_payload)
    except Exception:
        pass

    write_audit_log(
        actor_id=current_user["id"],
        actor=current_user["email"],
        action="IP_UNBLOCKED",
        resource="blocked_ips",
        resource_id=str(block_id),
        details={"ip": record["ip_address"], "reason": body.reason},
        source_ip=request.client.host if request.client else None,
    )
    return {"unblocked": True, "record": record}


@router.get("/stats/summary")
def ips_stats(current_user: dict = Depends(get_current_user)):
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    COUNT(*) FILTER (WHERE is_active)               AS active_blocks,
                    COUNT(*) FILTER (WHERE NOT is_active)           AS lifted_blocks,
                    COUNT(*) FILTER (WHERE blocked_at > now() - interval '24 hours') AS last_24h,
                    COUNT(*) FILTER (WHERE expires_at IS NULL AND is_active) AS permanent_blocks
                FROM blocked_ips
                """
            )
            return cur.fetchone()
