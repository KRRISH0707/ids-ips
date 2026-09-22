"""
Audit log viewer – compliance trail, read-only.

Only ADMIN users may view audit logs.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query

from ..core.database import get_sync_connection
from ..core.security import require_role

router = APIRouter(prefix="/audit-logs", tags=["audit-logs"])

_SELECT_COLS = """
    id, actor_id, actor, action, resource,
    resource_id, details, source_ip, created_at
"""


@router.get("")
def list_audit_logs(
    actor: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    resource: Optional[str] = Query(None),
    days: Optional[int] = Query(None, ge=1, le=365),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    current_user: dict = Depends(require_role("ADMIN")),
):
    """Paginated, filterable audit trail with time window support."""
    conditions, params = [], []
    if actor:
        conditions.append("actor ILIKE %s")
        params.append(f"%{actor}%")
    if action:
        conditions.append("action = %s")
        params.append(action.upper())
    if resource:
        conditions.append("resource = %s")
        params.append(resource)
    if days is not None:
        conditions.append("created_at >= now() - interval '1 day' * %s")
        params.append(days)

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params += [limit, skip]

    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT {_SELECT_COLS}
                FROM audit_logs {where}
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
                """,
                params,
            )
            items = cur.fetchall()
            cur.execute(
                f"SELECT COUNT(*) AS cnt FROM audit_logs {where}", params[:-2]
            )
            total = cur.fetchone()["cnt"]

    return {"items": items, "total": total}


@router.get("/actions")
def distinct_actions(current_user: dict = Depends(require_role("ADMIN"))):
    """Return the list of distinct action values for filter dropdowns."""
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT DISTINCT action FROM audit_logs ORDER BY action"
            )
            rows = cur.fetchall()
    return {"actions": [r["action"] for r in rows]}
