"""
Detection rule management – CRUD for the `rules` table.

Roles:
  * VIEWER  – read-only
  * ANALYST – read-only
  * ADMIN   – full CRUD
"""

from __future__ import annotations

from typing import Any, Optional
from uuid import UUID

import psycopg
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from psycopg.types.json import Jsonb

from ..core.database import get_sync_connection
from ..core.security import get_current_user, require_role, write_audit_log

router = APIRouter(prefix="/rules", tags=["rules"])

_SELECT_COLS = """
    id, name, description, rule_type, enabled,
    severity, action, conditions, created_at, updated_at
"""


# ── Schemas ───────────────────────────────────────────────────────────────────

class RuleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = ""
    rule_type: str = Field(
        default="SIGNATURE",
        pattern="^(SIGNATURE|ANOMALY|THRESHOLD|COMPOSITE)$",
    )
    enabled: bool = True
    severity: str = Field(default="MEDIUM", pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    action: str = Field(default="ALERT", pattern="^(ALERT|BLOCK|LOG)$")
    conditions: dict[str, Any] = Field(default_factory=dict)


class RuleUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = None
    enabled: Optional[bool] = None
    severity: Optional[str] = Field(
        default=None, pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$"
    )
    action: Optional[str] = Field(default=None, pattern="^(ALERT|BLOCK|LOG)$")
    conditions: Optional[dict[str, Any]] = None


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("")
def list_rules(
    enabled: Optional[bool] = Query(None),
    rule_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    current_user: dict = Depends(get_current_user),
):
    conditions, params = [], []
    if enabled is not None:
        conditions.append("enabled = %s")
        params.append(enabled)
    if rule_type:
        conditions.append("rule_type = %s")
        params.append(rule_type.upper())
    if severity:
        conditions.append("severity = %s")
        params.append(severity.upper())

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params += [limit, skip]

    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT {_SELECT_COLS} FROM rules {where} ORDER BY created_at DESC LIMIT %s OFFSET %s",
                params,
            )
            items = cur.fetchall()
            cur.execute(f"SELECT COUNT(*) AS cnt FROM rules {where}", params[:-2])
            total = cur.fetchone()["cnt"]

    return {"items": items, "total": total}


@router.get("/{rule_id}")
def get_rule(rule_id: UUID, current_user: dict = Depends(get_current_user)):
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT {_SELECT_COLS} FROM rules WHERE id = %s",
                (str(rule_id),),
            )
            rule = cur.fetchone()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@router.post("", status_code=status.HTTP_201_CREATED)
def create_rule(
    body: RuleCreate,
    request: Request,
    current_user: dict = Depends(require_role("ADMIN")),
):
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute(
                    f"""
                    INSERT INTO rules
                        (name, description, rule_type, enabled, severity, action, conditions)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING {_SELECT_COLS}
                    """,
                    (
                        body.name,
                        body.description,
                        body.rule_type,
                        body.enabled,
                        body.severity,
                        body.action,
                        Jsonb(body.conditions),
                    ),
                )
                rule = cur.fetchone()
                conn.commit()
            except psycopg.errors.UniqueViolation:
                conn.rollback()
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Rule with name '{body.name}' already exists",
                )

    write_audit_log(
        actor_id=current_user["id"],
        actor=current_user["email"],
        action="RULE_CREATED",
        resource="rules",
        resource_id=str(rule["id"]),
        details={"name": body.name, "rule_type": body.rule_type},
        source_ip=request.client.host if request.client else None,
    )
    return rule


@router.patch("/{rule_id}")
def update_rule(
    rule_id: UUID,
    body: RuleUpdate,
    request: Request,
    current_user: dict = Depends(require_role("ADMIN")),
):
    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    # JSON columns need special handling
    set_parts, values = [], []
    for k, v in updates.items():
        if k == "conditions":
            set_parts.append(f"{k} = %s")
            values.append(Jsonb(v))
        else:
            set_parts.append(f"{k} = %s")
            values.append(v)

    set_clause = ", ".join(set_parts)
    values.append(str(rule_id))

    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE rules
                SET {set_clause}, updated_at = now()
                WHERE id = %s
                RETURNING {_SELECT_COLS}
                """,
                values,
            )
            rule = cur.fetchone()
            conn.commit()

    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    write_audit_log(
        actor_id=current_user["id"],
        actor=current_user["email"],
        action="RULE_UPDATED",
        resource="rules",
        resource_id=str(rule_id),
        details=updates,
        source_ip=request.client.host if request.client else None,
    )
    return rule


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(
    rule_id: UUID,
    request: Request,
    current_user: dict = Depends(require_role("ADMIN")),
):
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM rules WHERE id = %s RETURNING id",
                (str(rule_id),),
            )
            deleted = cur.fetchone()
            conn.commit()

    if not deleted:
        raise HTTPException(status_code=404, detail="Rule not found")

    write_audit_log(
        actor_id=current_user["id"],
        actor=current_user["email"],
        action="RULE_DELETED",
        resource="rules",
        resource_id=str(rule_id),
        source_ip=request.client.host if request.client else None,
    )


@router.patch("/{rule_id}/toggle")
def toggle_rule(
    rule_id: UUID,
    request: Request,
    current_user: dict = Depends(require_role("ADMIN")),
):
    """Flip the enabled flag without a full PATCH body."""
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE rules
                SET enabled = NOT enabled, updated_at = now()
                WHERE id = %s
                RETURNING {_SELECT_COLS}
                """,
                (str(rule_id),),
            )
            rule = cur.fetchone()
            conn.commit()

    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    write_audit_log(
        actor_id=current_user["id"],
        actor=current_user["email"],
        action="RULE_TOGGLED",
        resource="rules",
        resource_id=str(rule_id),
        details={"enabled": rule["enabled"]},
        source_ip=request.client.host if request.client else None,
    )
    return rule
