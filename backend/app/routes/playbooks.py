"""
SOAR Playbooks & Remediation API Routes
"""

from typing import Any, Dict, List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from ..core.database import get_sync_connection
from ..core.security import get_current_user, require_role, write_audit_log
from ..services.soar_engine import soar_engine

router = APIRouter(prefix="/soar", tags=["soar"])

class PlaybookCreate(BaseModel):
    name: str
    description: str
    trigger_event: str
    severity_threshold: str = "HIGH"
    actions: List[str]
    is_active: bool = True

class PlaybookExecuteRequest(BaseModel):
    target: Optional[str] = None
    alert_id: Optional[str] = None
    parameters: Dict[str, Any] = {}

@router.get("/playbooks")
def list_playbooks(current_user: dict = Depends(get_current_user)):
    """List all available automated security response playbooks."""
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT p.id, p.name, p.description, p.trigger_event, p.severity_threshold,
                       p.actions, p.is_active, p.created_at,
                       COUNT(e.id) as total_executions,
                       MAX(e.executed_at) as last_executed
                FROM playbooks p
                LEFT JOIN playbook_executions e ON p.id = e.playbook_id
                GROUP BY p.id
                ORDER BY p.name ASC
                """
            )
            items = cur.fetchall()
            return {"items": items, "total": len(items)}

@router.post("/playbooks")
def create_playbook(
    body: PlaybookCreate,
    current_user: dict = Depends(require_role("ADMIN", "ANALYST"))
):
    """Create a new automated SOAR response playbook."""
    from psycopg.types.json import Jsonb
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO playbooks (name, description, trigger_event, severity_threshold, actions, is_active)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id, name, description, trigger_event, severity_threshold, actions, is_active, created_at
                """,
                (body.name, body.description, body.trigger_event, body.severity_threshold, Jsonb(body.actions), body.is_active)
            )
            created = cur.fetchone()
            conn.commit()

    write_audit_log(
        actor_id=current_user.get("id"),
        actor=current_user.get("email"),
        action="PLAYBOOK_CREATED",
        resource="playbooks",
        resource_id=str(created["id"]),
        details={"name": body.name, "trigger": body.trigger_event, "severity": body.severity_threshold},
    )
    return created

@router.post("/playbooks/{playbook_id}/execute")
def execute_playbook(
    playbook_id: UUID,
    body: PlaybookExecuteRequest,
    current_user: dict = Depends(require_role("ADMIN", "ANALYST"))
):
    """Trigger manual or automated execution of a response playbook."""
    try:
        res = soar_engine.execute_playbook(
            playbook_id=playbook_id,
            target=body.target,
            operator=current_user.get("email", "ANALYST")
        )
        write_audit_log(
            actor_id=current_user.get("id"),
            actor=current_user.get("email"),
            action="PLAYBOOK_EXECUTED",
            resource="playbooks",
            resource_id=str(playbook_id),
            details={"target": body.target, "operator": current_user.get("email")},
        )
        return res
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Execution failure: {str(e)}")

@router.get("/executions")
def list_executions(
    days: Optional[int] = Query(None, ge=1, le=365),
    limit: int = Query(50, ge=1, le=500),
    current_user: dict = Depends(get_current_user)
):
    """Retrieve audit history of executed SOAR playbooks with optional time window."""
    time_filter = ""
    params = []
    if days is not None:
        time_filter = "WHERE executed_at >= now() - interval '1 day' * %s"
        params.append(days)
    params.append(limit)

    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT id, playbook_id, playbook_name, alert_id, status, target,
                       actions_taken, logs, triggered_by, executed_at
                FROM playbook_executions
                {time_filter}
                ORDER BY executed_at DESC
                LIMIT %s
                """,
                params
            )
            items = cur.fetchall()
            return {"items": items, "total": len(items)}
