"""
Platform Configuration & Engine Settings API Router
"""

from typing import Optional
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from ..core.security import get_current_user, require_role, write_audit_log

router = APIRouter(prefix="/settings", tags=["settings"])

class SystemSettingsUpdate(BaseModel):
    anomalySensitivity: Optional[str] = "0.85"
    maxAlertsPerMin: Optional[str] = "500"
    autoBlockThreshold: Optional[str] = "0.92"
    kafkaBatchSize: Optional[str] = "100"

_current_settings = {
    "anomalySensitivity": "0.85",
    "maxAlertsPerMin": "500",
    "autoBlockThreshold": "0.92",
    "kafkaBatchSize": "100"
}

@router.get("")
def get_settings_config(current_user: dict = Depends(get_current_user)):
    return _current_settings

@router.post("")
def update_settings_config(
    body: SystemSettingsUpdate,
    request: Request,
    current_user: dict = Depends(require_role("ADMIN"))
):
    global _current_settings
    updates = body.model_dump(exclude_none=True)
    _current_settings.update(updates)

    write_audit_log(
        actor_id=current_user["id"],
        actor=current_user["email"],
        action="SETTINGS_UPDATED",
        resource="system_settings",
        resource_id="global",
        details=updates,
        source_ip=request.client.host if request.client else None,
    )
    return {"status": "success", "settings": _current_settings}
