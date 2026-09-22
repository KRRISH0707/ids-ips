"""
MITRE ATT&CK Matrix & Heatmap API Router
"""

from fastapi import APIRouter, Depends
from ..core.security import get_current_user
from ..services.mitre_engine import mitre_engine

router = APIRouter(prefix="/mitre", tags=["mitre"])

@router.get("/matrix")
def get_mitre_matrix(current_user: dict = Depends(get_current_user)):
    """Retrieve full MITRE ATT&CK enterprise tactic heatmap & detection mapping."""
    return mitre_engine.get_matrix_coverage()

@router.get("/techniques/{technique_id}")
def get_technique_details(technique_id: str, current_user: dict = Depends(get_current_user)):
    """Retrieve deep descriptive intelligence, detection signatures, mitigations, and live alerts for a MITRE technique."""
    return mitre_engine.get_technique_profile(technique_id)
