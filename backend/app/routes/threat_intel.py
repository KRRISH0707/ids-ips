"""
Threat Intelligence Hub & Live IOC Matching API Router
"""

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from psycopg.types.json import Jsonb

from ..core.database import get_sync_connection
from ..core.security import get_current_user, require_role, write_audit_log

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])

class IOCCreate(BaseModel):
    ioc_type: str
    value: str
    threat_type: str
    confidence: int = 90
    source: str = "SOC Internal Feed"
    tags: List[str] = []

class IOCLookupRequest(BaseModel):
    value: str
    ioc_type: Optional[str] = None

@router.get("")
def list_threat_intel(
    ioc_type: Optional[str] = None,
    q: Optional[str] = None,
    days: Optional[int] = Query(None, ge=1, le=365),
    limit: int = Query(500, ge=1, le=2000),
    current_user: dict = Depends(get_current_user)
):
    """List Threat Intelligence Indicators of Compromise (IOCs) with optional time-window filtering."""
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            # Self-healing check: if threat_intel has fewer than 200 items, auto-seed immediately!
            cur.execute("SELECT COUNT(*) as count FROM threat_intel")
            cnt_row = cur.fetchone()
            cnt = (cnt_row.get("count") if isinstance(cnt_row, dict) else cnt_row[0]) or 0
            if cnt < 200:
                try:
                    from ..seed_iocs_data import seed_threat_intel_iocs
                    seed_threat_intel_iocs(conn)
                except Exception:
                    pass

            query = "SELECT id, ioc_type, value, threat_type, confidence, source, tags, created_at FROM threat_intel WHERE 1=1"
            params = []

            if ioc_type:
                query += " AND ioc_type = %s"
                params.append(ioc_type.upper())
            if q:
                query += " AND (value ILIKE %s OR threat_type ILIKE %s OR source ILIKE %s)"
                params.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
            if days is not None:
                query += " AND created_at >= now() - interval '1 day' * %s"
                params.append(days)

            query += " ORDER BY confidence DESC, created_at DESC LIMIT %s"
            params.append(limit)

            cur.execute(query, params)
            items = cur.fetchall()

            # Feed summary statistics (scoped to same time window)
            breakdown_query = "SELECT ioc_type, COUNT(*) as count FROM threat_intel WHERE 1=1"
            breakdown_params = []
            if days is not None:
                breakdown_query += " AND created_at >= now() - interval '1 day' * %s"
                breakdown_params.append(days)
            breakdown_query += " GROUP BY ioc_type"
            cur.execute(breakdown_query, breakdown_params)
            breakdown = {row["ioc_type"]: row["count"] for row in cur.fetchall()}

            return {
                "items": items,
                "total": len(items),
                "breakdown": breakdown
            }

@router.post("/lookup")
def lookup_threat_indicator(
    body: IOCLookupRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Query real-time reputation score and threat classification for an IP, domain, or hash.
    """
    clean_val = body.value.strip().lower()
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            # Self-healing check if database needs baseline seeding
            cur.execute("SELECT COUNT(*) as count FROM threat_intel")
            cnt_row = cur.fetchone()
            cnt = (cnt_row.get("count") if isinstance(cnt_row, dict) else cnt_row[0]) or 0
            if cnt < 200:
                try:
                    from ..seed_iocs_data import seed_threat_intel_iocs
                    seed_threat_intel_iocs(conn)
                except Exception:
                    pass

            query = """
                SELECT id, ioc_type, value, threat_type, confidence, source, tags, created_at
                FROM threat_intel
                WHERE (LOWER(value) = %s OR LOWER(value) LIKE %s)
            """
            params = [clean_val, f"%{clean_val}%"]
            if body.ioc_type:
                query += " AND ioc_type = %s"
                params.append(body.ioc_type.upper())
            query += " ORDER BY (LOWER(value) = %s) DESC, confidence DESC LIMIT 1"
            params.append(clean_val)

            cur.execute(query, params)
            matched = cur.fetchone()

    if matched:
        rep_level = "MALICIOUS" if matched["confidence"] >= 80 else "SUSPICIOUS"
        return {
            "query": body.value,
            "status": "IDENTIFIED_THREAT",
            "reputation_level": rep_level,
            "reputation_score": matched["confidence"],
            "threat_family": matched["threat_type"],
            "source": matched["source"],
            "tags": matched.get("tags", []),
            "matched_indicator": matched
        }

    return {
        "query": body.value,
        "status": "NOT_FLAGGED",
        "reputation_level": "CLEAN",
        "reputation_score": 10,
        "threat_family": "BENIGN_TELEMETRY",
        "source": "Global Threat Feed (No match)",
        "tags": ["unclassified"]
    }

@router.post("/indicators")
def add_threat_indicator(
    body: IOCCreate,
    current_user: dict = Depends(require_role("ADMIN", "ANALYST"))
):
    """Add a verified IOC to the enterprise threat intelligence database."""
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO threat_intel (ioc_type, value, threat_type, confidence, source, tags)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (ioc_type, value) DO UPDATE
                SET confidence = EXCLUDED.confidence,
                    threat_type = EXCLUDED.threat_type,
                    source = EXCLUDED.source,
                    tags = EXCLUDED.tags
                RETURNING id, ioc_type, value, threat_type, confidence, source, tags, created_at
                """,
                (body.ioc_type.upper(), body.value, body.threat_type, body.confidence, body.source, Jsonb(body.tags))
            )
            created = cur.fetchone()
            conn.commit()

    write_audit_log(
        actor_id=current_user.get("id"),
        actor=current_user.get("email"),
        action="THREAT_INDICATOR_ADDED",
        resource="threat_intel",
        resource_id=str(created["id"]),
        details={"ioc_type": body.ioc_type, "value": body.value, "threat_type": body.threat_type, "confidence": body.confidence},
    )
    return created
