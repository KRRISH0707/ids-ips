"""
AI Threat Insights & Predictive Security Endpoints
"""

from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..core.database import get_sync_connection
from ..core.security import get_current_user
from ..services.ai_engine import ai_engine

router = APIRouter(prefix="/ai", tags=["ai"])

class ThreatPredictionRequest(BaseModel):
    src_ip: str
    dst_ip: str
    dst_port: int = 80
    protocol: str = "TCP"
    signature: str = ""
    category: str = "unknown"
    severity: str = "MEDIUM"
    risk_score: int = 50
    raw_event: Dict[str, Any] = {}

@router.post("/predict")
def predict_threat(
    body: ThreatPredictionRequest,
    current_user: dict = Depends(get_current_user)
):
    """Run real-time AI/ML threat evaluation & attack trajectory forecast."""
    prediction = ai_engine.evaluate_threat(body.model_dump())
    return prediction

@router.get("/forecast")
def get_threat_forecast(current_user: dict = Depends(get_current_user)):
    """
    Returns aggregated AI predictions, top predicted threat vectors,
    and host machines at high risk of isolation.
    """
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            # Query recent high-severity alerts to generate AI threat summary
            cur.execute(
                """
                SELECT id, src_ip::text, dst_ip::text, signature, category, severity, risk_score, timestamp
                FROM alerts
                ORDER BY timestamp DESC
                LIMIT 20
                """
            )
            recent_alerts = cur.fetchall()

            # Query count of isolated sensors
            cur.execute("SELECT COUNT(*) as isolated_count FROM sensors WHERE status = 'ISOLATED'")
            isolated_count = cur.fetchone()["isolated_count"]

    predictions = []
    top_threat_vectors = {}
    high_risk_hosts = set()

    for alert in recent_alerts:
        eval_res = ai_engine.evaluate_threat(alert)
        predictions.append(eval_res)
        family = eval_res["attack_family"]
        top_threat_vectors[family] = top_threat_vectors.get(family, 0) + 1
        if eval_res["auto_isolation_required"] or eval_res["anomaly_score"] >= 0.85:
            high_risk_hosts.add(eval_res["compromised_host_ip"])

    avg_anomaly = (
        sum(p["anomaly_score"] for p in predictions) / len(predictions)
        if predictions
        else 0.15
    )

    return {
        "global_ai_threat_level": "ELEVATED" if avg_anomaly > 0.6 else "NORMAL",
        "average_anomaly_score": round(avg_anomaly, 2),
        "total_analyzed": len(recent_alerts),
        "isolated_machines_count": isolated_count,
        "high_risk_hosts": list(high_risk_hosts),
        "top_predicted_vectors": top_threat_vectors,
        "latest_predictions": predictions[:5],
        "recommendation": (
            "Immediate Host Quarantine Recommended for compromised endpoints"
            if high_risk_hosts
            else "Standard telemetry monitoring active"
        )
    }
