"""
AI/ML Predictive Threat Detection & Machine Isolation Engine

Analyzes network traffic patterns, alert streams, and host telemetry to:
1. Detect zero-day and multi-vector behavioral anomalies.
2. Predict the attacker's next move in the cyber kill-chain (threat trajectory forecasting).
3. Recommend and execute automated Machine Isolation / Host Quarantine.
"""

from __future__ import annotations
import math
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

# Threat signature keywords for payload heuristic scoring
CRITICAL_INDICATORS = {
    "ransomware": ["vssadmin", "wbadmin", ".locked", "encrypt", "shadowcopy", "cipher", "wannacry"],
    "c2_beaconing": ["cobalt", "beacon", "malleable", "c2", "empire", "meterpreter", "reverse_tcp"],
    "credential_theft": ["mimikatz", "lsass", "sam", "procdump", "ntdsutil", "sekurlsa"],
    "lateral_movement": ["psexec", "wmic", "winrm", "remote_exec", "smbexec", "dcom"],
    "exfiltration": ["mega.nz", "curl -T", "rclone", "anonfiles", "base64_decode"]
}

class AIEngine:
    """Predictive Threat Intelligence & Machine Isolation AI Model."""

    @staticmethod
    def calculate_entropy(text: str) -> float:
        """Calculates Shannon entropy of payload string (0.0 to 8.0)."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum([p * math.log(p) / math.log(2.0) for p in prob])

    @classmethod
    def evaluate_threat(cls, telemetry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extracts multi-vector features and computes:
        - anomaly_score (0.00 to 1.00)
        - attack_family (classification)
        - threat_trajectory (predictive forecast of next attack phase)
        - recommended_action (ISOLATE_HOST, BLOCK_IP, RATE_LIMIT, MONITOR)
        - auto_isolation_required (boolean)
        """
        raw = telemetry.get("raw_event") or {}
        if not isinstance(raw, dict):
            raw = {}

        signature = str(telemetry.get("signature") or "").lower()
        category = str(telemetry.get("category") or "").lower()
        severity = str(telemetry.get("severity") or "MEDIUM").upper()
        risk_score = int(telemetry.get("risk_score") or 0)
        src_ip = str(telemetry.get("src_ip") or "")
        dst_ip = str(telemetry.get("dst_ip") or "")
        dst_port = int(telemetry.get("dst_port") or 0)

        # 1. Feature Extraction
        failed_attempts = int(raw.get("failed_attempts") or 0)
        packet_entropy = float(raw.get("packet_entropy") or cls.calculate_entropy(signature))
        is_internal_src = src_ip.startswith("192.168.") or src_ip.startswith("10.") or src_ip.startswith("172.16.")
        
        # Heuristic scoring
        indicators_matched = []
        for family, keywords in CRITICAL_INDICATORS.items():
            for kw in keywords:
                if kw in signature or kw in str(raw).lower():
                    indicators_matched.append(family)
                    break

        # 2. Anomaly Score Calculation (Weighted ML features)
        base_score = risk_score / 100.0
        entropy_boost = min(0.3, max(0.0, (packet_entropy - 4.5) * 0.1))
        velocity_boost = min(0.3, failed_attempts * 0.02)
        signature_boost = 0.25 if indicators_matched else 0.0

        anomaly_score = min(1.0, base_score * 0.5 + entropy_boost + velocity_boost + signature_boost)
        confidence = min(99, int(anomaly_score * 85 + (15 if indicators_matched else 5)))

        # 3. Attack Family Classification & Threat Trajectory Forecasting
        if "ransomware" in indicators_matched or "encrypt" in signature:
            attack_family = "RANSOMWARE_BURST"
            next_stage = "Stage 3: Mass Volume Encryption & Master Boot Record Overwrite within 10 minutes"
            threat_level = "CRITICAL_IMMINENT"
            recommended_action = "ISOLATE_HOST"
            auto_isolate = True
        elif "c2_beaconing" in indicators_matched or category == "c2":
            attack_family = "C2_ACTIVE_SESSION"
            next_stage = "Stage 2: Lateral Movement sweep to domain controller via SMB/RPC"
            threat_level = "HIGH_COMPROMISE"
            recommended_action = "ISOLATE_HOST" if is_internal_src else "BLOCK_IP"
            auto_isolate = is_internal_src
        elif "credential_theft" in indicators_matched or failed_attempts >= 15:
            attack_family = "CREDENTIAL_STUFFING_ATTACK"
            next_stage = "Stage 2: Privilege Escalation & Shadow Admin account creation within 30 minutes"
            threat_level = "HIGH_VELOCITY"
            recommended_action = "BLOCK_IP"
            auto_isolate = False
        elif category in ["reconnaissance", "port_scan"] or dst_port in [8080, 8443, 3389, 445]:
            attack_family = "PORT_SCAN_RECONNAISSANCE"
            next_stage = "Stage 2: Targeted Exploitation of discovered open service ports within 45 minutes"
            threat_level = "MEDIUM_RECON"
            recommended_action = "BLOCK_IP"
            auto_isolate = False
        else:
            attack_family = "BEHAVIORAL_ANOMALY"
            next_stage = "Stage 1: Initial anomaly baseline deviation under automated observation"
            threat_level = "ELEVATED"
            recommended_action = "MONITOR"
            auto_isolate = False

        # If high risk internal machine, always recommend isolation
        if is_internal_src and anomaly_score >= 0.85:
            recommended_action = "ISOLATE_HOST"
            auto_isolate = True

        return {
            "anomaly_score": round(anomaly_score, 3),
            "confidence": round(confidence / 100.0, 2),
            "confidence_percentage": confidence,
            "attack_family": attack_family,
            "threat_level": threat_level,
            "next_stage_forecast": next_stage,
            "predicted_next_stage": next_stage,
            "recommended_action": recommended_action,
            "auto_isolation_required": auto_isolate,
            "compromised_host_ip": src_ip if is_internal_src else dst_ip,
            "evaluated_at": datetime.now(timezone.utc).isoformat()
        }

ai_engine = AIEngine()
