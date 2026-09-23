import json
import math
import os
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import psycopg
import redis
import requests
from kafka import KafkaConsumer
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
ALERT_TOPIC = os.getenv("KAFKA_ALERT_TOPIC", "ids.alerts")
CONSUMER_GROUP = os.getenv("KAFKA_CONSUMER_GROUP", "detection-engine")

def _sanitize_db_url(raw_url: str) -> str:
    url = raw_url.replace("postgresql+psycopg://", "postgresql://")
    try:
        from urllib.parse import quote_plus
        if "://" in url:
            prefix, rest = url.split("://", 1)
            if "@" in rest:
                user_info, host_part = rest.rsplit("@", 1)
                if ":" in user_info:
                    username, password = user_info.split(":", 1)
                    if "%" not in password:
                        password = quote_plus(password)
                    return f"{prefix}://{username}:{password}@{host_part}"
    except Exception:
        pass
    return url

DATABASE_URL = _sanitize_db_url(os.getenv(
    "DATABASE_URL",
    "postgresql://idsips:change-me-in-development@postgres:5432/idsips",
))

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
OPENSEARCH_URL = os.getenv("OPENSEARCH_URL", "http://opensearch:9200")
OPENSEARCH_INDEX = os.getenv("OPENSEARCH_INDEX", "ids-alerts")

# Lazy Redis client
_redis_client: Optional[redis.Redis] = None


def get_redis_client() -> Optional[redis.Redis]:
    global _redis_client
    if _redis_client is None:
        try:
            _redis_client = redis.from_url(REDIS_URL, decode_responses=True)
            _redis_client.ping()
        except Exception as err:
            print(f"Warning: Redis connection failed ({err}). WebSocket real-time updates may be degraded.", flush=True)
            _redis_client = None
    return _redis_client


def get_connection():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


# ── Suricata Event Identification & Normalization ──────────────────────────────

def is_suricata_event(raw: dict[str, Any]) -> bool:
    """Detect if the payload is a raw or Vector-wrapped Suricata EVE JSON event."""
    if raw.get("ingest_source") == "suricata":
        return True
    if raw.get("event_type") in ("alert", "anomaly"):
        return True
    if "alert" in raw and isinstance(raw["alert"], dict) and "signature" in raw["alert"]:
        return True
    return False


def map_suricata_severity(eve_sev: Any) -> Tuple[str, int]:
    """
    Map Suricata severity integers to platform severity string and base risk score.
    In Suricata: 1 = Critical, 2 = High, 3 = Medium, 4 = Low / Info.
    """
    try:
        sev_int = int(eve_sev)
    except (ValueError, TypeError):
        sev_int = 3

    if sev_int == 1:
        return "CRITICAL", 92
    elif sev_int == 2:
        return "HIGH", 78
    elif sev_int == 3:
        return "MEDIUM", 50
    else:
        return "LOW", 25


def ensure_suricata_sensor(conn) -> str:
    """Ensure a Suricata network sensor entry exists in the PostgreSQL database."""
    with conn.cursor() as cur:
        cur.execute("SELECT id FROM sensors WHERE sensor_type = 'NETWORK' AND name ILIKE '%Suricata%' LIMIT 1")
        row = cur.fetchone()
        if row:
            return str(row["id"])

        cur.execute(
            """
            INSERT INTO sensors (name, hostname, sensor_type, status, version, metadata)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (
                "Suricata AF_PACKET Network Sensor",
                "suricata-sensor-01",
                "NETWORK",
                "ONLINE",
                "7.0.6",
                Jsonb({"interface": "eth0", "mode": "AF_PACKET", "pipeline": "Vector -> Kafka"}),
            ),
        )
        new_row = cur.fetchone()
        conn.commit()
        return str(new_row["id"])


def normalize_suricata_event(raw_event: dict[str, Any], conn) -> dict[str, Any]:
    """Normalize a Suricata EVE JSON event and persist it into the PostgreSQL alerts table."""
    alert_sub = raw_event.get("alert", {})
    if not isinstance(alert_sub, dict):
        alert_sub = {}

    sig = alert_sub.get("signature") or raw_event.get("signature") or "Suricata Real-Time Network Threat"
    cat = alert_sub.get("category") or raw_event.get("category") or "Network Intrusion"
    eve_sev = alert_sub.get("severity", 3)
    severity, base_risk = map_suricata_severity(eve_sev)

    src_ip = clean_ip(raw_event.get("src_ip") or "127.0.0.1")
    src_port = raw_event.get("src_port")
    dst_ip = clean_ip(raw_event.get("dest_ip") or raw_event.get("dst_ip") or "127.0.0.1")
    dst_port = raw_event.get("dest_port") or raw_event.get("dst_port")
    protocol = str(raw_event.get("proto") or "TCP").upper()

    ts = format_timestamp(raw_event.get("timestamp") or datetime.now(timezone.utc))

    sensor_id = ensure_suricata_sensor(conn)

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO alerts (
                sensor_id,
                timestamp,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                protocol,
                signature,
                category,
                severity,
                risk_score,
                status,
                raw_event
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, incident_id, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, signature, category, severity, risk_score, status, raw_event
            """,
            (
                sensor_id,
                ts,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                protocol,
                sig,
                cat,
                severity,
                base_risk,
                "OPEN",
                Jsonb(raw_event),
            ),
        )
        row = cur.fetchone()
        conn.commit()
        return dict(row)


# ── Mathematical Multi-Vector ML Anomaly Classifier ───────────────────────────

STRUCTURAL_CHARS = set("{}()[]<>;|&$%\\/'\"`!#*+^~")


def calculate_entropy(text: str) -> float:
    """Calculates Shannon Entropy H(X). Range 0.0 (uniform) to 8.0 (completely random/encrypted)."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def extract_ml_features(payload_str: str, alert: dict[str, Any]) -> dict[str, float]:
    """Extract statistical and structural anomaly features without reliance on static keywords."""
    entropy = calculate_entropy(payload_str)
    length = max(1, len(payload_str))

    delim_count = sum(1 for c in payload_str if c in STRUCTURAL_CHARS)
    delim_density = delim_count / length

    non_print_count = sum(1 for c in payload_str if ord(c) < 32 or ord(c) > 126)
    non_print_ratio = non_print_count / length

    # Byte variance
    if len(payload_str) > 1:
        vals = [ord(c) for c in payload_str]
        mean_b = sum(vals) / len(vals)
        variance = sum((b - mean_b) ** 2 for b in vals) / len(vals)
    else:
        variance = 0.0

    return {
        "entropy": entropy,
        "delim_density": delim_density,
        "non_print_ratio": non_print_ratio,
        "byte_variance": variance,
    }


def evaluate_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """
    Multi-vector detection: blends heuristic signature matching with
    unsupervised statistical anomaly evaluation.
    """
    severity = str(alert.get("severity", "LOW")).upper()
    risk_score = int(alert.get("risk_score", 0))
    category = str(alert.get("category", "")).lower()
    signature = str(alert.get("signature", "Generic Alert"))
    raw_event = alert.get("raw_event", {})
    if not isinstance(raw_event, dict):
        raw_event = {}

    # Gather textual payload representation for ML inspection
    payload_candidate = (
        raw_event.get("payload_printable")
        or raw_event.get("payload")
        or raw_event.get("http", {}).get("url")
        or signature
    )
    features = extract_ml_features(str(payload_candidate), alert)

    # Statistical anomaly distance calculation
    # Normal HTTP/text entropy is ~3.5; variance > 800 or high delimiters indicates shellcode/injection
    anomaly_distance = (
        max(0.0, (features["entropy"] - 3.4) * 0.45)
        + max(0.0, (features["delim_density"] - 0.15) * 2.2)
        + max(0.0, features["non_print_ratio"] * 3.5)
        + max(0.0, (features["byte_variance"] - 600.0) / 1000.0)
    )

    # Sigmoid mapping to probability [0.05, 0.99]
    anomaly_score = 1.0 / (1.0 + math.exp(-1.4 * (anomaly_distance - 1.2)))
    if severity == "CRITICAL":
        anomaly_score = max(anomaly_score, 0.92)
    elif severity == "HIGH":
        anomaly_score = max(anomaly_score, 0.78)

    anomaly_score = round(min(0.99, max(0.05, anomaly_score)), 3)

    detection_reasons = []

    if severity == "CRITICAL":
        detection_reasons.append("Critical severity intrusion signature")
    elif severity == "HIGH":
        detection_reasons.append("High severity intrusion signature")

    if risk_score >= 80:
        detection_reasons.append(f"Risk score is elevated ({risk_score}/100)")

    if anomaly_score >= 0.75:
        detection_reasons.append(f"AI Anomaly Model Divergence: {anomaly_score:.2f} (High statistical payload divergence)")
    elif anomaly_score >= 0.60:
        detection_reasons.append(f"AI Anomaly Model Score: {anomaly_score:.2f}")

    if any(k in category for k in ("brute_force", "attack", "injection", "exploit")):
        detection_reasons.append(f"Threat category heuristic: {category}")

    failed_attempts = int(raw_event.get("failed_attempts", 0))
    if failed_attempts >= 10:
        detection_reasons.append(f"Repeated authentication failures ({failed_attempts} attempts)")

    decision = "ESCALATE" if detection_reasons else "ACCEPT"

    return {
        "decision": decision,
        "reasons": detection_reasons,
        "anomaly_score": anomaly_score,
    }


# ── Storage & Escalation ───────────────────────────────────────────────────────

def save_detection_result(alert: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    alert_id = alert.get("id")
    if not alert_id:
        raise ValueError("Alert does not contain an id")

    decision = result["decision"]
    reasons = result["reasons"]
    anomaly_score = result.get("anomaly_score", 0.5)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO detection_results (
                    alert_id,
                    decision,
                    reasons,
                    anomaly_score
                )
                VALUES (%s, %s, %s, %s)
                RETURNING id
                """,
                (alert_id, decision, Jsonb(reasons), anomaly_score),
            )
            detection_result = cur.fetchone()
            incident_id = alert.get("incident_id")

            if decision == "ESCALATE" and not incident_id:
                severity = str(alert.get("severity", "MEDIUM")).upper()
                risk_score = int(alert.get("risk_score", 0))
                signature = str(alert.get("signature", "Security alert"))
                description = (
                    f"Autonomous Detection Engine escalated this incident. "
                    f"AI Anomaly Score: {anomaly_score:.2f}. "
                    f"Reasons: {', '.join(reasons)}"
                )

                is_contained = alert.get("status") == "AUTO_BLOCKED" or severity == "CRITICAL"
                inc_status = "CONTAINED" if is_contained else "NEW"

                cur.execute(
                    """
                    INSERT INTO incidents (
                        title,
                        description,
                        severity,
                        risk_score,
                        status
                    )
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (signature, description, severity, risk_score, inc_status),
                )
                incident = cur.fetchone()
                incident_id = incident["id"]

                cur.execute(
                    """
                    UPDATE alerts
                    SET incident_id = %s
                    WHERE id = %s
                    """,
                    (incident_id, alert_id),
                )

            # If Critical severity or high anomaly score, trigger autonomous IPS quarantine
            src_ip = alert.get("src_ip")
            should_block = (severity == "CRITICAL" or anomaly_score >= 0.85) and decision == "ESCALATE"
            if should_block and src_ip:
                clean_target = clean_ip(src_ip)
                if clean_target and clean_target not in ("127.0.0.1", "0.0.0.0", "localhost"):
                    cur.execute(
                        """
                        UPDATE alerts
                        SET status = 'AUTO_BLOCKED'
                        WHERE id = %s
                        """,
                        (alert_id,),
                    )
                    alert["status"] = "AUTO_BLOCKED"
                    block_reason = f"Autonomous Detection Engine Quarantine: {signature} (Anomaly: {anomaly_score:.2f})"

                    cur.execute(
                        """
                        INSERT INTO ips_actions (target, target_type, action, status, reason)
                        VALUES (%s, 'IP', 'DROP', 'ACTIVE', %s)
                        ON CONFLICT DO NOTHING
                        """,
                        (clean_target, block_reason),
                    )

                    # Persist into blocked_ips table so API gateway and dashboard sync immediately
                    cur.execute(
                        """
                        INSERT INTO blocked_ips (ip_address, reason, blocked_by, alert_id)
                        VALUES (%s::inet, %s, 'AUTONOMOUS_DETECTION_ENGINE', %s)
                        ON CONFLICT (ip_address) DO UPDATE
                            SET is_active = TRUE, blocked_at = NOW(), reason = EXCLUDED.reason
                        """,
                        (clean_target, block_reason, alert_id),
                    )

                    # Publish live command to Redis channel ids.ips.actions so IPS Controller drops packets immediately
                    r = get_redis_client()
                    if r:
                        try:
                            ips_event = {
                                "action": "BLOCK",
                                "ip_address": clean_target,
                                "reason": block_reason,
                                "alert_id": str(alert_id),
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                            }
                            r.publish("ids.ips.actions", json.dumps(ips_event))
                            print(f"⚡ [AUTONOMOUS IPS] Dispatched DROP command for {clean_target} to Redis ids.ips.actions", flush=True)

                            # If host isolation is warranted (e.g. ransomware, interactive reverse shell)
                            sig_lower = signature.lower()
                            if any(k in sig_lower for k in ("lockbit", "ransomware", "reverse shell", "c2", "trojan")):
                                r.publish("ips:host_isolation", json.dumps({
                                    "action": "ISOLATE",
                                    "hostname": clean_target,
                                    "ip_address": clean_target,
                                    "reason": f"Active containment: {signature}",
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                }))
                                print(f"🛡️ [AUTONOMOUS IPS] Dispatched HOST ISOLATION for {clean_target}", flush=True)
                        except Exception as pub_err:
                            print(f"Warning: Failed to publish IPS action to Redis ({pub_err})", flush=True)

            conn.commit()

    return {
        "detection_result_id": detection_result["id"],
        "decision": decision,
        "incident_id": incident_id,
        "anomaly_score": anomaly_score,
    }


def publish_to_live_subscribers(alert: dict[str, Any], result: dict[str, Any]) -> None:
    """Publish the processed alert to Redis pub/sub to push to WebSocket clients in real-time."""
    r = get_redis_client()
    if not r:
        return

    payload = {
        "id": str(alert.get("id")),
        "timestamp": format_timestamp(alert.get("timestamp")),
        "signature": alert.get("signature"),
        "severity": alert.get("severity"),
        "risk_score": alert.get("risk_score"),
        "category": alert.get("category"),
        "src_ip": clean_ip(alert.get("src_ip")),
        "src_port": alert.get("src_port"),
        "dst_ip": clean_ip(alert.get("dst_ip")),
        "dst_port": alert.get("dst_port"),
        "protocol": alert.get("protocol"),
        "status": alert.get("status", "OPEN"),
        "decision": result.get("decision"),
        "anomaly_score": result.get("anomaly_score"),
        "reasons": result.get("reasons", []),
    }

    try:
        data_str = json.dumps(payload, default=str)
        r.publish("alerts", data_str)
        r.publish("ids.live.alerts", data_str)
    except Exception as err:
        print(f"Warning: Failed to publish alert to Redis ({err})", flush=True)


# ── Utilities ──────────────────────────────────────────────────────────────────

def clean_ip(value):
    if value is None:
        return None
    value = str(value)
    if "/" in value:
        return value.split("/")[0]
    return value


def format_timestamp(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    value = str(value)
    try:
        parsed = datetime.fromisoformat(value.replace(" ", "T", 1))
        return parsed.isoformat().replace("+00:00", "Z")
    except ValueError:
        return value


def index_alert_in_opensearch(alert: dict[str, Any], result: dict[str, Any]):
    alert_id = str(alert.get("id"))
    if not alert_id:
        return

    document = {
        "alert_id": alert_id,
        "timestamp": format_timestamp(alert.get("timestamp")),
        "src_ip": clean_ip(alert.get("src_ip")),
        "src_port": alert.get("src_port"),
        "dst_ip": clean_ip(alert.get("dst_ip")),
        "dst_port": alert.get("dst_port"),
        "protocol": alert.get("protocol"),
        "signature": alert.get("signature"),
        "category": alert.get("category"),
        "severity": alert.get("severity"),
        "risk_score": alert.get("risk_score"),
        "status": alert.get("status"),
        "decision": result.get("decision"),
        "anomaly_score": result.get("anomaly_score"),
        "reasons": ", ".join(result.get("reasons", [])),
    }

    url = f"{OPENSEARCH_URL}/{OPENSEARCH_INDEX}/_doc/{alert_id}"

    try:
        requests.put(url, json=document, timeout=5)
    except Exception as err:
        print(f"Warning: OpenSearch index failed ({err})", flush=True)


def create_consumer():
    print(f"Connecting to Kafka at {KAFKA_BOOTSTRAP_SERVERS}...", flush=True)
    max_retries = 30
    retry_delay = 3
    for attempt in range(1, max_retries + 1):
        try:
            consumer = KafkaConsumer(
                ALERT_TOPIC,
                bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
                group_id=CONSUMER_GROUP,
                auto_offset_reset="earliest",
                enable_auto_commit=True,
                value_deserializer=lambda value: json.loads(value.decode("utf-8")),
            )
            print(f"Connected to Kafka broker on attempt {attempt}.", flush=True)
            return consumer
        except Exception as exc:
            if attempt == max_retries:
                raise
            print(f"Kafka not ready ({type(exc).__name__}: {exc}). Retrying {attempt}/{max_retries} in {retry_delay}s...", flush=True)
            time.sleep(retry_delay)


def main():
    print("================================================", flush=True)
    print("Starting Autonomous Detection Engine...", flush=True)
    print("Unified Ingress: Native Alerts + Suricata EVE", flush=True)
    print("================================================", flush=True)
    print(f"Kafka server: {KAFKA_BOOTSTRAP_SERVERS}", flush=True)
    print(f"Topic: {ALERT_TOPIC}", flush=True)
    print(f"Consumer group: {CONSUMER_GROUP}", flush=True)
    print(f"Database: {DATABASE_URL.split('@')[-1]}", flush=True)
    print(f"OpenSearch URL: {OPENSEARCH_URL}", flush=True)

    consumer = create_consumer()

    print("\nDetection Engine waiting for incoming telemetry...", flush=True)

    for message in consumer:
        try:
            raw_payload = message.value

            # Check if event is from Suricata EVE JSON or native internal alert
            if is_suricata_event(raw_payload):
                print("\n[INGEST: SURICATA EVE JSON DETECTED]", flush=True)
                with get_connection() as conn:
                    alert = normalize_suricata_event(raw_payload, conn)
            else:
                alert = raw_payload

            if not alert.get("id"):
                print("Skipping malformed alert without ID", flush=True)
                continue

            print(f"\n[EVALUATING ALERT] ID={alert.get('id')} Sig={alert.get('signature')} Sev={alert.get('severity')}", flush=True)

            result = evaluate_alert(alert)
            saved = save_detection_result(alert, result)

            print(f"[RESULT] Decision={result['decision']} AnomalyScore={result.get('anomaly_score')} IncidentID={saved.get('incident_id')}", flush=True)

            # Push live update to WebSockets
            publish_to_live_subscribers(alert, result)

            # Index into OpenSearch for search analytics
            index_alert_in_opensearch(alert, result)

        except Exception as exc:
            print(f"\n[ERROR] Processing alert: {type(exc).__name__}: {exc}", flush=True)
            time.sleep(0.5)


if __name__ == "__main__":
    main()
