import json
import os
import time
from datetime import datetime
from typing import Any

import psycopg
import requests
from kafka import KafkaConsumer
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb


KAFKA_BOOTSTRAP_SERVERS = os.getenv(
    "KAFKA_BOOTSTRAP_SERVERS",
    "kafka:9092",
)

ALERT_TOPIC = os.getenv(
    "KAFKA_ALERT_TOPIC",
    "ids.alerts",
)

CONSUMER_GROUP = os.getenv(
    "KAFKA_CONSUMER_GROUP",
    "detection-engine",
)

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://idsips:change-me-in-development@postgres:5432/idsips",
).replace(
    "postgresql+psycopg://",
    "postgresql://",
)

OPENSEARCH_URL = os.getenv(
    "OPENSEARCH_URL",
    "http://opensearch:9200",
)

OPENSEARCH_INDEX = os.getenv(
    "OPENSEARCH_INDEX",
    "ids-alerts",
)


def get_connection():
    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row,
    )


def evaluate_alert(
    alert: dict[str, Any],
) -> dict[str, Any]:

    severity = str(
        alert.get(
            "severity",
            "LOW",
        )
    ).upper()

    risk_score = int(
        alert.get(
            "risk_score",
            0,
        )
    )

    category = str(
        alert.get(
            "category",
            "",
        )
    ).lower()

    raw_event = alert.get(
        "raw_event",
        {},
    )

    if not isinstance(raw_event, dict):
        raw_event = {}

    detection_reasons = []

    if severity == "CRITICAL":
        detection_reasons.append(
            "Critical severity alert"
        )

    if severity == "HIGH":
        detection_reasons.append(
            "High severity alert"
        )

    if risk_score >= 80:
        detection_reasons.append(
            "Risk score is 80 or higher"
        )

    if category == "brute_force":
        detection_reasons.append(
            "Brute-force activity detected"
        )

    failed_attempts = int(
        raw_event.get(
            "failed_attempts",
            0,
        )
    )

    if failed_attempts >= 10:
        detection_reasons.append(
            "10 or more failed attempts"
        )

    decision = (
        "ESCALATE"
        if detection_reasons
        else "ACCEPT"
    )

    return {
        "decision": decision,
        "reasons": detection_reasons,
    }


def save_detection_result(
    alert: dict[str, Any],
    result: dict[str, Any],
):

    alert_id = alert.get("id")

    if not alert_id:
        raise ValueError(
            "Alert does not contain an id"
        )

    decision = result["decision"]
    reasons = result["reasons"]

    with get_connection() as conn:

        with conn.cursor() as cur:

            cur.execute(
                """
                INSERT INTO detection_results (
                    alert_id,
                    decision,
                    reasons
                )
                VALUES (
                    %s,
                    %s,
                    %s
                )
                RETURNING id
                """,
                (
                    alert_id,
                    decision,
                    Jsonb(reasons),
                ),
            )

            detection_result = cur.fetchone()

            incident_id = None

            if decision == "ESCALATE":

                severity = str(
                    alert.get(
                        "severity",
                        "MEDIUM",
                    )
                ).upper()

                risk_score = int(
                    alert.get(
                        "risk_score",
                        0,
                    )
                )

                signature = str(
                    alert.get(
                        "signature",
                        "Security alert",
                    )
                )

                description = (
                    "Detection Engine escalated "
                    "this alert. Reasons: "
                    f"{', '.join(reasons)}"
                )

                cur.execute(
                    """
                    INSERT INTO incidents (
                        title,
                        description,
                        severity,
                        risk_score,
                        status
                    )
                    VALUES (
                        %s,
                        %s,
                        %s,
                        %s,
                        'NEW'
                    )
                    RETURNING id
                    """,
                    (
                        signature,
                        description,
                        severity,
                        risk_score,
                    ),
                )

                incident = cur.fetchone()

                incident_id = incident["id"]

                cur.execute(
                    """
                    UPDATE alerts
                    SET incident_id = %s
                    WHERE id = %s
                    """,
                    (
                        incident_id,
                        alert_id,
                    ),
                )

            conn.commit()

    return {
        "detection_result_id": detection_result["id"],
        "decision": decision,
        "incident_id": incident_id,
    }


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
        return value.isoformat().replace(
            "+00:00",
            "Z",
        )

    value = str(value)

    try:
        parsed = datetime.fromisoformat(
            value.replace(
                " ",
                "T",
                1,
            )
        )

        return parsed.isoformat().replace(
            "+00:00",
            "Z",
        )

    except ValueError:
        return value


def index_alert_in_opensearch(
    alert: dict[str, Any],
    result: dict[str, Any],
):

    alert_id = str(
        alert.get("id")
    )

    if not alert_id:
        raise ValueError(
            "Alert does not contain an id"
        )

    document = {
        "alert_id": alert_id,

        "timestamp": format_timestamp(
            alert.get("timestamp")
        ),

        "src_ip": clean_ip(
            alert.get("src_ip")
        ),

        "src_port": alert.get(
            "src_port"
        ),

        "dst_ip": clean_ip(
            alert.get("dst_ip")
        ),

        "dst_port": alert.get(
            "dst_port"
        ),

        "protocol": alert.get(
            "protocol"
        ),

        "signature": alert.get(
            "signature"
        ),

        "category": alert.get(
            "category"
        ),

        "severity": alert.get(
            "severity"
        ),

        "risk_score": alert.get(
            "risk_score"
        ),

        "status": alert.get(
            "status"
        ),

        "decision": result.get(
            "decision"
        ),

        "reasons": ", ".join(
            result.get(
                "reasons",
                [],
            )
        ),
    }

    url = (
        f"{OPENSEARCH_URL}/"
        f"{OPENSEARCH_INDEX}/"
        f"_doc/{alert_id}"
    )

    print(
        "\nSENDING TO OPENSEARCH",
        flush=True,
    )

    print(
        json.dumps(
            document,
            indent=2,
            default=str,
        ),
        flush=True,
    )

    response = requests.put(
        url,
        json=document,
        timeout=10,
    )

    if not response.ok:

        print(
            "\nOPENSEARCH ERROR",
            flush=True,
        )

        print(
            f"HTTP STATUS: {response.status_code}",
            flush=True,
        )

        print(
            response.text,
            flush=True,
        )

        response.raise_for_status()

    print(
        "\nOPENSEARCH RESULT",
        flush=True,
    )

    print(
        json.dumps(
            response.json(),
            indent=2,
        ),
        flush=True,
    )


def create_consumer():

    print(
        "Connecting to Kafka...",
        flush=True,
    )

    consumer = KafkaConsumer(
        ALERT_TOPIC,
        bootstrap_servers=(
            KAFKA_BOOTSTRAP_SERVERS
        ),
        group_id=CONSUMER_GROUP,
        auto_offset_reset="earliest",
        enable_auto_commit=True,
        value_deserializer=lambda value:
            json.loads(
                value.decode("utf-8")
            ),
    )

    return consumer


def main():

    print(
        "================================",
        flush=True,
    )

    print(
        "Starting Detection Engine...",
        flush=True,
    )

    print(
        "================================",
        flush=True,
    )

    print(
        f"Kafka server: "
        f"{KAFKA_BOOTSTRAP_SERVERS}",
        flush=True,
    )

    print(
        f"Topic: "
        f"{ALERT_TOPIC}",
        flush=True,
    )

    print(
        f"Consumer group: "
        f"{CONSUMER_GROUP}",
        flush=True,
    )

    print(
        f"Database: "
        f"{DATABASE_URL.split('@')[-1]}",
        flush=True,
    )

    print(
        f"OpenSearch URL: "
        f"{OPENSEARCH_URL}",
        flush=True,
    )

    print(
        f"OpenSearch index: "
        f"{OPENSEARCH_INDEX}",
        flush=True,
    )

    consumer = create_consumer()

    print(
        "\nDetection Engine is waiting "
        "for alerts...",
        flush=True,
    )

    for message in consumer:

        try:

            alert = message.value

            print(
                "\n==============================",
                flush=True,
            )

            print(
                "ALERT RECEIVED",
                flush=True,
            )

            print(
                "==============================",
                flush=True,
            )

            print(
                json.dumps(
                    alert,
                    indent=2,
                    default=str,
                ),
                flush=True,
            )

            result = evaluate_alert(
                alert
            )

            print(
                "\nDETECTION RESULT",
                flush=True,
            )

            print(
                "==============================",
                flush=True,
            )

            print(
                json.dumps(
                    result,
                    indent=2,
                ),
                flush=True,
            )

            saved = save_detection_result(
                alert,
                result,
            )

            print(
                "\nDATABASE RESULT",
                flush=True,
            )

            print(
                "==============================",
                flush=True,
            )

            print(
                json.dumps(
                    saved,
                    indent=2,
                    default=str,
                ),
                flush=True,
            )

            index_alert_in_opensearch(
                alert,
                result,
            )

            print(
                "\nALERT PROCESSING COMPLETE",
                flush=True,
            )

        except Exception as exc:

            print(
                "\nERROR PROCESSING ALERT",
                flush=True,
            )

            print(
                f"{type(exc).__name__}: {exc}",
                flush=True,
            )

            time.sleep(1)


if __name__ == "__main__":
    main()
