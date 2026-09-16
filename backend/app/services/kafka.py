"""
Lazy-initialised Kafka producer.

The producer is created on first use so that the application can start
even if Kafka is temporarily unavailable (e.g. during Docker Compose
sequential startup).
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
ALERT_TOPIC = os.getenv("KAFKA_ALERT_TOPIC", "ids.alerts")

_producer = None


def _get_producer():
    global _producer
    if _producer is None:
        from kafka import KafkaProducer  # type: ignore[import]

        _producer = KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
            retries=3,
        )
    return _producer


def publish_alert(alert: dict[str, Any]) -> None:
    """Publish an alert event to the Kafka alerts topic."""
    try:
        _get_producer().send(ALERT_TOPIC, value=alert)
        _get_producer().flush(timeout=2)
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning("Kafka publish failed (alert dropped): %s", exc)