"""
Prometheus metrics scrape endpoint.

Exposes the standard /metrics text format.  Only ADMIN users should be able
to reach this via the API gateway; the raw scrape path is also available
directly from the container port for Prometheus.
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

router = APIRouter(prefix="/metrics", tags=["metrics"])


@router.get("", response_class=Response)
def prometheus_metrics():
    """Return Prometheus text-format metrics."""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )
