from prometheus_client import Counter, Histogram, Gauge

# ── Counters ──────────────────────────────────────────────────────────────────
alerts_ingested_total = Counter(
    "ids_alerts_ingested_total",
    "Total number of alerts ingested via the API",
    ["severity"],
)

incidents_created_total = Counter(
    "ids_incidents_created_total",
    "Total number of incidents created",
    ["severity"],
)

blocked_ips_total = Counter(
    "ids_blocked_ips_total",
    "Total number of IP block actions requested",
)

auth_attempts_total = Counter(
    "ids_auth_attempts_total",
    "Total authentication attempts",
    ["result"],  # success | failure
)

# ── Histograms ────────────────────────────────────────────────────────────────
api_request_duration_seconds = Histogram(
    "ids_api_request_duration_seconds",
    "API request duration in seconds",
    ["method", "path", "status_code"],
)

detection_engine_lag_seconds = Histogram(
    "ids_detection_engine_lag_seconds",
    "Time from alert ingestion to detection result",
)

# ── Gauges ────────────────────────────────────────────────────────────────────
open_alerts_gauge = Gauge(
    "ids_open_alerts",
    "Current number of open (unresolved) alerts",
)

active_sensors_gauge = Gauge(
    "ids_active_sensors",
    "Number of sensors with ONLINE status",
)

active_incidents_gauge = Gauge(
    "ids_active_incidents",
    "Number of incidents not yet resolved",
)
