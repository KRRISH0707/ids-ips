-- ============================================================
-- Enterprise IDS/IPS Platform — PostgreSQL Schema
-- ============================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================
-- ORGANIZATIONS
-- ============================================================
CREATE TABLE IF NOT EXISTS organizations (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================
-- USERS & AUTH
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT        NOT NULL UNIQUE,
    hashed_password TEXT        NOT NULL,
    full_name       TEXT,
    role            TEXT        NOT NULL DEFAULT 'ANALYST'
                                CHECK (role IN ('VIEWER','ANALYST','ADMIN')),
    is_active       BOOLEAN     NOT NULL DEFAULT TRUE,
    last_login      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS api_keys (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT        NOT NULL,
    key_hash    TEXT        NOT NULL UNIQUE,
    key_prefix  TEXT        NOT NULL,
    is_active   BOOLEAN     NOT NULL DEFAULT TRUE,
    expires_at  TIMESTAMPTZ,
    last_used   TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================
-- SENSORS
-- ============================================================
CREATE TABLE IF NOT EXISTS sensors (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL,
    hostname    TEXT,
    ip_address  INET,
    location    TEXT,
    sensor_type TEXT        NOT NULL DEFAULT 'NETWORK'
                            CHECK (sensor_type IN ('NETWORK','HOST','HYBRID')),
    status      TEXT        NOT NULL DEFAULT 'UNKNOWN'
                            CHECK (status IN ('ONLINE','OFFLINE','DEGRADED','UNKNOWN')),
    version     TEXT,
    last_seen   TIMESTAMPTZ,
    metadata    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================
-- DETECTION RULES
-- ============================================================
CREATE TABLE IF NOT EXISTS rules (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL,
    description TEXT,
    condition   JSONB       NOT NULL,
    action      TEXT        NOT NULL DEFAULT 'ALERT'
                            CHECK (action IN ('ALERT','BLOCK','LOG','IGNORE')),
    severity    TEXT        NOT NULL DEFAULT 'MEDIUM'
                            CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    category    TEXT,
    enabled     BOOLEAN     NOT NULL DEFAULT TRUE,
    hit_count   INTEGER     NOT NULL DEFAULT 0,
    created_by  UUID        REFERENCES users(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================
-- INCIDENTS
-- ============================================================
CREATE TABLE IF NOT EXISTS incidents (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    title       TEXT        NOT NULL,
    description TEXT,
    severity    TEXT        NOT NULL DEFAULT 'MEDIUM'
                            CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    risk_score  INTEGER     NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    status      TEXT        NOT NULL DEFAULT 'NEW'
                            CHECK (status IN ('NEW','INVESTIGATING','CONTAINED','RESOLVED','FALSE_POSITIVE')),
    assigned_to UUID        REFERENCES users(id),
    resolved_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================
-- ALERTS
-- ============================================================
CREATE TABLE IF NOT EXISTS alerts (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    sensor_id   UUID        REFERENCES sensors(id),
    incident_id UUID        REFERENCES incidents(id),
    rule_id     UUID        REFERENCES rules(id),
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT now(),
    src_ip      INET,
    src_port    INTEGER     CHECK (src_port BETWEEN 1 AND 65535),
    dst_ip      INET,
    dst_port    INTEGER     CHECK (dst_port BETWEEN 1 AND 65535),
    protocol    TEXT,
    signature   TEXT,
    category    TEXT,
    severity    TEXT        NOT NULL DEFAULT 'MEDIUM'
                            CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    risk_score  INTEGER     NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    status      TEXT        NOT NULL DEFAULT 'OPEN'
                            CHECK (status IN ('OPEN','INVESTIGATING','RESOLVED','FALSE_POSITIVE')),
    raw_event   JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================
-- DETECTION RESULTS
-- ============================================================
CREATE TABLE IF NOT EXISTS detection_results (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id    UUID        NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    decision    TEXT        NOT NULL CHECK (decision IN ('ACCEPT','ESCALATE','BLOCK')),
    reasons     JSONB       NOT NULL DEFAULT '[]',
    anomaly_score FLOAT,
    rule_matches  JSONB     DEFAULT '[]',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================
-- IPS ACTIONS & BLOCKED IPs
-- ============================================================
CREATE TABLE IF NOT EXISTS ips_actions (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    target          TEXT        NOT NULL,
    target_type     TEXT        NOT NULL DEFAULT 'IP'
                                CHECK (target_type IN ('IP','CIDR','PORT','RULE')),
    action          TEXT        NOT NULL CHECK (action IN ('BLOCK','UNBLOCK','RATE_LIMIT')),
    reason          TEXT,
    requested_by    UUID        REFERENCES users(id),
    approved_by     UUID        REFERENCES users(id),
    status          TEXT        NOT NULL DEFAULT 'PENDING'
                                CHECK (status IN ('PENDING','APPLIED','FAILED','EXPIRED','REVOKED')),
    expires_at      TIMESTAMPTZ,
    applied_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address  INET        NOT NULL UNIQUE,
    reason      TEXT,
    action_id   UUID        REFERENCES ips_actions(id),
    blocked_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ
);

-- ============================================================
-- THREAT INTELLIGENCE
-- ============================================================
CREATE TABLE IF NOT EXISTS threat_intel (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    ioc_type    TEXT        NOT NULL CHECK (ioc_type IN ('IP','DOMAIN','HASH','URL','EMAIL')),
    value       TEXT        NOT NULL,
    threat_type TEXT,
    confidence  INTEGER     CHECK (confidence BETWEEN 0 AND 100),
    source      TEXT,
    tags        JSONB       DEFAULT '[]',
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(ioc_type, value)
);

-- ============================================================
-- AUDIT LOGS
-- ============================================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id    UUID        REFERENCES users(id),
    actor       TEXT,
    action      TEXT        NOT NULL,
    resource    TEXT,
    resource_id TEXT,
    details     JSONB,
    source_ip   INET,
    user_agent  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================
-- INDEXES
-- ============================================================
-- Alerts
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp    ON alerts(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_risk         ON alerts(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_status       ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity     ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_src_ip       ON alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_incident     ON alerts(incident_id);

-- Incidents
CREATE INDEX IF NOT EXISTS idx_incidents_status    ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity  ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_created   ON incidents(created_at DESC);

-- Detection results
CREATE INDEX IF NOT EXISTS idx_detres_alert        ON detection_results(alert_id);
CREATE INDEX IF NOT EXISTS idx_detres_decision     ON detection_results(decision);

-- Audit logs
CREATE INDEX IF NOT EXISTS idx_audit_created       ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor         ON audit_logs(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_action        ON audit_logs(action);

-- Threat intel
CREATE INDEX IF NOT EXISTS idx_intel_value         ON threat_intel(value);
CREATE INDEX IF NOT EXISTS idx_intel_type          ON threat_intel(ioc_type);

-- Blocked IPs
CREATE INDEX IF NOT EXISTS idx_blocked_ip          ON blocked_ips(ip_address);

-- Sensors
CREATE INDEX IF NOT EXISTS idx_sensors_status      ON sensors(status);

-- Rules
CREATE INDEX IF NOT EXISTS idx_rules_enabled       ON rules(enabled);

-- Users
CREATE INDEX IF NOT EXISTS idx_users_email         ON users(email);
