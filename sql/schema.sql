-- file: sql/schema.sql
-- Multi-Tenant Smart SOCaaS Schema with Encrypted Users & RBAC

PRAGMA foreign_keys = ON;

-- 1. Tenants Table
CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    api_key TEXT UNIQUE NOT NULL,
    posture_score INTEGER DEFAULT 82,
    sla_response_mins INTEGER DEFAULT 30,
    retention_days INTEGER DEFAULT 90,
    created_at TEXT DEFAULT (datetime('now'))
);

-- 2. Encrypted Users & Role-Based Access Control (RBAC) Table
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    username_lookup TEXT UNIQUE NOT NULL,  -- Blind HMAC-SHA256 index for lookup
    username_encrypted TEXT NOT NULL,      -- AES/Stream Cipher encrypted username
    password_encrypted TEXT NOT NULL,      -- Encrypted PBKDF2-HMAC-SHA256 password hash
    role TEXT NOT NULL DEFAULT 'analyst',  -- 'admin', 'analyst', 'viewer'
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

-- 3. Engine 2: Per-Tenant False-Positive Suppression Rules
CREATE TABLE IF NOT EXISTS fp_rules (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    entity_pattern TEXT NOT NULL,
    suppressed_by TEXT NOT NULL,
    reason TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

-- 4. Engine 3: Behavioural Analysis (UEBA) Baselines
CREATE TABLE IF NOT EXISTS ueba_baselines (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    entity TEXT NOT NULL,
    normal_hosts TEXT NOT NULL,
    avg_daily_bytes_out INTEGER DEFAULT 50000000,
    updated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

-- 5. Engine 4: Integrated Node Status & Connector Heartbeats
CREATE TABLE IF NOT EXISTS node_status (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    node_name TEXT NOT NULL,
    node_type TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    status TEXT DEFAULT 'online',
    eps INTEGER DEFAULT 0,
    last_seen TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

-- 6. Engine 5 & 6: Correlated Incidents
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    title TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    severity TEXT NOT NULL,
    status TEXT DEFAULT 'open',
    primary_entity TEXT NOT NULL,
    ai_story TEXT NOT NULL,
    recommended_action TEXT NOT NULL,
    action_approved INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

-- 7. MITRE ATT&CK Kill-Chain Steps
CREATE TABLE IF NOT EXISTS incident_steps (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    stage_order INTEGER NOT NULL,
    tactic TEXT NOT NULL,
    technique_group TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    title TEXT NOT NULL,
    event_time TEXT NOT NULL,
    source TEXT NOT NULL,
    entity TEXT NOT NULL,
    severity TEXT NOT NULL,
    raw_log TEXT NOT NULL,
    ti_enrichment TEXT,
    ai_explanation TEXT,
    pinned INTEGER DEFAULT 0,
    FOREIGN KEY (incident_id) REFERENCES incidents(id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);

-- 8. Immutable Compliance & Action Audit Trail
CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    details TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id)
);