-- RECON-X Schema Migration 001: Initial Schema

CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    program TEXT NOT NULL,
    profile TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('created', 'running', 'paused', 'stopped', 'completed')),
    started_at TEXT NOT NULL,
    finished_at TEXT,
    request_budget INTEGER NOT NULL,
    requests_used INTEGER NOT NULL DEFAULT 0,
    config_snapshot TEXT NOT NULL,
    scope_snapshot TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    value TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('domain', 'ip', 'cidr', 'url')),
    in_scope INTEGER NOT NULL CHECK (in_scope IN (0, 1)),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program TEXT NOT NULL,
    hostname TEXT NOT NULL,
    confidence TEXT NOT NULL DEFAULT 'low' CHECK (confidence IN ('low', 'medium', 'high', 'verified')),
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE (program, hostname)
);

CREATE TABLE IF NOT EXISTS asset_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    seen_at TEXT NOT NULL,
    UNIQUE (asset_id, source)
);

CREATE TABLE IF NOT EXISTS dns_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    ttl INTEGER,
    observed_at TEXT NOT NULL,
    UNIQUE (asset_id, scan_id, type, value)
);

CREATE TABLE IF NOT EXISTS http_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    status_code INTEGER,
    title TEXT,
    server TEXT,
    content_type TEXT,
    content_length INTEGER,
    redirect_chain TEXT,
    tls TEXT,
    body_hash TEXT,
    soft_404_fingerprint TEXT,
    is_cdn INTEGER DEFAULT 0,
    observed_at TEXT NOT NULL,
    UNIQUE (asset_id, scan_id, url)
);

CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    service TEXT,
    version TEXT,
    banner TEXT,
    observed_at TEXT NOT NULL,
    UNIQUE (asset_id, scan_id, port, protocol)
);

CREATE TABLE IF NOT EXISTS urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    url_normalized TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL,
    category TEXT,
    status_code INTEGER,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS technologies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    version TEXT,
    category TEXT,
    evidence TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    UNIQUE (asset_id, name, version)
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
    type TEXT NOT NULL,
    title TEXT NOT NULL,
    severity_hint TEXT,
    confidence TEXT NOT NULL DEFAULT 'low' CHECK (confidence IN ('low', 'medium', 'high', 'verified')),
    status TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'confirmed', 'false_positive', 'reported', 'duplicate', 'fixed')),
    notes TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id TEXT REFERENCES findings(id) ON DELETE CASCADE,
    asset_id INTEGER REFERENCES assets(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    raw_redacted TEXT NOT NULL,
    source TEXT NOT NULL,
    captured_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ts TEXT NOT NULL,
    level TEXT NOT NULL,
    event TEXT NOT NULL,
    detail TEXT
);

CREATE TABLE IF NOT EXISTS scope_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    rule_type TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS asset_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    snapshot_json TEXT NOT NULL,
    snapshot_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS asset_relationships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    child_asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    relation TEXT NOT NULL,
    observed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS request_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ts TEXT NOT NULL,
    method TEXT NOT NULL,
    url TEXT NOT NULL,
    host TEXT NOT NULL,
    status INTEGER,
    bytes INTEGER,
    duration_ms INTEGER,
    scope_decision TEXT NOT NULL,
    prev_hash TEXT,
    row_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tool_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    tool TEXT NOT NULL,
    args_redacted TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    exit_code INTEGER,
    rate_flag_present INTEGER NOT NULL CHECK (rate_flag_present IN (0, 1))
);

CREATE TABLE IF NOT EXISTS scan_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    module TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'skipped')),
    attempts INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS js_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL UNIQUE,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_id INTEGER REFERENCES urls(id) ON DELETE CASCADE,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    parameters TEXT,
    js_file_id INTEGER REFERENCES js_files(id) ON DELETE SET NULL,
    first_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS secret_candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    js_file_id INTEGER REFERENCES js_files(id) ON DELETE CASCADE,
    pattern TEXT NOT NULL,
    preview_redacted TEXT NOT NULL,
    entropy REAL,
    status TEXT NOT NULL DEFAULT 'unverified' CHECK (status = 'unverified'),
    discovered_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cve_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    lookup_key TEXT NOT NULL UNIQUE,
    payload TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS screenshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    http_service_id INTEGER NOT NULL REFERENCES http_services(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    captured_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL
);
