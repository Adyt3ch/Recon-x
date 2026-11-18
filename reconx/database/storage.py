"""SQLite storage layer, connection management, migrations, and upsert helpers."""

from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def get_db(db_path: Path | str = "data/reconx.db") -> sqlite3.Connection:
    """Create and return a configured SQLite connection with FKs and WAL enabled."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn


def apply_migrations(db: sqlite3.Connection, migrations_dir: Path | str | None = None) -> list[str]:
    """Find and execute unapplied .sql migrations in numerical order."""
    if migrations_dir is None:
        mig_path = Path(__file__).parent / "migrations"
    else:
        mig_path = Path(migrations_dir)

    # Ensure schema_migrations table exists
    db.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL
        );
    """)
    db.commit()

    applied_cursor = db.execute("SELECT version FROM schema_migrations")
    applied_versions = {row[0] for row in applied_cursor.fetchall()}

    newly_applied = []
    sql_files = sorted(mig_path.glob("*.sql"))

    for sql_file in sql_files:
        version = sql_file.name
        if version not in applied_versions:
            sql_text = sql_file.read_text(encoding="utf-8")
            with db:
                db.executescript(sql_text)
                db.execute(
                    "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                    (version, utc_now_iso()),
                )
            newly_applied.append(version)

    return newly_applied


def generate_scan_id(db: sqlite3.Connection) -> str:
    """Generate next sequential scan ID (e.g. RX-001, RX-002)."""
    cursor = db.execute("SELECT id FROM scans")
    rows = cursor.fetchall()
    highest = 0
    for r in rows:
        match = re.search(r"RX-(\d+)", r["id"])
        if match:
            num = int(match.group(1))
            if num > highest:
                highest = num
    return f"RX-{highest + 1:03d}"


# Confidence ranking helper
CONFIDENCE_LEVELS = {"low": 1, "medium": 2, "high": 3, "verified": 4}


def upsert_asset(
    db: sqlite3.Connection,
    program: str,
    hostname: str,
    confidence: str = "low",
    source: str | None = None,
) -> int:
    """Upsert asset by (program, hostname), updating last_seen and upgrading confidence."""
    now = utc_now_iso()
    cursor = db.execute(
        "SELECT id, confidence FROM assets WHERE program = ? AND hostname = ?",
        (program, hostname),
    )
    existing = cursor.fetchone()

    if existing:
        asset_id = existing["id"]
        current_conf = existing["confidence"]
        # Never downgrade confidence within a scan/program
        new_conf = (
            confidence
            if CONFIDENCE_LEVELS.get(confidence, 1) > CONFIDENCE_LEVELS.get(current_conf, 1)
            else current_conf
        )
        db.execute(
            "UPDATE assets SET last_seen = ?, confidence = ? WHERE id = ?",
            (now, new_conf, asset_id),
        )
    else:
        cursor = db.execute(
            """
            INSERT INTO assets (program, hostname, confidence, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?)
            """,
            (program, hostname, confidence, now, now),
        )
        asset_id = cursor.lastrowid

    if source:
        db.execute(
            """
            INSERT INTO asset_sources (asset_id, source, seen_at)
            VALUES (?, ?, ?)
            ON CONFLICT(asset_id, source) DO UPDATE SET seen_at = excluded.seen_at
            """,
            (asset_id, source, now),
        )

    db.commit()
    return asset_id


def upsert_dns_record(
    db: sqlite3.Connection,
    asset_id: int,
    scan_id: str,
    record_type: str,
    value: str,
    ttl: int | None = None,
) -> int:
    """Upsert DNS record on (asset_id, scan_id, type, value)."""
    now = utc_now_iso()
    cursor = db.execute(
        """
        INSERT INTO dns_records (asset_id, scan_id, type, value, ttl, observed_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(asset_id, scan_id, type, value) DO UPDATE SET
            ttl = excluded.ttl,
            observed_at = excluded.observed_at
        RETURNING id
        """,
        (asset_id, scan_id, record_type, value, ttl, now),
    )
    row = cursor.fetchone()
    db.commit()
    return row[0]


def upsert_http_service(
    db: sqlite3.Connection,
    asset_id: int,
    scan_id: str,
    url: str,
    status_code: int | None = None,
    title: str | None = None,
    server: str | None = None,
    content_type: str | None = None,
    content_length: int | None = None,
    redirect_chain: str | None = None,
    tls: str | None = None,
    body_hash: str | None = None,
    is_cdn: int = 0,
    soft_404_fingerprint: str | None = None,
) -> int:
    """Upsert live HTTP service for an asset."""
    now = utc_now_iso()
    cursor = db.execute(
        """
        INSERT INTO http_services (
            asset_id, scan_id, url, status_code, title, server, content_type,
            content_length, redirect_chain, tls, body_hash, is_cdn,
            soft_404_fingerprint, observed_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(asset_id, scan_id, url) DO UPDATE SET
            status_code = excluded.status_code,
            title = excluded.title,
            server = excluded.server,
            content_type = excluded.content_type,
            content_length = excluded.content_length,
            redirect_chain = excluded.redirect_chain,
            tls = excluded.tls,
            body_hash = excluded.body_hash,
            is_cdn = excluded.is_cdn,
            soft_404_fingerprint = excluded.soft_404_fingerprint,
            observed_at = excluded.observed_at
        RETURNING id
        """,
        (
            asset_id,
            scan_id,
            url,
            status_code,
            title,
            server,
            content_type,
            content_length,
            redirect_chain,
            tls,
            body_hash,
            is_cdn,
            soft_404_fingerprint,
            now,
        ),
    )
    row = cursor.fetchone()
    db.commit()
    return row[0]


def create_scan(
    db: sqlite3.Connection,
    scan_id: str,
    program: str,
    profile: str,
    request_budget: int,
    config_snapshot: str = "",
    scope_snapshot: str = "",
) -> None:
    """Create a new scan entry in created/running state."""
    now = utc_now_iso()
    db.execute(
        """
        INSERT INTO scans (
            id, program, profile, status, started_at, request_budget,
            requests_used, config_snapshot, scope_snapshot
        ) VALUES (?, ?, ?, 'created', ?, ?, 0, ?, ?)
        """,
        (scan_id, program, profile, now, request_budget, config_snapshot, scope_snapshot),
    )
    db.commit()


def get_scan(db: sqlite3.Connection, scan_id: str) -> dict[str, Any] | None:
    """Retrieve scan by ID."""
    cursor = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    return dict(row) if row else None


def update_scan_status(
    db: sqlite3.Connection,
    scan_id: str,
    status: str,
    requests_used: int | None = None,
    finished_at: str | None = None,
) -> None:
    """Update status, request usage, and optional finish time of a scan."""
    updates = ["status = ?"]
    params: list[Any] = [status]

    if requests_used is not None:
        updates.append("requests_used = ?")
        params.append(requests_used)

    if finished_at is not None:
        updates.append("finished_at = ?")
        params.append(finished_at)

    params.append(scan_id)
    sql = f"UPDATE scans SET {', '.join(updates)} WHERE id = ?"
    db.execute(sql, params)
    db.commit()


def list_scans(db: sqlite3.Connection) -> list[dict[str, Any]]:
    """List all recorded scans in reverse chronological order."""
    cursor = db.execute("SELECT * FROM scans ORDER BY started_at DESC")
    return [dict(row) for row in cursor.fetchall()]


def insert_scan_event(
    db: sqlite3.Connection,
    scan_id: str,
    level: str,
    event: str,
    detail: str | None = None,
) -> None:
    """Record an operational scan event (pause, error, backoff, stop)."""
    db.execute(
        """
        INSERT INTO scan_events (scan_id, ts, level, event, detail)
        VALUES (?, ?, ?, ?, ?)
        """,
        (scan_id, utc_now_iso(), level, event, detail),
    )
    db.commit()
