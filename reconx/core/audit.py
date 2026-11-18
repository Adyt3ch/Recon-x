"""Audit trail and tamper-evident request logging with SHA-256 hash chains."""

from __future__ import annotations

import hashlib
import sqlite3

from reconx.database.storage import utc_now_iso


def compute_row_hash(
    scan_id: str,
    ts: str,
    method: str,
    url: str,
    host: str,
    status: int | None,
    bytes_count: int | None,
    duration_ms: int | None,
    scope_decision: str,
    prev_hash: str | None,
) -> str:
    """Compute deterministic SHA-256 hash for a request_log row."""
    payload = (
        f"{scan_id}|{ts}|{method}|{url}|{host}|"
        f"{status if status is not None else ''}|"
        f"{bytes_count if bytes_count is not None else ''}|"
        f"{duration_ms if duration_ms is not None else ''}|"
        f"{scope_decision}|{prev_hash or ''}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def log_request(
    db: sqlite3.Connection,
    scan_id: str,
    method: str,
    url: str,
    host: str,
    status: int | None,
    bytes_count: int | None,
    duration_ms: int | None,
    scope_decision: str,
    ts: str | None = None,
) -> int:
    """Append a row to request_log linking to the preceding row's hash."""
    timestamp = ts or utc_now_iso()

    # Get the row_hash of the previous entry for this scan
    cursor = db.execute(
        "SELECT row_hash FROM request_log WHERE scan_id = ? ORDER BY id DESC LIMIT 1",
        (scan_id,),
    )
    last_row = cursor.fetchone()
    prev_hash = last_row["row_hash"] if last_row else None

    row_hash = compute_row_hash(
        scan_id=scan_id,
        ts=timestamp,
        method=method,
        url=url,
        host=host,
        status=status,
        bytes_count=bytes_count,
        duration_ms=duration_ms,
        scope_decision=scope_decision,
        prev_hash=prev_hash,
    )

    cursor = db.execute(
        """
        INSERT INTO request_log (
            scan_id, ts, method, url, host, status, bytes,
            duration_ms, scope_decision, prev_hash, row_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            timestamp,
            method,
            url,
            host,
            status,
            bytes_count,
            duration_ms,
            scope_decision,
            prev_hash,
            row_hash,
        ),
    )
    db.commit()
    return cursor.lastrowid


def verify_chain(db: sqlite3.Connection, scan_id: str) -> tuple[bool, str | None]:
    """Verify cryptographic integrity of the request_log hash chain for a scan.

    Returns (True, None) if valid, or (False, reason) if corrupted/tampered.
    """
    cursor = db.execute(
        """
        SELECT id, scan_id, ts, method, url, host, status, bytes,
               duration_ms, scope_decision, prev_hash, row_hash
        FROM request_log
        WHERE scan_id = ?
        ORDER BY id ASC
        """,
        (scan_id,),
    )
    rows = cursor.fetchall()
    if not rows:
        return True, None

    expected_prev_hash: str | None = None

    for row in rows:
        row_id = row["id"]
        # 1. Verify prev_hash matches preceding row_hash
        if row["prev_hash"] != expected_prev_hash:
            return (
                False,
                f"Broken chain at row {row_id}: stored prev_hash {row['prev_hash']} "
                f"does not match expected {expected_prev_hash}",
            )

        # 2. Recompute row hash
        recomputed = compute_row_hash(
            scan_id=row["scan_id"],
            ts=row["ts"],
            method=row["method"],
            url=row["url"],
            host=row["host"],
            status=row["status"],
            bytes_count=row["bytes"],
            duration_ms=row["duration_ms"],
            scope_decision=row["scope_decision"],
            prev_hash=row["prev_hash"],
        )

        if recomputed != row["row_hash"]:
            return (
                False,
                f"Hash mismatch at row {row_id}: stored {row['row_hash']} "
                f"!= recomputed {recomputed}",
            )

        expected_prev_hash = row["row_hash"]

    return True, None
