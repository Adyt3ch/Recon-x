"""Section 13 Metrics and Quality Assurance Evaluator for RECON-X."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any


def calculate_scope_violations(db: sqlite3.Connection, scan_id: str) -> int:
    """Calculate out-of-scope requests sent to the network.

    A scope violation occurs if a request was actually dispatched over the wire
    (status is not null) while the scope decision was denied.
    Starting target: 0.
    """
    cursor = db.execute(
        """
        SELECT COUNT(*)
        FROM request_log
        WHERE scan_id = ?
          AND status IS NOT NULL
          AND scope_decision LIKE 'denied%'
        """,
        (scan_id,),
    )
    return int(cursor.fetchone()[0])


def calculate_rate_limit_breaches(
    db: sqlite3.Connection,
    scan_id: str,
    max_rps: float = 1.0,
    burst_tolerance: int = 1,
) -> int:
    """Audit request timestamps against the configured requests-per-second limit.

    Evaluates 1-second sliding windows over all executed requests.
    Starting target: 0.
    """
    cursor = db.execute(
        """
        SELECT ts
        FROM request_log
        WHERE scan_id = ? AND status IS NOT NULL
        ORDER BY id ASC
        """,
        (scan_id,),
    )
    rows = cursor.fetchall()
    if len(rows) <= 1:
        return 0

    timestamps: list[float] = []
    for r in rows:
        ts_str = r["ts"]
        try:
            # Parse ISO timestamp
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            timestamps.append(dt.timestamp())
        except Exception:
            continue

    timestamps.sort()
    breaches = 0
    max_allowed = int(max_rps) + burst_tolerance

    # Check 1-second rolling windows
    start_idx = 0
    for i in range(len(timestamps)):
        while timestamps[i] - timestamps[start_idx] > 1.0:
            start_idx += 1
        count_in_window = i - start_idx + 1
        if count_in_window > max_allowed:
            breaches += 1

    return breaches


def calculate_duplicate_asset_percentage(assets: list[str]) -> float:
    """Calculate duplicate asset percentage after merge.

    Starting target: 0.0%.
    """
    if not assets:
        return 0.0
    duplicates = len(assets) - len(set(assets))
    return round((duplicates / len(assets)) * 100.0, 2)


def calculate_requests_per_asset(db: sqlite3.Connection, scan_id: str) -> float:
    """Calculate total requests sent divided by verified (or discovered) assets.

    Starting target: <= 3.0 for baseline.
    """
    # Count requests sent
    req_cursor = db.execute(
        "SELECT COUNT(*) FROM request_log WHERE scan_id = ? AND status IS NOT NULL",
        (scan_id,),
    )
    total_requests = req_cursor.fetchone()[0]

    # Count verified/high confidence assets
    scan_cursor = db.execute("SELECT program FROM scans WHERE id = ?", (scan_id,))
    scan_row = scan_cursor.fetchone()
    program = scan_row["program"] if scan_row else ""

    asset_cursor = db.execute(
        "SELECT COUNT(*) FROM assets WHERE program = ? AND confidence IN ('verified', 'high')",
        (program,),
    )
    verified_assets = asset_cursor.fetchone()[0]

    if verified_assets == 0:
        # Fall back to any assets in program
        asset_cursor2 = db.execute(
            "SELECT COUNT(*) FROM assets WHERE program = ?",
            (program,),
        )
        verified_assets = asset_cursor2.fetchone()[0]

    if verified_assets == 0:
        return float(total_requests)

    return round(total_requests / verified_assets, 2)


def calculate_dns_verification_rate(resolved_count: int, total_candidates: int) -> float:
    """Resolved assets divided by assets expected to resolve.

    Record baseline.
    """
    if total_candidates <= 0:
        return 0.0
    return round(resolved_count / total_candidates, 3)


def calculate_http_verification_rate(live_count: int, total_resolved: int) -> float:
    """Live responses divided by assets expected to be live.

    Record baseline.
    """
    if total_resolved <= 0:
        return 0.0
    return round(live_count / total_resolved, 3)


def calculate_endpoint_precision_recall(
    extracted: set[str],
    ground_truth: set[str],
) -> dict[str, float]:
    """Endpoint extraction precision and recall compared with hand-labeled fixture.

    Starting target: Precision 0.9 or better.
    """
    if not extracted and not ground_truth:
        return {"precision": 1.0, "recall": 1.0, "f1": 1.0}
    if not extracted:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0}
    if not ground_truth:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0}

    true_positives = len(extracted & ground_truth)
    precision = true_positives / len(extracted)
    recall = true_positives / len(ground_truth)
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return {
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
    }


def calculate_false_positive_rate(db: sqlite3.Connection, scan_id: str | None = None) -> float:
    """Findings marked false_positive divided by all findings.

    Record baseline, then lower it.
    """
    if scan_id:
        total_cursor = db.execute("SELECT COUNT(*) FROM findings WHERE scan_id = ?", (scan_id,))
        fp_cursor = db.execute(
            "SELECT COUNT(*) FROM findings WHERE scan_id = ? AND status = 'false_positive'",
            (scan_id,),
        )
    else:
        total_cursor = db.execute("SELECT COUNT(*) FROM findings")
        fp_cursor = db.execute("SELECT COUNT(*) FROM findings WHERE status = 'false_positive'")

    total = total_cursor.fetchone()[0]
    fp = fp_cursor.fetchone()[0]

    if total == 0:
        return 0.0
    return round(fp / total, 3)


def calculate_subdomain_coverage(discovered: set[str], known_subdomains: set[str]) -> float:
    """Known subdomains found divided by expected full list.

    Record baseline.
    """
    if not known_subdomains:
        return 1.0
    found = len(discovered & known_subdomains)
    return round(found / len(known_subdomains), 3)


def calculate_scan_completion_rate(db: sqlite3.Connection) -> float:
    """Scans that finished or resumed to completion divided by scans started.

    Record baseline.
    """
    cursor_all = db.execute("SELECT COUNT(*) FROM scans")
    cursor_done = db.execute("SELECT COUNT(*) FROM scans WHERE status = 'completed'")
    total = cursor_all.fetchone()[0]
    done = cursor_done.fetchone()[0]
    if total == 0:
        return 1.0
    return round(done / total, 3)


def compute_scan_metrics(
    db: sqlite3.Connection,
    scan_id: str,
    max_rps: float = 1.0,
) -> dict[str, Any]:
    """Compile all Section 13 metrics for a given scan."""
    scope_violations = calculate_scope_violations(db, scan_id)
    rate_breaches = calculate_rate_limit_breaches(db, scan_id, max_rps=max_rps)
    reqs_per_asset = calculate_requests_per_asset(db, scan_id)
    fp_rate = calculate_false_positive_rate(db, scan_id)
    scan_completion = calculate_scan_completion_rate(db)

    # Check assets in program
    scan_cursor = db.execute("SELECT program FROM scans WHERE id = ?", (scan_id,))
    scan_row = scan_cursor.fetchone()
    program = scan_row["program"] if scan_row else ""

    asset_cursor = db.execute("SELECT hostname FROM assets WHERE program = ?", (program,))
    assets = [r["hostname"] for r in asset_cursor.fetchall()]
    dup_percent = calculate_duplicate_asset_percentage(assets)

    return {
        "scan_id": scan_id,
        "scope_violations": scope_violations,
        "rate_limit_breaches": rate_breaches,
        "duplicate_asset_percentage": dup_percent,
        "requests_per_asset": reqs_per_asset,
        "false_positive_rate": fp_rate,
        "scan_completion_rate": scan_completion,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
