"""JSON report generator for RECON-X."""

from __future__ import annotations

import sqlite3
from typing import Any

from reconx.database.storage import get_scan


def generate_json_report(db: sqlite3.Connection, scan_id: str) -> dict[str, Any]:
    """Extract all scan data and format as comprehensive JSON report."""
    scan = get_scan(db, scan_id)
    if not scan:
        raise ValueError(f"Scan {scan_id} not found in database")

    # Assets
    asset_cursor = db.execute(
        """
        SELECT a.id, a.hostname, a.confidence, a.first_seen, a.last_seen,
               GROUP_CONCAT(s.source, ',') as sources
        FROM assets a
        LEFT JOIN asset_sources s ON a.id = s.asset_id
        WHERE a.program = ?
        GROUP BY a.id
        ORDER BY a.hostname ASC
        """,
        (scan["program"],),
    )
    assets = []
    for r in asset_cursor.fetchall():
        sources_list = [s.strip() for s in (r["sources"] or "").split(",") if s.strip()]
        assets.append({
            "id": r["id"],
            "hostname": r["hostname"],
            "confidence": r["confidence"],
            "first_seen": r["first_seen"],
            "last_seen": r["last_seen"],
            "sources": sources_list,
        })

    # DNS records
    dns_cursor = db.execute(
        """
        SELECT d.id, a.hostname, d.type, d.value, d.ttl, d.observed_at
        FROM dns_records d
        JOIN assets a ON d.asset_id = a.id
        WHERE d.scan_id = ?
        ORDER BY a.hostname, d.type
        """,
        (scan_id,),
    )
    dns_records = [
        {
            "hostname": r["hostname"],
            "type": r["type"],
            "value": r["value"],
            "ttl": r["ttl"],
            "observed_at": r["observed_at"],
        }
        for r in dns_cursor.fetchall()
    ]

    # HTTP services
    http_cursor = db.execute(
        """
        SELECT h.id, a.hostname, h.url, h.status_code, h.title, h.server,
               h.content_type, h.content_length, h.is_cdn, h.body_hash, h.observed_at
        FROM http_services h
        JOIN assets a ON h.asset_id = a.id
        WHERE h.scan_id = ?
        ORDER BY h.url ASC
        """,
        (scan_id,),
    )
    http_services = [
        {
            "hostname": r["hostname"],
            "url": r["url"],
            "status_code": r["status_code"],
            "title": r["title"],
            "server": r["server"],
            "content_type": r["content_type"],
            "content_length": r["content_length"],
            "is_cdn": bool(r["is_cdn"]),
            "body_hash": r["body_hash"],
            "observed_at": r["observed_at"],
        }
        for r in http_cursor.fetchall()
    ]

    # Findings
    findings_cursor = db.execute(
        """
        SELECT f.id, a.hostname, f.type, f.title, f.severity_hint, f.confidence, f.status, f.notes
        FROM findings f
        LEFT JOIN assets a ON f.asset_id = a.id
        WHERE f.scan_id = ?
        ORDER BY f.id ASC
        """,
        (scan_id,),
    )
    findings = [
        {
            "id": r["id"],
            "hostname": r["hostname"],
            "type": r["type"],
            "title": r["title"],
            "severity_hint": r["severity_hint"],
            "confidence": r["confidence"],
            "status": r["status"],
            "notes": r["notes"],
        }
        for r in findings_cursor.fetchall()
    ]

    # Request statistics from request_log
    stats_cursor = db.execute(
        """
        SELECT status, COUNT(*) as count
        FROM request_log
        WHERE scan_id = ?
        GROUP BY status
        """,
        (scan_id,),
    )
    status_counts = {str(r["status"]): r["count"] for r in stats_cursor.fetchall()}

    return {
        "scan": {
            "id": scan["id"],
            "program": scan["program"],
            "profile": scan["profile"],
            "status": scan["status"],
            "started_at": scan["started_at"],
            "finished_at": scan["finished_at"],
            "request_budget": scan["request_budget"],
            "requests_used": scan["requests_used"],
        },
        "summary": {
            "total_assets": len(assets),
            "total_dns_records": len(dns_records),
            "total_http_services": len(http_services),
            "total_findings": len(findings),
            "request_status_codes": status_counts,
        },
        "assets": assets,
        "dns_records": dns_records,
        "http_services": http_services,
        "findings": findings,
    }
