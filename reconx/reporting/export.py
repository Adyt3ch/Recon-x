"""Export utilities for plain lists, Burp Suite scope configurations, and Nuclei target files."""

from __future__ import annotations

import re
import sqlite3
from typing import Any

from reconx.database.storage import get_scan


def regex_escape_host(pattern: str) -> str:
    """Convert domain or wildcard pattern into Burp Suite scope regex."""
    p_clean = pattern.strip().lower()
    if p_clean.startswith("*."):
        suffix = p_clean[2:]
        escaped_suffix = re.escape(suffix)
        return f"^.*\\.{escaped_suffix}$"
    escaped = re.escape(p_clean)
    return f"^{escaped}$"


def export_hosts(db: sqlite3.Connection, scan_id: str) -> str:
    """Return plain newline-delimited list of in-scope discovered hostnames."""
    scan = get_scan(db, scan_id)
    if not scan:
        raise ValueError(f"Scan {scan_id} not found in database")

    cursor = db.execute(
        "SELECT hostname FROM assets WHERE program = ? ORDER BY hostname ASC",
        (scan["program"],),
    )
    hosts = [r[0] for r in cursor.fetchall()]
    return "\n".join(hosts)


def export_urls(db: sqlite3.Connection, scan_id: str) -> str:
    """Return plain newline-delimited list of normalized discovered URLs."""
    cursor = db.execute("SELECT url_normalized FROM urls ORDER BY url_normalized ASC")
    urls = [r[0] for r in cursor.fetchall()]
    return "\n".join(urls)


def export_nuclei_targets(db: sqlite3.Connection, scan_id: str) -> str:
    """Return newline-delimited list of live, verified HTTP/HTTPS target URLs."""
    cursor = db.execute(
        "SELECT DISTINCT url FROM http_services WHERE scan_id = ? ORDER BY url ASC",
        (scan_id,),
    )
    urls = [r[0] for r in cursor.fetchall()]
    return "\n".join(urls)


def export_burp_scope(db: sqlite3.Connection, scan_id: str) -> dict[str, Any]:
    """Generate standard Burp Suite scope JSON configuration."""
    scan = get_scan(db, scan_id)
    if not scan:
        raise ValueError(f"Scan {scan_id} not found in database")

    cursor = db.execute(
        "SELECT hostname FROM assets WHERE program = ? ORDER BY hostname ASC",
        (scan["program"],),
    )
    hosts = [r[0] for r in cursor.fetchall()]

    include_rules = []
    for h in hosts:
        include_rules.append({
            "enabled": True,
            "host": regex_escape_host(h),
            "protocol": "any",
        })

    return {
        "target": {
            "scope": {
                "advanced_mode": True,
                "include": include_rules,
                "exclude": [],
            }
        }
    }
