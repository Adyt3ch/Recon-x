"""Scan history tracking, historical snapshot diffing, and monitor alerts."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any

from reconx.database.storage import utc_now_iso


def build_scan_snapshot(db: sqlite3.Connection, scan_id: str) -> dict[str, Any]:
    """Extract a complete state dictionary for a scan to compare over time."""
    cursor = db.execute("SELECT program FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    if not row:
        raise ValueError(f"Scan {scan_id} does not exist")
    program = row[0]

    # 1. Assets
    a_cursor = db.execute(
        "SELECT hostname, confidence FROM assets WHERE program = ? ORDER BY hostname",
        (program,),
    )
    assets = {r[0]: r[1] for r in a_cursor.fetchall()}

    # 2. DNS records
    d_cursor = db.execute(
        """
        SELECT a.hostname, d.type, d.value
        FROM dns_records d
        JOIN assets a ON d.asset_id = a.id
        WHERE d.scan_id = ?
        ORDER BY a.hostname, d.type, d.value
        """,
        (scan_id,),
    )
    dns_records: dict[str, list[dict[str, str]]] = {}
    for h, t, v in d_cursor.fetchall():
        dns_records.setdefault(h, []).append({"type": t, "value": v})

    # 3. HTTP Services
    h_cursor = db.execute(
        """
        SELECT a.hostname, h.url, h.status_code, h.title, h.server, h.body_hash
        FROM http_services h
        JOIN assets a ON h.asset_id = a.id
        WHERE h.scan_id = ?
        ORDER BY h.url
        """,
        (scan_id,),
    )
    services: dict[str, dict[str, Any]] = {}
    for r in h_cursor.fetchall():
        services[r["url"]] = {
            "hostname": r["hostname"],
            "status_code": r["status_code"],
            "title": r["title"],
            "server": r["server"],
            "body_hash": r["body_hash"],
        }

    # 4. Technologies
    t_cursor = db.execute(
        """
        SELECT a.hostname, t.name, t.version
        FROM technologies t
        JOIN assets a ON t.asset_id = a.id
        WHERE a.program = ?
        ORDER BY a.hostname, t.name
        """,
        (program,),
    )
    technologies: dict[str, list[str]] = {}
    for h, name, ver in t_cursor.fetchall():
        ver_str = f" v{ver}" if ver else ""
        technologies.setdefault(h, []).append(f"{name}{ver_str}")

    # 5. Endpoints
    ep_cursor = db.execute("SELECT method, path FROM endpoints ORDER BY path")
    endpoints = [f"{m} {p}" for m, p in ep_cursor.fetchall()]

    # 6. JavaScript hashes
    js_cursor = db.execute("SELECT url, sha256 FROM js_files ORDER BY url")
    js_hashes = {r[0]: r[1] for r in js_cursor.fetchall()}

    return {
        "scan_id": scan_id,
        "program": program,
        "assets": assets,
        "dns_records": dns_records,
        "services": services,
        "technologies": technologies,
        "endpoints": endpoints,
        "js_hashes": js_hashes,
    }


def save_scan_snapshot(db: sqlite3.Connection, scan_id: str) -> str:
    """Save canonical JSON snapshot into asset_snapshots table and return hash."""
    snapshot_data = build_scan_snapshot(db, scan_id)
    canonical_json = json.dumps(snapshot_data, sort_keys=True)
    snap_hash = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    now = utc_now_iso()

    db.execute(
        """
        INSERT INTO asset_snapshots (scan_id, asset_id, snapshot_json, snapshot_hash, created_at)
        VALUES (?, 0, ?, ?, ?)
        """,
        (scan_id, canonical_json, snap_hash, now),
    )
    db.commit()
    return snap_hash


def load_scan_snapshot(db: sqlite3.Connection, scan_id: str) -> dict[str, Any]:
    """Retrieve saved snapshot from asset_snapshots, falling back to building on the fly."""
    cursor = db.execute(
        "SELECT snapshot_json FROM asset_snapshots WHERE scan_id = ? ORDER BY id DESC LIMIT 1",
        (scan_id,),
    )
    row = cursor.fetchone()
    if row and row[0]:
        return json.loads(row[0])
    return build_scan_snapshot(db, scan_id)


def diff_scans(db: sqlite3.Connection, scan_id_old: str, scan_id_new: str) -> dict[str, Any]:
    """Calculate deep structural difference between two scans."""
    snap1 = load_scan_snapshot(db, scan_id_old)
    snap2 = load_scan_snapshot(db, scan_id_new)

    # Assets
    old_hosts = set(snap1["assets"].keys())
    new_hosts = set(snap2["assets"].keys())
    added_assets = sorted(new_hosts - old_hosts)
    removed_assets = sorted(old_hosts - new_hosts)

    # DNS changes
    dns_diff = []
    common_hosts = old_hosts.intersection(new_hosts)
    for h in common_hosts:
        d1 = snap1["dns_records"].get(h, [])
        d2 = snap2["dns_records"].get(h, [])
        if d1 != d2:
            dns_diff.append({"hostname": h, "old": d1, "new": d2})

    # Services & Status codes
    service_diff = []
    all_urls = set(snap1["services"].keys()).union(set(snap2["services"].keys()))
    for u in all_urls:
        s1 = snap1["services"].get(u)
        s2 = snap2["services"].get(u)
        if s1 and not s2:
            service_diff.append({"url": u, "change": "removed", "old_status": s1["status_code"]})
        elif s2 and not s1:
            service_diff.append({"url": u, "change": "new", "status_code": s2["status_code"]})
        elif s1 and s2:
            if s1["status_code"] != s2["status_code"] or s1["body_hash"] != s2["body_hash"]:
                service_diff.append({
                    "url": u,
                    "change": "modified",
                    "old_status": s1["status_code"],
                    "new_status": s2["status_code"],
                })

    # Technologies
    tech_diff = []
    for h in common_hosts:
        t1 = snap1["technologies"].get(h, [])
        t2 = snap2["technologies"].get(h, [])
        if t1 != t2:
            tech_diff.append({"hostname": h, "old": t1, "new": t2})

    # Endpoints
    old_eps = set(snap1["endpoints"])
    new_eps = set(snap2["endpoints"])
    added_endpoints = sorted(new_eps - old_eps)

    # JS hashes
    js_diff = []
    for js_url in set(snap1["js_hashes"].keys()).intersection(set(snap2["js_hashes"].keys())):
        h1 = snap1["js_hashes"][js_url]
        h2 = snap2["js_hashes"][js_url]
        if h1 != h2:
            js_diff.append({"url": js_url, "old_hash": h1, "new_hash": h2})

    return {
        "scan_old": scan_id_old,
        "scan_new": scan_id_new,
        "added_assets": added_assets,
        "removed_assets": removed_assets,
        "dns_changes": dns_diff,
        "service_changes": service_diff,
        "technology_changes": tech_diff,
        "new_endpoints": added_endpoints,
        "changed_js_files": js_diff,
    }


def has_changes(diff: dict[str, Any]) -> bool:
    """Check if any actionable differences exist between two scans."""
    return bool(
        diff.get("added_assets")
        or diff.get("removed_assets")
        or diff.get("dns_changes")
        or diff.get("service_changes")
        or diff.get("technology_changes")
        or diff.get("new_endpoints")
        or diff.get("changed_js_files")
    )


def format_alert_message(diff: dict[str, Any]) -> str:
    """Format monitoring diff into human-readable notification text (strictly no secrets)."""
    lines = [f"🚨 RECON-X Alert: Changes detected between {diff['scan_old']} and {diff['scan_new']}"]

    if diff["added_assets"]:
        lines.append(f"\n➕ New Assets ({len(diff['added_assets'])}):")
        for a in diff["added_assets"][:10]:
            lines.append(f"  • {a}")
        if len(diff["added_assets"]) > 10:
            lines.append(f"  ... and {len(diff['added_assets']) - 10} more")

    if diff["service_changes"]:
        lines.append(f"\n🌐 Changed Services ({len(diff['service_changes'])}):")
        for s in diff["service_changes"][:10]:
            lines.append(f"  • {s['url']} ({s['change']})")

    if diff["new_endpoints"]:
        lines.append(f"\n⚡ New Endpoints ({len(diff['new_endpoints'])}):")
        for ep in diff["new_endpoints"][:10]:
            lines.append(f"  • {ep}")

    if diff["changed_js_files"]:
        lines.append(f"\n📜 Changed JavaScript ({len(diff['changed_js_files'])}):")
        for j in diff["changed_js_files"][:10]:
            lines.append(f"  • {j['url']}")

    return "\n".join(lines)


async def send_monitor_alert(
    diff: dict[str, Any],
    req_mgr: Any,
    webhook_url: str | None = None,
) -> bool:
    """Send webhook alert (Slack, Discord, or generic) if changes detected."""
    if not has_changes(diff):
        return False

    import os
    target_webhook = webhook_url or os.environ.get("RECONX_WEBHOOK_URL") or os.environ.get("SLACK_WEBHOOK_URL") or os.environ.get("DISCORD_WEBHOOK_URL")
    if not target_webhook:
        return False

    msg = format_alert_message(diff)

    # Format payload (compatible with Slack, Discord, and Telegram webhooks)
    if "discord.com" in target_webhook:
        payload = {"content": msg}
    elif "api.telegram.org" in target_webhook:
        payload = {"text": msg}
    else:
        payload = {"text": msg}

    return await req_mgr.send_webhook(target_webhook, payload)

