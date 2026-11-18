"""CSV export generator for assets, DNS, and HTTP services."""

from __future__ import annotations

import csv
import io
import sqlite3
from typing import Literal

from reconx.reporting.json_report import generate_json_report


def generate_csv_report(
    db: sqlite3.Connection,
    scan_id: str,
    export_type: Literal["assets", "dns", "http", "urls", "technologies"] = "assets",
) -> str:
    """Generate RFC 4180 CSV export for selected entity type."""
    data = generate_json_report(db, scan_id)
    output = io.StringIO()

    if export_type == "assets":
        writer = csv.writer(output)
        writer.writerow(["Hostname", "Confidence", "First Seen", "Last Seen", "Sources"])
        for a in data["assets"]:
            writer.writerow([
                a["hostname"],
                a["confidence"],
                a["first_seen"],
                a["last_seen"],
                ";".join(a["sources"]),
            ])

    elif export_type == "dns":
        writer = csv.writer(output)
        writer.writerow(["Hostname", "Record Type", "Value", "TTL", "Observed At"])
        for d in data["dns_records"]:
            writer.writerow([
                d["hostname"],
                d["type"],
                d["value"],
                d["ttl"] or "",
                d["observed_at"],
            ])

    elif export_type == "http":
        writer = csv.writer(output)
        writer.writerow(["URL", "Hostname", "Status Code", "Title", "Server", "Content Type", "CDN", "Body Hash"])
        for h in data["http_services"]:
            writer.writerow([
                h["url"],
                h["hostname"],
                h["status_code"],
                h["title"] or "",
                h["server"] or "",
                h["content_type"] or "",
                "yes" if h["is_cdn"] else "no",
                h["body_hash"],
            ])

    elif export_type == "urls":
        writer = csv.writer(output)
        writer.writerow(["Normalized URL", "Hostname", "Category", "Source", "Status Code"])
        for u in data.get("urls", []):
            writer.writerow([
                u["url"],
                u["hostname"],
                u["category"] or "",
                u["source"],
                u["status_code"] or "",
            ])

    elif export_type == "technologies":
        writer = csv.writer(output)
        writer.writerow(["Hostname", "Technology", "Version", "Category", "Evidence"])
        for t in data.get("technologies", []):
            writer.writerow([
                t["hostname"],
                t["name"],
                t["version"] or "",
                t["category"] or "",
                t["evidence"],
            ])

    return output.getvalue()
