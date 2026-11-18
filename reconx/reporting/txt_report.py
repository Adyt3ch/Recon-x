"""Plain-text human-readable report generator."""

from __future__ import annotations

import sqlite3

from reconx.reporting.json_report import generate_json_report


def generate_txt_report(db: sqlite3.Connection, scan_id: str) -> str:
    """Generate structured plain-text report from scan data."""
    data = generate_json_report(db, scan_id)
    scan = data["scan"]
    summary = data["summary"]

    lines = []
    lines.append("=" * 70)
    lines.append(f" RECON-X ASSESSMENT REPORT: {scan['id']}")
    lines.append("=" * 70)
    lines.append(f"Program:        {scan['program']}")
    lines.append(f"Profile:        {scan['profile']}")
    lines.append(f"Status:         {scan['status']}")
    lines.append(f"Started At:     {scan['started_at']}")
    lines.append(f"Finished At:    {scan['finished_at'] or 'N/A'}")
    lines.append(f"Requests Used:  {scan['requests_used']} / {scan['request_budget']}")
    lines.append("-" * 70)
    lines.append(" SUMMARY")
    lines.append("-" * 70)
    lines.append(f"Total Assets Discovered:  {summary['total_assets']}")
    lines.append(f"Total DNS Records:        {summary['total_dns_records']}")
    lines.append(f"Live HTTP Services:       {summary['total_http_services']}")
    lines.append(f"Security Observations:    {summary['total_findings']}")
    lines.append("")

    # Assets section
    lines.append("-" * 70)
    lines.append(" DISCOVERED ASSETS")
    lines.append("-" * 70)
    for a in data["assets"]:
        srcs = ", ".join(a["sources"]) if a["sources"] else "manual"
        lines.append(f"  • {a['hostname']} [{a['confidence'].upper()}] (sources: {srcs})")
    lines.append("")

    # Live HTTP Services section
    lines.append("-" * 70)
    lines.append(" LIVE HTTP SERVICES")
    lines.append("-" * 70)
    for h in data["http_services"]:
        cdn_str = " [CDN]" if h["is_cdn"] else ""
        lines.append(f"  • {h['url']} (Status: {h['status_code']}{cdn_str})")
        if h["title"]:
            lines.append(f"    Title: {h['title']}")
        if h["server"]:
            lines.append(f"    Server: {h['server']}")
    lines.append("")

    # Security Observations section
    lines.append("-" * 70)
    lines.append(" SECURITY OBSERVATIONS & LEADS")
    lines.append("-" * 70)
    if data["findings"]:
        for f in data["findings"]:
            host_str = f" ({f['hostname']})" if f["hostname"] else ""
            lines.append(f"  • [{f['severity_hint'].upper()}] {f['title']}{host_str}")
    else:
        lines.append("  (No observations recorded)")
    lines.append("")
    lines.append("=" * 70)
    lines.append(" END OF REPORT")
    lines.append("=" * 70)

    return "\n".join(lines)
