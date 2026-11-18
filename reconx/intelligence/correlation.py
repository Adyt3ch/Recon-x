"""Correlation engine, priority scoring for leads, finding lifecycle, and report export."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from reconx.database.storage import utc_now_iso

# Allowed state machine transitions for finding lifecycle
ALLOWED_FINDING_TRANSITIONS: dict[str, set[str]] = {
    "new": {"confirmed", "false_positive", "duplicate"},
    "confirmed": {"reported"},
    "reported": {"fixed"},
    "fixed": set(),
    "false_positive": set(),
    "duplicate": set(),
}


@dataclass
class Lead:
    """Actionable reconnaissance lead prioritized for manual testing. Never labeled a vulnerability."""

    id: str
    target: str
    score: int
    reasons: list[str] = field(default_factory=list)
    suggested_test: str = ""
    evidence_links: list[str] = field(default_factory=list)
    asset_id: int | None = None


def load_scoring_weights(config_path: Path | str = "config/scoring.yaml") -> dict[str, dict[str, int]]:
    """Load scoring configuration weights."""
    p = Path(config_path)
    if p.exists():
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return {
                    "names": data.get("names", {}),
                    "endpoints": data.get("endpoints", {}),
                    "parameters": data.get("parameters", {}),
                    "findings": data.get("findings", {}),
                }
        except Exception:
            pass

    return {
        "names": {"dev": 10, "staging": 10, "admin": 15, "test": 8, "old": 10},
        "endpoints": {"login": 15, "admin": 20, "upload": 20, "graphql": 15, "api": 8},
        "parameters": {"redirect": 15, "file": 20, "path": 20, "id": 10},
        "findings": {"takeover_candidate": 30, "cors_misconfig": 25, "secret_candidate": 25, "exposure": 30},
    }


def calculate_leads(
    db: sqlite3.Connection,
    scan_id: str,
    scoring_config_path: Path | str = "config/scoring.yaml",
) -> list[Lead]:
    """Calculate and rank prioritised investigative leads for a scan."""
    weights = load_scoring_weights(scoring_config_path)
    name_weights = weights["names"]
    ep_weights = weights["endpoints"]
    param_weights = weights["parameters"]
    finding_weights = weights["findings"]

    leads_by_target: dict[str, Lead] = {}

    # 1. Evaluate Findings
    f_cursor = db.execute(
        """
        SELECT f.id, f.asset_id, f.type, f.title, f.severity_hint, f.notes, a.hostname
        FROM findings f
        LEFT JOIN assets a ON f.asset_id = a.id
        WHERE f.scan_id = ?
        """,
        (scan_id,),
    )
    for row in f_cursor.fetchall():
        target = row["hostname"] or "global"
        lead = leads_by_target.setdefault(
            target,
            Lead(
                id=f"LEAD-{abs(hash(target)) % 100000:05d}",
                target=target,
                score=0,
                asset_id=row["asset_id"],
            ),
        )

        title_lower = row["title"].lower()
        if "takeover" in title_lower:
            lead.score += finding_weights.get("takeover_candidate", 30)
            lead.reasons.append(f"Subdomain takeover candidate: {row['title']}")
            lead.suggested_test = "Check dangling CNAME DNS registration status"
        elif "cors" in title_lower:
            lead.score += finding_weights.get("cors_misconfig", 25)
            lead.reasons.append(f"CORS policy observation: {row['title']}")
            lead.suggested_test = "Verify CORS origin reflection with credentials"
        elif any(exp in title_lower for exp in ("git repository", ".env", "server-status", "actuator")):
            lead.score += finding_weights.get("exposure", 30)
            lead.reasons.append(f"Sensitive configuration exposure: {row['title']}")
            lead.suggested_test = "Verify information disclosure and credential leakage"
        elif "directory listing" in title_lower:
            lead.score += finding_weights.get("directory_listing", 15)
            lead.reasons.append("Directory listing enabled")
            lead.suggested_test = "Inspect directory contents for backup files"
        else:
            lead.score += 5
            lead.reasons.append(f"Security observation: {row['title']}")

        lead.evidence_links.append(f"finding:{row['id']}")

    # 2. Evaluate Asset Hostnames (forgotten names: dev, staging, admin, test)
    a_cursor = db.execute(
        """
        SELECT id, hostname FROM assets
        WHERE program = (SELECT program FROM scans WHERE id = ?)
        """,
        (scan_id,),
    )
    for a_row in a_cursor.fetchall():
        hostname = a_row["hostname"]
        labels = hostname.lower().split(".")
        subdomain_part = labels[0] if labels else ""

        for kw, weight in name_weights.items():
            if kw in subdomain_part:
                lead = leads_by_target.setdefault(
                    hostname,
                    Lead(
                        id=f"LEAD-{abs(hash(hostname)) % 100000:05d}",
                        target=hostname,
                        score=0,
                        asset_id=a_row["id"],
                    ),
                )
                lead.score += weight
                lead.reasons.append(f"Forgotten or high-value hostname label: '{kw}'")
                if not lead.suggested_test:
                    lead.suggested_test = "Review environment isolation and forgotten endpoints"
                lead.evidence_links.append(f"asset:{hostname}")

    # 3. Evaluate URLs & Parameters
    u_cursor = db.execute("SELECT url_normalized, category FROM urls")
    for u_row in u_cursor.fetchall():
        url = u_row["url_normalized"]
        cat = u_row["category"]

        # Parse hostname from url
        try:
            import urllib.parse
            parsed = urllib.parse.urlsplit(url)
            host = parsed.netloc.split(":")[0]
            query = parsed.query
        except Exception:
            continue

        if not host:
            continue

        lead = leads_by_target.setdefault(
            host,
            Lead(
                id=f"LEAD-{abs(hash(host)) % 100000:05d}",
                target=host,
                score=0,
            ),
        )

        # Category weights
        if cat and cat in ep_weights:
            weight = ep_weights[cat]
            lead.score += weight
            lead.reasons.append(f"Identified {cat} interface: {parsed.path}")
            if cat in ("login", "admin", "auth") and not lead.suggested_test:
                lead.suggested_test = "Review authentication controls, brute force protection, and MFA"
            elif cat == "upload" and not lead.suggested_test:
                lead.suggested_test = "Verify file upload restrictions and extension validation"
            elif cat == "graphql" and not lead.suggested_test:
                lead.suggested_test = "Check GraphQL schema introspection and batch query limits"
            lead.evidence_links.append(f"url:{url}")

        # Parameter weights
        if query:
            q_lower = query.lower()
            for param, p_weight in param_weights.items():
                if f"{param}=" in q_lower or param == q_lower:
                    lead.score += p_weight
                    lead.reasons.append(f"Interesting query parameter '{param}' in {url}")
                    if param in ("redirect", "next", "url", "return"):
                        lead.suggested_test = "Test open redirect and SSRF handling"
                    elif param in ("file", "path", "template"):
                        lead.suggested_test = "Test local/remote file inclusion and path traversal"
                    elif param in ("id", "user_id", "account"):
                        lead.suggested_test = "Test Insecure Direct Object References (IDOR)"
                    lead.evidence_links.append(f"url:{url}")

    # 4. Evaluate Secret Candidates
    s_cursor = db.execute("SELECT id, pattern, preview_redacted FROM secret_candidates")
    for s_row in s_cursor.fetchall():
        lead = leads_by_target.setdefault(
            "secrets",
            Lead(
                id="LEAD-SECRETS",
                target="JavaScript Secrets",
                score=0,
            ),
        )
        lead.score += finding_weights.get("secret_candidate", 25)
        lead.reasons.append(f"Detected unverified token signature ({s_row['pattern']})")
        lead.suggested_test = "Manually inspect script origin and determine if key is public/client-side"
        lead.evidence_links.append(f"secret:{s_row['id']}")

    results = list(leads_by_target.values())
    results.sort(key=lambda x: x.score, reverse=True)
    return results


def update_finding_status(
    db: sqlite3.Connection,
    finding_id: str,
    new_status: str,
    note: str | None = None,
) -> None:
    """Transition a finding status according to the authorized lifecycle state machine."""
    cursor = db.execute("SELECT status, notes FROM findings WHERE id = ?", (finding_id,))
    row = cursor.fetchone()
    if not row:
        raise ValueError(f"Finding {finding_id} not found in database")

    current_status = row["status"]
    allowed_next = ALLOWED_FINDING_TRANSITIONS.get(current_status, set())

    if new_status not in allowed_next:
        raise ValueError(
            f"Invalid finding status transition from '{current_status}' to '{new_status}'. "
            f"Allowed transitions: {sorted(allowed_next) or 'None (terminal state)'}"
        )

    # Append note if provided
    updated_notes = row["notes"] or ""
    if note:
        timestamp = utc_now_iso()
        note_entry = f"[{timestamp}] Status -> {new_status}: {note}"
        updated_notes = f"{updated_notes}\n{note_entry}".strip()

    db.execute(
        "UPDATE findings SET status = ?, notes = ? WHERE id = ?",
        (new_status, updated_notes, finding_id),
    )
    db.commit()


def list_findings(
    db: sqlite3.Connection,
    scan_id: str | None = None,
    status: str | None = None,
) -> list[dict[str, Any]]:
    """List stored findings filtered by scan_id and/or status."""
    query = """
        SELECT f.id, f.scan_id, a.hostname, f.type, f.title, f.severity_hint,
               f.confidence, f.status, f.notes, f.created_at
        FROM findings f
        LEFT JOIN assets a ON f.asset_id = a.id
        WHERE 1=1
    """
    params: list[Any] = []
    if scan_id:
        query += " AND f.scan_id = ?"
        params.append(scan_id)
    if status:
        query += " AND f.status = ?"
        params.append(status)

    query += " ORDER BY f.created_at DESC"
    cursor = db.execute(query, tuple(params))
    return [dict(r) for r in cursor.fetchall()]


def add_manual_note(
    db: sqlite3.Connection,
    entity_type: str,
    entity_id: str,
    body: str,
) -> int:
    """Record a user-provided manual assessment note against an asset or finding."""
    now = utc_now_iso()
    cursor = db.execute(
        """
        INSERT INTO notes (entity_type, entity_id, body, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (entity_type, entity_id, body, now),
    )
    db.commit()
    return cursor.lastrowid


def render_finding_hackerone_report(db: sqlite3.Connection, finding_id: str) -> str:
    """Generate Markdown report in HackerOne format with evidence auto-filled and manual placeholders."""
    cursor = db.execute(
        """
        SELECT f.id, f.scan_id, a.hostname, f.type, f.title, f.severity_hint,
               f.confidence, f.status, f.notes, f.created_at
        FROM findings f
        LEFT JOIN assets a ON f.asset_id = a.id
        WHERE f.id = ?
        """,
        (finding_id,),
    )
    row = cursor.fetchone()
    if not row:
        raise ValueError(f"Finding {finding_id} not found in database")

    finding = dict(row)

    # Fetch evidence records
    e_cursor = db.execute(
        """
        SELECT kind, raw_redacted, source, captured_at
        FROM evidence
        WHERE finding_id = ?
        ORDER BY id ASC
        """,
        (finding_id,),
    )
    evidence_items = e_cursor.fetchall()

    evidence_md = ""
    if evidence_items:
        for idx, e in enumerate(evidence_items, 1):
            evidence_md += f"\n**Evidence {idx} ({e['kind']} via {e['source']})**:\n```\n{e['raw_redacted']}\n```\n"
    else:
        evidence_md = "\n*(No raw HTTP evidence stored for this finding)*\n"

    target = finding.get("hostname") or "N/A"

    report = f"""# Vulnerability Report: {finding['title']}

**Target Host**: `{target}`
**Finding ID**: `{finding['id']}`
**Discovered Via**: RECON-X Assessment Scan `{finding['scan_id']}`
**Assessment Type**: {finding['type']} (Confidence: {finding['confidence']})
**Severity**: [Manual Triage Required - Select on HackerOne: None / Low / Medium / High / Critical]

---

## Summary
A security observation ({finding['title']}) was identified on `{target}`.
{finding['notes'] or ''}

## Steps to Reproduce
1. [Describe step-by-step reproduction instructions here]
2. [Include parameters, HTTP request methods, and exact test payloads]
3. [Observe target behavior and compare against expected secure baseline]

## Impact
[Describe the business and security impact of this finding if exploited. For example, unauthorized data access, session hijacking, or infrastructure compromise.]

## Evidence
{evidence_md}

## Remediation
[Provide vendor-recommended configuration changes or patching guidance to resolve the root cause of this observation.]
"""
    return report.strip()
