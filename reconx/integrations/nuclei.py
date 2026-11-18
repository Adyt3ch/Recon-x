"""Nuclei external tool wrapper for automated template-based security checks.

Enforces strict safety boundaries:
1. Off by default. Refuses to run unless rules.allow_nuclei is explicitly true.
2. Intrusive, dos, fuzz, and bruteforce tags are excluded by default and cannot be enabled.
3. Strict rate-limit (-rate-limit) and concurrency (-concurrency) flags are always enforced.
4. Findings enter the database as type 'observation' with at most 'medium' confidence.
"""

from __future__ import annotations

import json
from typing import Any

from reconx.core.tool_runner import run_tool
from reconx.database.storage import utc_now_iso

EXCLUDED_TAGS = {"intrusive", "dos", "fuzz", "bruteforce"}


class NucleiExecutionError(Exception):
    """Raised when nuclei execution violates safety constraints or fails."""
    pass


def parse_nuclei_jsonl(output: str) -> list[dict[str, Any]]:
    """Parse nuclei JSONL output into standardized finding dictionaries."""
    findings = []
    for line in output.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
            info = item.get("info", {})
            f_id = item.get("template-id") or item.get("templateID") or "unknown"
            name = info.get("name") or f_id
            severity = info.get("severity", "info").lower()
            matched_at = item.get("matched-at") or item.get("host") or ""
            description = info.get("description", "")
            extracted = item.get("extracted-results", [])

            findings.append({
                "template_id": f_id,
                "title": name,
                "severity": severity,
                "matched_at": matched_at,
                "description": description,
                "extracted": extracted,
                "raw": line,
            })
        except Exception:
            continue
    return findings


class NucleiRunner:
    """Safe runner for ProjectDiscovery's Nuclei scanner."""

    def __init__(
        self,
        binary_path: str = "auto",
        rate_limit: int = 1,
        concurrency: int = 1,
        timeout: int = 600,
        allowed_tags: list[str] | None = None,
    ):
        self.binary_path = binary_path
        self.rate_limit = max(1, rate_limit)
        self.concurrency = max(1, concurrency)
        self.timeout = timeout
        self.allowed_tags = allowed_tags or ["exposure", "misconfiguration", "cve", "tech"]

    def run(
        self,
        targets: list[str],
        allow_nuclei: bool,
        requested_tags: list[str] | None = None,
        scan_id: str = "RX-UNKNOWN",
        db: Any = None,
    ) -> list[dict[str, Any]]:
        """Execute nuclei with enforced rate limits and tag safety guards."""
        # Safety Rule 1: Nuclei is off by default
        if not allow_nuclei:
            raise NucleiExecutionError(
                "Nuclei execution rejected: 'allow_nuclei' is false in scope rules."
            )

        if not targets:
            return []

        # Safety Rule 2: Excluded dangerous tags
        tags_to_use = requested_tags or self.allowed_tags
        for tag in tags_to_use:
            if tag.lower() in EXCLUDED_TAGS:
                raise NucleiExecutionError(
                    f"Nuclei execution rejected: forbidden tag '{tag}' specified. "
                    f"Excluded tags: {sorted(EXCLUDED_TAGS)}"
                )

        tags_str = ",".join(tags_to_use)
        etags_str = ",".join(sorted(EXCLUDED_TAGS))

        # Build command arguments with required rate flags
        # Rate flag is MANDATORY for run_tool to accept it
        target_args: list[str] = []
        for t in targets:
            target_args.extend(["-u", t])

        args = [
            *target_args,
            "-rate-limit", str(self.rate_limit),
            "-c", str(self.concurrency),
            "-timeout", "10",
            "-tags", tags_str,
            "-etags", etags_str,
            "-silent",
            "-jsonl",
            "-no-interactsh",
        ]

        result = run_tool(
            tool_name="nuclei",
            args=args,
            timeout=self.timeout,
            scan_id=scan_id,
            db=db,
            binary_override=self.binary_path if self.binary_path != "auto" else None,
        )

        if result.exit_code != 0 and not result.stdout:
            raise NucleiExecutionError(f"Nuclei failed with exit code {result.exit_code}: {result.stderr}")

        findings = parse_nuclei_jsonl(result.stdout)

        # Store in findings table if db connection provided
        if db:
            for item in findings:
                finding_id = f"F-NUC-{abs(hash((item['template_id'], item['matched_at']))) % 100000:05d}"
                db.execute(
                    """
                    INSERT INTO findings (
                        id, scan_id, type, title, severity_hint,
                        confidence, status, notes, created_at
                    ) VALUES (?, ?, 'observation', ?, ?, 'medium', 'new', ?, ?)
                    ON CONFLICT(id) DO NOTHING
                    """,
                    (
                        finding_id,
                        scan_id,
                        f"[Nuclei] {item['title']}",
                        item["severity"],
                        f"Matched on {item['matched_at']}: {item['description']}",
                        utc_now_iso(),
                    ),
                )
                db.execute(
                    """
                    INSERT INTO evidence (finding_id, kind, raw_redacted, source, captured_at)
                    VALUES (?, 'nuclei_match', ?, 'nuclei', ?)
                    """,
                    (finding_id, item["raw"][:1000], utc_now_iso()),
                )
            db.commit()

        return findings
