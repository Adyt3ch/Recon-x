"""Subdomain takeover detection against known cloud provider fingerprints."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from reconx.core.engine import ScanContext
from reconx.core.scheduler import Task
from reconx.database.storage import insert_scan_event, utc_now_iso


@dataclass
class TakeoverCandidate:
    hostname: str
    cname: str
    provider: str
    status: str  # "confirmed_pattern", "no_match", "unclear"
    evidence: str = ""


DEFAULT_TAKEOVER_PROVIDERS = [
    {
        "name": "GitHub Pages",
        "cname": ["github.io"],
        "fingerprints": ["There isn't a GitHub Pages site here."],
    },
    {
        "name": "AWS S3",
        "cname": ["s3.amazonaws.com", "s3-website"],
        "fingerprints": ["The specified bucket does not exist", "NoSuchBucket"],
    },
    {
        "name": "Heroku",
        "cname": ["herokuapp.com", "herokudns.com"],
        "fingerprints": ["No such app", "Heroku | No such app"],
    },
    {
        "name": "Azure",
        "cname": ["azurewebsites.net", "cloudapp.net"],
        "fingerprints": ["404 Web Site not found"],
    },
]


def load_takeover_rules(config_path: Path | str = "config/fingerprints/takeover.yaml") -> list[dict[str, Any]]:
    """Load takeover fingerprints from YAML configuration."""
    p = Path(config_path)
    if p.exists():
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "providers" in data and isinstance(data["providers"], list):
                return data["providers"]
        except Exception:
            pass
    return DEFAULT_TAKEOVER_PROVIDERS


def match_takeover_pattern(content: str, fingerprints: list[str]) -> bool:
    """Check if HTTP response text contains any takeover signature string."""
    for fp in fingerprints:
        if fp in content:
            return True
    return False


class TakeoverModule:
    """Active takeover verification for dangling CNAME assets."""

    name = "takeover"

    def __init__(self, config_path: Path | str = "config/fingerprints/takeover.yaml"):
        self.providers = load_takeover_rules(config_path)

    def plan(self, ctx: ScanContext) -> list[Task]:
        """Plan takeover checks for assets with CNAME records pointing to third parties."""
        cursor = ctx.db.execute(
            """
            SELECT DISTINCT a.hostname, d.value
            FROM dns_records d
            JOIN assets a ON d.asset_id = a.id
            WHERE d.type = 'CNAME' AND a.program = ?
            """,
            (ctx.program,),
        )
        tasks = []
        for hostname, cname_val in cursor.fetchall():
            cname_clean = cname_val.rstrip(".").lower()
            # Check if CNAME matches any known provider
            for prov in self.providers:
                suffixes = prov.get("cname", [])
                if any(cname_clean.endswith(sfx) or sfx in cname_clean for sfx in suffixes):
                    tasks.append(
                        Task(
                            scan_id=ctx.scan_id,
                            module=self.name,
                            target=f"{hostname}|{cname_clean}|{prov['name']}",
                            estimated_requests=1,
                        )
                    )
                    break
        return tasks

    async def run(self, ctx: ScanContext, task: Task) -> TakeoverCandidate | None:
        """Verify takeover vulnerability using a single read-only GET request."""
        parts = task.target.split("|")
        if len(parts) != 3:
            return None

        hostname, cname, provider_name = parts

        # Locate provider rule
        prov_rule = next((p for p in self.providers if p["name"] == provider_name), None)
        if not prov_rule:
            return None

        fingerprints = prov_rule.get("fingerprints", [])

        # Fetch asset_id
        cursor = ctx.db.execute(
            "SELECT id FROM assets WHERE program = ? AND hostname = ?",
            (ctx.program, hostname),
        )
        asset_row = cursor.fetchone()
        asset_id = asset_row["id"] if asset_row else None

        probe_url = f"http://{hostname}/"
        try:
            resp = await ctx.requests.request(
                "GET",
                probe_url,
                module=self.name,
                purpose="takeover_check",
            )
            is_vulnerable = match_takeover_pattern(resp.text, fingerprints)

            if is_vulnerable:
                evidence = f"CNAME {cname} responded with provider signature from {provider_name}"
                candidate = TakeoverCandidate(
                    hostname=hostname,
                    cname=cname,
                    provider=provider_name,
                    status="confirmed_pattern",
                    evidence=evidence,
                )

                if asset_id:
                    finding_id = f"F-TAKEOVER-{abs(hash((hostname, cname))) % 100000:05d}"
                    ctx.db.execute(
                        """
                        INSERT INTO findings (
                            id, scan_id, asset_id, type, title, severity_hint,
                            confidence, status, notes, created_at
                        ) VALUES (?, ?, ?, 'observation', ?, 'high', 'medium', 'new', ?, ?)
                        ON CONFLICT(id) DO NOTHING
                        """,
                        (
                            finding_id,
                            ctx.scan_id,
                            asset_id,
                            f"Potential subdomain takeover on {provider_name}",
                            evidence,
                            utc_now_iso(),
                        ),
                    )
                    # Insert evidence
                    ctx.db.execute(
                        """
                        INSERT INTO evidence (finding_id, asset_id, kind, raw_redacted, source, captured_at)
                        VALUES (?, ?, 'takeover_proof', ?, 'takeover_module', ?)
                        """,
                        (finding_id, asset_id, resp.text[:500], utc_now_iso()),
                    )
                    ctx.db.commit()

                insert_scan_event(
                    ctx.db,
                    ctx.scan_id,
                    "WARN",
                    f"Subdomain takeover pattern detected for {hostname} -> {cname} ({provider_name})",
                )
                return candidate
            else:
                return TakeoverCandidate(
                    hostname=hostname,
                    cname=cname,
                    provider=provider_name,
                    status="no_match",
                )
        except Exception as e:
            insert_scan_event(ctx.db, ctx.scan_id, "DEBUG", f"Takeover probe error for {hostname}: {e}")
            return TakeoverCandidate(
                hostname=hostname,
                cname=cname,
                provider=provider_name,
                status="unclear",
                evidence=str(e),
            )
