"""DNS resolution, wildcard detection, and observation module."""

from __future__ import annotations

import random
import string
from dataclasses import dataclass, field

from reconx.core.engine import ScanContext
from reconx.core.scheduler import Task
from reconx.database.storage import (
    insert_scan_event,
    upsert_asset,
    upsert_dns_record,
    utc_now_iso,
)
from reconx.intelligence.confidence import upgrade_confidence

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]


@dataclass
class DnsResult:
    hostname: str
    records: dict[str, list[str]] = field(default_factory=dict)
    is_wildcard: bool = False
    observations: list[str] = field(default_factory=list)
    dangling_cname: str | None = None
    is_authorized: bool = True


class DnsModule:
    """DNS resolution and domain health reconnaissance module."""
    name = "dns"

    def plan(self, ctx: ScanContext) -> list[Task]:
        """Plan DNS queries for all discovered assets in the database."""
        cursor = ctx.db.execute(
            "SELECT hostname FROM assets WHERE program = ?",
            (ctx.program,),
        )
        hosts = [row[0] for row in cursor.fetchall()]
        return [
            Task(scan_id=ctx.scan_id, module=self.name, target=h, estimated_requests=1)
            for h in hosts
        ]

    async def _detect_wildcard(self, ctx: ScanContext, domain: str) -> set[str]:
        """Test for wildcard DNS by querying random subdomains."""
        rand_prefix = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        rand_host = f"reconx-wc-{rand_prefix}.{domain}"
        answers = await ctx.requests.dns_query(rand_host, "A")
        return set(answers)

    async def run(self, ctx: ScanContext, task: Task) -> DnsResult:
        """Resolve DNS records for target asset and check security observations."""
        raw_target = task.target
        hostname = raw_target.split(":")[0] if ":" in raw_target else raw_target
        result = DnsResult(hostname=hostname)

        # 1. Fetch asset_id from database (try raw_target first, then hostname)
        cursor = ctx.db.execute(
            "SELECT id, confidence FROM assets WHERE program = ? AND hostname = ?",
            (ctx.program, raw_target),
        )
        asset_row = cursor.fetchone()
        if not asset_row and raw_target != hostname:
            cursor = ctx.db.execute(
                "SELECT id, confidence FROM assets WHERE program = ? AND hostname = ?",
                (ctx.program, hostname),
            )
            asset_row = cursor.fetchone()

        asset_id = asset_row["id"] if asset_row else None
        current_conf = asset_row["confidence"] if asset_row else "low"

        # 2. Check for wildcard DNS on the immediate parent domain
        parent_domain = hostname
        if "." in hostname:
            parts = hostname.split(".")
            if len(parts) > 2:
                parent_domain = ".".join(parts[1:])

        wildcard_ips = await self._detect_wildcard(ctx, parent_domain)

        # 3. Query all configured record types
        resolved_ips: list[str] = []
        cname_target: str | None = None

        for rtype in RECORD_TYPES:
            records = await ctx.requests.dns_query(hostname, rtype)
            if records:
                result.records[rtype] = records
                for val in records:
                    if rtype in ("A", "AAAA"):
                        resolved_ips.append(val)
                    elif rtype == "CNAME":
                        cname_target = val.rstrip(".")

                    if asset_id:
                        upsert_dns_record(
                            db=ctx.db,
                            asset_id=asset_id,
                            scan_id=ctx.scan_id,
                            record_type=rtype,
                            value=val,
                        )

        # 4. Check for wildcard match
        if wildcard_ips and any(ip in wildcard_ips for ip in resolved_ips):
            result.is_wildcard = True
            insert_scan_event(
                ctx.db,
                ctx.scan_id,
                "INFO",
                f"Hostname {hostname} matched wildcard zone answers",
            )

        # 5. Check dangling CNAME
        if cname_target:
            cname_ans = await ctx.requests.dns_query(cname_target, "A")
            if not cname_ans:
                result.dangling_cname = cname_target
                result.observations.append(f"Dangling CNAME candidate: {cname_target}")

        # 6. Post-DNS scope re-check
        if resolved_ips:
            dns_decision = ctx.scope.recheck_after_dns(hostname, resolved_ips)
            if not dns_decision.allowed:
                result.is_authorized = False
                insert_scan_event(
                    ctx.db,
                    ctx.scan_id,
                    "WARN",
                    f"Resolved IPs for {hostname} violate scope: {dns_decision.reason}",
                )
                return result

        # 7. Check observations: SPF, DMARC, CAA
        txt_records = result.records.get("TXT", [])
        has_spf = any("v=spf1" in txt.lower() for txt in txt_records)
        if not has_spf:
            result.observations.append("Missing SPF record")

        dmarc_records = await ctx.requests.dns_query(f"_dmarc.{hostname}", "TXT")
        if not dmarc_records:
            result.observations.append("Missing DMARC record")
        elif any("p=none" in rec.lower() for rec in dmarc_records):
            result.observations.append("DMARC policy is p=none")

        if "CAA" not in result.records:
            result.observations.append("Missing CAA record")

        # 8. Record observations in findings table
        if asset_id and result.observations:
            for obs in result.observations:
                finding_id = f"F-DNS-{abs(hash((hostname, obs))) % 100000:05d}"
                ctx.db.execute(
                    """
                    INSERT INTO findings (
                        id, scan_id, asset_id, type, title, severity_hint,
                        confidence, status, notes, created_at
                    ) VALUES (?, ?, ?, 'observation', ?, 'info', 'high', 'new', ?, ?)
                    ON CONFLICT(id) DO NOTHING
                    """,
                    (finding_id, ctx.scan_id, asset_id, obs, "DNS observation lead", utc_now_iso()),
                )
            ctx.db.commit()

        # 9. Update asset confidence: resolved in-scope -> high
        if asset_id and resolved_ips and not result.is_wildcard:
            new_conf = upgrade_confidence(current_conf, "high")
            upsert_asset(ctx.db, ctx.program, raw_target, confidence=new_conf)
            if raw_target != hostname:
                upsert_asset(ctx.db, ctx.program, hostname, confidence=new_conf)

        return result
