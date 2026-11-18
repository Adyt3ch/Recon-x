"""Passive subdomain discovery module integrating crt.sh and Subfinder."""

from __future__ import annotations

import json
from typing import Any

from reconx.core.deduplicator import deduplicate_hosts
from reconx.core.engine import ScanContext
from reconx.core.normalizer import NormalizationError, normalize_hostname
from reconx.core.scheduler import Task
from reconx.core.tool_runner import ToolRunner
from reconx.database.storage import insert_scan_event, upsert_asset
from reconx.integrations.subfinder import DiscoveredHost, SubfinderIntegration
from reconx.intelligence.confidence import calculate_asset_confidence


def parse_crtsh_json(entries: list[dict[str, Any]]) -> list[str]:
    """Parse crt.sh JSON output, splitting multi-name cert entries and stripping wildcards."""
    discovered: set[str] = set()

    for entry in entries:
        name_val = entry.get("name_value", "")
        if not name_val:
            continue

        # May contain multiple lines or comma-separated names
        lines = name_val.replace(",", "\n").splitlines()
        for raw in lines:
            cleaned = raw.strip()
            if cleaned.startswith("*."):
                cleaned = cleaned[2:]
            if cleaned:
                try:
                    norm = normalize_hostname(cleaned).value
                    discovered.add(norm)
                except NormalizationError:
                    continue

    return sorted(discovered)


class SubdomainsModule:
    """Module responsible for passive subdomain discovery."""
    name = "subdomains"

    def __init__(self, tool_runner: ToolRunner | None = None):
        self.tool_runner = tool_runner

    def plan(self, ctx: ScanContext) -> list[Task]:
        """Generate tasks for all in-scope root domains."""
        tasks: list[Task] = []
        for domain in ctx.scope.config.in_scope.domains:
            d = domain.strip().lstrip("*.")
            if d:
                tasks.append(
                    Task(
                        scan_id=ctx.scan_id,
                        module=self.name,
                        target=d,
                        estimated_requests=1,
                    )
                )
        return tasks

    async def run(self, ctx: ScanContext, task: Task) -> list[DiscoveredHost]:
        """Perform passive reconnaissance on task.target domain."""
        raw_target = task.target
        base_domain = raw_target.split(":")[0] if ":" in raw_target else raw_target
        all_hosts: list[DiscoveredHost] = [
            DiscoveredHost(hostname=raw_target, sources=["seed"])
        ]

        # 1. crt.sh Query via passive_get (never touches target budget)
        crtsh_url = f"https://crt.sh/?q=%.{base_domain}&output=json"
        try:
            resp = await ctx.requests.passive_get(crtsh_url)
            if resp.status_code == 200 and resp.content:
                try:
                    cert_data = json.loads(resp.text)
                    if isinstance(cert_data, list):
                        names = parse_crtsh_json(cert_data)
                        for name in names:
                            all_hosts.append(DiscoveredHost(hostname=name, sources=["crtsh"]))
                except Exception:
                    pass
        except Exception as e:
            insert_scan_event(ctx.db, ctx.scan_id, "WARN", f"crt.sh lookup error for {base_domain}: {e}")

        # 2. Subfinder CLI discovery
        runner = self.tool_runner or ToolRunner(scan_id=ctx.scan_id, db_path=ctx.settings.storage.database)
        subfinder = SubfinderIntegration(runner)
        sub_limit = ctx.settings.external_tools.subfinder.rate_limit or 10
        sub_timeout = ctx.settings.external_tools.subfinder.timeout or 300

        sub_hosts, warn = subfinder.discover(
            domain=base_domain,
            rate_limit=sub_limit,
            timeout=sub_timeout,
        )
        if warn:
            insert_scan_event(ctx.db, ctx.scan_id, "INFO", warn)
        if sub_hosts:
            all_hosts.extend(sub_hosts)

        # 3. Deduplicate across sources
        merged = deduplicate_hosts(all_hosts)
        saved_assets: list[DiscoveredHost] = []

        # 4. Scope verification & Database persistence
        for host_item in merged:
            decision = ctx.scope.check(host_item.hostname)
            if decision.allowed:
                confidence = calculate_asset_confidence(host_item.sources)
                for src in host_item.sources:
                    upsert_asset(
                        db=ctx.db,
                        program=ctx.program,
                        hostname=host_item.hostname,
                        confidence=confidence,
                        source=src,
                    )
                saved_assets.append(host_item)
            else:
                insert_scan_event(
                    ctx.db,
                    ctx.scan_id,
                    "DEBUG",
                    f"Out-of-scope passive asset dropped: {host_item.hostname}",
                )

        return saved_assets
