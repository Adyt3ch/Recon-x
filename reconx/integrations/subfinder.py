"""Subfinder CLI integration and JSONL output parser."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from reconx.core.normalizer import NormalizationError, normalize_hostname
from reconx.core.tool_runner import ToolMissing, ToolRunner


@dataclass
class DiscoveredHost:
    hostname: str
    sources: list[str] = field(default_factory=list)


def parse_subfinder_jsonl(jsonl_text: str) -> list[DiscoveredHost]:
    """Parse Subfinder -oJ (JSON Lines) output and normalize hostnames."""
    results: list[DiscoveredHost] = []
    seen: set[str] = set()

    for line in jsonl_text.strip().splitlines():
        line = line.strip()
        if not line:
            continue

        raw_host = ""
        sources: list[str] = ["subfinder"]

        # Parse JSON
        if line.startswith("{") and line.endswith("}"):
            try:
                data = json.loads(line)
                raw_host = data.get("host", "").strip()
                srcs = data.get("sources")
                if isinstance(srcs, list) and srcs:
                    sources = [str(s) for s in srcs]
            except Exception:
                continue
        else:
            raw_host = line

        if not raw_host:
            continue

        try:
            norm_res = normalize_hostname(raw_host)
            canonical = norm_res.value
            if canonical not in seen:
                seen.add(canonical)
                results.append(DiscoveredHost(hostname=canonical, sources=sources))
        except NormalizationError:
            continue

    return results


class SubfinderIntegration:
    """Wrapper for executing Subfinder via ToolRunner."""

    def __init__(self, tool_runner: ToolRunner | None = None):
        self.runner = tool_runner or ToolRunner()

    def discover(
        self,
        domain: str,
        rate_limit: int = 10,
        timeout: int = 300,
    ) -> tuple[list[DiscoveredHost], str | None]:
        """Run Subfinder for domain. Returns (discovered_hosts, error_or_warning)."""
        args = ["-d", domain, "-silent", "-oJ", "-rl", str(rate_limit)]

        try:
            result = self.runner.run(
                tool="subfinder",
                args=args,
                timeout=timeout,
            )
            hosts = parse_subfinder_jsonl(result.stdout)
            return hosts, None
        except ToolMissing as e:
            return [], f"Subfinder skipped: {e}"
        except Exception as e:
            return [], f"Subfinder error: {e}"
