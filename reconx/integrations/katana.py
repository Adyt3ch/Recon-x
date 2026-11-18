"""Katana crawler integration with rate-limit compliance."""

from __future__ import annotations

import json
from collections.abc import Sequence

from reconx.core.tool_runner import (
    OptionInjectionError,
    ToolExecutionError,
    ToolMissing,
    ToolRunner,
)


def parse_katana_jsonl(lines: Sequence[str] | str) -> list[str]:
    """Parse JSONL output lines from Katana crawler into unique URLs."""
    if isinstance(lines, str):
        raw_lines = lines.splitlines()
    else:
        raw_lines = list(lines)

    urls: list[str] = []
    seen: set[str] = set()

    for line in raw_lines:
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            endpoint = ""
            if isinstance(data, dict):
                req = data.get("request", {})
                if isinstance(req, dict) and "endpoint" in req:
                    endpoint = str(req["endpoint"])
                elif "endpoint" in data:
                    endpoint = str(data["endpoint"])
                elif "url" in data:
                    endpoint = str(data["url"])
            elif isinstance(data, str):
                endpoint = data

            if endpoint and endpoint not in seen:
                seen.add(endpoint)
                urls.append(endpoint)
        except json.JSONDecodeError:
            # Fallback if plain URL string line
            if line.startswith(("http://", "https://")) and line not in seen:
                seen.add(line)
                urls.append(line)

    return urls


class KatanaIntegration:
    """Wrapper executing Katana safely through ToolRunner."""

    def __init__(self, runner: ToolRunner):
        self.runner = runner

    def crawl(
        self,
        url: str,
        rate_limit: int = 10,
        depth: int = 2,
        concurrency: int = 1,
        timeout: int = 300,
    ) -> tuple[list[str], str | None]:
        """Crawl a verified live URL.

        Returns (urls, warning_or_error_message).
        """
        if url.startswith("-"):
            raise OptionInjectionError(f"Target URL cannot begin with hyphen: {url!r}")

        args = [
            "-u",
            url,
            "-rl",
            str(rate_limit),
            "-d",
            str(depth),
            "-c",
            str(concurrency),
            "-silent",
            "-jsonl",
        ]

        try:
            res = self.runner.run(
                tool="katana",
                args=args,
                target=url,
                timeout=timeout,
            )
            parsed_urls = parse_katana_jsonl(res.stdout)
            return parsed_urls, None
        except ToolMissing:
            return [], "Katana binary not found on PATH; skipping active crawl"
        except ToolExecutionError as e:
            return [], f"Katana crawl failed: {e}"
