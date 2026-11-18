"""GAU (GetAllUrls) passive archive URL discovery integration."""

from __future__ import annotations

from collections.abc import Sequence

from reconx.core.tool_runner import (
    OptionInjectionError,
    ToolExecutionError,
    ToolMissing,
    ToolRunner,
)


def parse_gau_output(output: Sequence[str] | str) -> list[str]:
    """Parse plain-text output from GAU into unique URLs."""
    if isinstance(output, str):
        lines = output.splitlines()
    else:
        lines = list(output)

    urls: list[str] = []
    seen: set[str] = set()

    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith(("http://", "https://")) and line not in seen:
            seen.add(line)
            urls.append(line)

    return urls


class GauIntegration:
    """Wrapper executing GAU safely through ToolRunner."""

    def __init__(self, runner: ToolRunner):
        self.runner = runner

    def fetch(
        self,
        domain: str,
        threads: int = 2,
        timeout: int = 180,
    ) -> tuple[list[str], str | None]:
        """Fetch historical URLs for a domain from web archives.

        Returns (urls, warning_or_error_message).
        """
        if domain.startswith("-"):
            raise OptionInjectionError(f"Target domain cannot begin with hyphen: {domain!r}")

        args = ["--threads", str(threads), domain]

        try:
            res = self.runner.run(
                tool="gau",
                args=args,
                target=domain,
                timeout=timeout,
            )
            urls = parse_gau_output(res.stdout)
            return urls, None
        except ToolMissing:
            return [], "GAU binary not found on PATH; skipping archive URL lookup"
        except ToolExecutionError as e:
            return [], f"GAU lookup failed: {e}"
