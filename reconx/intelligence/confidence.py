"""Asset confidence evaluation and monotonic state progression."""

from __future__ import annotations

from typing import Sequence

CONFIDENCE_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "verified": 4,
}


def calculate_asset_confidence(
    sources: Sequence[str],
    dns_resolved: bool = False,
    http_live: bool = False,
    is_wildcard: bool = False,
) -> str:
    """Calculate asset confidence based on deterministic source and verification criteria.

    - Low: seen by one source only, or wildcard matches.
    - Medium: seen by two or more independent sources.
    - High: DNS resolves successfully.
    - Verified: Live HTTP response received with stored evidence.
    """
    if is_wildcard:
        return "low"

    if http_live:
        return "verified"

    if dns_resolved:
        return "high"

    # Distinct data providers count as independent sources
    unique_sources = {s.strip().lower() for s in sources if s.strip()}
    if len(unique_sources) >= 2:
        return "medium"

    return "low"


def upgrade_confidence(current: str, candidate: str) -> str:
    """Return the higher confidence level, ensuring confidence never drops."""
    curr_rank = CONFIDENCE_RANK.get(current.lower(), 1)
    cand_rank = CONFIDENCE_RANK.get(candidate.lower(), 1)
    return candidate if cand_rank > curr_rank else current
