"""Asset deduplication and source merging by canonical hostname."""

from __future__ import annotations

from typing import Sequence

from reconx.core.normalizer import NormalizationError, normalize_hostname
from reconx.integrations.subfinder import DiscoveredHost


def deduplicate_hosts(hosts: Sequence[DiscoveredHost]) -> list[DiscoveredHost]:
    """Merge duplicate hosts by normalized hostname, unioning all discovery sources."""
    merged: dict[str, set[str]] = {}

    for item in hosts:
        raw_name = item.hostname
        try:
            norm_res = normalize_hostname(raw_name)
            canonical = norm_res.value
        except NormalizationError:
            continue

        if canonical not in merged:
            merged[canonical] = set()

        for s in item.sources:
            if s and s.strip():
                merged[canonical].add(s.strip().lower())

    return [
        DiscoveredHost(hostname=h, sources=sorted(sources))
        for h, sources in sorted(merged.items())
    ]
