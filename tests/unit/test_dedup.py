"""Unit tests for host deduplication and source merging."""

from reconx.core.deduplicator import deduplicate_hosts
from reconx.integrations.subfinder import DiscoveredHost


def test_dedup_case_and_trailing_dots():
    hosts = [
        DiscoveredHost("EXAMPLE.com.", sources=["crtsh"]),
        DiscoveredHost("example.com", sources=["subfinder"]),
        DiscoveredHost("Example.Com", sources=["alienvault"]),
    ]
    merged = deduplicate_hosts(hosts)
    assert len(merged) == 1
    assert merged[0].hostname == "example.com"
    assert set(merged[0].sources) == {"alienvault", "crtsh", "subfinder"}


def test_dedup_fixture_1000_items():
    # 1000 items with known duplicates
    raw_list = []
    for i in range(500):
        raw_list.append(DiscoveredHost(f"sub{i}.example.com", sources=["source1"]))
        # duplicate
        raw_list.append(DiscoveredHost(f"SUB{i}.EXAMPLE.COM.", sources=["source2"]))

    assert len(raw_list) == 1000
    deduped = deduplicate_hosts(raw_list)
    assert len(deduped) == 500
    assert all(len(h.sources) == 2 for h in deduped)
