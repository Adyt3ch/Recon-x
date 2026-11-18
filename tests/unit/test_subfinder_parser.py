"""Unit tests for Subfinder output parser against recorded fixture."""

from pathlib import Path

from reconx.integrations.subfinder import parse_subfinder_jsonl


def test_parse_subfinder_fixture():
    fixture_path = Path("tests/fixtures/subfinder_sample.jsonl")
    content = fixture_path.read_text(encoding="utf-8")

    hosts = parse_subfinder_jsonl(content)
    host_map = {h.hostname: h.sources for h in hosts}

    assert "api.example.com" in host_map
    assert "alienvault" in host_map["api.example.com"]
    assert "mail.example.com" in host_map
    assert "dev.example.com" in host_map
    assert "evil.com" in host_map
    assert len(hosts) == 5
