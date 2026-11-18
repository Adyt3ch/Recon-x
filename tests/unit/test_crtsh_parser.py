"""Unit tests for crt.sh certificate transparency log parser."""

import json
from pathlib import Path

from reconx.modules.subdomains import parse_crtsh_json


def test_parse_crtsh_fixture():
    fixture_path = Path("tests/fixtures/crtsh_sample.json")
    content = fixture_path.read_text(encoding="utf-8")
    data = json.loads(content)

    hosts = parse_crtsh_json(data)
    assert "example.com" in hosts
    assert "admin.example.com" in hosts
    assert "internal.admin.example.com" in hosts
    # Wildcard prefix *. was cleaned
    assert not any(h.startswith("*.") for h in hosts)
