"""Unit tests for ASN, RDAP pivots, and passive infrastructure correlation."""

from __future__ import annotations

import sqlite3

import pytest

from reconx.database.storage import apply_migrations, create_scan, upsert_asset
from reconx.intelligence.pivots import (
    parse_rdap_response,
    parse_shodan_response,
    record_asn_pivot,
)


@pytest.fixture
def pivots_db():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    apply_migrations(db)
    create_scan(db, "RX-PIV", "test-corp", "cautious", 100)
    yield db
    db.close()


def test_parse_rdap_response():
    rdap_sample = {
        "handle": "NET-192-0-2-0-1",
        "name": "TEST-NET-1",
        "startAddress": "192.0.2.0",
        "endAddress": "192.0.2.255",
        "entities": [
            {
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Corp Hosting"]]],
            }
        ],
    }
    parsed = parse_rdap_response(rdap_sample)
    assert parsed["handle"] == "NET-192-0-2-0-1"
    assert parsed["name"] == "Example Corp Hosting"
    assert "192.0.2.0" in parsed["cidr_range"]


def test_parse_shodan_response():
    shodan_sample = {
        "asn": "AS15169",
        "org": "Google LLC",
        "ports": [80, 443, 8080],
        "hostnames": ["mail.google.com"],
    }
    parsed = parse_shodan_response(shodan_sample)
    assert parsed["asn"] == "AS15169"
    assert parsed["org"] == "Google LLC"
    assert 443 in parsed["ports"]
    assert parsed["source"] == "shodan"


def test_record_asn_pivot(pivots_db):
    upsert_asset(pivots_db, "test-corp", "host.test-corp.com", confidence="verified")
    cursor = pivots_db.execute("SELECT id FROM assets WHERE hostname = 'host.test-corp.com'")
    asset_id = cursor.fetchone()["id"]

    rdap_data = {
        "handle": "AS13335",
        "name": "Cloudflare Inc",
        "cidr_range": "104.16.0.0/12",
    }
    rel_id = record_asn_pivot(pivots_db, asset_id, rdap_data)
    assert rel_id > 0

    cursor = pivots_db.execute("SELECT * FROM asset_relationships WHERE id = ?", (rel_id,))
    row = cursor.fetchone()
    assert row is not None
    assert "AS13335" in row["relation"]
    assert "Cloudflare Inc" in row["relation"]
