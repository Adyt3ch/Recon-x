"""Unit tests for port scanning, Nmap XML parsing, Naabu, CDN skipping, and cloud storage detection."""

from __future__ import annotations

import sqlite3

import pytest

from reconx.core.config import ScopeConfig, ScopeInScope, ScopeRules, Settings
from reconx.core.engine import ScanContext
from reconx.core.scope import ScopeEngine
from reconx.database.storage import apply_migrations, create_scan, upsert_asset, upsert_http_service
from reconx.modules.ports import (
    PortsModule,
    extract_cloud_storage_references,
    is_ip_cdn_or_waf,
    parse_naabu_output,
    parse_nmap_xml,
)


@pytest.fixture
def ports_db():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    apply_migrations(db)
    create_scan(db, "RX-PORTS", "test-corp", "cautious", 100)
    yield db
    db.close()


def test_ports_planning_disabled_by_default(ports_db):
    upsert_asset(ports_db, "test-corp", "app.test-corp.com", confidence="verified")
    cursor = ports_db.execute("SELECT id FROM assets WHERE hostname = 'app.test-corp.com'")
    asset_id = cursor.fetchone()["id"]
    ports_db.execute(
        "INSERT INTO dns_records (asset_id, scan_id, type, value, ttl, observed_at) VALUES (?, 'RX-PORTS', 'A', '1.2.3.4', 300, '2026-11-18')",
        (asset_id,),
    )
    ports_db.commit()

    scope_cfg = ScopeConfig(
        program="test-corp",
        in_scope=ScopeInScope(domains=["*.test-corp.com"]),
        rules=ScopeRules(allow_port_scan=False),
    )
    ctx = ScanContext(
        scan_id="RX-PORTS",
        program="test-corp",
        settings=Settings(),
        scope=ScopeEngine(scope_cfg),
        requests=None,  # type: ignore
        db=ports_db,
    )

    mod = PortsModule()
    tasks = mod.plan(ctx)
    assert len(tasks) == 0  # Strictly disabled by default


def test_ports_skips_cdn_waf(ports_db):
    upsert_asset(ports_db, "test-corp", "cdn.test-corp.com", confidence="verified")
    cursor = ports_db.execute("SELECT id FROM assets WHERE hostname = 'cdn.test-corp.com'")
    asset_id = cursor.fetchone()["id"]

    # Flag as CDN
    upsert_http_service(
        db=ports_db,
        asset_id=asset_id,
        scan_id="RX-PORTS",
        url="https://cdn.test-corp.com",
        status_code=200,
        title="CDN Home",
        is_cdn=1,
    )

    assert is_ip_cdn_or_waf(ports_db, asset_id) is True


def test_ports_dedupes_by_ip(ports_db):
    # Enable port scanning in scope rules
    scope_cfg = ScopeConfig(
        program="test-corp",
        in_scope=ScopeInScope(domains=["*.test-corp.com"]),
        rules=ScopeRules(allow_port_scan=True),
    )

    # 3 hostnames resolving to the SAME IP 10.0.0.1
    for host in ("web1.test-corp.com", "web2.test-corp.com", "web3.test-corp.com"):
        upsert_asset(ports_db, "test-corp", host, confidence="verified")
        cursor = ports_db.execute("SELECT id FROM assets WHERE hostname = ?", (host,))
        aid = cursor.fetchone()["id"]
        ports_db.execute(
            "INSERT INTO dns_records (asset_id, scan_id, type, value, ttl, observed_at) VALUES (?, 'RX-PORTS', 'A', '10.0.0.1', 300, '2026-11-18')",
            (aid,),
        )
    ports_db.commit()

    ctx = ScanContext(
        scan_id="RX-PORTS",
        program="test-corp",
        settings=Settings(),
        scope=ScopeEngine(scope_cfg),
        requests=None,  # type: ignore
        db=ports_db,
    )

    mod = PortsModule()
    tasks = mod.plan(ctx)
    # 3 hostnames pointing to 1 IP must produce exactly 1 scan task!
    assert len(tasks) == 1
    assert "10.0.0.1" in tasks[0].target


def test_parse_nmap_xml():
    xml_data = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -p 80,443 --max-rate 100 1.2.3.4" start="1600000000">
<host>
<address addr="1.2.3.4" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="80">
  <state state="open" reason="syn-ack"/>
  <service name="http" product="nginx" version="1.18.0" method="probed"/>
</port>
<port protocol="tcp" portid="443">
  <state state="open" reason="syn-ack"/>
  <service name="https" product="Apache" version="2.4.41" method="probed"/>
</port>
<port protocol="tcp" portid="8080">
  <state state="closed" reason="reset"/>
</port>
</ports>
</host>
</nmaprun>
"""
    results = parse_nmap_xml(xml_data)
    assert len(results) == 2
    assert results[0]["port"] == 80
    assert results[0]["service"] == "http"
    assert results[0]["banner"] == "nginx 1.18.0"
    assert results[1]["port"] == 443
    assert results[1]["banner"] == "Apache 2.4.41"


def test_parse_naabu_output():
    json_lines = '{"host":"1.2.3.4","ip":"1.2.3.4","port":80}\n{"host":"1.2.3.4","ip":"1.2.3.4","port":443}\n'
    results = parse_naabu_output(json_lines)
    assert len(results) == 2
    assert results[0]["port"] == 80
    assert results[1]["port"] == 443

    plain_lines = "1.2.3.4:8080\n1.2.3.4:8443\n"
    res_plain = parse_naabu_output(plain_lines)
    assert len(res_plain) == 2
    assert res_plain[0]["port"] == 8080


def test_cloud_storage_bucket_detection():
    sample_text = """
    var s3url = "https://company-backups.s3.amazonaws.com/data.tar.gz";
    var gcs = "https://storage.googleapis.com/static-assets-bucket/main.js";
    var azure = "https://privateblobs.blob.core.windows.net/logs/";
    var s3uri = "s3://prod-exports-archive/2026/";
    """
    buckets = extract_cloud_storage_references(sample_text)
    assert len(buckets) == 4

    names = [b["bucket"] for b in buckets]
    assert "company-backups" in names
    assert "static-assets-bucket" in names
    assert "privateblobs" in names
    assert "prod-exports-archive" in names
