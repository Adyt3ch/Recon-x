"""Unit tests for exporting scan results: hosts, URLs, Burp Suite scope, and Nuclei targets."""

from __future__ import annotations

import json
import sqlite3

import pytest

from reconx.database.storage import (
    apply_migrations,
    create_scan,
    upsert_asset,
    upsert_http_service,
    upsert_url,
)
from reconx.reporting.export import (
    export_burp_scope,
    export_hosts,
    export_nuclei_targets,
    export_urls,
    regex_escape_host,
)


@pytest.fixture
def export_db():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    apply_migrations(db)
    create_scan(db, "RX-EXP", "test-corp", "cautious", 100)

    # Assets
    upsert_asset(db, "test-corp", "api.test-corp.com", confidence="verified")
    upsert_asset(db, "test-corp", "app.test-corp.com", confidence="verified")
    cursor = db.execute("SELECT id FROM assets WHERE hostname = 'app.test-corp.com'")
    app_id = cursor.fetchone()["id"]

    # HTTP service
    upsert_http_service(
        db=db,
        asset_id=app_id,
        scan_id="RX-EXP",
        url="https://app.test-corp.com:8443",
        status_code=200,
        title="App Portal",
    )

    # URLs
    upsert_url(db, asset_id=app_id, url_normalized="https://app.test-corp.com:8443/login", source="katana")
    upsert_url(db, asset_id=app_id, url_normalized="https://app.test-corp.com:8443/dashboard", source="katana")

    yield db
    db.close()


def test_regex_escape_host():
    assert regex_escape_host("example.com") == r"^example\.com$"
    assert regex_escape_host("*.example.com") == r"^.*\.example\.com$"
    assert regex_escape_host("api.sub.example.com") == r"^api\.sub\.example\.com$"


def test_export_hosts(export_db):
    hosts_txt = export_hosts(export_db, "RX-EXP")
    lines = hosts_txt.strip().splitlines()
    assert len(lines) == 2
    assert "api.test-corp.com" in lines
    assert "app.test-corp.com" in lines


def test_export_urls(export_db):
    urls_txt = export_urls(export_db, "RX-EXP")
    lines = urls_txt.strip().splitlines()
    assert len(lines) == 2
    assert "https://app.test-corp.com:8443/login" in lines
    assert "https://app.test-corp.com:8443/dashboard" in lines


def test_export_nuclei_targets(export_db):
    nuclei_txt = export_nuclei_targets(export_db, "RX-EXP")
    lines = nuclei_txt.strip().splitlines()
    assert len(lines) == 1
    assert lines[0] == "https://app.test-corp.com:8443"


def test_export_burp_scope_valid_json(export_db):
    burp_data = export_burp_scope(export_db, "RX-EXP")
    assert "target" in burp_data
    assert "scope" in burp_data["target"]
    scope = burp_data["target"]["scope"]
    assert scope["advanced_mode"] is True
    assert len(scope["include"]) == 2

    # Verify JSON serializability
    json_str = json.dumps(burp_data)
    reloaded = json.loads(json_str)
    assert reloaded == burp_data
    hosts = [item["host"] for item in reloaded["target"]["scope"]["include"]]
    assert r"^api\.test\-corp\.com$" in hosts or r"^api\.test-corp\.com$" in hosts
