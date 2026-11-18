"""Unit tests for vulnerability intelligence: CPE mapping, NVD caching, and CISA KEV."""

from __future__ import annotations

import sqlite3
from unittest.mock import AsyncMock

import pytest

from reconx.core.config import Settings
from reconx.core.engine import ScanContext
from reconx.database.storage import apply_migrations, create_scan, upsert_asset, upsert_technology
from reconx.modules.vulnerability_intel import (
    VulnerabilityIntelModule,
    format_cpe_uri,
    load_cpe_map,
    parse_cisa_kev_catalog,
    parse_nvd_cve_response,
    query_cve_cache,
    save_cve_cache,
)


@pytest.fixture
def vuln_db():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    apply_migrations(db)
    create_scan(db, "RX-VULN", "test-corp", "cautious", 100)
    yield db
    db.close()


def test_cpe_map_and_formatting():
    cpe_map = load_cpe_map("config/cpe_map.yaml")
    assert "nginx" in cpe_map
    assert "apache" in cpe_map
    cpe_uri = format_cpe_uri(cpe_map["nginx"], "1.18.0")
    assert cpe_uri == "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"


def test_cve_cache_ttl_and_expiry(vuln_db):
    sample_payload = {"vulnerabilities": [{"cve": {"id": "CVE-2021-23017"}}]}
    lookup_key = "nvd:test_cpe"

    # Save with 24 hour TTL
    save_cve_cache(vuln_db, "nvd", lookup_key, sample_payload, ttl_hours=24)
    cached = query_cve_cache(vuln_db, lookup_key)
    assert cached is not None
    assert cached["vulnerabilities"][0]["cve"]["id"] == "CVE-2021-23017"

    # Save with negative TTL (already expired)
    save_cve_cache(vuln_db, "nvd", lookup_key, sample_payload, ttl_hours=-1)
    expired = query_cve_cache(vuln_db, lookup_key)
    assert expired is None


def test_parse_nvd_cve_response():
    nvd_sample = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-23017",
                    "descriptions": [{"lang": "en", "value": "A 1-byte memory overwrite in nginx resolver."}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                        ]
                    },
                }
            }
        ]
    }
    records = parse_nvd_cve_response(nvd_sample)
    assert len(records) == 1
    assert records[0]["cve_id"] == "CVE-2021-23017"
    assert records[0]["cvss_score"] == 9.8
    assert "memory overwrite" in records[0]["description"]


def test_parse_cisa_kev_catalog():
    kev_sample = {
        "vulnerabilities": [
            {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j"},
            {"cveID": "cve-2023-38606", "vendorProject": "Apple", "product": "iOS"},
        ]
    }
    cves = parse_cisa_kev_catalog(kev_sample)
    assert "CVE-2021-44228" in cves
    assert "CVE-2023-38606" in cves


@pytest.mark.asyncio
async def test_version_match_only_low_confidence(vuln_db):
    upsert_asset(vuln_db, "test-corp", "nginx.test-corp.com", confidence="verified")
    cursor = vuln_db.execute("SELECT id FROM assets WHERE hostname = 'nginx.test-corp.com'")
    asset_id = cursor.fetchone()["id"]

    upsert_technology(
        vuln_db,
        asset_id=asset_id,
        name="nginx",
        version="1.18.0",
        category="web-servers",
        evidence="Server: nginx/1.18.0",
    )

    # Pre-seed cache so no outgoing request is made
    nvd_sample = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-23017",
                    "descriptions": [{"lang": "en", "value": "Buffer overflow in resolver"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.5}}]},
                }
            }
        ]
    }
    save_cve_cache(vuln_db, "nvd", "nvd:cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*", nvd_sample, ttl_hours=24)

    ctx = ScanContext(
        scan_id="RX-VULN",
        program="test-corp",
        settings=Settings(),
        scope=AsyncMock(),
        requests=AsyncMock(),
        db=vuln_db,
    )

    mod = VulnerabilityIntelModule()
    tasks = mod.plan(ctx)
    assert len(tasks) == 1
    assert "nginx|1.18.0" in tasks[0].target

    results = await mod.run(ctx, tasks[0])
    assert len(results) == 1

    # Safety Rule 7: Version-only match is NEVER above low confidence!
    assert results[0]["confidence"] == "low"

    cursor = vuln_db.execute("SELECT * FROM findings WHERE id = 'F-CVE-CVE-2021-23017'")
    finding = cursor.fetchone()
    assert finding is not None
    assert finding["type"] == "observation"
    assert finding["confidence"] == "low"
