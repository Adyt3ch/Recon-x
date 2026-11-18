"""Unit tests for intelligence correlation, priority scoring, and leads ranking."""

from __future__ import annotations

import sqlite3

import pytest

from reconx.database.storage import apply_migrations, create_scan, upsert_asset, upsert_url
from reconx.intelligence.correlation import (
    calculate_leads,
    load_scoring_weights,
)


@pytest.fixture
def correlation_db():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    apply_migrations(db)
    create_scan(db, "RX-LEADS", "target-corp", "cautious", 100)
    yield db
    db.close()


def test_load_scoring_weights():
    weights = load_scoring_weights("config/scoring.yaml")
    assert "names" in weights
    assert "endpoints" in weights
    assert "parameters" in weights
    assert "findings" in weights
    assert weights["names"]["admin"] == 15
    assert weights["findings"]["takeover_candidate"] == 30


def test_calculate_leads_ranking(correlation_db):
    # 1. High value target: admin-dev with login endpoint & redirect parameter
    upsert_asset(correlation_db, "target-corp", "admin-dev.target-corp.com", confidence="verified")
    cursor = correlation_db.execute("SELECT id FROM assets WHERE hostname = 'admin-dev.target-corp.com'")
    admin_id = cursor.fetchone()["id"]

    upsert_url(
        correlation_db,
        asset_id=admin_id,
        url_normalized="https://admin-dev.target-corp.com/login?redirect=/dashboard",
        source="katana",
        category="login",
        status_code=200,
    )

    # 2. Moderate value target: api endpoint
    upsert_asset(correlation_db, "target-corp", "api.target-corp.com", confidence="verified")
    cursor = correlation_db.execute("SELECT id FROM assets WHERE hostname = 'api.target-corp.com'")
    api_id = cursor.fetchone()["id"]

    upsert_url(
        correlation_db,
        asset_id=api_id,
        url_normalized="https://api.target-corp.com/v1/users",
        source="katana",
        category="api",
        status_code=200,
    )

    # 3. Low value target: static blog
    upsert_asset(correlation_db, "target-corp", "blog.target-corp.com", confidence="verified")

    # 4. Critical finding on admin-dev: Takeover candidate
    correlation_db.execute(
        """
        INSERT INTO findings (id, scan_id, asset_id, type, title, severity_hint, confidence, status, notes, created_at)
        VALUES ('F-1', 'RX-LEADS', ?, 'observation', 'Subdomain takeover candidate on GitHub Pages', 'high', 'medium', 'new', 'proof', '2026-11-18')
        """,
        (admin_id,),
    )
    correlation_db.commit()

    leads = calculate_leads(correlation_db, "RX-LEADS")

    assert len(leads) >= 2
    top_lead = leads[0]
    assert top_lead.target == "admin-dev.target-corp.com"
    # Admin hostname (15) + Login category (15) + Redirect param (15) + Takeover finding (30) = >= 75
    assert top_lead.score >= 70

    # Ensure blog has lower score than admin
    admin_lead = next(lead_item for lead_item in leads if lead_item.target == "admin-dev.target-corp.com")
    api_lead = next((lead_item for lead_item in leads if lead_item.target == "api.target-corp.com"), None)
    if api_lead:
        assert admin_lead.score > api_lead.score


def test_every_lead_has_reason_and_evidence(correlation_db):
    upsert_asset(correlation_db, "target-corp", "staging-api.target-corp.com", confidence="verified")
    cursor = correlation_db.execute("SELECT id FROM assets WHERE hostname = 'staging-api.target-corp.com'")
    asset_id = cursor.fetchone()["id"]

    upsert_url(
        correlation_db,
        asset_id=asset_id,
        url_normalized="https://staging-api.target-corp.com/upload?file=test.png",
        source="katana",
        category="upload",
    )

    leads = calculate_leads(correlation_db, "RX-LEADS")
    assert len(leads) > 0

    for lead in leads:
        assert len(lead.reasons) >= 1, f"Lead {lead.target} missing reasons"
        assert len(lead.evidence_links) >= 1, f"Lead {lead.target} missing evidence links"
        assert len(lead.suggested_test) > 0, f"Lead {lead.target} missing suggested test"


def test_lead_never_called_vulnerability(correlation_db):
    upsert_asset(correlation_db, "target-corp", "test.target-corp.com", confidence="verified")
    leads = calculate_leads(correlation_db, "RX-LEADS")
    for lead in leads:
        for r in lead.reasons:
            assert "vulnerability" not in r.lower()
