"""Unit tests for finding lifecycle transitions, manual notes, and HackerOne report exports."""

from __future__ import annotations

import sqlite3

import pytest

from reconx.database.storage import apply_migrations, create_scan, upsert_asset
from reconx.intelligence.correlation import (
    add_manual_note,
    list_findings,
    render_finding_hackerone_report,
    update_finding_status,
)


@pytest.fixture
def findings_db():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    apply_migrations(db)
    create_scan(db, "RX-FND", "test-corp", "cautious", 100)
    upsert_asset(db, "test-corp", "vuln.test-corp.com", confidence="verified")
    cursor = db.execute("SELECT id FROM assets WHERE hostname = 'vuln.test-corp.com'")
    asset_id = cursor.fetchone()["id"]

    db.execute(
        """
        INSERT INTO findings (id, scan_id, asset_id, type, title, severity_hint, confidence, status, notes, created_at)
        VALUES ('F-TEST-001', 'RX-FND', ?, 'observation', 'CORS origin reflection', 'high', 'medium', 'new', 'initial notes', '2026-11-18')
        """,
        (asset_id,),
    )
    db.execute(
        """
        INSERT INTO evidence (finding_id, asset_id, kind, raw_redacted, source, captured_at)
        VALUES ('F-TEST-001', ?, 'cors_response', 'Access-Control-Allow-Origin: https://recon-x.invalid', 'misconfiguration', '2026-11-18')
        """,
        (asset_id,),
    )
    db.commit()
    yield db
    db.close()


def test_finding_valid_lifecycle_transitions(findings_db):
    # 1. new -> confirmed
    update_finding_status(findings_db, "F-TEST-001", "confirmed", note="Verified manually in browser")
    f = list_findings(findings_db, scan_id="RX-FND")[0]
    assert f["status"] == "confirmed"
    assert "Verified manually in browser" in f["notes"]

    # 2. confirmed -> reported
    update_finding_status(findings_db, "F-TEST-001", "reported", note="Submitted report #1234")
    f = list_findings(findings_db, scan_id="RX-FND")[0]
    assert f["status"] == "reported"

    # 3. reported -> fixed
    update_finding_status(findings_db, "F-TEST-001", "fixed", note="Patched by dev team")
    f = list_findings(findings_db, scan_id="RX-FND")[0]
    assert f["status"] == "fixed"


def test_finding_invalid_lifecycle_transitions(findings_db):
    # new -> reported (invalid: must be confirmed first!)
    with pytest.raises(ValueError, match="Invalid finding status transition"):
        update_finding_status(findings_db, "F-TEST-001", "reported")

    # new -> fixed (invalid)
    with pytest.raises(ValueError, match="Invalid finding status transition"):
        update_finding_status(findings_db, "F-TEST-001", "fixed")

    # Move to false_positive (terminal state)
    update_finding_status(findings_db, "F-TEST-001", "false_positive")
    # false_positive -> confirmed (invalid: terminal state)
    with pytest.raises(ValueError, match="Invalid finding status transition"):
        update_finding_status(findings_db, "F-TEST-001", "confirmed")


def test_add_manual_note(findings_db):
    note_id = add_manual_note(
        findings_db,
        entity_type="finding",
        entity_id="F-TEST-001",
        body="Attacker can craft cross-origin request to read user profile",
    )
    assert note_id > 0

    cursor = findings_db.execute("SELECT * FROM notes WHERE id = ?", (note_id,))
    note_row = cursor.fetchone()
    assert note_row is not None
    assert note_row["entity_id"] == "F-TEST-001"
    assert "cross-origin request" in note_row["body"]


def test_hackerone_report_template(findings_db):
    report_md = render_finding_hackerone_report(findings_db, "F-TEST-001")

    # Must contain required sections
    assert "## Summary" in report_md
    assert "## Steps to Reproduce" in report_md
    assert "## Impact" in report_md
    assert "## Evidence" in report_md
    assert "## Remediation" in report_md

    # Placeholders for manual sections
    assert "[Describe step-by-step reproduction instructions here]" in report_md
    assert "[Describe the business and security impact of this finding if exploited" in report_md

    # Severity must NOT be pre-filled
    assert "[Manual Triage Required - Select on HackerOne" in report_md

    # Evidence must be automatically populated
    assert "Access-Control-Allow-Origin: https://recon-x.invalid" in report_md
