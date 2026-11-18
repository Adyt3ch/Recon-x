"""Unit tests for scan history tracking, snapshot diffing, and monitor alerts."""

from __future__ import annotations

import sqlite3
from unittest.mock import AsyncMock

import pytest

from reconx.database.storage import apply_migrations, create_scan, upsert_asset
from reconx.intelligence.history import (
    build_scan_snapshot,
    diff_scans,
    format_alert_message,
    has_changes,
    save_scan_snapshot,
    send_monitor_alert,
)


@pytest.fixture
def history_db():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    apply_migrations(db)
    yield db
    db.close()


def test_build_and_save_scan_snapshot(history_db):
    create_scan(history_db, "RX-001", "test-corp", "cautious", 100)
    upsert_asset(history_db, "test-corp", "app.test-corp.com", confidence="verified")

    snap = build_scan_snapshot(history_db, "RX-001")
    assert snap["scan_id"] == "RX-001"
    assert snap["program"] == "test-corp"
    assert "app.test-corp.com" in snap["assets"]

    h = save_scan_snapshot(history_db, "RX-001")
    assert isinstance(h, str)
    assert len(h) == 64

    # Verify saved in asset_snapshots
    cursor = history_db.execute("SELECT snapshot_hash FROM asset_snapshots WHERE scan_id = 'RX-001'")
    row = cursor.fetchone()
    assert row is not None
    assert row["snapshot_hash"] == h


def test_diff_scans_table_driven(history_db):
    # Scan 1: Baseline
    create_scan(history_db, "RX-001", "test-corp", "cautious", 100)
    upsert_asset(history_db, "test-corp", "old.test-corp.com", confidence="verified")
    upsert_asset(history_db, "test-corp", "steady.test-corp.com", confidence="verified")

    cursor = history_db.execute("SELECT id FROM assets WHERE hostname = 'steady.test-corp.com'")
    steady_id = cursor.fetchone()["id"]

    # Steady host DNS in scan 1
    history_db.execute(
        """
        INSERT INTO dns_records (asset_id, scan_id, type, value, ttl, observed_at)
        VALUES (?, 'RX-001', 'A', '1.1.1.1', 300, '2026-11-18T00:00:00Z')
        """,
        (steady_id,),
    )
    # Steady host service in scan 1
    history_db.execute(
        """
        INSERT INTO http_services (asset_id, scan_id, url, status_code, title, server, body_hash, is_cdn, observed_at)
        VALUES (?, 'RX-001', 'https://steady.test-corp.com', 200, 'Home', 'nginx', 'hash1', 0, '2026-11-18T00:00:00Z')
        """,
        (steady_id,),
    )
    # Endpoint in scan 1
    history_db.execute(
        """
        INSERT INTO endpoints (url_id, method, path, first_seen)
        VALUES (1, 'GET', '/api/v1/users', '2026-11-18T00:00:00Z')
        """
    )
    # JS file in scan 1
    history_db.execute(
        """
        INSERT INTO js_files (url, sha256, size, first_seen, last_seen)
        VALUES ('https://steady.test-corp.com/bundle.js', 'old_js_hash', 1024, '2026-11-18T00:00:00Z', '2026-11-18T00:00:00Z')
        """
    )
    history_db.commit()

    save_scan_snapshot(history_db, "RX-001")

    # Scan 2: New scan with mutations
    create_scan(history_db, "RX-002", "test-corp", "cautious", 100)
    # 1. Added new asset
    upsert_asset(history_db, "test-corp", "new.test-corp.com", confidence="verified")
    # 2. Steady asset DNS changed to 2.2.2.2
    history_db.execute(
        """
        INSERT INTO dns_records (asset_id, scan_id, type, value, ttl, observed_at)
        VALUES (?, 'RX-002', 'A', '2.2.2.2', 300, '2026-11-18T01:00:00Z')
        """,
        (steady_id,),
    )
    # 3. Steady host service changed body_hash and status_code
    history_db.execute(
        """
        INSERT INTO http_services (asset_id, scan_id, url, status_code, title, server, body_hash, is_cdn, observed_at)
        VALUES (?, 'RX-002', 'https://steady.test-corp.com', 403, 'Forbidden', 'nginx', 'hash2', 0, '2026-11-18T01:00:00Z')
        """,
        (steady_id,),
    )
    # 4. New endpoint discovered
    history_db.execute(
        """
        INSERT INTO endpoints (url_id, method, path, first_seen)
        VALUES (1, 'POST', '/api/v2/admin', '2026-11-18T01:00:00Z')
        """
    )
    # 5. Changed JS hash
    history_db.execute(
        """
        UPDATE js_files SET sha256 = 'new_js_hash' WHERE url = 'https://steady.test-corp.com/bundle.js'
        """
    )
    history_db.commit()

    save_scan_snapshot(history_db, "RX-002")

    diff = diff_scans(history_db, "RX-001", "RX-002")

    assert has_changes(diff) is True
    assert "new.test-corp.com" in diff["added_assets"]
    assert any(d["hostname"] == "steady.test-corp.com" for d in diff["dns_changes"])
    assert any(s["url"] == "https://steady.test-corp.com" and s["change"] == "modified" for s in diff["service_changes"])
    assert "POST /api/v2/admin" in diff["new_endpoints"]
    assert any(j["url"] == "https://steady.test-corp.com/bundle.js" for j in diff["changed_js_files"])

    msg = format_alert_message(diff)
    assert "new.test-corp.com" in msg
    assert "POST /api/v2/admin" in msg
    # Verify alert message contains NO secrets or credentials
    assert "password" not in msg.lower()
    assert "secret" not in msg.lower()


@pytest.mark.asyncio
async def test_send_monitor_alert(history_db):
    diff = {
        "scan_old": "RX-001",
        "scan_new": "RX-002",
        "added_assets": ["sub.target.com"],
        "removed_assets": [],
        "dns_changes": [],
        "service_changes": [],
        "technology_changes": [],
        "new_endpoints": [],
        "changed_js_files": [],
    }

    mock_req_mgr = AsyncMock()
    mock_req_mgr.send_webhook.return_value = True

    sent = await send_monitor_alert(
        diff,
        req_mgr=mock_req_mgr,
        webhook_url="https://hooks.slack.com/services/test",
    )
    assert sent is True
    assert mock_req_mgr.send_webhook.called

    # When no changes, alert is NOT sent
    empty_diff = {
        "scan_old": "RX-001",
        "scan_new": "RX-002",
        "added_assets": [],
        "removed_assets": [],
        "dns_changes": [],
        "service_changes": [],
        "technology_changes": [],
        "new_endpoints": [],
        "changed_js_files": [],
    }
    mock_req_mgr.send_webhook.reset_mock()
    sent_empty = await send_monitor_alert(
        empty_diff,
        req_mgr=mock_req_mgr,
        webhook_url="https://hooks.slack.com/services/test",
    )
    assert sent_empty is False
    assert not mock_req_mgr.send_webhook.called
