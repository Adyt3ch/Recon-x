"""Integration test for monitor mode: baseline creation, change detection, and webhook alerts."""

from __future__ import annotations

import sqlite3
from unittest.mock import AsyncMock

import pytest

from reconx.database.storage import apply_migrations, create_scan, upsert_asset
from reconx.intelligence.history import (
    diff_scans,
    format_alert_message,
    has_changes,
    save_scan_snapshot,
    send_monitor_alert,
)


@pytest.fixture
def monitor_db():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    apply_migrations(db)
    yield db
    db.close()


@pytest.mark.asyncio
async def test_monitor_workflow_and_webhook_alert(monitor_db):
    program = "monitor-target"

    # --- Run 1: Baseline Scan ---
    scan_id_1 = "RX-MON-001"
    create_scan(monitor_db, scan_id_1, program, "cautious", 50)
    upsert_asset(monitor_db, program, "app.monitor-target.com", confidence="verified")
    save_scan_snapshot(monitor_db, scan_id_1)

    # --- Run 2: Unchanged target ---
    scan_id_2 = "RX-MON-002"
    create_scan(monitor_db, scan_id_2, program, "cautious", 50)
    save_scan_snapshot(monitor_db, scan_id_2)

    diff_unchanged = diff_scans(monitor_db, scan_id_1, scan_id_2)
    assert has_changes(diff_unchanged) is False

    mock_req = AsyncMock()
    mock_req.send_webhook.return_value = True

    # No alert sent when target is unchanged
    sent_1 = await send_monitor_alert(diff_unchanged, mock_req, webhook_url="https://hooks.slack.com/test")
    assert sent_1 is False
    assert not mock_req.send_webhook.called

    # --- Run 3: Intentional change (new subdomain added) ---
    scan_id_3 = "RX-MON-003"
    create_scan(monitor_db, scan_id_3, program, "cautious", 50)
    upsert_asset(monitor_db, program, "admin-staging.monitor-target.com", confidence="verified")
    save_scan_snapshot(monitor_db, scan_id_3)

    diff_changed = diff_scans(monitor_db, scan_id_2, scan_id_3)
    assert has_changes(diff_changed) is True
    assert "admin-staging.monitor-target.com" in diff_changed["added_assets"]

    alert_text = format_alert_message(diff_changed)
    assert "admin-staging.monitor-target.com" in alert_text

    # Webhook alert sent with exact change
    sent_2 = await send_monitor_alert(diff_changed, mock_req, webhook_url="https://hooks.slack.com/test")
    assert sent_2 is True
    assert mock_req.send_webhook.called
    payload = mock_req.send_webhook.call_args[0][1]
    assert "admin-staging.monitor-target.com" in payload["text"]
