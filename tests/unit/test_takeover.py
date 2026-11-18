"""Unit tests for subdomain takeover detection module."""

from __future__ import annotations

import sqlite3
from unittest.mock import AsyncMock

import pytest

from reconx.core.config import Settings
from reconx.core.engine import ScanContext
from reconx.core.request_manager import ReconResponse, RequestManager
from reconx.core.scheduler import Task
from reconx.database.storage import apply_migrations, create_scan, upsert_asset
from reconx.intelligence.takeover import (
    TakeoverModule,
    load_takeover_rules,
    match_takeover_pattern,
)


@pytest.fixture
def takeover_db():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    apply_migrations(db)
    create_scan(db, "RX-TEST", "test-prog", "cautious", 100)
    yield db
    db.close()


def test_load_takeover_rules():
    rules = load_takeover_rules("config/fingerprints/takeover.yaml")
    assert isinstance(rules, list)
    assert len(rules) >= 4
    names = [r["name"] for r in rules]
    assert "GitHub Pages" in names
    assert "AWS S3" in names


def test_match_takeover_pattern():
    fps = ["There isn't a GitHub Pages site here.", "NoSuchBucket"]
    assert match_takeover_pattern("404 Not Found: There isn't a GitHub Pages site here.", fps) is True
    assert match_takeover_pattern("The specified bucket does not exist: NoSuchBucket", fps) is True
    assert match_takeover_pattern("Welcome to my active blog!", fps) is False


def test_takeover_planning(takeover_db):
    upsert_asset(takeover_db, "test-prog", "blog.example.com", confidence="high")
    upsert_asset(takeover_db, "test-prog", "api.example.com", confidence="high")

    # Add CNAME pointing to github.io for blog.example.com
    cursor = takeover_db.execute("SELECT id FROM assets WHERE hostname = 'blog.example.com'")
    blog_id = cursor.fetchone()["id"]
    takeover_db.execute(
        """
        INSERT INTO dns_records (asset_id, scan_id, type, value, ttl, observed_at)
        VALUES (?, 'RX-TEST', 'CNAME', 'myuser.github.io.', 300, '2026-11-18T00:00:00Z')
        """,
        (blog_id,),
    )

    # Add A record for api.example.com (no CNAME)
    cursor = takeover_db.execute("SELECT id FROM assets WHERE hostname = 'api.example.com'")
    api_id = cursor.fetchone()["id"]
    takeover_db.execute(
        """
        INSERT INTO dns_records (asset_id, scan_id, type, value, ttl, observed_at)
        VALUES (?, 'RX-TEST', 'A', '1.2.3.4', 300, '2026-11-18T00:00:00Z')
        """,
        (api_id,),
    )
    takeover_db.commit()

    ctx = ScanContext(
        scan_id="RX-TEST",
        program="test-prog",
        settings=Settings(),
        scope=AsyncMock(),
        requests=AsyncMock(),
        db=takeover_db,
    )

    mod = TakeoverModule("config/fingerprints/takeover.yaml")
    tasks = mod.plan(ctx)

    assert len(tasks) == 1
    assert "blog.example.com" in tasks[0].target
    assert "GitHub Pages" in tasks[0].target
    assert tasks[0].estimated_requests == 1


@pytest.mark.asyncio
async def test_takeover_run_vulnerable(takeover_db):
    upsert_asset(takeover_db, "test-prog", "dangling.example.com", confidence="high")

    mock_req = AsyncMock(spec=RequestManager)
    mock_req.request.return_value = ReconResponse(
        status_code=404,
        headers={"Server": "GitHub.com"},
        content=b"404: There isn't a GitHub Pages site here.",
        text="404: There isn't a GitHub Pages site here.",
        url="http://dangling.example.com/",
    )

    ctx = ScanContext(
        scan_id="RX-TEST",
        program="test-prog",
        settings=Settings(),
        scope=AsyncMock(),
        requests=mock_req,
        db=takeover_db,
    )

    task = Task(
        scan_id="RX-TEST",
        module="takeover",
        target="dangling.example.com|myuser.github.io|GitHub Pages",
    )

    mod = TakeoverModule()
    candidate = await mod.run(ctx, task)

    assert candidate is not None
    assert candidate.status == "confirmed_pattern"
    assert candidate.provider == "GitHub Pages"

    # Verify stored finding is observation, NEVER labeled vulnerability
    cursor = takeover_db.execute("SELECT * FROM findings WHERE scan_id = 'RX-TEST'")
    finding = cursor.fetchone()
    assert finding is not None
    assert finding["type"] == "observation"
    assert "takeover" in finding["title"].lower()

    # Verify evidence stored
    e_cursor = takeover_db.execute("SELECT * FROM evidence WHERE finding_id = ?", (finding["id"],))
    evidence = e_cursor.fetchone()
    assert evidence is not None
    assert evidence["kind"] == "takeover_proof"


@pytest.mark.asyncio
async def test_takeover_run_normal_no_match(takeover_db):
    upsert_asset(takeover_db, "test-prog", "active.example.com", confidence="high")

    mock_req = AsyncMock(spec=RequestManager)
    mock_req.request.return_value = ReconResponse(
        status_code=200,
        headers={"Content-Type": "text/html"},
        content=b"<html><body><h1>Legitimate Production App</h1></body></html>",
        text="<html><body><h1>Legitimate Production App</h1></body></html>",
        url="http://active.example.com/",
    )

    ctx = ScanContext(
        scan_id="RX-TEST",
        program="test-prog",
        settings=Settings(),
        scope=AsyncMock(),
        requests=mock_req,
        db=takeover_db,
    )

    task = Task(
        scan_id="RX-TEST",
        module="takeover",
        target="active.example.com|live.s3.amazonaws.com|AWS S3",
    )

    mod = TakeoverModule()
    candidate = await mod.run(ctx, task)

    assert candidate is not None
    assert candidate.status == "no_match"

    cursor = takeover_db.execute("SELECT COUNT(*) FROM findings WHERE scan_id = 'RX-TEST'")
    assert cursor.fetchone()[0] == 0
