"""Integration tests for HttpModule against mock server."""

import pytest

from reconx.core.config import ScopeConfig, ScopeInScope, ScopeRules, Settings
from reconx.core.engine import ScanContext
from reconx.core.rate_limiter import AsyncRateLimiter
from reconx.core.request_manager import RequestManager
from reconx.core.scheduler import Task
from reconx.core.scope import ScopeEngine
from reconx.database.storage import apply_migrations, create_scan, get_db, upsert_asset
from reconx.modules.http import HttpModule, extract_title, is_cdn_service


def test_extract_title():
    html = "<html><head><title>  Dashboard - Admin Panel  </title></head><body><h1>Hello</h1></body></html>"
    assert extract_title(html) == "Dashboard - Admin Panel"
    assert extract_title("<html><body>No title here</body></html>") is None


def test_is_cdn_service():
    assert is_cdn_service({"server": "cloudflare", "cf-ray": "123456789"}) is True
    assert is_cdn_service({"server": "Apache/2.4"}) is False


@pytest.mark.integration
@pytest.mark.asyncio
async def test_http_module_full_probing(mock_server, tmp_path):
    port = mock_server.port
    db = get_db(tmp_path / "http_mod.db")
    apply_migrations(db)

    scan_id = "RX-HTTP-01"
    create_scan(db, scan_id, "http-test", "cautious", 100)

    scope_cfg = ScopeConfig(
        program="http-test",
        authorized_by="Self",
        in_scope=ScopeInScope(
            domains=["127.0.0.1", "localhost"],
            ips=["127.0.0.1"],
            web_ports=[port, 80, 443],
        ),
        rules=ScopeRules(),
    )
    scope = ScopeEngine(scope_cfg)
    settings = Settings()
    # Fast retry & timeouts for test
    settings.request_control.retry.max_attempts = 0
    settings.request_control.timeouts.connect = 0.5
    settings.request_control.timeouts.read = 0.5

    limiter = AsyncRateLimiter(
        requests_per_second=50.0,
        requests_per_minute=3000,
        min_delay=0.0,
        max_delay=0.0,
    )

    req_mgr = RequestManager(
        scan_id=scan_id,
        scope_engine=scope,
        settings=settings,
        db=db,
        rate_limiter=limiter,
    )

    ctx = ScanContext(
        scan_id=scan_id,
        program="http-test",
        settings=settings,
        scope=scope,
        requests=req_mgr,
        db=db,
    )

    # Insert initial asset at high confidence (post-DNS)
    target_host = f"127.0.0.1:{port}"
    upsert_asset(db, "http-test", target_host, confidence="high")

    http_mod = HttpModule()
    task = Task(scan_id=scan_id, module="http", target=target_host)

    res = await http_mod.run(ctx, task)
    assert res is not None
    assert res["status_code"] in (200, 404)

    # 1. Verify asset confidence upgraded to verified
    cursor = db.execute("SELECT confidence FROM assets WHERE hostname = ?", (target_host,))
    assert cursor.fetchone()[0] == "verified"

    # 2. Verify http_services entry created
    srv_cursor = db.execute("SELECT status_code, soft_404_fingerprint FROM http_services WHERE scan_id = ?", (scan_id,))
    srv_row = srv_cursor.fetchone()
    assert srv_row is not None
    assert srv_row[0] is not None

    # 3. Verify evidence saved
    ev_cursor = db.execute("SELECT COUNT(*) FROM evidence WHERE kind = 'http_response'")
    assert ev_cursor.fetchone()[0] >= 1
