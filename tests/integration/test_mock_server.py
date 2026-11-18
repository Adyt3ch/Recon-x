"""Integration tests for RequestManager against local threaded MockServer."""

import pytest

from reconx.core.config import (
    ScopeConfig,
    ScopeInScope,
    ScopeOutOfScope,
    ScopeRules,
    Settings,
)
from reconx.core.rate_limiter import AsyncRateLimiter
from reconx.core.request_manager import RequestManager
from reconx.core.scope import ScopeEngine
from reconx.database.storage import apply_migrations, create_scan, get_db


@pytest.mark.integration
@pytest.mark.asyncio
async def test_request_manager_mock_server_routes(mock_server, tmp_path):
    base_url = mock_server.base_url
    port = mock_server.port

    # Setup database and scope
    db = get_db(tmp_path / "integ.db")
    apply_migrations(db)
    create_scan(db, "RX-001", "lab", "cautious", 100)

    scope_cfg = ScopeConfig(
        program="lab",
        authorized_by="Self",
        in_scope=ScopeInScope(
            domains=["127.0.0.1", "localhost"],
            ips=["127.0.0.1"],
            web_ports=[port, 80, 443],
        ),
        out_of_scope=ScopeOutOfScope(
            domains=["evil.com"],
        ),
        rules=ScopeRules(max_requests=100),
    )
    scope_engine = ScopeEngine(scope_cfg)

    settings = Settings()
    settings.request_control.limits.max_response_bytes = 10_000
    settings.request_control.retry.max_attempts = 0

    limiter = AsyncRateLimiter(
        requests_per_second=50.0,
        requests_per_minute=3000,
        min_delay=0.0,
        max_delay=0.0,
    )

    manager = RequestManager(
        scan_id="RX-001",
        scope_engine=scope_engine,
        settings=settings,
        db=db,
        rate_limiter=limiter,
    )

    # 1. /ok
    resp_ok = await manager.request("GET", f"{base_url}/ok")
    assert resp_ok.status_code == 200
    assert resp_ok.text == "OK"

    # 2. /redir-out (redirect to evil.com is blocked)
    resp_redir = await manager.request("GET", f"{base_url}/redir-out")
    assert resp_redir.status_code == 302
    assert "evil.com" in resp_redir.header("Location", "")

    # 3. /429
    resp_429 = await manager.request("GET", f"{base_url}/429")
    assert resp_429.status_code == 429

    # 4. /503
    resp_503 = await manager.request("GET", f"{base_url}/503")
    assert resp_503.status_code == 503

    # 5. /big (truncated at 10,000 bytes)
    resp_big = await manager.request("GET", f"{base_url}/big")
    assert resp_big.status_code == 200
    assert len(resp_big.content) == 10_000
    assert resp_big.is_truncated is True

    # 6. /soft404/test
    resp_soft = await manager.request("GET", f"{base_url}/soft404/test")
    assert resp_soft.status_code == 200
    assert "404 Not Found" in resp_soft.text

    # Audit check
    cursor = db.execute("SELECT COUNT(*) FROM request_log WHERE scan_id = 'RX-001'")
    assert cursor.fetchone()[0] >= 6
