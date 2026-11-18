"""Unit tests for the RequestManager with MockTransport and fake clock."""

import httpx
import pytest

from reconx.core.config import (
    ScopeConfig,
    ScopeInScope,
    ScopeOutOfScope,
    ScopeRules,
    Settings,
)
from reconx.core.rate_limiter import AsyncRateLimiter, FakeClock
from reconx.core.request_manager import (
    BudgetExceeded,
    RequestManager,
    ScanPaused,
    ScopeDenied,
)
from reconx.core.scope import ScopeEngine
from reconx.database.storage import apply_migrations, create_scan, get_db


@pytest.fixture
def mock_env(tmp_path):
    clock = FakeClock()
    db = get_db(tmp_path / "req.db")
    apply_migrations(db)
    create_scan(db, "RX-001", "test-prog", "cautious", 1000)

    scope_cfg = ScopeConfig(
        program="test-prog",
        authorized_by="Policy",
        in_scope=ScopeInScope(
            domains=["example.com", "*.example.com"],
            web_ports=[80, 443, 8080],
        ),
        out_of_scope=ScopeOutOfScope(
            domains=["evil.com", "out.example.com"],
        ),
        rules=ScopeRules(max_requests=10),
    )
    scope_engine = ScopeEngine(scope_cfg)

    settings = Settings()
    settings.request_control.budget.max_requests = 10
    settings.request_control.limits.max_response_bytes = 1000
    settings.request_control.limits.max_redirects = 3
    settings.request_control.retry.max_attempts = 1
    settings.request_control.protection.repeated_error_threshold = 3

    limiter = AsyncRateLimiter(
        requests_per_second=100.0,
        requests_per_minute=6000,
        min_delay=0.0,
        max_delay=0.0,
        clock=clock.now,
        sleep_func=clock.sleep,
    )

    return {
        "clock": clock,
        "db": db,
        "scope_engine": scope_engine,
        "settings": settings,
        "limiter": limiter,
    }


@pytest.mark.asyncio
async def test_request_out_of_scope_raises_and_sends_nothing(mock_env):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(handler)
    manager = RequestManager(
        scan_id="RX-001",
        scope_engine=mock_env["scope_engine"],
        settings=mock_env["settings"],
        db=mock_env["db"],
        rate_limiter=mock_env["limiter"],
        clock=mock_env["clock"].now,
        sleep_func=mock_env["clock"].sleep,
        transport=transport,
    )

    with pytest.raises(ScopeDenied):
        await manager.request("GET", "https://evil.com/phish")

    assert len(calls) == 0


@pytest.mark.asyncio
async def test_budget_exhaustion(mock_env):
    mock_env["settings"].request_control.budget.max_requests = 3

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    manager = RequestManager(
        scan_id="RX-001",
        scope_engine=mock_env["scope_engine"],
        settings=mock_env["settings"],
        db=mock_env["db"],
        rate_limiter=mock_env["limiter"],
        clock=mock_env["clock"].now,
        sleep_func=mock_env["clock"].sleep,
        transport=httpx.MockTransport(handler),
    )

    # 3 allowed
    for i in range(3):
        res = await manager.request("GET", f"https://example.com/page{i}")
        assert res.status_code == 200

    # 4th raises BudgetExceeded
    with pytest.raises(BudgetExceeded):
        await manager.request("GET", "https://example.com/page4")


@pytest.mark.asyncio
async def test_redirect_to_out_of_scope_not_followed(mock_env):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(302, headers={"Location": "https://evil.com/stolen"})
        return httpx.Response(200, text="at evil")

    manager = RequestManager(
        scan_id="RX-001",
        scope_engine=mock_env["scope_engine"],
        settings=mock_env["settings"],
        db=mock_env["db"],
        rate_limiter=mock_env["limiter"],
        clock=mock_env["clock"].now,
        sleep_func=mock_env["clock"].sleep,
        transport=httpx.MockTransport(handler),
    )

    res = await manager.request("GET", "https://example.com/start")
    assert res.status_code == 302
    assert res.header("Location") == "https://evil.com/stolen"
    # Evil was not probed; manager stopped following
    assert res.url == "https://example.com/start"


@pytest.mark.asyncio
async def test_retry_after_respected(mock_env):
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(429, headers={"Retry-After": "7"})
        return httpx.Response(200, text="recovered")

    clock = mock_env["clock"]
    manager = RequestManager(
        scan_id="RX-001",
        scope_engine=mock_env["scope_engine"],
        settings=mock_env["settings"],
        db=mock_env["db"],
        rate_limiter=mock_env["limiter"],
        clock=clock.now,
        sleep_func=clock.sleep,
        transport=httpx.MockTransport(handler),
    )

    t0 = clock.now()
    res = await manager.request("GET", "https://example.com/rate-limited")
    t1 = clock.now()

    assert res.status_code == 200
    assert (t1 - t0) >= 7.0


@pytest.mark.asyncio
async def test_repeated_503_backoff_and_scan_paused(mock_env):
    mock_env["settings"].request_control.protection.repeated_error_threshold = 3

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="Service Unavailable")

    clock = mock_env["clock"]
    manager = RequestManager(
        scan_id="RX-001",
        scope_engine=mock_env["scope_engine"],
        settings=mock_env["settings"],
        db=mock_env["db"],
        rate_limiter=mock_env["limiter"],
        clock=clock.now,
        sleep_func=clock.sleep,
        transport=httpx.MockTransport(handler),
    )

    # After 3 consecutive 503 errors, manager raises ScanPaused
    with pytest.raises(ScanPaused):
        for i in range(5):
            await manager.request("GET", f"https://example.com/item{i}")

    # Backoff increased across attempts (30, 60, etc.)
    assert clock.now() >= 30.0


@pytest.mark.asyncio
async def test_oversized_body_is_truncated(mock_env):
    mock_env["settings"].request_control.limits.max_response_bytes = 50

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="A" * 500)

    manager = RequestManager(
        scan_id="RX-001",
        scope_engine=mock_env["scope_engine"],
        settings=mock_env["settings"],
        db=mock_env["db"],
        rate_limiter=mock_env["limiter"],
        clock=mock_env["clock"].now,
        sleep_func=mock_env["clock"].sleep,
        transport=httpx.MockTransport(handler),
    )

    res = await manager.request("GET", "https://example.com/huge")
    assert len(res.content) <= 50
    assert res.is_truncated is True


@pytest.mark.asyncio
async def test_request_log_audit_rows_written(mock_env):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="ok")

    manager = RequestManager(
        scan_id="RX-001",
        scope_engine=mock_env["scope_engine"],
        settings=mock_env["settings"],
        db=mock_env["db"],
        rate_limiter=mock_env["limiter"],
        clock=mock_env["clock"].now,
        sleep_func=mock_env["clock"].sleep,
        transport=httpx.MockTransport(handler),
    )

    await manager.request("GET", "https://example.com/log1")
    await manager.request("GET", "https://example.com/log2")

    cursor = mock_env["db"].execute("SELECT COUNT(*) FROM request_log WHERE scan_id = 'RX-001'")
    count = cursor.fetchone()[0]
    assert count == 2
