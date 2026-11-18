"""Integration test for host-restricted authenticated crawling and log redaction."""

from __future__ import annotations

import sqlite3

import httpx
import pytest

from reconx.core.config import AuthProfileConfig, ScopeConfig, ScopeInScope, Settings
from reconx.core.rate_limiter import AsyncRateLimiter
from reconx.core.request_manager import RequestManager
from reconx.core.scope import ScopeEngine


@pytest.fixture
def auth_db():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute("""
        CREATE TABLE request_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            ts TEXT NOT NULL,
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            host TEXT NOT NULL,
            status INTEGER,
            bytes INTEGER,
            duration_ms INTEGER,
            scope_decision TEXT NOT NULL,
            prev_hash TEXT,
            row_hash TEXT NOT NULL
        );
    """)
    db.commit()
    yield db
    db.close()


@pytest.mark.asyncio
async def test_auth_profile_host_restriction_and_redaction(auth_db):
    captured_requests: list[httpx.Request] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return httpx.Response(200, text="OK")

    transport = httpx.MockTransport(_handler)

    scope_cfg = ScopeConfig(
        program="auth-test",
        in_scope=ScopeInScope(domains=["allowed.example.com", "other.example.com"]),
    )
    scope = ScopeEngine(scope_cfg)

    # Auth profile configured ONLY for allowed.example.com
    secret_token = "SecretToken123456789"
    auth_prof = AuthProfileConfig(
        hosts=["allowed.example.com"],
        headers={"Authorization": f"Bearer {secret_token}"},
        cookies={"session_token": "CookieSecret999"},
    )

    settings = Settings()
    limiter = AsyncRateLimiter(requests_per_second=100.0, requests_per_minute=1000)

    mgr = RequestManager(
        scan_id="RX-AUTH",
        scope_engine=scope,
        settings=settings,
        db=auth_db,
        rate_limiter=limiter,
        transport=transport,
        auth_profile=auth_prof,
    )

    # 1. Request to matching host: MUST attach credentials
    resp1 = await mgr.request("GET", "https://allowed.example.com/api/profile")
    assert resp1.status_code == 200
    req1 = captured_requests[-1]
    assert req1.headers.get("Authorization") == f"Bearer {secret_token}"
    assert "CookieSecret999" in req1.headers.get("Cookie", "")

    # 2. Request to other in-scope host: MUST NOT attach credentials
    resp2 = await mgr.request("GET", "https://other.example.com/public")
    assert resp2.status_code == 200
    req2 = captured_requests[-1]
    assert "Authorization" not in req2.headers
    assert "Cookie" not in req2.headers

    # 3. Verify request log never contains the secret token
    cursor = auth_db.execute("SELECT * FROM request_log")
    rows = cursor.fetchall()
    assert len(rows) == 2
    for r in rows:
        assert secret_token not in r["url"]
        assert "CookieSecret999" not in r["url"]
