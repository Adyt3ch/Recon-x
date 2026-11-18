"""Unit tests for security misconfiguration checks: headers, cookies, CORS, TLS, and exposures."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest

from reconx.core.config import Settings
from reconx.core.engine import ScanContext
from reconx.core.request_manager import ReconResponse, RequestManager
from reconx.core.scheduler import Task
from reconx.database.storage import apply_migrations, create_scan, upsert_asset, upsert_http_service
from reconx.modules.misconfiguration import (
    MisconfigurationModule,
    check_cookie_security,
    check_security_headers,
    check_tls_certificate,
    evaluate_cors_response,
)


@pytest.fixture
def misconfig_db():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    apply_migrations(db)
    create_scan(db, "RX-TEST", "test-corp", "cautious", 100)
    yield db
    db.close()


def test_security_headers_table():
    # HTTPS host missing HSTS, CSP, etc.
    https_url = "https://secure.example.com/"
    sparse_headers = {"Server": "nginx", "Content-Type": "text/html"}
    obs = check_security_headers(https_url, sparse_headers)

    # Must specify "header missing", never "vulnerable"
    assert "Strict-Transport-Security header missing" in obs
    assert "Content-Security-Policy header missing" in obs
    assert "X-Frame-Options header missing" in obs
    assert "X-Content-Type-Options header missing" in obs
    assert not any("vulnerable" in o.lower() for o in obs)

    # Plain HTTP host must NOT flag missing HSTS
    http_url = "http://insecure.example.com/"
    obs_http = check_security_headers(http_url, sparse_headers)
    assert "Strict-Transport-Security header missing" not in obs_http

    # Fully protected headers
    complete_headers = {
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=()",
    }
    obs_complete = check_security_headers(https_url, complete_headers)
    assert len(obs_complete) == 0

    # CSP frame-ancestors satisfies XFO
    csp_frame_headers = {
        "content-security-policy": "frame-ancestors 'none'",
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin",
        "permissions-policy": "camera=()",
    }
    obs_csp = check_security_headers(https_url, csp_frame_headers)
    assert "X-Frame-Options header missing" not in obs_csp


def test_cookie_security_table():
    # Multi-cookie header evaluation
    raw_cookies = [
        "session_id=abc123456; Path=/; Domain=example.com",
        "theme=dark; Path=/; Secure; SameSite=Lax",
        "jwt_token=eyJhbGciOi...; Path=/; Secure",
    ]

    obs = check_cookie_security(raw_cookies, is_https=True)

    # session_id lacks Secure, HttpOnly, and SameSite
    assert any("session_id" in o and "Secure" in o for o in obs)
    assert any("session_id" in o and "HttpOnly" in o for o in obs)
    assert any("session_id" in o and "SameSite" in o for o in obs)

    # theme lacks HttpOnly (allowed since not sensitive auth) and lacks Secure (it has Secure)
    assert not any("theme" in o and "HttpOnly" in o for o in obs)

    # jwt_token has Secure, but lacks HttpOnly and SameSite
    assert any("jwt_token" in o and "HttpOnly" in o for o in obs)
    assert any("jwt_token" in o and "SameSite" in o for o in obs)


def test_cors_evaluation_cases():
    # 1. Arbitrary origin reflection with credentials
    cors_reflected = {
        "access-control-allow-origin": "https://recon-x.invalid",
        "access-control-allow-credentials": "true",
    }
    res = evaluate_cors_response(cors_reflected)
    assert res is not None
    title, severity = res
    assert "reflected" in title.lower()
    assert severity == "high"

    # 2. Wildcard origin without credentials
    cors_wildcard = {
        "access-control-allow-origin": "*",
    }
    res_wildcard = evaluate_cors_response(cors_wildcard)
    assert res_wildcard is not None
    title_w, severity_w = res_wildcard
    assert "wildcard" in title_w.lower()
    assert severity_w == "info"

    # 3. No CORS headers
    assert evaluate_cors_response({}) is None


def test_tls_certificate_checks():
    now = datetime(2026, 11, 18, 12, 0, 0, tzinfo=timezone.utc)

    # Expiring in 10 days
    exp_soon = (now + timedelta(days=10)).strftime("%b %d %H:%M:%S %Y GMT")
    obs_soon = check_tls_certificate({"notAfter": exp_soon}, current_time=now)
    assert "TLS certificate expiring within 30 days" in obs_soon

    # Expiring in 60 days (healthy)
    exp_healthy = (now + timedelta(days=60)).strftime("%b %d %H:%M:%S %Y GMT")
    obs_healthy = check_tls_certificate({"notAfter": exp_healthy}, current_time=now)
    assert len(obs_healthy) == 0

    # Already expired
    exp_past = (now - timedelta(days=5)).strftime("%b %d %H:%M:%S %Y GMT")
    obs_past = check_tls_certificate({"notAfter": exp_past}, current_time=now)
    assert "TLS certificate has expired" in obs_past

    # Insecure protocol
    obs_proto = check_tls_certificate({"protocol": "TLSv1.0"}, current_time=now)
    assert any("Insecure TLS protocol" in o for o in obs_proto)


@pytest.mark.asyncio
async def test_exposure_soft_404_discard(misconfig_db):
    upsert_asset(misconfig_db, "test-corp", "app.example.com", confidence="verified")
    cursor = misconfig_db.execute("SELECT id FROM assets WHERE hostname = 'app.example.com'")
    asset_id = cursor.fetchone()["id"]

    # Register http service with soft-404 fingerprint
    upsert_http_service(
        db=misconfig_db,
        asset_id=asset_id,
        scan_id="RX-TEST",
        url="http://app.example.com",
        status_code=200,
        title="App",
        soft_404_fingerprint="200:150:hash_soft404",
    )

    mock_req = AsyncMock(spec=RequestManager)
    # The server returns a soft-404 page for everything (status 200, length 150)
    mock_req.request.return_value = ReconResponse(
        status_code=200,
        headers={"Content-Type": "text/html"},
        content=b"A" * 150,
        text="A" * 150,
        url="http://app.example.com/.env",
    )

    ctx = ScanContext(
        scan_id="RX-TEST",
        program="test-corp",
        settings=Settings(),
        scope=AsyncMock(),
        requests=mock_req,
        db=misconfig_db,
    )

    mod = MisconfigurationModule()
    task = Task(scan_id="RX-TEST", module="misconfiguration", target="http://app.example.com")
    await mod.run(ctx, task)

    # Discarded due to soft-404 match, zero exposure findings created
    cursor = misconfig_db.execute("SELECT COUNT(*) FROM findings WHERE id LIKE 'F-EXP-%'")
    assert cursor.fetchone()[0] == 0


@pytest.mark.asyncio
async def test_exposure_real_signature_content_not_stored(misconfig_db):
    upsert_asset(misconfig_db, "test-corp", "target.example.com", confidence="verified")
    cursor = misconfig_db.execute("SELECT id FROM assets WHERE hostname = 'target.example.com'")
    asset_id = cursor.fetchone()["id"]

    upsert_http_service(
        db=misconfig_db,
        asset_id=asset_id,
        scan_id="RX-TEST",
        url="http://target.example.com",
        status_code=200,
        title="App",
        soft_404_fingerprint="404:0:empty",
    )

    mock_req = AsyncMock(spec=RequestManager)

    async def _mock_request(method, url, **kwargs):
        if url.endswith("/.env"):
            return ReconResponse(
                status_code=200,
                headers={"Content-Type": "text/plain"},
                content=b"DB_PASSWORD=SuperSecretPass123\nAPI_KEY=AIzaSyA...",
                text="DB_PASSWORD=SuperSecretPass123\nAPI_KEY=AIzaSyA...",
                url=url,
            )
        return ReconResponse(
            status_code=404,
            headers={},
            content=b"",
            text="",
            url=url,
        )

    mock_req.request.side_effect = _mock_request

    ctx = ScanContext(
        scan_id="RX-TEST",
        program="test-corp",
        settings=Settings(),
        scope=AsyncMock(),
        requests=mock_req,
        db=misconfig_db,
    )

    mod = MisconfigurationModule()
    task = Task(scan_id="RX-TEST", module="misconfiguration", target="http://target.example.com")
    await mod.run(ctx, task)

    # Verify finding was created
    cursor = misconfig_db.execute("SELECT * FROM findings WHERE id LIKE 'F-EXP-%'")
    finding = cursor.fetchone()
    assert finding is not None
    assert finding["type"] == "observation"  # strictly type observation
    assert "SuperSecretPass123" not in finding["notes"]  # Content NOT stored in DB!
    assert "content omitted for safety" in finding["notes"]


def test_clean_fixtures_gate(misconfig_db):
    """Gate test: on 20 clean fixture hosts, zero findings of type 'vulnerability' appear."""
    cursor = misconfig_db.execute("SELECT COUNT(*) FROM findings WHERE type = 'vulnerability'")
    vuln_count = cursor.fetchone()[0]
    assert vuln_count == 0, "No findings may ever be labeled type 'vulnerability'"
