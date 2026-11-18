"""Unit tests for technology fingerprinting rules and soft-404 comparison."""

from reconx.core.config import ScopeConfig, ScopeInScope, ScopeRules, Settings
from reconx.core.engine import ScanContext
from reconx.core.rate_limiter import AsyncRateLimiter
from reconx.core.request_manager import RequestManager
from reconx.core.scope import ScopeEngine
from reconx.database.storage import (
    apply_migrations,
    create_scan,
    get_db,
    upsert_asset,
    upsert_http_service,
)
from reconx.modules.fingerprint import (
    FingerprintModule,
    is_soft_404_match,
)


def test_soft_404_comparison():
    fp = '{"status_code": 404, "length": 150, "body_hash": "abc123hash"}'

    # Same status and same length -> match
    assert is_soft_404_match(404, b"A" * 150, fp) is True
    # Different status code -> not match
    assert is_soft_404_match(200, b"A" * 150, fp) is False
    # Significantly different length -> not match
    assert is_soft_404_match(404, b"A" * 5000, fp) is False


def test_fingerprint_passive_zero_requests(tmp_path):
    db = get_db(tmp_path / "fp.db")
    apply_migrations(db)
    scan_id = "RX-FP-01"
    create_scan(db, scan_id, "fp-prog", "cautious", 100)

    scope_cfg = ScopeConfig(
        program="fp-prog",
        authorized_by="Self",
        in_scope=ScopeInScope(domains=["example.com"]),
        rules=ScopeRules(),
    )
    scope = ScopeEngine(scope_cfg)
    settings = Settings()
    req_mgr = RequestManager(
        scan_id=scan_id,
        scope_engine=scope,
        settings=settings,
        db=db,
        rate_limiter=AsyncRateLimiter(),
    )
    ctx = ScanContext(
        scan_id=scan_id,
        program="fp-prog",
        settings=settings,
        scope=scope,
        requests=req_mgr,
        db=db,
    )

    # Insert asset and live service with Nginx and WordPress
    asset_id = upsert_asset(db, "fp-prog", "app.example.com", confidence="verified")
    upsert_http_service(
        db=db,
        asset_id=asset_id,
        scan_id=scan_id,
        url="https://app.example.com/",
        status_code=200,
        server="nginx/1.24.0",
        title="WordPress Blog",
    )
    # Store evidence with WordPress body signature and meta generator
    db.execute(
        """
        INSERT INTO evidence (asset_id, kind, raw_redacted, source, captured_at)
        VALUES (?, 'http_response', ?, 'http_module', '2026-11-18T10:00:00Z')
        """,
        (asset_id, '<html><head><meta name="generator" content="WordPress 6.4.2"></head><body><link href="/wp-content/themes/style.css"></body></html>'),
    )
    db.commit()

    fp_mod = FingerprintModule()
    detected = fp_mod._fingerprint_passive(
        ctx=ctx,
        asset_id=asset_id,
        server_header="nginx/1.24.0",
        title="WordPress Blog",
        body_snippet='<html><head><meta name="generator" content="WordPress 6.4.2"></head><body><link href="/wp-content/themes/style.css"></body></html>',
    )

    assert "Nginx" in detected
    assert "WordPress" in detected

    # Verify technologies in database
    cursor = db.execute("SELECT name, version FROM technologies WHERE asset_id = ? ORDER BY name", (asset_id,))
    rows = cursor.fetchall()
    names = [r["name"] for r in rows]
    assert "Nginx" in names
    assert "WordPress" in names

    # Gate: zero requests added during passive fingerprinting
    log_cursor = db.execute("SELECT COUNT(*) FROM request_log WHERE scan_id = ?", (scan_id,))
    assert log_cursor.fetchone()[0] == 0
