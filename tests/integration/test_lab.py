"""Lab target integration tests against OWASP Juice Shop on localhost:3000."""

from __future__ import annotations

import os
import socket
from pathlib import Path

import pytest

from reconx.core.audit import verify_chain
from reconx.core.config import load_scope, load_settings
from reconx.core.engine import ScanContext, ScanEngine
from reconx.core.rate_limiter import AsyncRateLimiter
from reconx.core.request_manager import RequestManager
from reconx.core.scope import ScopeEngine
from reconx.database.storage import apply_migrations, create_scan, get_db
from reconx.modules.http import HttpModule
from reconx.reporting.metrics import (
    calculate_rate_limit_breaches,
    calculate_requests_per_asset,
    calculate_scope_violations,
)


def is_juice_shop_running(host: str = "127.0.0.1", port: int = 3000, timeout: float = 0.5) -> bool:
    """Check if the lab container is reachable."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@pytest.mark.lab
@pytest.mark.asyncio
async def test_juice_shop_lab_scan(tmp_path: Path):
    """Run lab scan against OWASP Juice Shop if running, validating Section 13 gates."""
    lab_enabled = os.environ.get("RECONX_LAB") == "1"
    juice_running = is_juice_shop_running()

    if not lab_enabled and not juice_running:
        pytest.skip(
            "OWASP Juice Shop not running on 127.0.0.1:3000 and RECONX_LAB!=1. "
            "Start with: docker run -d --name juiceshop -p 127.0.0.1:3000:3000 bkimminich/juice-shop"
        )

    # Database
    db_path = tmp_path / "lab.db"
    db = get_db(db_path)
    apply_migrations(db)

    scan_id = "RX-LAB"
    create_scan(db, scan_id, "lab", "cautious", 50)

    # Load lab scope
    scope_path = Path("config/scope.lab.yaml")
    if not scope_path.exists():
        pytest.skip("config/scope.lab.yaml not found")
    scope_cfg = load_scope(scope_path)
    scope_engine = ScopeEngine(scope_cfg)

    settings = load_settings(profile_override="cautious")
    limiter = AsyncRateLimiter(
        requests_per_second=settings.request_control.global_rate.requests_per_second,
        requests_per_minute=settings.request_control.global_rate.requests_per_minute,
        min_delay=settings.request_control.delay.minimum,
        max_delay=settings.request_control.delay.maximum,
    )

    req_mgr = RequestManager(
        scan_id=scan_id,
        scope_engine=scope_engine,
        settings=settings,
        db=db,
        rate_limiter=limiter,
    )

    ctx = ScanContext(
        scan_id=scan_id,
        program="lab",
        settings=settings,
        scope=scope_engine,
        requests=req_mgr,
        db=db,
    )

    # Seed asset
    db.execute(
        "INSERT INTO assets (program, hostname, confidence) VALUES ('lab', 'localhost', 'verified')"
    )
    db.commit()

    http_module = HttpModule()
    engine = ScanEngine([http_module])
    await engine.run(ctx)

    # Section 13 Gates Verification
    is_valid, err = verify_chain(db, scan_id)
    assert is_valid is True, f"Hash chain verification failed: {err}"

    scope_violations = calculate_scope_violations(db, scan_id)
    assert scope_violations == 0, f"Scope violations detected: {scope_violations}"

    rate_breaches = calculate_rate_limit_breaches(db, scan_id, max_rps=1.0)
    assert rate_breaches == 0, f"Rate breaches detected: {rate_breaches}"

    rpa = calculate_requests_per_asset(db, scan_id)
    assert rpa <= 5.0, f"Requests per asset exceeded threshold: {rpa}"

    db.close()
