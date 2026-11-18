"""Tests for Section 13 metrics and quality assurance verification."""

from __future__ import annotations

from reconx.core.audit import log_request
from reconx.database.storage import (
    apply_migrations,
    create_scan,
    get_db,
    upsert_asset,
)
from reconx.reporting.metrics import (
    calculate_dns_verification_rate,
    calculate_duplicate_asset_percentage,
    calculate_endpoint_precision_recall,
    calculate_false_positive_rate,
    calculate_http_verification_rate,
    calculate_rate_limit_breaches,
    calculate_requests_per_asset,
    calculate_scan_completion_rate,
    calculate_scope_violations,
    calculate_subdomain_coverage,
    compute_scan_metrics,
)


def test_calculate_scope_violations(tmp_path):
    db_path = tmp_path / "metrics_test.db"
    db = get_db(db_path)
    apply_migrations(db)
    create_scan(db, "RX-001", "test-corp", "cautious", 100)

    # 1. Clean log: in-scope requests sent, denied requests blocked (status is None)
    log_request(
        db,
        "RX-001",
        "GET",
        "https://app.test-corp.com/",
        "app.test-corp.com",
        200,
        100,
        50,
        "allow",
        ts="2026-11-18T10:00:00Z",
    )
    log_request(
        db,
        "RX-001",
        "GET",
        "https://evil.com/",
        "evil.com",
        None,
        None,
        None,
        "denied: out of scope",
        ts="2026-11-18T10:00:01Z",
    )

    violations = calculate_scope_violations(db, "RX-001")
    assert violations == 0

    # 2. Add an illegal request (dispatched over the wire despite being denied)
    log_request(
        db,
        "RX-001",
        "GET",
        "https://unauthorized.com/",
        "unauthorized.com",
        200,
        100,
        50,
        "denied: illegal",
        ts="2026-11-18T10:00:02Z",
    )

    violations = calculate_scope_violations(db, "RX-001")
    assert violations == 1
    db.close()


def test_calculate_rate_limit_breaches(tmp_path):
    db_path = tmp_path / "rate_test.db"
    db = get_db(db_path)
    apply_migrations(db)
    create_scan(db, "RX-002", "test-corp", "cautious", 100)

    # Compliant: 1 request every 1.5 seconds
    log_request(
        db,
        "RX-002",
        "GET",
        "https://a.test/",
        "a.test",
        200,
        100,
        50,
        "allow",
        ts="2026-11-18T10:00:00.000Z",
    )
    log_request(
        db,
        "RX-002",
        "GET",
        "https://a.test/2",
        "a.test",
        200,
        100,
        50,
        "allow",
        ts="2026-11-18T10:00:01.500Z",
    )

    breaches = calculate_rate_limit_breaches(db, "RX-002", max_rps=1.0)
    assert breaches == 0

    # Non-compliant: 4 requests within 0.2 seconds (burst exceeds max_rps 1.0 + tolerance 1)
    for i in range(4):
        log_request(
            db,
            "RX-002",
            "GET",
            f"https://a.test/{i}",
            "a.test",
            200,
            100,
            50,
            "allow",
            ts=f"2026-11-18T10:00:03.0{i}0Z",
        )

    breaches = calculate_rate_limit_breaches(db, "RX-002", max_rps=1.0)
    assert breaches > 0
    db.close()


def test_calculate_duplicate_asset_percentage():
    clean_assets = ["a.com", "b.com", "c.com"]
    assert calculate_duplicate_asset_percentage(clean_assets) == 0.0

    duplicate_assets = ["a.com", "b.com", "a.com", "c.com"]
    assert calculate_duplicate_asset_percentage(duplicate_assets) == 25.0

    assert calculate_duplicate_asset_percentage([]) == 0.0


def test_calculate_requests_per_asset(tmp_path):
    db_path = tmp_path / "reqs_asset.db"
    db = get_db(db_path)
    apply_migrations(db)
    create_scan(db, "RX-003", "test-corp", "cautious", 100)

    # 2 assets verified
    upsert_asset(db, "test-corp", "a.test-corp.com", confidence="verified")
    upsert_asset(db, "test-corp", "b.test-corp.com", confidence="verified")

    # 4 requests sent
    for i in range(4):
        log_request(
            db,
            "RX-003",
            "GET",
            f"https://a.test-corp.com/{i}",
            "a.test-corp.com",
            200,
            100,
            50,
            "allow",
            ts=f"2026-11-18T10:00:0{i}.000Z",
        )

    rpa = calculate_requests_per_asset(db, "RX-003")
    assert rpa == 2.0  # 4 / 2 = 2.0 <= 3.0 baseline target
    db.close()


def test_calculate_dns_and_http_rates():
    assert calculate_dns_verification_rate(80, 100) == 0.8
    assert calculate_dns_verification_rate(0, 0) == 0.0

    assert calculate_http_verification_rate(65, 80) == 0.812
    assert calculate_http_verification_rate(0, 0) == 0.0


def test_calculate_endpoint_precision_recall():
    ground_truth = {"/api/v1/users", "/api/v1/auth", "/api/v1/orders", "/dashboard", "/login"}
    extracted = {"/api/v1/users", "/api/v1/auth", "/api/v1/orders", "/dashboard", "/fake_route"}

    metrics = calculate_endpoint_precision_recall(extracted, ground_truth)
    assert metrics["precision"] == 0.8
    assert metrics["recall"] == 0.8

    # Perfect extraction meets >= 0.9 target
    perfect = calculate_endpoint_precision_recall(ground_truth, ground_truth)
    assert perfect["precision"] >= 0.9
    assert perfect["recall"] == 1.0


def test_calculate_false_positive_rate(tmp_path):
    db_path = tmp_path / "fp_test.db"
    db = get_db(db_path)
    apply_migrations(db)
    create_scan(db, "RX-004", "test-corp", "cautious", 100)

    upsert_asset(db, "test-corp", "app.test-corp.com", confidence="verified")
    cursor = db.execute("SELECT id FROM assets WHERE hostname = 'app.test-corp.com'")
    asset_id = cursor.fetchone()["id"]

    db.execute(
        """
        INSERT INTO findings (id, scan_id, asset_id, type, title, severity_hint, confidence, status, created_at)
        VALUES ('F-MTR-001', 'RX-004', ?, 'observation', 'CORS Misconfig', 'low', 'medium', 'false_positive', '2026-11-18')
        """,
        (asset_id,),
    )
    db.execute(
        """
        INSERT INTO findings (id, scan_id, asset_id, type, title, severity_hint, confidence, status, created_at)
        VALUES ('F-MTR-002', 'RX-004', ?, 'observation', 'Missing HSTS', 'info', 'medium', 'confirmed', '2026-11-18')
        """,
        (asset_id,),
    )
    db.commit()

    fp_rate = calculate_false_positive_rate(db, "RX-004")
    assert fp_rate == 0.5  # 1 out of 2 is false_positive
    db.close()


def test_calculate_subdomain_coverage():
    known = {"a.com", "b.com", "c.com", "d.com", "e.com"}
    discovered = {"a.com", "b.com", "c.com", "x.com"}
    coverage = calculate_subdomain_coverage(discovered, known)
    assert coverage == 0.6  # 3 of 5


def test_calculate_scan_completion_rate(tmp_path):
    db_path = tmp_path / "scans_test.db"
    db = get_db(db_path)
    apply_migrations(db)

    create_scan(db, "RX-001", "corp", "cautious", 100)
    create_scan(db, "RX-002", "corp", "cautious", 100)
    db.execute("UPDATE scans SET status = 'completed' WHERE id = 'RX-001'")
    db.commit()

    rate = calculate_scan_completion_rate(db)
    assert rate == 0.5
    db.close()


def test_compute_scan_metrics_e2e(tmp_path):
    db_path = tmp_path / "e2e_metrics.db"
    db = get_db(db_path)
    apply_migrations(db)
    create_scan(db, "RX-005", "corp", "cautious", 100)

    upsert_asset(db, "corp", "api.corp.com", confidence="verified")
    cursor = db.execute("SELECT id FROM assets WHERE hostname = 'api.corp.com'")
    asset_id = cursor.fetchone()["id"]

    log_request(
        db,
        "RX-005",
        "GET",
        "https://api.corp.com/v1",
        "api.corp.com",
        200,
        100,
        50,
        "allow",
        ts="2026-11-18T10:00:00.000Z",
    )
    log_request(
        db,
        "RX-005",
        "GET",
        "https://api.corp.com/v2",
        "api.corp.com",
        200,
        100,
        50,
        "allow",
        ts="2026-11-18T10:00:01.200Z",
    )

    db.execute(
        """
        INSERT INTO findings (id, scan_id, asset_id, type, title, severity_hint, confidence, status, created_at)
        VALUES ('F-MTR-003', 'RX-005', ?, 'observation', 'CORS', 'low', 'medium', 'confirmed', '2026-11-18')
        """,
        (asset_id,),
    )
    db.execute("UPDATE scans SET status = 'completed' WHERE id = 'RX-005'")
    db.commit()

    metrics = compute_scan_metrics(db, "RX-005", max_rps=1.0)
    assert metrics["scan_id"] == "RX-005"
    assert metrics["scope_violations"] == 0
    assert metrics["rate_limit_breaches"] == 0
    assert metrics["duplicate_asset_percentage"] == 0.0
    assert metrics["requests_per_asset"] <= 3.0
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["scan_completion_rate"] == 1.0
    db.close()
