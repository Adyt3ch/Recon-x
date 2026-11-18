"""Unit tests for self-contained HTML report generator and anti-XSS autoescaping."""

from __future__ import annotations

import sqlite3

import pytest

from reconx.database.storage import apply_migrations, create_scan, upsert_asset, upsert_http_service
from reconx.reporting.html_report import generate_html_report


@pytest.fixture
def html_db():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    apply_migrations(db)
    create_scan(db, "RX-HTML", "test-corp", "cautious", 100)
    yield db
    db.close()


def test_html_report_escapes_xss_page_title(html_db):
    """Key security test: hostile server title with <script> must be strictly escaped."""
    upsert_asset(html_db, "test-corp", "victim.test-corp.com", confidence="verified")
    cursor = html_db.execute("SELECT id FROM assets WHERE hostname = 'victim.test-corp.com'")
    asset_id = cursor.fetchone()["id"]

    hostile_title = '<script>alert("XSS")</script>'
    hostile_server = '<img src=x onerror=alert(1)>'

    upsert_http_service(
        db=html_db,
        asset_id=asset_id,
        scan_id="RX-HTML",
        url="https://victim.test-corp.com",
        status_code=200,
        title=hostile_title,
        server=hostile_server,
    )

    # Insert finding with HTML characters
    html_db.execute(
        """
        INSERT INTO findings (id, scan_id, asset_id, type, title, severity_hint, confidence, status, notes, created_at)
        VALUES ('F-XSS-1', 'RX-HTML', ?, 'observation', '<b>Injection</b>', 'high', 'medium', 'new', '<svg/onload=alert(1)>', '2026-11-18')
        """,
        (asset_id,),
    )
    html_db.commit()

    report_html = generate_html_report(html_db, "RX-HTML")

    # Raw script tag MUST NOT appear
    assert '<script>alert("XSS")</script>' not in report_html
    # Escaped version MUST appear
    assert '&lt;script&gt;alert(&#34;XSS&#34;)&lt;/script&gt;' in report_html or '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;' in report_html

    # Raw img and svg tags MUST NOT appear unescaped
    assert '<img src=x onerror=alert(1)>' not in report_html
    assert '<svg/onload=alert(1)>' not in report_html
    assert '&lt;b&gt;Injection&lt;/b&gt;' in report_html


def test_html_report_zero_external_requests(html_db):
    """The HTML report must be 100% self-contained with no external CDN scripts or stylesheets."""
    upsert_asset(html_db, "test-corp", "app.test-corp.com", confidence="verified")
    cursor = html_db.execute("SELECT id FROM assets WHERE hostname = 'app.test-corp.com'")
    asset_id = cursor.fetchone()["id"]

    upsert_http_service(
        db=html_db,
        asset_id=asset_id,
        scan_id="RX-HTML",
        url="https://app.test-corp.com",
        status_code=200,
        title="Production Dashboard",
    )

    report_html = generate_html_report(html_db, "RX-HTML")

    # Check for external script or stylesheet sources
    assert '<script src="http' not in report_html.lower()
    assert '<link rel="stylesheet" href="http' not in report_html.lower()
    assert '@import url("http' not in report_html.lower()
