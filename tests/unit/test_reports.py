"""Unit tests for report generation (JSON, TXT, CSV)."""

from reconx.database.storage import (
    apply_migrations,
    create_scan,
    get_db,
    upsert_asset,
    upsert_dns_record,
    upsert_http_service,
)
from reconx.reporting.csv_report import generate_csv_report
from reconx.reporting.json_report import generate_json_report
from reconx.reporting.txt_report import generate_txt_report


def test_reports_generation(tmp_path):
    db = get_db(tmp_path / "rep.db")
    apply_migrations(db)

    scan_id = "RX-REP-01"
    create_scan(db, scan_id, "rep-prog", "cautious", 100)
    asset_id = upsert_asset(db, "rep-prog", "api.example.com", "verified", "subfinder")
    upsert_dns_record(db, asset_id, scan_id, "A", "93.184.216.34")
    upsert_http_service(
        db,
        asset_id,
        scan_id,
        "https://api.example.com/",
        status_code=200,
        title="API Documentation",
        server="nginx/1.20",
        is_cdn=1,
    )

    # 1. JSON Report
    json_data = generate_json_report(db, scan_id)
    assert json_data["scan"]["id"] == scan_id
    assert json_data["summary"]["total_assets"] == 1
    assert json_data["summary"]["total_dns_records"] == 1
    assert json_data["summary"]["total_http_services"] == 1
    assert json_data["assets"][0]["hostname"] == "api.example.com"
    assert json_data["http_services"][0]["title"] == "API Documentation"

    # 2. TXT Report
    txt_data = generate_txt_report(db, scan_id)
    assert "RECON-X ASSESSMENT REPORT" in txt_data
    assert "api.example.com [VERIFIED]" in txt_data
    assert "API Documentation" in txt_data
    assert "[CDN]" in txt_data

    # 3. CSV Reports
    csv_assets = generate_csv_report(db, scan_id, "assets")
    assert "Hostname,Confidence,First Seen,Last Seen,Sources" in csv_assets
    assert "api.example.com,verified" in csv_assets

    csv_http = generate_csv_report(db, scan_id, "http")
    assert "URL,Hostname,Status Code,Title" in csv_http
    assert "https://api.example.com/,api.example.com,200" in csv_http
