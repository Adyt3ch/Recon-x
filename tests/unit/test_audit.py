"""Unit tests for tamper-evident request_log audit trail and logging redaction."""

import io
import logging

from reconx.core.audit import log_request, verify_chain
from reconx.core.logging import SecretRedactingFilter
from reconx.database.storage import apply_migrations, create_scan, get_db


def test_audit_hash_chain_validity(tmp_path):
    db = get_db(tmp_path / "audit.db")
    apply_migrations(db)

    scan_id = "RX-001"
    create_scan(db, scan_id, "test", "cautious", 100)

    # Log 5 requests
    for i in range(5):
        log_request(
            db,
            scan_id=scan_id,
            method="GET",
            url=f"https://example.com/page{i}",
            host="example.com",
            status=200,
            bytes_count=1024,
            duration_ms=50,
            scope_decision="allowed",
        )

    # Chain must verify successfully
    is_valid, err = verify_chain(db, scan_id)
    assert is_valid is True
    assert err is None

    db.close()


def test_audit_tampering_detected(tmp_path):
    db = get_db(tmp_path / "audit.db")
    apply_migrations(db)

    scan_id = "RX-001"
    create_scan(db, scan_id, "test", "cautious", 100)

    for i in range(3):
        log_request(
            db,
            scan_id=scan_id,
            method="GET",
            url=f"https://example.com/item{i}",
            host="example.com",
            status=200,
            bytes_count=500,
            duration_ms=40,
            scope_decision="allowed",
        )

    # Tamper with the second row (modify status code)
    db.execute("UPDATE request_log SET status = 500 WHERE id = 2")
    db.commit()

    is_valid, err = verify_chain(db, scan_id)
    assert is_valid is False
    assert "Hash mismatch at row 2" in err

    db.close()


def test_logging_secret_redaction():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(SecretRedactingFilter())

    logger = logging.getLogger("test_redact")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)

    test_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMC6Y5nV3iMTZwUHGdKA"
    logger.info("Sending request with Authorization: %s", test_token)
    logger.info("Setting Telegram bot token: 123456789:ABCdefGHIjklMNOpqrSTUvwxYZ123456789")
    logger.info("Connecting with key: token=secret12345 in URL")

    output = stream.getvalue()
    assert "Bearer" not in output
    assert "[REDACTED]" in output
    assert "123456789:ABCdefGHIjklMNOpqrSTUvwxYZ123456789" not in output
    assert "secret12345" not in output
