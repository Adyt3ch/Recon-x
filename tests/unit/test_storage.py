"""Unit tests for SQLite database storage, migrations, and upserts."""

import sqlite3

import pytest

from reconx.database.storage import (
    apply_migrations,
    create_scan,
    generate_scan_id,
    get_db,
    get_scan,
    upsert_asset,
    upsert_dns_record,
)


def test_migrations_apply_and_are_idempotent(tmp_path):
    db_file = tmp_path / "test.db"
    db = get_db(db_file)

    # First migration run applies 001_init.sql
    applied1 = apply_migrations(db)
    assert len(applied1) > 0

    # Second migration run applies 0
    applied2 = apply_migrations(db)
    assert len(applied2) == 0

    db.close()


def test_asset_upsert_deduplication(tmp_path):
    db = get_db(tmp_path / "test.db")
    apply_migrations(db)

    # Insert asset first time
    id1 = upsert_asset(db, program="example", hostname="test.example.com", confidence="low", source="crtsh")
    assert id1 > 0

    # Insert same asset with medium confidence
    id2 = upsert_asset(db, program="example", hostname="test.example.com", confidence="medium", source="subfinder")
    assert id1 == id2

    # Verify only one row exists and confidence was upgraded
    cursor = db.execute("SELECT COUNT(*), confidence FROM assets WHERE program = 'example'")
    row = cursor.fetchone()
    assert row[0] == 1
    assert row[1] == "medium"

    # Verify sources table has two independent sources
    src_cursor = db.execute("SELECT source FROM asset_sources WHERE asset_id = ?", (id1,))
    sources = {r[0] for r in src_cursor.fetchall()}
    assert sources == {"crtsh", "subfinder"}

    db.close()


def test_foreign_keys_enforced(tmp_path):
    db = get_db(tmp_path / "test.db")
    apply_migrations(db)

    # Attempting to insert dns_record with invalid asset_id and scan_id must fail
    with pytest.raises(sqlite3.IntegrityError):
        upsert_dns_record(
            db,
            asset_id=99999,
            scan_id="RX-999",
            record_type="A",
            value="1.2.3.4",
        )

    db.close()


def test_persistence_across_reopen(tmp_path):
    db_file = tmp_path / "persist.db"
    db = get_db(db_file)
    apply_migrations(db)

    create_scan(db, "RX-001", "program1", "cautious", 500)
    db.close()

    # Reopen
    db2 = get_db(db_file)
    scan = get_scan(db2, "RX-001")
    assert scan is not None
    assert scan["program"] == "program1"
    assert scan["request_budget"] == 500
    db2.close()


def test_scan_id_generator(tmp_path):
    db = get_db(tmp_path / "test.db")
    apply_migrations(db)

    assert generate_scan_id(db) == "RX-001"
    create_scan(db, "RX-001", "prog", "cautious", 100)
    assert generate_scan_id(db) == "RX-002"
    create_scan(db, "RX-002", "prog", "cautious", 100)
    assert generate_scan_id(db) == "RX-003"
    db.close()
