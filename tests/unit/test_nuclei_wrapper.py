"""Unit tests for the Nuclei external tool wrapper and safety checks."""

from __future__ import annotations

import sqlite3
from unittest.mock import patch

import pytest

from reconx.core.tool_runner import ToolResult
from reconx.database.storage import apply_migrations, create_scan
from reconx.integrations.nuclei import (
    NucleiExecutionError,
    NucleiRunner,
    parse_nuclei_jsonl,
)


@pytest.fixture
def nuclei_db():
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    apply_migrations(db)
    create_scan(db, "RX-NUC", "test-corp", "cautious", 100)
    yield db
    db.close()


def test_nuclei_refuses_when_disabled():
    runner = NucleiRunner()
    with pytest.raises(NucleiExecutionError, match="allow_nuclei' is false"):
        runner.run(targets=["https://example.com"], allow_nuclei=False)


def test_nuclei_refuses_excluded_tags():
    runner = NucleiRunner()
    for tag in ("intrusive", "dos", "fuzz", "bruteforce"):
        with pytest.raises(NucleiExecutionError, match="forbidden tag"):
            runner.run(
                targets=["https://example.com"],
                allow_nuclei=True,
                requested_tags=["cve", tag],
            )


def test_parse_nuclei_jsonl():
    jsonl = (
        '{"template-id":"git-config","info":{"name":".git/config exposed","severity":"medium"},"matched-at":"https://example.com/.git/config"}\n'
        '{"template-id":"cve-2021-44228","info":{"name":"Log4j RCE","severity":"critical"},"matched-at":"https://example.com/login"}\n'
    )
    findings = parse_nuclei_jsonl(jsonl)
    assert len(findings) == 2
    assert findings[0]["template_id"] == "git-config"
    assert findings[0]["severity"] == "medium"
    assert findings[1]["severity"] == "critical"


def test_nuclei_run_stores_observation_medium_confidence(nuclei_db):
    runner = NucleiRunner(rate_limit=1, concurrency=1)
    mock_stdout = '{"template-id":"git-config","info":{"name":"Git Config Exposure","severity":"medium","description":"Git repository exposed"},"matched-at":"https://app.test-corp.com/.git/config"}\n'

    mock_res = ToolResult(
        tool="nuclei",
        command=["nuclei", "-u", "https://app.test-corp.com"],
        stdout=mock_stdout,
        stderr="",
        exit_code=0,
        duration_ms=500,
    )

    with patch("reconx.integrations.nuclei.run_tool", return_value=mock_res):
        findings = runner.run(
            targets=["https://app.test-corp.com"],
            allow_nuclei=True,
            scan_id="RX-NUC",
            db=nuclei_db,
        )

    assert len(findings) == 1

    # Verify database finding
    cursor = nuclei_db.execute("SELECT * FROM findings WHERE scan_id = 'RX-NUC'")
    f = cursor.fetchone()
    assert f is not None
    assert f["type"] == "observation"
    assert f["confidence"] == "medium"  # at most medium confidence
    assert "Git Config Exposure" in f["title"]

    # Verify evidence stored
    e_cursor = nuclei_db.execute("SELECT * FROM evidence WHERE finding_id = ?", (f["id"],))
    ev = e_cursor.fetchone()
    assert ev is not None
    assert ev["kind"] == "nuclei_match"
