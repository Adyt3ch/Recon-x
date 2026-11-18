"""Unit tests for importing scope files (HackerOne CSV, plain lists) with line number validation."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from reconx.main import app

runner = CliRunner()


def test_scope_import_hackerone_csv(tmp_path: Path):
    h1_csv = tmp_path / "hackerone_targets.csv"
    h1_csv.write_text(
        "identifier,asset_type,eligible_for_bounty\n"
        "example.com,URL,true\n"
        "*.api.example.com,WILDCARD,true\n"
        "192.168.1.1,IP_ADDRESS,false\n",
        encoding="utf-8",
    )

    scope_yaml = tmp_path / "scope.yaml"
    scope_yaml.write_text("in_scope:\n  domains: []\n  ips: []\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["scope", "import", str(h1_csv), "--format", "hackerone-csv", "--scope", str(scope_yaml)],
    )
    assert result.exit_code == 0
    assert "Successfully imported 3 targets" in result.stdout

    content = scope_yaml.read_text(encoding="utf-8")
    assert "example.com" in content
    assert "*.api.example.com" in content
    assert "192.168.1.1" in content


def test_scope_import_malformed_line_reported(tmp_path: Path):
    bad_csv = tmp_path / "bad.csv"
    bad_csv.write_text(
        "target\n"
        "good.example.com\n"
        "bad target with spaces\n",
        encoding="utf-8",
    )

    scope_yaml = tmp_path / "scope.yaml"
    scope_yaml.write_text("in_scope:\n  domains: []\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["scope", "import", str(bad_csv), "--format", "csv", "--scope", str(scope_yaml)],
    )
    assert result.exit_code != 0
    # Must report error with specific line number
    assert "Line 3" in result.stdout
    assert "invalid target contains spaces" in result.stdout
