"""Smoke tests verifying the CLI runs and prints usage."""

from typer.testing import CliRunner

from reconx.main import app

runner = CliRunner()


def test_help_runs():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Usage" in result.stdout or "recon-x" in result.stdout
