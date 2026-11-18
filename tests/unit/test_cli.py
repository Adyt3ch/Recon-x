"""Unit tests for the Typer CLI commands using CliRunner."""

from typer.testing import CliRunner

from reconx.main import app

runner = CliRunner()


def test_cli_init_command(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["init"])
    assert result.exit_code == 0
    assert "initialized successfully" in result.stdout

    # Verify folders and files were created
    assert (tmp_path / "config" / "settings.yaml").exists()
    assert (tmp_path / "config" / "scope.yaml").exists()
    assert (tmp_path / "data" / "reconx.db").exists()


def test_cli_scope_add_and_check(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner.invoke(app, ["init"])

    # Add in-scope target
    add_res = runner.invoke(app, ["scope", "add", "target.example.com"])
    assert add_res.exit_code == 0
    assert "Added target.example.com" in add_res.stdout

    # Scope check allowed
    chk_res = runner.invoke(app, ["scope", "check", "target.example.com"])
    assert "ALLOWED" in chk_res.stdout

    # Scope check denied
    deny_res = runner.invoke(app, ["scope", "check", "evil.com"])
    assert "DENIED" in deny_res.stdout


def test_cli_scope_list(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner.invoke(app, ["init"])

    res = runner.invoke(app, ["scope", "list"])
    assert res.exit_code == 0
    assert "Scope Rules" in res.stdout
    assert "example.com" in res.stdout


def test_cli_scope_import_txt_with_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner.invoke(app, ["init"])

    # File with bad target on line 3
    import_file = tmp_path / "targets.txt"
    import_file.write_text("sub1.example.com\nsub2.example.com\nbad target with spaces\n", encoding="utf-8")

    res = runner.invoke(app, ["scope", "import", str(import_file), "--format", "txt"])
    assert res.exit_code != 0
    assert "Line 3" in res.stdout


def test_cli_scope_import_csv(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner.invoke(app, ["init"])

    csv_file = tmp_path / "targets.csv"
    csv_file.write_text("imported1.example.com\nimported2.example.com\n", encoding="utf-8")

    res = runner.invoke(app, ["scope", "import", str(csv_file), "--format", "csv"])
    assert res.exit_code == 0
    assert "Successfully imported 2 targets" in res.stdout

    chk = runner.invoke(app, ["scope", "check", "imported1.example.com"])
    assert "ALLOWED" in chk.stdout


def test_cli_config_show(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner.invoke(app, ["init"])

    res = runner.invoke(app, ["config", "show"])
    assert res.exit_code == 0
    assert "cautious" in res.stdout


def test_cli_doctor(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner.invoke(app, ["init"])

    res = runner.invoke(app, ["doctor"])
    assert res.exit_code == 0
    assert "RECON-X Environment Health Check" in res.stdout
    assert "Python version" in res.stdout


def test_cli_status(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner.invoke(app, ["init"])

    res = runner.invoke(app, ["status"])
    assert res.exit_code == 0
    assert "No scans recorded" in res.stdout


def test_cli_audit_and_metrics_cmd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner.invoke(app, ["init"])

    # Audit a non-existent or fresh scan
    audit_res = runner.invoke(app, ["audit", "RX-001"])
    assert audit_res.exit_code == 0
    assert "Cryptographic Audit" in audit_res.stdout
    assert "Scope violations over wire" in audit_res.stdout

    # Metrics command
    metrics_res = runner.invoke(app, ["metrics", "RX-001"])
    assert metrics_res.exit_code == 0
    assert "Section 13 Metrics Evaluation" in metrics_res.stdout
    assert "Scope Violations" in metrics_res.stdout
    assert "Rate-limit Breaches" in metrics_res.stdout
