"""CLI commands implementation for RECON-X."""

from __future__ import annotations

import asyncio
import csv
import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path

import typer
import yaml
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from reconx.core.audit import verify_chain
from reconx.core.config import (
    load_scope,
    load_settings,
)
from reconx.core.engine import ScanContext, ScanEngine
from reconx.core.normalizer import (
    NormalizationError,
    normalize_ip,
)
from reconx.core.rate_limiter import AsyncRateLimiter
from reconx.core.request_manager import RequestManager
from reconx.core.scheduler import Task
from reconx.core.scope import ScopeEngine
from reconx.core.tool_runner import check_tool_version
from reconx.database.storage import (
    apply_migrations,
    create_scan,
    generate_scan_id,
    get_db,
    get_scan,
    list_scans,
)
from reconx.modules.dns import DnsModule
from reconx.modules.fingerprint import FingerprintModule
from reconx.modules.http import HttpModule
from reconx.modules.javascript import JavascriptModule
from reconx.modules.subdomains import SubdomainsModule
from reconx.modules.urls import UrlsModule
from reconx.reporting.csv_report import generate_csv_report
from reconx.reporting.json_report import generate_json_report
from reconx.reporting.txt_report import generate_txt_report

console = Console()

# Scope subcommand group
scope_app = typer.Typer(help="Manage and verify scan scope rules.")
config_app = typer.Typer(help="Manage and display configuration.")


def register_commands(app: typer.Typer) -> None:
    """Register all top-level and sub-commands with the main Typer application."""
    app.command(name="init", help="Initialize folders, configuration files, and SQLite database.")(init_cmd)
    app.add_typer(scope_app, name="scope")
    app.add_typer(config_app, name="config")
    app.command(name="doctor", help="Check dependencies, database, and external tools on PATH.")(doctor_cmd)
    app.command(name="status", help="List scans and their execution status.")(status_cmd)
    app.command(name="passive", help="Passive subdomain discovery with zero target traffic.")(passive_cmd)
    app.command(name="scan", help="Run full reconnaissance pipeline (passive -> DNS -> HTTP).")(scan_cmd)
    app.command(name="results", help="View results of a completed or paused scan.")(results_cmd)
    app.command(name="report", help="Export scan report in JSON, TXT, or CSV format.")(report_cmd)
    app.command(name="audit", help="Verify request audit hash chain and check scope decisions.")(audit_cmd)
    app.command(name="resume", help="Resume an interrupted or paused scan.")(resume_cmd)


# Default templates
DEFAULT_SETTINGS_YAML = """# RECON-X Settings
profile: cautious            # cautious | normal | program-custom

program:
  name: example-program
  policy_url: "https://example.com/security"
  user_agent: "RECON-X/0.1 (authorized security assessment)"
  extra_headers:
    X-Bug-Bounty: "researcher-handle"

request_control:
  concurrency: 1
  global:   { requests_per_second: 1, requests_per_minute: 30 }
  per_host: { requests_per_second: 1, requests_per_minute: 30 }
  delay:    { minimum: 1, maximum: 2 }
  budget:   { max_requests: 1000 }
  timeouts: { connect: 5, read: 10 }
  limits:   { max_response_bytes: 2000000, max_redirects: 3 }
  retry:    { max_attempts: 1, respect_retry_after: true }
  backoff:  { enabled: true, initial_delay: 30, maximum_delay: 300 }
  protection:
    pause_on_429: true
    pause_on_503: true
    pause_on_repeated_errors: true
    repeated_error_threshold: 5
    preserve_results_on_stop: true

external_tools:
  subfinder: { path: auto, rate_limit: 10, timeout: 300 }
  katana:    { path: auto, rate_limit: 1, depth: 2, timeout: 600 }
  naabu:     { path: auto, rate: 100, enabled: false }
  nuclei:    { path: auto, rate_limit: 1, enabled: false }

storage:
  database: data/reconx.db
  reports_dir: reports
  logs_dir: logs

notifications:
  telegram:
    enabled: false
    token_env: RECONX_TELEGRAM_TOKEN
    chat_id_env: RECONX_TELEGRAM_CHAT
"""

DEFAULT_SCOPE_YAML = """program: example-program
authorized_by: "Program policy saved"

in_scope:
  domains:
    - example.com
    - "*.example.com"
  cidrs: []
  ips: []
  web_ports: [80, 443, 8080, 8443]

out_of_scope:
  domains:
    - mail.example.com
    - "*.internal.example.com"
  cidrs: []
  ips: []

rules:
  allow_port_scan: false
  allow_nuclei: false
  max_requests: 1000
"""


def init_cmd(
    target_dir: Path = typer.Option(Path("."), "--dir", "-d", help="Directory to initialize")
) -> None:
    """Initialize folders, default configs, and database."""
    base = target_dir.resolve()
    console.print(f"[bold cyan]Initializing RECON-X workspace in {base}[/bold cyan]")

    dirs = ["config", "config/fingerprints", "data", "reports", "logs"]
    for d in dirs:
        p = base / d
        p.mkdir(parents=True, exist_ok=True)
        console.print(f"  [green]✓[/green] Directory ready: {d}")

    settings_file = base / "config/settings.yaml"
    if not settings_file.exists():
        settings_file.write_text(DEFAULT_SETTINGS_YAML, encoding="utf-8")
        console.print("  [green]✓[/green] Created config/settings.yaml")

    scope_file = base / "config/scope.yaml"
    if not scope_file.exists():
        scope_file.write_text(DEFAULT_SCOPE_YAML, encoding="utf-8")
        console.print("  [green]✓[/green] Created config/scope.yaml")

    # Categories, scoring, fingerprints templates
    cat_file = base / "config/categories.yaml"
    if not cat_file.exists():
        cat_file.write_text("categories:\n  login: ['login', 'signin', 'auth']\n", encoding="utf-8")

    scoring_file = base / "config/scoring.yaml"
    if not scoring_file.exists():
        scoring_file.write_text("weights:\n  dev: 10\n  admin: 15\n", encoding="utf-8")

    cpe_file = base / "config/cpe_map.yaml"
    if not cpe_file.exists():
        cpe_file.write_text("mappings: {}\n", encoding="utf-8")

    tech_file = base / "config/fingerprints/tech.yaml"
    if not tech_file.exists():
        tech_file.write_text("fingerprints: []\n", encoding="utf-8")

    takeover_file = base / "config/fingerprints/takeover.yaml"
    if not takeover_file.exists():
        takeover_file.write_text("providers: []\n", encoding="utf-8")

    db_path = base / "data/reconx.db"
    db = get_db(db_path)
    migrations = apply_migrations(db)
    db.close()
    console.print(f"  [green]✓[/green] Database initialized with {len(migrations)} migrations: {db_path}")

    console.print("[bold green]RECON-X initialized successfully.[/bold green]")


@scope_app.command(name="check")
def scope_check_cmd(
    target: str = typer.Argument(..., help="Target host, IP, or URL to evaluate"),
    scope_path: Path = typer.Option(Path("config/scope.yaml"), "--scope", "-s", help="Path to scope.yaml"),
) -> None:
    """Evaluate target against scope and print reason."""
    try:
        cfg = load_scope(scope_path)
    except Exception as e:
        console.print(f"[bold red]Error loading scope file {scope_path}:[/bold red] {e}")
        raise typer.Exit(code=4)

    engine = ScopeEngine(cfg)
    decision = engine.check(target)

    if decision.allowed:
        status_text = "[bold green]ALLOWED[/bold green]"
    else:
        status_text = "[bold red]DENIED[/bold red]"

    table = Table(show_header=False, box=None)
    table.add_row("Target:", target)
    table.add_row("Decision:", status_text)
    if decision.rule:
        table.add_row("Matched Rule:", f"[cyan]{decision.rule}[/cyan]")
    table.add_row("Reason:", decision.reason)

    console.print(Panel(table, title="Scope Evaluation", expand=False))
    if not decision.allowed:
        raise typer.Exit(code=0)


@scope_app.command(name="add")
def scope_add_cmd(
    target: str = typer.Argument(..., help="Domain, wildcard, or CIDR to add to in_scope"),
    scope_path: Path = typer.Option(Path("config/scope.yaml"), "--scope", "-s", help="Path to scope.yaml"),
) -> None:
    """Add a target to in_scope in the scope YAML file."""
    if not scope_path.exists():
        console.print(f"[bold red]Scope file {scope_path} not found. Run 'recon-x init' first.[/bold red]")
        raise typer.Exit(code=1)

    try:
        with open(scope_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except Exception as e:
        console.print(f"[bold red]Failed to read {scope_path}:[/bold red] {e}")
        raise typer.Exit(code=1)

    in_scope = data.setdefault("in_scope", {})
    t = target.strip()

    # Determine kind
    if "/" in t:
        cidrs = in_scope.setdefault("cidrs", [])
        if t not in cidrs:
            cidrs.append(t)
    elif t.replace(".", "").isdigit() or ":" in t:
        # IP address
        try:
            norm_ip = normalize_ip(t).value
            ips = in_scope.setdefault("ips", [])
            if norm_ip not in ips:
                ips.append(norm_ip)
        except NormalizationError:
            domains = in_scope.setdefault("domains", [])
            if t not in domains:
                domains.append(t)
    else:
        domains = in_scope.setdefault("domains", [])
        if t not in domains:
            domains.append(t)

    with open(scope_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=False)

    console.print(f"[green]Added [bold]{t}[/bold] to in_scope in {scope_path}[/green]")


@scope_app.command(name="list")
def scope_list_cmd(
    scope_path: Path = typer.Option(Path("config/scope.yaml"), "--scope", "-s", help="Path to scope.yaml"),
) -> None:
    """List all current in-scope and out-of-scope rules."""
    try:
        cfg = load_scope(scope_path)
    except Exception as e:
        console.print(f"[bold red]Failed to load scope {scope_path}:[/bold red] {e}")
        raise typer.Exit(code=1)

    table = Table(title=f"Scope Rules: {cfg.program}")
    table.add_column("Type", style="cyan")
    table.add_column("In-Scope", style="green")
    table.add_column("Out-of-Scope (Exclusions)", style="red")

    table.add_row(
        "Domains",
        "\n".join(cfg.in_scope.domains) or "(none)",
        "\n".join(cfg.out_of_scope.domains) or "(none)",
    )
    table.add_row(
        "CIDRs",
        "\n".join(cfg.in_scope.cidrs) or "(none)",
        "\n".join(cfg.out_of_scope.cidrs) or "(none)",
    )
    table.add_row(
        "IPs",
        "\n".join(cfg.in_scope.ips) or "(none)",
        "\n".join(cfg.out_of_scope.ips) or "(none)",
    )
    table.add_row(
        "Web Ports",
        ", ".join(map(str, cfg.in_scope.web_ports)),
        "-",
    )
    console.print(table)


@scope_app.command(name="import")
def scope_import_cmd(
    file_path: Path = typer.Argument(..., help="File to import targets from"),
    format_type: str = typer.Option("txt", "--format", "-f", help="Format: txt | csv | yaml | hackerone-csv"),
    scope_path: Path = typer.Option(Path("config/scope.yaml"), "--scope", "-s", help="Target scope.yaml"),
) -> None:
    """Import scope targets from TXT, CSV, YAML, or HackerOne export with line validation."""
    if not file_path.exists():
        console.print(f"[bold red]Input file {file_path} does not exist.[/bold red]")
        raise typer.Exit(code=1)

    fmt = format_type.lower()
    imported_targets: list[str] = []

    try:
        if fmt == "txt":
            with open(file_path, "r", encoding="utf-8") as f:
                for line_num, line in enumerate(f, start=1):
                    raw = line.strip()
                    if not raw or raw.startswith("#"):
                        continue
                    # Validate
                    if " " in raw:
                        raise ValueError(f"Line {line_num}: invalid target contains spaces: {raw!r}")
                    imported_targets.append(raw)

        elif fmt == "csv":
            with open(file_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                for line_num, row in enumerate(reader, start=1):
                    if not row or not row[0].strip() or row[0].startswith("#"):
                        continue
                    val = row[0].strip()
                    if " " in val:
                        raise ValueError(f"Line {line_num}: invalid target contains spaces: {val!r}")
                    imported_targets.append(val)

        elif fmt == "hackerone-csv":
            with open(file_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for line_num, row in enumerate(reader, start=2):
                    # HackerOne columns typically include identifier, asset_type, eligible_for_bounty
                    identifier = row.get("identifier") or row.get("asset") or row.get("target")
                    if identifier:
                        val = identifier.strip()
                        if " " in val:
                            raise ValueError(f"Line {line_num}: invalid target contains spaces: {val!r}")
                        imported_targets.append(val)

        elif fmt == "yaml":
            with open(file_path, "r", encoding="utf-8") as f:
                y = yaml.safe_load(f)
                if isinstance(y, list):
                    imported_targets = [str(x).strip() for x in y if str(x).strip()]
                elif isinstance(y, dict):
                    in_s = y.get("in_scope", {})
                    imported_targets.extend(in_s.get("domains", []))
                    imported_targets.extend(in_s.get("cidrs", []))
                    imported_targets.extend(in_s.get("ips", []))
        else:
            console.print(f"[bold red]Unsupported format: {format_type}[/bold red]")
            raise typer.Exit(code=1)

    except ValueError as e:
        console.print(f"[bold red]Import error:[/bold red] {e}")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[bold red]Failed reading file:[/bold red] {e}")
        raise typer.Exit(code=1)

    # Add targets to scope
    for target in imported_targets:
        scope_add_cmd(target=target, scope_path=scope_path)

    console.print(f"[bold green]Successfully imported {len(imported_targets)} targets from {file_path}.[/bold green]")


@config_app.command(name="show")
def config_show_cmd(
    settings_path: Path = typer.Option(Path("config/settings.yaml"), "--settings", help="Settings file"),
) -> None:
    """Print the active merged configuration with secrets masked."""
    try:
        cfg = load_settings(settings_path=settings_path)
        data = cfg.model_dump(mode="json", by_alias=True)
        # Redact secrets
        if "notifications" in data and "telegram" in data["notifications"]:
            tg = data["notifications"]["telegram"]
            if tg.get("token_env"):
                val = os.environ.get(tg["token_env"])
                tg["token_value"] = "**********" if val else "(not set in env)"
        console.print(Panel(yaml.safe_dump(data, sort_keys=False), title="Active Configuration"))
    except Exception as e:
        console.print(f"[bold red]Error displaying config:[/bold red] {e}")
        raise typer.Exit(code=1)


def doctor_cmd() -> None:
    """Run health checks on Python, packages, database, and external tools."""
    console.print(Panel("[bold]RECON-X Environment Health Check (Doctor)[/bold]"))
    all_ok = True

    # 1. Python version check
    py_ver = sys.version_info
    py_str = f"{py_ver.major}.{py_ver.minor}.{py_ver.micro}"
    if py_ver >= (3, 11):
        console.print(f"  [green]✓[/green] Python version: {py_str} (>= 3.11)")
    else:
        console.print(f"  [red]✗[/red] Python version: {py_str} (Must be >= 3.11)")
        all_ok = False

    # 2. Dependency checks
    required_modules = [
        ("typer", "typer"),
        ("httpx", "httpx"),
        ("dnspython", "dns.resolver"),
        ("beautifulsoup4", "bs4"),
        ("pydantic", "pydantic"),
        ("PyYAML", "yaml"),
        ("rich", "rich"),
        ("Jinja2", "jinja2"),
        ("idna", "idna"),
        ("defusedxml", "defusedxml"),
        ("pytest", "pytest"),
    ]
    for pkg_name, mod_name in required_modules:
        if importlib.util.find_spec(mod_name.split(".")[0]):
            console.print(f"  [green]✓[/green] Library {pkg_name}: installed")
        else:
            console.print(f"  [red]✗[/red] Library {pkg_name}: missing")
            all_ok = False

    # 3. Database check
    db_path = Path("data/reconx.db")
    try:
        db = get_db(db_path)
        cursor = db.execute("SELECT COUNT(*) FROM schema_migrations")
        count = cursor.fetchone()[0]
        db.close()
        console.print(f"  [green]✓[/green] SQLite database accessible: {db_path} ({count} migrations applied)")
    except Exception:
        console.print(f"  [yellow]![/yellow] Database not initialized at {db_path} (run 'recon-x init')")

    # 4. External tools check
    console.print("\n[bold]External Reconnaissance Tools:[/bold]")
    external_tools = ["subfinder", "katana", "naabu", "nuclei", "gau", "waybackurls", "nmap"]
    for tool in external_tools:
        tool_path = shutil.which(tool)
        if tool_path:
            ver_text = check_tool_version(tool) or "found"
            console.print(f"  [green]✓[/green] {tool}: {tool_path} ({ver_text})")
        else:
            console.print(f"  [yellow]![/yellow] {tool}: not found on PATH (warning: tool-dependent tasks will be skipped)")

    # 5. httpx binary check
    httpx_bin = shutil.which("httpx")
    httpx_tk = shutil.which("httpx-toolkit")
    if httpx_tk:
        console.print(f"  [cyan]ℹ[/cyan] ProjectDiscovery HTTP prober: {httpx_tk} (httpx-toolkit)")
    elif httpx_bin:
        console.print(f"  [cyan]ℹ[/cyan] 'httpx' on PATH: {httpx_bin}")
    else:
        console.print("  [cyan]ℹ[/cyan] ProjectDiscovery HTTP prober: not installed on PATH")

    if all_ok:
        console.print("\n[bold green]Doctor check complete. Core environment is ready.[/bold green]")
    else:
        console.print("\n[bold red]Doctor check found errors in core requirements.[/bold red]")


def status_cmd() -> None:
    """List all scans and execution state."""
    db_path = Path("data/reconx.db")
    if not db_path.exists():
        console.print("[yellow]No database found. Run 'recon-x init' first.[/yellow]")
        return

    db = get_db(db_path)
    scans = list_scans(db)
    db.close()

    if not scans:
        console.print("[cyan]No scans recorded in database.[/cyan]")
        return

    table = Table(title="RECON-X Scans")
    table.add_column("Scan ID", style="bold cyan")
    table.add_column("Program", style="green")
    table.add_column("Profile", style="magenta")
    table.add_column("Status", style="yellow")
    table.add_column("Started", style="blue")
    table.add_column("Requests Used / Budget")

    for s in scans:
        budget_str = f"{s['requests_used']} / {s['request_budget']}"
        table.add_row(
            s["id"],
            s["program"],
            s["profile"],
            s["status"],
            s["started_at"][:19],
            budget_str,
        )

    console.print(table)


def passive_cmd(
    target: str = typer.Argument(..., help="Domain to passively discover subdomains for"),
    scope_path: Path = typer.Option(Path("config/scope.yaml"), "--scope", "-s", help="Scope file"),
    settings_path: Path = typer.Option(Path("config/settings.yaml"), "--settings", help="Settings file"),
) -> None:
    """Run passive subdomain discovery with zero network traffic to the target."""
    console.print(f"[bold cyan]Starting passive discovery for {target}...[/bold cyan]")
    db_path = Path("data/reconx.db")
    if not db_path.exists():
        console.print("[yellow]Database not initialized. Running init...[/yellow]")
        init_cmd()

    db = get_db(db_path)
    scope_cfg = load_scope(scope_path)
    scope_engine = ScopeEngine(scope_cfg)
    settings = load_settings(settings_path=settings_path)

    scan_id = generate_scan_id(db)
    create_scan(
        db=db,
        scan_id=scan_id,
        program=scope_cfg.program,
        profile="cautious",
        request_budget=settings.request_control.budget.max_requests,
    )

    rate_limiter = AsyncRateLimiter(
        requests_per_second=1.0,
        requests_per_minute=30,
    )
    req_mgr = RequestManager(
        scan_id=scan_id,
        scope_engine=scope_engine,
        settings=settings,
        db=db,
        rate_limiter=rate_limiter,
    )
    ctx = ScanContext(
        scan_id=scan_id,
        program=scope_cfg.program,
        settings=settings,
        scope=scope_engine,
        requests=req_mgr,
        db=db,
    )

    sub_mod = SubdomainsModule()
    task = Task(scan_id=scan_id, module="subdomains", target=target)

    async def _run():
        return await sub_mod.run(ctx, task)

    results = asyncio.run(_run())
    console.print(f"[bold green]Passive discovery complete for {scan_id}. Found {len(results)} in-scope subdomains.[/bold green]")
    for r in results:
        console.print(f"  • {r.hostname} (sources: {', '.join(r.sources)})")
    db.close()


def scan_cmd(
    target: str = typer.Argument(..., help="Target domain to scan"),
    profile: str = typer.Option("cautious", "--profile", "-p", help="Scan profile: cautious | normal | program-custom"),
    scope_path: Path = typer.Option(Path("config/scope.yaml"), "--scope", "-s", help="Scope file"),
    settings_path: Path = typer.Option(Path("config/settings.yaml"), "--settings", help="Settings file"),
    rate: float | None = typer.Option(None, "--rate", "-r", help="Requests per second"),
    concurrency: int | None = typer.Option(None, "--concurrency", "-c", help="Concurrency"),
    max_requests: int | None = typer.Option(None, "--max-requests", "-m", help="Request budget"),
    confirm_rate: bool = typer.Option(False, "--confirm-rate", help="Confirm raising rate/concurrency"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate scan and count requests without sending"),
) -> None:
    """Execute full reconnaissance pipeline: Subdomains -> DNS -> HTTP."""
    db_path = Path("data/reconx.db")
    if not db_path.exists():
        init_cmd()

    db = get_db(db_path)
    scope_cfg = load_scope(scope_path)
    scope_engine = ScopeEngine(scope_cfg)

    # Check target authorization
    t_clean = target.strip()
    if not scope_engine.check(t_clean).allowed:
        # If domain isn't in scope, ask or fail
        console.print(f"[bold red]Target {target} is not permitted by {scope_path}. Add it with 'recon-x scope add' first.[/bold red]")
        db.close()
        raise typer.Exit(code=4)

    cli_overrides = {}
    if rate is not None:
        cli_overrides["rate"] = rate
    if concurrency is not None:
        cli_overrides["concurrency"] = concurrency
    if max_requests is not None:
        cli_overrides["max_requests"] = max_requests

    try:
        settings = load_settings(
            settings_path=settings_path,
            profile_override=profile,
            cli_overrides=cli_overrides,
            confirm_rate=confirm_rate,
        )
    except ValueError as e:
        console.print(f"[bold red]Configuration error:[/bold red] {e}")
        db.close()
        raise typer.Exit(code=4)

    scan_id = generate_scan_id(db)
    budget = settings.request_control.budget.max_requests

    create_scan(
        db=db,
        scan_id=scan_id,
        program=scope_cfg.program,
        profile=settings.profile.value,
        request_budget=budget,
    )

    rate_limiter = AsyncRateLimiter(
        requests_per_second=settings.request_control.global_rate.requests_per_second,
        requests_per_minute=settings.request_control.global_rate.requests_per_minute,
        per_host_rps=settings.request_control.per_host.requests_per_second,
        per_host_rpm=settings.request_control.per_host.requests_per_minute,
        min_delay=settings.request_control.delay.minimum,
        max_delay=settings.request_control.delay.maximum,
    )

    req_mgr = RequestManager(
        scan_id=scan_id,
        scope_engine=scope_engine,
        settings=settings,
        db=db,
        rate_limiter=rate_limiter,
    )

    ctx = ScanContext(
        scan_id=scan_id,
        program=scope_cfg.program,
        settings=settings,
        scope=scope_engine,
        requests=req_mgr,
        db=db,
        dry_run=dry_run,
    )

    modules = [
        SubdomainsModule(),
        DnsModule(),
        HttpModule(),
        UrlsModule(),
        JavascriptModule(),
        FingerprintModule(),
    ]
    engine = ScanEngine(modules)

    if dry_run:
        summary = engine.dry_run(ctx)
        console.print(Panel(f"[bold cyan]Scan Simulation Plan for {scan_id}[/bold cyan]"))
        table = Table(title="Planned Tasks by Module")
        table.add_column("Module", style="cyan")
        table.add_column("Planned Tasks", style="green")
        for m, count in summary["tasks_by_module"].items():
            table.add_row(m, str(count))
        console.print(table)
        console.print(f"Estimated Total Requests: [bold]{summary['estimated_requests']}[/bold]")
        console.print(f"Allocated Budget:         [bold]{summary['budget']}[/bold]")
        db.close()
        return

    # Execute full pipeline
    console.print(f"[bold green]Starting scan {scan_id} on {target} (profile: {settings.profile.value})...[/bold green]")

    async def _execute():
        # Phase 1: Subdomains
        sub_tasks = [Task(scan_id=scan_id, module="subdomains", target=t_clean)]
        await engine.run_scan(ctx, tasks=sub_tasks)

        # Phase 2: DNS on all discovered assets
        dns_tasks = engine.modules["dns"].plan(ctx)
        if dns_tasks:
            await engine.run_scan(ctx, tasks=dns_tasks)

        # Phase 3: HTTP on resolved assets
        http_tasks = engine.modules["http"].plan(ctx)
        if http_tasks:
            await engine.run_scan(ctx, tasks=http_tasks)

        # Phase 4: URL Discovery on live services
        url_tasks = engine.modules["urls"].plan(ctx)
        if url_tasks:
            await engine.run_scan(ctx, tasks=url_tasks)

        # Phase 5: JavaScript analysis on live services
        js_tasks = engine.modules["javascript"].plan(ctx)
        if js_tasks:
            await engine.run_scan(ctx, tasks=js_tasks)

        # Phase 6: Technology fingerprinting and API discovery
        fp_tasks = engine.modules["fingerprint"].plan(ctx)
        if fp_tasks:
            await engine.run_scan(ctx, tasks=fp_tasks)

    try:
        asyncio.run(_execute())
        console.print(f"[bold green]Scan {scan_id} finished successfully.[/bold green]")
    except KeyboardInterrupt:
        console.print(f"[yellow]Scan {scan_id} interrupted by user. State saved as stopped.[/yellow]")
    finally:
        db.close()


def results_cmd(
    scan_id: str = typer.Argument(..., help="Scan ID (e.g. RX-001)"),
) -> None:
    """View asset, DNS, and HTTP service results for a scan."""
    db_path = Path("data/reconx.db")
    if not db_path.exists():
        console.print("[red]Database not found.[/red]")
        raise typer.Exit(code=1)

    db = get_db(db_path)
    data = generate_json_report(db, scan_id)
    db.close()

    console.print(Panel(f"[bold]Results for {scan_id} ({data['scan']['program']})[/bold]"))

    # Assets table
    table = Table(title="Assets & Confidence")
    table.add_column("Hostname", style="cyan")
    table.add_column("Confidence", style="bold")
    table.add_column("Sources")

    for a in data["assets"]:
        conf = a["confidence"].upper()
        style = "green" if conf in ("HIGH", "VERIFIED") else "yellow"
        table.add_row(a["hostname"], f"[{style}]{conf}[/{style}]", ", ".join(a["sources"]))
    console.print(table)

    # HTTP table
    if data["http_services"]:
        http_table = Table(title="Live HTTP Services")
        http_table.add_column("URL", style="blue")
        http_table.add_column("Status", style="bold")
        http_table.add_column("Title")
        http_table.add_column("CDN")
        for h in data["http_services"]:
            http_table.add_row(
                h["url"],
                str(h["status_code"]),
                h["title"] or "(no title)",
                "Yes" if h["is_cdn"] else "No",
            )
        console.print(http_table)

    # Technologies table
    if data.get("technologies"):
        tech_table = Table(title="Detected Technologies")
        tech_table.add_column("Hostname", style="cyan")
        tech_table.add_column("Technology", style="bold green")
        tech_table.add_column("Version")
        tech_table.add_column("Category")
        for t in data["technologies"]:
            tech_table.add_row(
                t["hostname"],
                t["name"],
                t["version"] or "-",
                t["category"] or "-",
            )
        console.print(tech_table)

    # URLs table
    if data.get("urls"):
        urls_table = Table(title="Discovered URLs (Sample)")
        urls_table.add_column("URL", style="blue")
        urls_table.add_column("Category", style="yellow")
        urls_table.add_column("Source")
        for u in data["urls"][:15]:
            urls_table.add_row(
                u["url"],
                u["category"] or "-",
                u["source"],
            )
        console.print(urls_table)


def report_cmd(
    scan_id: str = typer.Option(..., "--scan-id", "-s", help="Scan ID to generate report for"),
    format_type: str = typer.Option("json", "--format", "-f", help="Format: json | txt | csv"),
    output_dir: Path = typer.Option(Path("reports"), "--out", "-o", help="Reports output folder"),
) -> None:
    """Export assessment report for submission or client review."""
    db_path = Path("data/reconx.db")
    if not db_path.exists():
        console.print("[red]Database not found.[/red]")
        raise typer.Exit(code=1)

    db = get_db(db_path)
    target_dir = output_dir / scan_id
    target_dir.mkdir(parents=True, exist_ok=True)

    fmt = format_type.lower()
    if fmt == "json":
        data = generate_json_report(db, scan_id)
        out_file = target_dir / "report.json"
        out_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
        console.print(f"[bold green]Generated JSON report:[/bold green] {out_file}")

    elif fmt == "txt":
        text_data = generate_txt_report(db, scan_id)
        out_file = target_dir / "report.txt"
        out_file.write_text(text_data, encoding="utf-8")
        console.print(f"[bold green]Generated TXT report:[/bold green] {out_file}")

    elif fmt == "csv":
        for entity in ("assets", "dns", "http", "urls", "technologies"):
            csv_content = generate_csv_report(db, scan_id, entity)  # type: ignore
            out_file = target_dir / f"{entity}.csv"
            out_file.write_text(csv_content, encoding="utf-8")
        console.print(f"[bold green]Generated CSV reports in:[/bold green] {target_dir}")
    else:
        console.print(f"[bold red]Unsupported format: {format_type}[/bold red]")
        db.close()
        raise typer.Exit(code=1)

    db.close()


def audit_cmd(
    scan_id: str = typer.Argument(..., help="Scan ID to verify (e.g. RX-001)"),
) -> None:
    """Verify tamper-evident request log SHA-256 hash chain and audit scope decisions."""
    db_path = Path("data/reconx.db")
    if not db_path.exists():
        console.print("[red]Database not found.[/red]")
        raise typer.Exit(code=1)

    db = get_db(db_path)
    is_valid, err = verify_chain(db, scan_id)

    console.print(Panel(f"[bold]Cryptographic Audit for {scan_id}[/bold]"))
    if is_valid:
        console.print("  [green]✓[/green] SHA-256 Hash Chain: [bold green]VALID (No tampering detected)[/bold green]")
    else:
        console.print(f"  [red]✗[/red] SHA-256 Hash Chain: [bold red]BROKEN[/bold red] - {err}")

    # Check for scope violations
    cursor = db.execute(
        "SELECT COUNT(*) FROM request_log WHERE scan_id = ? AND scope_decision LIKE 'denied%'",
        (scan_id,),
    )
    denied_count = cursor.fetchone()[0]

    cursor2 = db.execute(
        "SELECT COUNT(*) FROM request_log WHERE scan_id = ?",
        (scan_id,),
    )
    total_count = cursor2.fetchone()[0]

    console.print(f"  [green]✓[/green] Out-of-scope requests blocked: {denied_count}")
    console.print(f"  [green]✓[/green] Total logged target requests: {total_count}")
    db.close()


def resume_cmd(
    scan_id: str = typer.Argument(..., help="Scan ID to resume"),
    scope_path: Path = typer.Option(Path("config/scope.yaml"), "--scope", "-s", help="Scope file"),
    settings_path: Path = typer.Option(Path("config/settings.yaml"), "--settings", help="Settings file"),
) -> None:
    """Resume an interrupted or paused scan."""
    db_path = Path("data/reconx.db")
    db = get_db(db_path)
    scan_data = get_scan(db, scan_id)
    if not scan_data:
        console.print(f"[bold red]Scan {scan_id} not found.[/bold red]")
        db.close()
        raise typer.Exit(code=1)

    scope_cfg = load_scope(scope_path)
    scope_engine = ScopeEngine(scope_cfg)
    settings = load_settings(settings_path=settings_path, profile_override=scan_data["profile"])

    rate_limiter = AsyncRateLimiter(
        requests_per_second=settings.request_control.global_rate.requests_per_second,
        requests_per_minute=settings.request_control.global_rate.requests_per_minute,
    )
    req_mgr = RequestManager(
        scan_id=scan_id,
        scope_engine=scope_engine,
        settings=settings,
        db=db,
        rate_limiter=rate_limiter,
    )
    ctx = ScanContext(
        scan_id=scan_id,
        program=scan_data["program"],
        settings=settings,
        scope=scope_engine,
        requests=req_mgr,
        db=db,
    )

    engine = ScanEngine([SubdomainsModule(), DnsModule(), HttpModule()])
    console.print(f"[bold cyan]Resuming scan {scan_id}...[/bold cyan]")

    async def _resume():
        return await engine.resume_scan(scan_id, ctx)

    status = asyncio.run(_resume())
    console.print(f"[bold green]Scan {scan_id} resumed and finished with status: {status}[/bold green]")
    db.close()
