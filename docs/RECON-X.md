# RECON-X: Installation, Execution and Implementation Guide

Nov 17, 2026 · @Someone

## 1. Overview

RECON-X is a Python command-line framework that maps an authorized target's attack surface with few requests and stores every result with evidence. This guide covers installing it on Windows and Kali, configuring it, running it, and building it in 24 tested steps.

**What it gives you in bug bounty and VAPT work**

- A scoped, rate-controlled inventory of subdomains, DNS records, live web services, URLs, JavaScript endpoints and technologies.
- Leads for manual testing, ranked so you test the best assets first instead of thousands of hosts.
- Monitoring that reports new assets and endpoints before other hunters find them, which cuts duplicate reports.
- Reports with evidence you can attach to a submission or a client deliverable.

**What recon cannot do**

Recon finds and prioritizes attack surface. It does not prove a vulnerability. A missing header, an old version number or an exposed panel is a lead to verify by hand, and the tool labels it that way. Accuracy comes from three habits: verify every asset, deduplicate across sources, and keep asset confidence separate from vulnerability confidence.

**How to read this guide**

| Part | Sections | Use it when |
| --- | --- | --- |
| Rules | 2 | Before your first scan, and before each new program |
| Setup | 3 to 7 | Installing, configuring and checking your machines |
| Design | 8 to 9 | You want to know how the tool works inside |
| Build | 10 to 13 | Writing the code, one tested step at a time |
| Operate | 14 to 16 | Running scans, adding features, fixing problems |

## 2. Rules of engagement

Scan only targets you are authorized to test, and only inside the program's written rules. RECON-X enforces scope in code, but the authorization itself is your responsibility.

**Before every new program, read and record:**

- [ ] In-scope domains, wildcards, IP ranges and apps, and the out-of-scope list
- [ ] Allowed request rate, and any required User-Agent or custom header (often your researcher handle)
- [ ] Forbidden activity: denial of service, brute force, social engineering, data extraction, automated scanners on some assets
- [ ] Whether port scanning, directory brute forcing or vulnerability scanners (Nuclei) are allowed
- [ ] Rules for third-party assets, CDN-hosted hosts and cloud storage
- [ ] How to handle exposed personal data: stop, do not store it, report it
- [ ] Safe-harbor language, and where the program's policy page is saved (keep a dated copy)

**Hard rules built into RECON-X**

- Every active request is checked against scope immediately before it is sent, and again after DNS resolution and after every redirect.
- A target outside scope is never probed. It is logged as skipped with the reason.
- Default profile is `cautious`: 1 request per second, concurrency 1, port scanning off.
- No exploitation, no brute forcing, no authentication attacks, no credential use. Secret candidates found in JavaScript are stored as unverified and never tested.
- Do not scan shared CDN, WAF or cloud IP ranges at the port level. They belong to other people.
- If a target returns repeated 429 or 503 responses, the scan pauses. Do not override it.

**Evidence you keep for every scan**

The scan record stores the scope file as used, the program policy reference, the profile, the request budget and a request log. If a program ever asks whether you stayed in scope, this is your answer.

## 3. Requirements and environment layout

Write and unit-test the code on Windows, and run the real tools and lab targets on Kali. The core is pure Python, so the same tests pass on both.

**Where each job runs**

| Job | Windows | Kali |
| --- | --- | --- |
| Code editing, git, VS Code | Yes | Optional |
| Unit tests and mock-server tests | Yes | Yes |
| Subfinder, Katana, GAU, Nmap, Nuclei | Mostly not | Yes |
| Docker lab targets (Juice Shop, crAPI) | Optional | Yes |
| Authorized real-target scans | Possible | Preferred |

**Minimum requirements**

| Item | Requirement |
| --- | --- |
| Python | 3.11 or newer on both machines |
| RAM | 8 GB minimum, 16 GB comfortable with Docker labs |
| Disk | 20 GB free (Kali, Go tools, Docker images) |
| Network | Internet access for passive sources. Lab scans need no internet |
| Windows | Windows 10 22H2 or Windows 11, with virtualization enabled in BIOS for WSL2 |

**Kali on WSL2 or in a VM**

| Option | Choose it when | Watch out for |
| --- | --- | --- |
| WSL2 Kali | You want fast setup and one machine for editing and running | Raw-socket Nmap scans can behave oddly. Keep the repo inside the Linux filesystem, not under `/mnt/c` |
| VirtualBox or VMware Kali VM | You need full network control or SYN scans | More RAM, slower file sharing. Use git to move code |

Start with WSL2. Move to a VM only if you hit a limit.

**Folder layout across both machines**

Keep one git repository. Edit on Windows or inside WSL, push to your own private remote, and pull on the other side. Do not edit the same working copy from both sides at once.

## 4. Installation on Windows

Install Python, Git and VS Code, create a virtual environment, install the dependencies and verify. It takes about 15 minutes.

**Step 1. Install the base tools (PowerShell)**

```powershell
winget install Python.Python.3.12
winget install Git.Git
winget install Microsoft.VisualStudioCode
```

Close and reopen PowerShell, then check the versions:

```powershell
py -3.12 --version
git --version
```

If `winget` is missing, use the installers from python.org (tick "Add python.exe to PATH"), git-scm.com and code.visualstudio.com.

**Step 2. Create the project and virtual environment**

```powershell
mkdir recon-x
cd recon-x
git init
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
```

If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` and activate again. The prompt should now start with `(.venv)`.

**Step 3. Create the dependency files**

`requirements.txt`:

```text
typer>=0.12
httpx>=0.27
dnspython>=2.6
beautifulsoup4>=4.12
pydantic>=2.7
PyYAML>=6.0
rich>=13.7
Jinja2>=3.1
idna>=3.7
defusedxml>=0.7
```

`requirements-dev.txt`:

```text
-r requirements.txt
pytest>=8.0
pytest-asyncio>=0.23
pytest-cov>=5.0
ruff>=0.5
mypy>=1.10
```

Install them, then freeze exact versions once everything works:

```powershell
pip install -r requirements-dev.txt
pip freeze > requirements.lock
```

**Step 4. Set up VS Code**

Install the Python, Pylance and YAML extensions, plus the WSL extension if you will open Kali folders. Press Ctrl+Shift+P, choose "Python: Select Interpreter" and pick the `.venv` one.

**Step 5. Verify the install**

```powershell
python -c "import typer, httpx, dns.resolver, bs4, pydantic, yaml, rich, jinja2; print('imports ok')"
pytest --version
```

Both must succeed before you write any code.

**What Windows will not run**

Subfinder, Katana, GAU, Nmap and Nuclei live on Kali. On Windows, `recon-x doctor` reports them as missing and those modules skip with a clear message instead of crashing. Everything else, including all unit tests, runs on Windows.

## 5. Installation on Kali Linux

Install Kali on WSL2 (or a VM), add Go and the recon tools, set up Docker for lab targets, and verify. Allow 30 to 45 minutes. Install commands change between releases, so check each tool's README if one fails.

**Step 1. Install Kali (WSL2)**

In an Administrator PowerShell:

```powershell
wsl --install -d kali-linux
wsl --set-default-version 2
wsl -l -v
```

Reboot if asked, open Kali, and create your Linux user. `wsl -l -v` must show VERSION 2. For a VM instead, download the Kali VM image from kali.org and import it into VirtualBox or VMware.

**Step 2. Update and install base packages**

```bash
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y python3 python3-venv python3-pip git golang-go nmap libpcap-dev curl jq
```

**Step 3. Put Go tools on your PATH**

```bash
go version
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.zshrc
source ~/.zshrc
```

If a tool refuses to build because your Go is too old, install the current Go from go.dev and repeat.

**Step 4. Install the recon tools**

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/waybackurls@latest
nuclei -update-templates
```

| Tool | Purpose | RECON-X module | Needed from step |
| --- | --- | --- | --- |
| Subfinder | Passive subdomain discovery | subdomains | 11 |
| GAU, waybackurls | Historical URLs | urls | 16 |
| Katana | Crawling | urls, javascript | 16 |
| Nmap, Naabu | Port and service discovery | ports | 24 |
| Nuclei | Approved non-destructive checks | vulnerability\_intel | 23 |

Kali packages ProjectDiscovery's HTTP tool as `httpx-toolkit` to avoid a clash with the Python `httpx` command. RECON-X only imports the Python `httpx` library, so it is not affected. `recon-x doctor` reports which binary it finds.

**Step 5. Optional: passive-source API keys**

Subfinder finds more with keys for services such as Shodan, Censys and VirusTotal. Put them in `~/.config/subfinder/provider-config.yaml` and set the file mode to 600. Never commit keys to git, and never put them in `settings.yaml`.

**Step 6. Get the project onto Kali**

Clone into the Linux home directory, not `/mnt/c`, which is slow and breaks file permissions:

```bash
git clone <your-private-repo-url> ~/recon-x
cd ~/recon-x
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
```

**Step 7. Docker for lab targets**

Enable systemd in WSL by adding this to `/etc/wsl.conf`:

```ini
[boot]
systemd=true
```

Then run `wsl --shutdown` in PowerShell, reopen Kali and continue:

```bash
sudo apt install -y docker.io docker-compose
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
```

Log out and back in, then run `docker run --rm hello-world`. Docker Desktop for Windows with WSL integration also works if you prefer it.

**Step 8. Verify everything**

```bash
python3 --version
go version
subfinder -version
katana -version
nuclei -version
nmap --version
docker --version
```

Each command must print a version. From step 6 of the build plan onward, `recon-x doctor` runs this check for you.

## 6. Project setup

Create the skeleton from your design document, add a `pyproject.toml` so `recon-x` becomes a real command, and confirm it with `recon-x --help`. Do this on one machine, commit, then pull on the other.

**Folder layout**

```text
recon-x/
  pyproject.toml
  requirements.txt
  requirements-dev.txt
  README.md
  .gitignore
  .gitattributes
  .github/workflows/tests.yml
  config/
    settings.yaml, scope.yaml, scope.lab.yaml
    categories.yaml, scoring.yaml, cpe_map.yaml
    fingerprints/  tech.yaml, takeover.yaml
  reconx/
    __init__.py
    main.py
    cli/          commands.py, arguments.py
    core/         engine.py, config.py, logging.py, scope.py, normalizer.py,
                  deduplicator.py, rate_limiter.py, request_manager.py,
                  scheduler.py, tool_runner.py, audit.py
    modules/      subdomains.py, dns.py, http.py, ports.py, urls.py,
                  javascript.py, fingerprint.py, misconfiguration.py,
                  vulnerability_intel.py
    integrations/ subfinder.py, katana.py, gau.py, nmap.py, nuclei.py
    database/     models.py, storage.py, migrations/
    intelligence/ confidence.py, correlation.py, history.py
    reporting/    json_report.py, html_report.py, csv_report.py, templates/
  tests/
    unit/  integration/  fixtures/  mock_server/  metrics/
  data/  reports/  logs/
```

Compared with the original design, this adds `audit.py` and `tool_runner.py` in core, `migrations/` in database, a `templates/` folder for reports, and a full `tests/` tree.

**pyproject.toml**

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "recon-x"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = [
  "typer>=0.12", "httpx>=0.27", "dnspython>=2.6",
  "beautifulsoup4>=4.12", "pydantic>=2.7", "PyYAML>=6.0",
  "rich>=13.7", "Jinja2>=3.1", "idna>=3.7", "defusedxml>=0.7",
]

[project.scripts]
recon-x = "reconx.main:app"

[tool.setuptools.packages.find]
include = ["reconx*"]

[tool.setuptools.package-data]
reconx = ["reporting/templates/*.j2"]

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
markers = [
  "integration: uses the local mock server",
  "tools: needs external tools on PATH (Kali)",
  "lab: needs Docker lab targets running",
]
```

**.gitignore**

```text
.venv/
__pycache__/
*.db
data/
reports/
logs/
config/*secret*
.env
```

**Install as a command and run the first checks**

```bash
pip install -e .
recon-x --help
pytest -m "not tools and not lab"
```

The `-m` filter is how you run only the tests that work on Windows. On Kali with tools installed, run plain `pytest`. Lab tests also need `RECONX_LAB=1` set so they never run by accident.

| Command | Runs | Where |
| --- | --- | --- |
| `pytest -m "not tools and not lab"` | Unit and mock-server tests | Windows and Kali |
| `pytest -m tools` | Wrapper tests against real binaries | Kali |
| `pytest -m lab` | End-to-end tests on Juice Shop and crAPI | Kali with Docker |

**First smoke test** (`tests/unit/test_smoke.py`)

```python
from typer.testing import CliRunner
from reconx.main import app

def test_help_runs():
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Usage" in result.stdout
```

## 7. Configuration

Two YAML files drive every scan: `scope.yaml` says what you may touch, and `settings.yaml` says how carefully to touch it. Pydantic validates both on load, and a bad value stops the scan with a plain explanation.

**scope.yaml**

```yaml
program: example-program
authorized_by: "Program policy saved 2026-11-17"

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

rules:
  allow_port_scan: false
  allow_nuclei: false
  max_requests: 1000
```

Exclusions always beat inclusions. A rule such as `allow_port_scan: false` beats any command-line flag.

**settings.yaml**

```yaml
profile: cautious            # cautious | normal | program-custom

program:
  name: example-program
  policy_url: "https://example.com/security"
  user_agent: "RECON-X/0.1 (researcher: your-handle)"
  extra_headers:
    X-Bug-Bounty: "your-handle"

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
```

The `external_tools` limits are enforced by the integration wrappers, which pass each tool's own rate flags (for example Subfinder `-rl`, Katana `-rl`, Nuclei `-rl`, Naabu `-rate`). Confirm the exact flag names with each tool's `-h` output, and add a test that the wrapper always includes them.

**Scan profiles**

| Profile | Rate | Concurrency | Port scan | Nuclei | Use it for |
| --- | --- | --- | --- | --- | --- |
| `cautious` (default) | 1 request per second | 1 | Off | Off | First contact with any target |
| `normal` | Suggested 5 per second globally, 2 per host | 3 | Only if scope allows | Only if scope allows | Programs that state a higher allowed rate |
| `program-custom` | Values you copy from the policy | You set it | You set it | You set it | Programs with their own rules |

The `normal` numbers are suggestions, not program-approved limits. `program-custom` refuses to start until `program.policy_url` and the rate are filled in.

**Precedence and secrets**

- Order: scope rules, then command-line flags, then `settings.yaml`, then profile defaults. A scope rule that forbids something always wins.
- A command-line flag can lower a rate freely. Raising a rate above the profile needs `--confirm-rate` so it is never done by accident.
- Secrets (Telegram token, Shodan key) live in environment variables or the OS keyring. The config file stores only the variable name. Logs and reports redact anything matching a known secret pattern.

## 8. Architecture and execution flow

No module opens its own connection to a target. Active traffic goes through the request controller, and a test fails the build if any module bypasses it.

&#91;embedded content: architecture and request path · 8 checks in the controller\]

Read the picture from the top. The CLI loads scope and configuration, and the engine hands tasks to passive or active modules. Passive modules reach third-party sources and external tools through the passive gateway, which has its own limiter. Active modules reach the target only through the controller, which sends nothing unless all its checks pass. Everything that comes back is normalized, deduplicated and scored before it is stored.

**Module interface**

Every module implements the same two methods. `plan()` lets `--dry-run` count requests without sending any.

```python
class Module(Protocol):
    name: str

    def plan(self, ctx: ScanContext) -> list[Task]:
        """Return the tasks this module would run, with estimated request counts."""

    async def run(self, ctx: ScanContext, task: Task) -> list[Result]:
        """Do the work using ctx.requests (the controller). Never open sockets directly."""
```

**Execution sequence of a scan**

1. The CLI parses the command and loads the configuration.
2. The scope engine loads and validates the scope file. A dry run stops after printing the plan.
3. The engine creates the scan record and queues tasks in the database.
4. Passive stage: Subfinder and crt.sh return candidate hostnames. Out-of-scope names are dropped and counted.
5. Normalize and deduplicate. Assets start at low or medium confidence.
6. DNS stage: resolve records, test for wildcards, and re-check scope after resolution. Resolving assets reach high confidence.
7. HTTP stage: probe each resolved in-scope host, take the soft-404 fingerprint, tag CDN hosts and store evidence. Live hosts become verified.
8. V1.5 stages (URLs, JavaScript, fingerprints, API discovery) work only from verified assets.
9. V2.0 stages (observations, leads, vulnerability intelligence) read stored data.
10. Results are committed after each batch. The scan ends with a report, and `audit` can verify the log.

**Rules the architecture enforces**

- Passive discovery and active verification stay separate, so you can run one without the other.
- Every stored fact carries its source, a timestamp and evidence.
- An interrupted scan loses at most the request in progress.

## 9. Database schema

SQLite stores everything in one file, `data/reconx.db`. Assets live across scans so the tool can compare today with last week, and every observation carries a scan id and timestamp.

**Tables from the original design**

| Table | Key columns | Notes |
| --- | --- | --- |
| `scans` | id (RX-001), program, profile, status, started\_at, finished\_at, request\_budget, requests\_used, config\_snapshot, scope\_snapshot | Status: running, paused, completed, stopped |
| `targets` | id, scan\_id, value, type, in\_scope | Type: domain, ip, cidr |
| `assets` | id, hostname, program, confidence, first\_seen, last\_seen | Unique on (program, hostname) |
| `dns_records` | id, asset\_id, scan\_id, type, value, ttl, observed\_at | Unique on (asset\_id, scan\_id, type, value) |
| `http_services` | id, asset\_id, scan\_id, url, status\_code, title, server, content\_type, content\_length, redirect\_chain, tls, body\_hash | Stores soft-404 fingerprint and CDN flag too |
| `ports` | id, asset\_id, scan\_id, port, protocol, service, version, banner | Unique on (asset\_id, scan\_id, port, protocol) |
| `urls` | id, asset\_id, url\_normalized, source, category, status\_code, first\_seen, last\_seen | Unique on normalized URL |
| `technologies` | id, asset\_id, name, version, category, evidence | Version is nullable |
| `findings` | id, scan\_id, asset\_id, type, title, severity\_hint, confidence, status, notes | Status: new, confirmed, false\_positive, reported, duplicate, fixed |
| `evidence` | id, finding\_id, asset\_id, kind, raw\_redacted, source, captured\_at | Raw values are redacted before saving |
| `scan_events` | id, scan\_id, ts, level, event, detail | Pauses, errors, backoff, interrupts |

**Tables added in this plan**

| Table | Key columns | Why it is needed |
| --- | --- | --- |
| `scope_rules` | id, scan\_id, rule\_type, kind, value | Records the exact rules used for each scan |
| `asset_sources` | asset\_id, source, seen\_at | Source attribution and cross-source confidence |
| `asset_snapshots` | scan\_id, asset\_id, snapshot\_json, snapshot\_hash | Historical diffing |
| `asset_relationships` | parent\_asset\_id, child\_asset\_id, relation | CNAME, IP, ASN and redirect links |
| `request_log` | id, scan\_id, ts, method, url, host, status, bytes, duration\_ms, scope\_decision, prev\_hash, row\_hash | Audit trail. The hash chain makes edits detectable |
| `tool_runs` | id, scan\_id, tool, args\_redacted, started\_at, finished\_at, exit\_code, rate\_flag\_present | Proves external tools ran with rate limits |
| `scan_tasks` | id, scan\_id, module, target, status, attempts | Task queue that makes pause and resume possible (migration 002) |
| `js_files` | id, url, sha256, size, first\_seen, last\_seen | Detects changed JavaScript |
| `endpoints` | id, url\_id, method, path, parameters, js\_file\_id | Endpoint and parameter inventory |
| `secret_candidates` | id, js\_file\_id, pattern, preview\_redacted, entropy, status | Status stays `unverified` |
| `cve_cache` | id, source, lookup\_key, payload, fetched\_at, expires\_at | Caches NVD and CISA KEV lookups (migration 003) |
| `screenshots` | id, http\_service\_id, path, sha256 | Optional visual triage |
| `notes` | id, entity\_type, entity\_id, body, created\_at | Your manual notes per asset or finding |
| `schema_migrations` | version, applied\_at | Tracks database upgrades |

**Example definitions**

```sql
CREATE TABLE assets (
  id          INTEGER PRIMARY KEY,
  program     TEXT NOT NULL,
  hostname    TEXT NOT NULL,
  confidence  TEXT NOT NULL DEFAULT 'low'
              CHECK (confidence IN ('low','medium','high','verified')),
  first_seen  TEXT NOT NULL,
  last_seen   TEXT NOT NULL,
  UNIQUE (program, hostname)
);

CREATE TABLE request_log (
  id             INTEGER PRIMARY KEY,
  scan_id        TEXT NOT NULL REFERENCES scans(id),
  ts             TEXT NOT NULL,
  method         TEXT NOT NULL,
  url            TEXT NOT NULL,
  host           TEXT NOT NULL,
  status         INTEGER,
  bytes          INTEGER,
  duration_ms    INTEGER,
  scope_decision TEXT NOT NULL,
  prev_hash      TEXT,
  row_hash       TEXT NOT NULL
);
```

**Rules for the storage layer**

- Turn on `PRAGMA foreign_keys=ON` and `PRAGMA journal_mode=WAL` for every connection.
- All timestamps are UTC, ISO 8601 text.
- Store normalized values. Keep the raw value only in `evidence`, redacted.
- Write with upserts: `INSERT ... ON CONFLICT(...) DO UPDATE SET last_seen = excluded.last_seen`. Re-running a scan updates rows instead of duplicating them.
- Commit after each batch of results, so an interrupted scan keeps what it already found.
- Schema changes are numbered `.sql` files in `database/migrations/`, applied in order and recorded in `schema_migrations`.
- `request_log.row_hash` is a SHA-256 over the row's fields plus the previous row's hash.

## 10. Implementation plan, steps 1 to 6: foundation

The plan has 24 steps. Each has a build list, tests that must pass, and a gate. Do not start the next step until the gate passes, then commit and tag it (for example `git tag step-04-done`). Steps 3, 4, 7 and 8 are test-first: write the tests before the code, because those four hold the safety logic.

### Step 1. Skeleton, packaging and CI

**Build**

- The folder layout from section 6, `pyproject.toml`, `.gitignore`, and a Typer app in `reconx/main.py`.
- A GitHub Actions workflow that runs on Windows and Ubuntu:

```yaml
name: tests
on: [push, pull_request]
jobs:
  test:
    strategy:
      matrix:
        os: [windows-latest, ubuntu-latest]
        python: ["3.11", "3.12"]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python }}
      - run: pip install -r requirements-dev.txt
      - run: pip install -e .
      - run: ruff check .
      - run: pytest -m "not tools and not lab"
```

**Test:** `pytest tests/unit/test_smoke.py` and `ruff check .`

**Gate:** the smoke test passes on Windows, on Kali and in CI.

### Step 2. Configuration manager

**Build**

- `reconx/core/config.py` with Pydantic models for settings, request control, profiles and external tools.
- A loader that merges profile defaults, then `settings.yaml`, then command-line overrides.
- Validation: rates above zero, minimum delay not above maximum delay, budget above zero, `program-custom` requires `policy_url`.
- Secrets read from environment variables and hidden in `repr` and logs.

**Test:** `pytest tests/unit/test_config.py`

- Defaults load with no file present.
- Invalid YAML and invalid values fail with a readable message that names the field.
- A command-line flag may lower a rate. Raising it without `--confirm-rate` is rejected.
- A secret never appears in the printed config.

**Gate:** a bad configuration stops the program before any network code exists.

### Step 3. Normalizer (test first)

**Build:** `reconx/core/normalizer.py` with functions for hostnames, URLs, IPs and ports. Use the `idna` package for internationalized names. Every function returns the normalized value plus flags such as `obfuscated_ip` or `userinfo_present`, and raises a clear error for invalid input.

**Test:** `pytest tests/unit/test_normalizer.py`. Start with these cases, then add more as you find them:

| Input | Expected result |
| --- | --- |
| `EXAMPLE.com.` | `example.com` |
| `bücher.example` | `xn--bcher-kva.example` |
| `https://example.com:443/a#x` | `https://example.com/a` |
| `http://example.com@evil.com/` | host `evil.com`, flag `userinfo_present` |
| `http://2130706433/` | host `127.0.0.1`, flag `obfuscated_ip` |
| `http://0177.0.0.1/` | host `127.0.0.1`, flag `obfuscated_ip` |
| `http://[::1]:8080/` | host `::1`, port 8080 |
| `exa mple.com` and `a..b.com` | rejected |

Also add a loop test that feeds many random strings and checks that normalizing twice gives the same result as normalizing once.

**Gate:** all cases pass, and no input can crash the function. It either returns a value or raises the documented error.

### Step 4. Scope engine (test first)

**Build:** `reconx/core/scope.py`.

- `ScopeEngine.check(target)` returns a decision with `allowed`, the matching rule and a plain-language reason. Anything not matched is denied.
- Rule types: exact domain, wildcard, IP, CIDR, port, and exclusions. Exclusions always win.
- Matching works on whole labels of the normalized host, never on substrings.
- Loopback, link-local (including the cloud metadata address 169.254.169.254) and private ranges are denied unless explicitly listed.
- `check_redirect(from_url, to_url)` for every redirect hop, and `recheck_after_dns(host, ips)` after resolution.
- Only `http` and `https` schemes are allowed.

**Test:** `pytest tests/unit/test_scope.py --cov=reconx.core.scope --cov-fail-under=95`

| Case | Expected |
| --- | --- |
| `example.com` against rule `example.com` | allow |
| `a.example.com` against `*.example.com` | allow |
| `example.com` against only `*.example.com` | deny, the apex is not covered |
| `evilexample.com` | deny |
| `example.com.evil.com` | deny |
| `mail.example.com` when excluded | deny, even though the wildcard matches |
| `http://example.com@evil.com/` | deny, the real host is `evil.com` |
| A name using a Cyrillic letter that looks like Latin `a` | deny |
| `10.0.0.5` against `10.0.0.0/24` | allow |
| `10.0.1.5` against `10.0.0.0/24` | deny |
| `127.0.0.1` with no explicit rule | deny |
| `::ffff:10.0.0.5` | evaluated as `10.0.0.5` |
| Port 22 when web ports are 80 and 443 | deny |
| Redirect from an in-scope host to an out-of-scope host | deny, not followed |
| Empty scope | deny everything |

Add a loop test that generates random hostnames not covered by any rule and asserts none is ever allowed.

**Gate:** coverage is at least 95%, every decision has a reason, and zero out-of-scope inputs are allowed.

### Step 5. SQLite storage, migrations and audit log

**Build**

- `database/storage.py`: connection factory with the pragmas from section 9, a migration runner, and upsert helpers.
- `database/migrations/001_init.sql` with every table from section 9.
- `core/audit.py`: writes `request_log` rows with the hash chain, and a `verify_chain()` function.
- A logging setup with a filter that redacts tokens, API keys and Authorization headers.
- A scan id generator that produces `RX-001`, `RX-002` and so on.

**Test:** `pytest tests/unit/test_storage.py tests/unit/test_audit.py`

- Migrations apply to an empty database, and running them twice changes nothing.
- Inserting the same asset twice updates `last_seen` and leaves one row.
- Foreign keys are enforced.
- Changing one `request_log` row makes `verify_chain()` fail.
- Data written, closed and reopened is still there.
- A log line containing a bearer token is written with the token redacted.

**Gate:** all storage tests pass on Windows and Kali. SQLite file paths work with `pathlib` on both.

### Step 6. CLI shell

**Build:** Typer commands in `cli/commands.py`:

- `init` creates the folders, default config and database.
- `scope add`, `scope list`, `scope import` for TXT, CSV and YAML, and `scope check <target>`, which prints the decision and the reason.
- `config show` with secrets hidden.
- `doctor` checks the Python version, dependencies, database access, and each external tool with its version. A missing tool is a warning, not an error. It also reports which `httpx` binary is on PATH.
- `status`, which lists scans from the database.

**Test:** `pytest tests/unit/test_cli.py` using `CliRunner` and a temporary directory. Cover each command, an import file with a bad line (the error names the line number), and `doctor` on a machine with no tools installed. Then run it by hand on both machines:

```bash
recon-x init
recon-x scope add example.com
recon-x scope check a.example.com
recon-x scope check evil.com
recon-x doctor
```

**Gate (end of Part A):** all unit tests are green on Windows, Kali and CI, and `scope check` gives the correct answer for every case in the step 4 table. Tag `part-a-done`.

## 11. Implementation plan, steps 7 to 15: traffic control and V1.0

Part B (steps 7 to 10) builds the request controller that every active module must use. Part C (steps 11 to 15) adds the first recon modules and ends with the V1.0 release.

### Step 7. Rate limiter (test first)

**Build:** `reconx/core/rate_limiter.py`.

- An async token bucket whose clock and sleep function are injected, so tests run on a fake clock and never wait in real time.
- A global limiter and a per-host limiter, plus a per-minute cap using a sliding window.
- A random delay between the configured minimum and maximum, with an injectable random source.

**Test:** `pytest tests/unit/test_rate_limiter.py`

- 100 acquisitions at 1 request per second take at least 99 simulated seconds.
- No one-second window ever contains more requests than the limit.
- The per-minute cap of 30 holds.
- Two hosts are limited independently, but the global limit still binds both.
- Every delay falls inside the minimum and maximum.

**Gate:** across 10,000 simulated acquisitions, the maximum requests in any one-second window never exceeds the configured limit.

### Step 8. Request controller (test first)

**Build:** `reconx/core/request_manager.py`, the only module allowed to open network connections to targets. It exposes one entry point, `request(method, url, module, purpose)`, which runs these checks in order:

1. Normalize the URL.
2. Check scope. Deny raises `ScopeDenied` and nothing is sent.
3. Check the budget. Exhausted raises `BudgetExceeded`.
4. Wait for the global and per-host limiters.
5. Send with `httpx`, with automatic redirects turned off.
6. Follow redirects manually. Each hop is re-checked against scope and counts against the budget, up to the redirect limit.
7. Stop reading the body at `max_response_bytes`, counting decompressed bytes so a compressed bomb cannot exhaust memory.
8. On 429 or 503, honor `Retry-After` (seconds or date), then back off from 30 seconds, doubling to a 300 second maximum.
9. After the configured number of consecutive errors, save state and raise `ScanPaused`.
10. Write a `request_log` row with the scope decision and hash chain.

It also sets the program User-Agent and extra headers, applies connect and read timeouts, supports an optional proxy (Burp or Caido), and never executes JavaScript. Retries count against the budget. Passive third-party sources go through a separate `passive_get()` with an allow-list of source domains and its own limiter, so they never touch the target budget. DNS goes through `dns_query()` the same way.

**Test:** `pytest tests/unit/test_request_manager.py` using `httpx.MockTransport`:

- An out-of-scope URL raises `ScopeDenied`, and the transport receives zero calls.
- A budget of N allows exactly N requests, then raises.
- A redirect to an out-of-scope host is logged and not followed. Each followed hop uses budget.
- `Retry-After: 7` waits at least 7 simulated seconds.
- Repeated 503 responses back off 30, 60, 120 and so on, never above 300.
- Five consecutive errors raise `ScanPaused` with state saved.
- An oversized body is cut at the limit.
- Every transport call has a matching `request_log` row.

**Gate:** across the whole suite, out-of-scope requests sent equal zero, and request counts match the log.

### Step 9. Mock server and the no-bypass guard

**Build**

- `tests/mock_server/server.py`, a threaded server using only the standard library, started by a pytest fixture on a random local port. Routes: `/ok` (200), `/redir-out` (redirect to an out-of-scope host), `/redir-loop`, `/429` (with Retry-After), `/503`, `/slow`, `/big`, `/gzip-bomb`, and `/soft404/...` (returns 200 with a not-found page for any path).
- `tests/unit/test_no_bypass.py`, a guard that parses every file under `reconx/` with Python's `ast` module and fails if `httpx`, `requests`, `aiohttp`, `urllib.request`, `socket` or `dns.resolver` is imported anywhere except `core/request_manager.py`, or if `subprocess` is imported anywhere except `core/tool_runner.py`.
- A `tests/conftest.py` that skips `lab` tests unless `RECONX_LAB=1` and skips `tools` tests when binaries are missing.

**Test:** `pytest -m integration` and `pytest tests/unit/test_no_bypass.py`

**Gate:** all pass. Then prove the guard works: add a stray `import httpx` to `modules/http.py`, confirm the guard fails, and revert it.

### Step 10. Scan state, interrupt, resume and dry-run

**Build:** `core/engine.py` and `core/scheduler.py`, plus migration `002` adding a `scan_tasks` table (id, scan\_id, module, target, status, attempts).

- The engine queues tasks in the database and runs them one at a time through the controller.
- States: created, running, paused, stopped, completed.
- Ctrl+C (and SIGTERM on Kali) finishes the current request, commits results and marks the scan `stopped`.
- `resume RX-001` re-queues every task that is not done and keeps the budget already used.
- `scan --dry-run` prints the planned tasks, the estimated request count and the budget share. It runs on a transport that raises if anything tries to send.

**Test:** `pytest tests/integration/test_resume.py`

- Queue 20 tasks against the mock server, interrupt after 5, and confirm 5 are done and committed.
- Resume finishes the other 15 and sends no repeat request for the 5 already done.
- `requests_used` carries across the resume.
- A dry run makes zero network calls.

Repeat the interrupt by hand on both machines: start a scan against the mock server and press Ctrl+C. Windows and Linux handle signals differently, so run this on both.

**Gate (end of Part B):** rate, budget, scope, pause and resume are all proven against the mock server on Windows and Kali. Tag `part-b-done`.

### Step 11. External tool runner and passive subdomains

**Build**

- `core/tool_runner.py` is the only place that starts subprocesses. It never uses a shell, passes arguments as a list, rejects any target that starts with `-` (option injection), enforces a timeout and an output size cap, and kills the whole process tree on timeout or interrupt. Each run is written to `tool_runs`.
- Each integration declares the rate-limit flags it requires. The runner refuses to start a tool when its required flag is missing. This is how external tools stay inside the same limits as the Python code.
- `integrations/subfinder.py` runs Subfinder in silent mode with JSON output and its rate flag, then parses each line into hostname, sources and time seen. Confirm the exact flags with `subfinder -h`.
- A built-in crt.sh source goes through `passive_get()` and splits multi-name certificate entries and `*.example.com` names correctly.
- Every result is normalized and scope-filtered. Out-of-scope names are counted in `scan_events`, not saved as assets.

**Test**

- `pytest tests/unit/test_tool_runner.py`: the runner refuses a missing rate flag and a target starting with `-`. A fake tool that sleeps for 60 seconds is killed at the timeout. A missing binary raises `ToolMissing`, and the module skips with a warning.
- `pytest tests/unit/test_subfinder_parser.py tests/unit/test_crtsh_parser.py`: save real output from Subfinder and crt.sh once into `tests/fixtures/`, then test the parsers against those files. These run on Windows without the tools installed.
- `pytest -m tools` on Kali: the real wrapper runs against a domain you are authorized to test.

**Gate:** parser tests pass on Windows, and the `tools` test passes on Kali.

### Step 12. Deduplication and confidence, version 1

**Build**

- `core/deduplicator.py` merges assets by normalized hostname, keeps every source, takes the earliest `first_seen` and latest `last_seen`.
- `intelligence/confidence.py` sets asset confidence with fixed rules:

| Level | Rule |
| --- | --- |
| Low | Seen by one source only |
| Medium | Seen by two or more independent sources |
| High | DNS resolves |
| Verified | A live HTTP response was received and evidence is stored |

Independent means different data providers. Vulnerability confidence is a separate class added in V2.0 and is never mixed with this one.

**Test:** `pytest tests/unit/test_dedup.py tests/unit/test_confidence.py`

- The same host from three sources, with different case and a trailing dot, becomes one asset with three sources.
- A table-driven test covers every confidence transition.
- Confidence never drops within a scan.

**Gate:** on a fixture of 1,000 hostnames with a known number of injected duplicates, the duplicate rate after merging is 0%.

### Step 13. DNS module

**Build:** `modules/dns.py`, using dnspython through `dns_query()`.

- Record types: A, AAAA, CNAME, MX, NS, TXT, SOA, CAA. Resolvers are configurable, defaulting to the system resolver.
- Wildcard detection: query two or three random labels under the parent. If they resolve, the zone is wildcard. Hosts whose answers equal the wildcard answers are flagged `wildcard_match` and held at low confidence.
- Observations, not vulnerabilities: missing SPF, DMARC with `p=none`, missing CAA, DNSSEC absent.
- Dangling CNAME candidates: a CNAME whose target returns NXDOMAIN is flagged `dangling_candidate`. Takeover verification comes in step 19.
- After resolution, call `recheck_after_dns`. A CNAME or IP outside scope is recorded and flagged, never probed.

**Test:** `pytest tests/unit/test_dns.py` with an injected fake resolver and canned answers: A and AAAA, a CNAME chain, NXDOMAIN, a wildcard zone, a missing SPF record, DMARC `p=none`, a CNAME to a third-party host, and timeouts or SERVFAIL (retried once, then recorded as an error).

**Gate:** all DNS tests pass, and the no-bypass guard shows no `dns.resolver` use outside the controller.

### Step 14. HTTP module

**Build:** `modules/http.py`, using only `request()`.

- For each resolved in-scope asset, request `https://host/`, and try `http://host/` only if HTTPS fails.
- Store status, title (parsed from the first 100 KB with BeautifulSoup), headers, server, content type and length, redirect chain, and body hash.
- Read the TLS certificate from the same connection httpx already opened, so it costs no extra request.
- Soft-404 fingerprint: one request to a random path per host. Store its status, length and hash, and let later modules compare against it.
- CDN and WAF tagging from headers (for example Cloudflare, CloudFront or Akamai markers) and from resolved IP ranges. Tagged assets are excluded from port scanning later.
- Group hosts that return identical bodies or titles, so 500 copies of one login page appear as one cluster.
- Save headers and a redacted body sample as evidence.

**Test:** `pytest tests/integration/test_http_module.py -m integration` against the mock server, covering title extraction, redirect chains, an out-of-scope redirect (recorded, not followed), soft-404 detection, oversized bodies, non-HTML content and CDN header fixtures. Test certificate parsing from a saved `getpeercert()` fixture.

**Gate:** requests per asset are at most 3 (HTTPS, HTTP fallback, soft-404 probe), checked from `request_log`, and every verified asset has an evidence row.

### Step 15. Reports and the V1.0 release

**Build**

- `reporting/json_report.py`, a TXT report, and a CSV export. Sections: target, configuration, scope snapshot, subdomains, DNS, live services, evidence, confidence, request statistics and summary.
- The `scan` command wires the pipeline: passive, then DNS, then HTTP.
- Commands `results`, `report --scan-id RX-001 --format json|txt|csv`, `status`, `resume`, and `scan --dry-run` work end to end.
- A new `audit RX-001` command verifies the hash chain, lists any scope denials, and checks the logged request rate against the configured limit.
- README with installation and usage.

**Test**

- `pytest tests/unit/test_reports.py`: golden-file tests compare the JSON report from a seeded database to a stored file, ignoring timestamps. The CSV has its header row, the TXT contains every section, and secrets are redacted.
- Mock-server run on any machine:

```bash
recon-x scan localhost --profile cautious --dry-run
recon-x scan localhost --profile cautious --max-requests 50
recon-x audit RX-001
recon-x report --scan-id RX-001 --format json
```

- Lab run on Kali (see section 13): scan Juice Shop on `localhost:3000` with port 3000 in scope.
- Real run: one authorized program, `cautious` profile, `--max-requests 100` first.

**Gate (V1.0 release):** you can start a scan, press Ctrl+C partway, resume it and get a valid report. `audit` shows zero scope violations and no rate breach. Tag `v1.0`.

## 12. Implementation plan, steps 16 to 24: V1.5 and V2.0

Steps 16 to 20 make up V1.5 (web intelligence and monitoring). Steps 21 to 24 make up V2.0 (intelligence and workflow). The same rules apply: build, test, pass the gate, tag.

### Step 16. URL discovery

**Build:** `modules/urls.py`, `integrations/katana.py`, `integrations/gau.py` and a waybackurls wrapper.

- Katana crawls only from verified live assets. Pass its depth, rate and concurrency flags from config (confirm names with `katana -h`), and still filter every returned URL through the scope engine.
- GAU and waybackurls read historical archives, so they send no traffic to the target.
- `sitemap.xml` and `robots.txt` are fetched with `request()`. Disallowed paths are recorded as leads and are not fetched unless you pass `--probe-robots-paths`. Parse XML with `defusedxml` and limit sitemap nesting.
- Normalize every URL, drop fragments and tracking parameters, and use sorted query keys as the dedupe key, so `?b=1&a=2` equals `?a=2&b=1`. Cap URLs per host.
- Categorize with rules in `config/categories.yaml`: login, admin, api, upload, docs, graphql, static.
- Store parameter names only. Values that look like tokens are redacted.

**Test**

- `pytest tests/unit/test_urls.py`: saved Katana and GAU output fixtures, a table of categorization cases, the query-order dedupe case, scope filtering, robots and sitemap parsing, a nested sitemap limit.
- `pytest -m tools` on Kali: real Katana and GAU runs against the Docker lab.
- `pytest -m lab`: crawling Juice Shop finds routes you have listed in a fixture, for example `/rest/products/search` and `/ftp`. Check the list against your running instance.

**Gate:** parser tests pass, and the lab crawl finds the expected routes within the request budget.

### Step 17. JavaScript intelligence

**Build:** `modules/javascript.py`.

- Find script URLs in HTML and in crawl results. Fetch each in-scope file with `request()`. Third-party CDN scripts are denied by scope, but their library name and version are still read from the filename.
- Save a SHA-256 per file in `js_files`. If the hash is unchanged since the last scan, skip parsing. A changed hash becomes a monitoring signal.
- Extract with regular expressions: absolute and relative URLs, API routes, `fetch`, `axios` and XHR calls, GraphQL paths, WebSocket URLs, parameter names, internal hostnames and private IPs, and `sourceMappingURL` comments. Fetch a source map only with `--fetch-sourcemaps`.
- Secret candidates: match known token shapes (AWS key IDs, Google API keys, JWT format, private key headers, Slack token prefixes) and score by entropy. Store them with status `unverified`, a redacted preview (first four characters and the length), and never test or print them in full.
- Start with regular expressions. Add a real JavaScript parser only if measured false positives justify it.

**Test:** `pytest tests/unit/test_javascript.py`

- A labeled fixture of small JS files with a known list of expected endpoints. Write precision and recall to `tests/metrics/js_endpoints.json` on every run.
- Fake keys, such as the AWS documentation example, are flagged. Random hex strings are not.
- A test greps logs and reports and fails if any secret value appears unredacted.

**Gate:** secret candidates never appear in full anywhere, and precision on the fixture is recorded (aim for 0.9 or better to start).

### Step 18. Technology fingerprinting and API discovery

**Build:** `modules/fingerprint.py` and an API discovery routine.

- Fingerprinting reads responses already collected, so it adds zero requests. Rules live in `config/fingerprints/tech.yaml`: header patterns (`Server`, `X-Powered-By`), cookie names, `meta generator`, path patterns such as `/wp-content/`, and library banners. Each match records the technology, an optional version, the evidence and a confidence.
- WhatWeb is optional and off by default. If you enable it, use its lowest-noise level and check its request rate yourself.
- API discovery probes a short fixed list per live host: `/swagger.json`, `/openapi.json`, `/v3/api-docs`, `/api-docs`, `/swagger-ui/` and `/graphql`. Discard hits that match the host's soft-404 fingerprint.
- OpenAPI files (versions 2 and 3) are parsed into the `endpoints` table.
- GraphQL: detect the endpoint and record it as a lead. Introspection queries run only with `--graphql-introspection` and only if scope allows it.

**Test:** `pytest tests/unit/test_fingerprint.py tests/unit/test_openapi.py`

- Header and cookie fixtures produce the expected technologies and evidence.
- OpenAPI fixtures parse into the right endpoint count.
- Soft-404 pages are not reported as API docs.
- A GraphQL endpoint receives no POST unless introspection is enabled.

**Gate:** fingerprinting adds zero requests (compare `request_log` before and after), and API probes stay at 6 or fewer per host.

### Step 19. Takeover checks, diff and monitor mode

**Build**

- `config/fingerprints/takeover.yaml` lists provider CNAME suffixes and the response that indicates an unclaimed resource. Start from the community-maintained can-i-take-over-xyz list, and copy only entries you have checked. A candidate gets one read-only GET and a result of confirmed pattern, no match, or unclear. RECON-X never registers or claims anything. Doing that is a manual decision under the program's rules.
- `intelligence/history.py` compares two scans using `asset_snapshots` and reports new and removed assets, changed DNS records, changed status codes, new endpoints, changed technologies and changed JavaScript hashes.
- Commands: `recon-x diff RX-001 RX-002` and `recon-x monitor example.com --profile cautious`. Monitor runs passive discovery, verifies only new assets within a small budget, saves a snapshot, diffs against the last one, and sends alerts.
- Alerts go to Telegram, Discord or Slack through webhook URLs read from environment variables. Messages contain host names and URLs only, never secrets.
- Monitor is a normal command, not a service. Schedule it with cron or Task Scheduler:

```bash
# Kali cron, daily at 06:30
30 6 * * * cd ~/recon-x && .venv/bin/recon-x monitor example.com --profile cautious >> logs/monitor.log 2>&1
```

```powershell
schtasks /Create /SC DAILY /ST 06:30 /TN "reconx-monitor" /TR "C:\path\to\recon-x\.venv\Scripts\recon-x.exe monitor example.com --profile cautious"
```

WSL stops when idle, so cron inside WSL may not fire. For reliable monitoring use a VM, or have Windows Task Scheduler call `wsl -d kali-linux -- <command>`.

**Test**

- `pytest tests/unit/test_history.py`: two seeded snapshots produce the exact expected diff, table-driven.
- `pytest tests/unit/test_takeover.py`: vulnerable and normal response fixtures.
- `pytest tests/integration/test_monitor.py`: run monitor twice against the mock server, flip a route in between, and confirm exactly one new asset is alerted through a fake webhook route.

**Gate:** the monitor test passes, no alert text contains a secret, and a monitor run on an unchanged target sends no alert.

### Step 20. HTML report, exports, scope import, screenshots

**Build**

- `reporting/html_report.py` with Jinja2, producing one self-contained file with no external scripts. Turn on autoescape, because page titles and headers come from hostile servers.
- `recon-x export --scan-id RX-001 --type hosts|urls|burp-scope|nuclei-targets` for plain lists, a Burp scope file and a Nuclei target list. Check the Burp format against your Burp version.
- `scope import --format hackerone-csv` (and plain lists for Bugcrowd and Intigriti) from files you download from the program page. It imports targets only. You still read the rules yourself.
- Optional screenshots, installed as `pip install recon-x[screenshots]` with a headless browser. A browser fires many sub-requests, so intercept every one, check it against scope and budget, and abort anything out of scope. Screenshots are the one place a page's JavaScript runs, so they stay opt-in.

**Test**

- `pytest tests/unit/test_html_report.py`: a page title containing a `<script>` tag appears escaped in the report. This is the key security test for this step.
- Golden-file tests for exports, and JSON validity for the Burp file.
- A scope CSV fixture imports to the expected rules, and a malformed line is reported by number.
- Screenshot test (optional, `tools` marker): an out-of-scope sub-request is aborted.

**Gate (V1.5 release):** a full lab run on Juice Shop matches the expected route list, monitor detects an intentional change, and the HTML report opens with no external requests. Tag `v1.5`.

### Step 21. Security misconfiguration checks

**Build:** `modules/misconfiguration.py`. Findings are typed `observation`, never `vulnerability`.

- Headers, cookies and TLS are read from responses already collected, so they add no requests. Headers: HSTS (only judged on HTTPS), CSP, X-Frame-Options or `frame-ancestors`, X-Content-Type-Options, Referrer-Policy, Permissions-Policy. Cookies: Secure, HttpOnly, SameSite, domain, path, expiry (read every `Set-Cookie` header, not just the first). TLS: expiry, issuer, hostname match, protocol version.
- CORS: one extra request per host with `Origin: https://recon-x.invalid` (a reserved name that cannot belong to anyone). Record the allowed origin, credentials flag, methods and headers. A reflected arbitrary origin with credentials allowed becomes a high-priority lead. A wildcard without credentials is informational.
- Exposure candidates: a short fixed list in config, such as `/.git/HEAD`, `/.env`, `/server-status` and `/actuator/health`. Enable with `--checks exposure`. Read at most the first 512 bytes, confirm a signature (for example `/.git/HEAD` starts with `ref:`), and store only that a signature matched, not the content, because the content may hold secrets. A status code alone is never enough, and every hit is compared with the soft-404 fingerprint.
- Directory listing is detected from the `Index of /` page pattern.

**Test:** `pytest tests/unit/test_misconfiguration.py`

- A header fixture table: a missing HSTS on an HTTPS host gives an observation with wording "header missing". It does not give "vulnerable".
- Cookie fixtures with several `Set-Cookie` headers.
- A CORS case table: reflected origin with credentials gives a high lead, wildcard without credentials gives info, no header gives nothing.
- A host that returns 200 with an HTML page for `/.env` is not reported. A real signature is reported, with the content not stored.
- A certificate expiring within 30 days is flagged.

**Gate:** on 20 fixture hosts known to be clean, zero findings of type `vulnerability` appear, and every observation carries evidence.

### Step 22. Leads, priority scoring and the finding workflow

**Build:** `intelligence/correlation.py` and a findings command group.

- Leads come from rules, with weights in `config/scoring.yaml`: forgotten-looking names (dev, staging, uat, test, old, beta, preprod, admin), login, admin and upload endpoints, parameters that suggest redirects (`url`, `redirect`, `next`, `return`), file access (`file`, `path`, `template`), object IDs (`id`, `user_id`, `account`) or outbound fetches (`callback`, `webhook`, `uri`), exposed API docs and GraphQL, old technology versions, takeover candidates, CORS leads and secret candidates.
- Each lead carries a score, the reasons, links to evidence, and a suggested manual test class (for example "check redirect handling"). A lead is never called a vulnerability.
- `recon-x leads RX-001 --top 20` lists the highest-scoring leads.
- Finding lifecycle: `new`, then `confirmed`, `false_positive` or `duplicate`; `confirmed` then `reported`, then `fixed`. Invalid jumps (for example `fixed` back to `new`) are rejected. Commands: `findings list`, `findings set <id> --status confirmed --note "..."`, `notes add`.
- `report --finding F-12 --template hackerone` produces Markdown with Summary, Steps to Reproduce, Impact, Evidence and Remediation. Evidence is filled automatically. Steps and impact are left for you to write, and severity is never filled in for you.

**Test:** `pytest tests/unit/test_correlation.py tests/unit/test_findings.py`

- A table-driven scoring test, and a ranking test on a fixture of assets.
- Every lead has at least one reason and one evidence link.
- Invalid lifecycle transitions are rejected.
- The template renders with clear placeholders for the manual parts.

**Gate:** on the lab target, your fixture list of known interesting routes appears in the top 10 leads. Record each one's rank as a metric.

### Step 23. Vulnerability intelligence and Nuclei

**Build:** `modules/vulnerability_intel.py` and `integrations/nuclei.py`.

- A small mapping file, `config/cpe_map.yaml`, links technology names to CPE identifiers. Query the NVD API through `passive_get()` with its own limiter (the public limit is low without an API key, so read the current limit from NVD's documentation). Cache results in a new `cve_cache` table (migration `003`) with an expiry. Download the CISA Known Exploited Vulnerabilities catalog once a day and flag matching CVEs.
- Vulnerability confidence is its own scale, separate from asset confidence:

| Level | Meaning |
| --- | --- |
| Low | Version match only. Distributions often backport fixes without changing the version, so this is a lead |
| Medium | Version match plus a vendor advisory confirming the affected range |
| High | Confirmed by an approved non-destructive check |
| Verified | You reproduced it manually |

- Nuclei is off by default. It runs only when `rules.allow_nuclei` is true, against verified in-scope hosts, with rate and concurrency flags, an allow-list of template tags, and the intrusive, dos, fuzz and bruteforce tags excluded. Results enter `findings` with `source=nuclei` and at most medium confidence until you verify them. The template version is recorded in `tool_runs`. Confirm flag names with `nuclei -h`.

**Test:** `pytest tests/unit/test_vuln_intel.py tests/unit/test_nuclei_wrapper.py`

- Saved NVD and KEV responses parse correctly, and the cache respects its expiry.
- A version-only match is stored as low confidence.
- The Nuclei wrapper refuses to run when it is disabled, when the rate flag is missing, or when excluded tags appear in the configuration. A saved JSONL fixture parses.

**Gate:** no finding above low confidence comes from a version match alone, and Nuclei never runs unless explicitly enabled.

### Step 24. Ports, ASN pivots, passive indexes and authenticated crawling

**Build**

- `modules/ports.py` with Naabu and Nmap wrappers. Off by default. It runs only with `rules.allow_port_scan: true`, and skips any IP tagged CDN, WAF or shared cloud hosting. Scan each IP once, even when many hostnames point at it. Use a configurable port list, Naabu `-rate`, Nmap `--max-rate` with a slow timing template, service detection at low intensity, and no scripts by default. Store banners as evidence.
- ASN and RDAP pivots: from resolved IPs, record the ASN, organization and range in `asset_relationships`. These are suggestions only. They are never added to scope automatically, because scope is whatever the program lists.
- Passive Shodan and Censys lookups with keys from environment variables. Results are saved as passive observations labeled with their source and are not treated as verified.
- Authenticated crawling with `--auth-profile`. The profile lists the exact hosts it applies to, and the controller attaches credentials only to those hosts. Use test accounts you created within the program's rules. Credentials are read from environment variables or the keyring and redacted in logs.
- Cloud storage: record bucket references found in URLs and JavaScript. Guessing bucket names is off by default because those resources belong to third parties. Never list or read objects.

**Test**

- `pytest tests/unit/test_ports.py`: an Nmap XML fixture parses. The wrapper refuses when port scanning is disallowed or the IP is tagged CDN, and many hosts on one IP produce one scan.
- `pytest tests/unit/test_pivots.py`: saved RDAP and Shodan responses parse.
- `pytest tests/integration/test_auth_profile.py`: a mock route that echoes headers shows credentials sent only to the listed host, and the log shows them redacted.

**Gate (V2.0 release):** a full lab run completes, `audit` is clean, and the false-positive and request-per-asset metrics from section 13 are recorded. Tag `v2.0`.

## 13. Testing strategy

Most of the risk sits in the safety logic, so most tests run without a network. Each layer below adds more realism and needs more setup.

| Layer | What it proves | Needs | Runs on |
| --- | --- | --- | --- |
| Unit | Scope, limiter, normalizer, confidence and parser logic | Nothing | Windows, Kali, CI |
| Mock-server integration (`integration`) | Controller behavior under 429, 503, redirects, slow and huge responses | Local Python server | Windows, Kali, CI |
| Recorded fixtures | Wrappers parse real tool output | Saved files | Windows, Kali, CI |
| Tools (`tools`) | Wrappers pass rate flags to real binaries | Kali tools installed | Kali |
| Lab (`lab`) | The whole pipeline on a live app, plus false-positive and request metrics | Docker, `RECONX_LAB=1` | Kali |
| Real target | Behavior on real infrastructure | Written authorization | Kali, `cautious` profile |

**Recording fixtures**

Run a tool once against a domain you are authorized to test, save the output, and replace the real domain with `example.com` before committing:

```bash
subfinder -d YOUR-AUTHORIZED-DOMAIN -silent -oJ -o tests/fixtures/subfinder_sample.jsonl
sed -i 's/YOUR-AUTHORIZED-DOMAIN/example.com/g' tests/fixtures/subfinder_sample.jsonl
```

Never commit real target data. Whenever real use exposes a bug, add the failing input as a new fixture test before fixing it.

**Lab targets (Kali with Docker)**

Bind lab containers to localhost so nothing else on your network can reach them:

```bash
# OWASP Juice Shop on http://localhost:3000
docker run -d --name juiceshop -p 127.0.0.1:3000:3000 bkimminich/juice-shop

# OWASP WebGoat on http://localhost:8080/WebGoat
docker run -d --name webgoat -p 127.0.0.1:8080:8080 -p 127.0.0.1:9090:9090 webgoat/webgoat
```

crAPI runs as a multi-container stack. Follow the current steps in the OWASP crAPI README (it publishes a Docker Compose file; the web app is normally on port 8888). Stop labs with `docker stop <name>` when you finish.

**Lab scope file** (`config/scope.lab.yaml`)

```yaml
program: lab
authorized_by: "Local lab containers that I run myself"
in_scope:
  domains: [localhost]
  ips: [127.0.0.1]
  web_ports: [3000, 8080, 8888]
out_of_scope:
  domains: []
rules:
  allow_port_scan: false
  allow_nuclei: false
  max_requests: 300
```

Run the lab scan with `RECONX_LAB=1 pytest -m lab`, or by hand:

```bash
recon-x scan localhost:3000 --profile cautious --max-requests 300
recon-x audit RX-001
```

**Metrics to record after each release**

Measure each module separately, and do not claim 100% accuracy. The targets below are starting goals. Replace them with the baseline you measure.

| Metric | How to measure | Starting target |
| --- | --- | --- |
| Scope violations | `audit` over `request_log` | 0 |
| Rate-limit breaches | `audit` checks timestamps against the configured rate | 0 |
| Duplicate asset percentage | Duplicates after merge, on a fixture with known duplicates | 0% |
| Requests per asset | Total requests divided by verified assets | 3 or fewer for V1.0 |
| DNS verification success | Resolved assets divided by assets expected to resolve | Record baseline |
| HTTP verification success | Live responses divided by assets expected to be live | Record baseline |
| Endpoint extraction precision and recall | Output compared with a hand-labeled fixture | Precision 0.9 or better |
| False-positive rate | Findings you mark `false_positive` divided by all findings | Record baseline, then lower it |
| Subdomain coverage | Known subdomains found on a domain where you know the full list | Record baseline |
| Scan completion rate | Scans that finish or resume to completion divided by scans started | Record baseline |

**Benchmark against plain tools**

On one authorized target, run Subfinder plus ProjectDiscovery's HTTP prober by themselves, then RECON-X. Compare unique verified assets, duplicates, requests sent and time taken. This tells you honestly what RECON-X adds.

**Before any real-target scan**

- [ ] `pytest -m "not tools and not lab"` is green on both machines
- [ ] `recon-x doctor` shows no errors
- [ ] `scope.yaml` matches the program's current scope page
- [ ] Rate, headers and allowed checks match the program policy
- [ ] `scan --dry-run` output looks right
- [ ] First run uses `--max-requests 100`

## 14. Running RECON-X

This section is the day-to-day manual. Each command becomes available at the build step shown, so use it as a checklist while you build and as the user guide afterward.

**Command reference**

| Command | What it does | Built in step |
| --- | --- | --- |
| `recon-x init` | Creates folders, default config and the database | 6 |
| `recon-x scope add \| list \| import \| check` | Manages scope and explains any allow or deny decision | 6 |
| `recon-x config show` | Prints the active configuration with secrets hidden | 6 |
| `recon-x doctor` | Checks Python, dependencies, database and external tools | 6 |
| `recon-x passive example.com` | Passive discovery only, with no traffic to the target | 11 |
| `recon-x scan example.com --profile cautious` | Full pipeline: passive, DNS, HTTP | 15 |
| `recon-x status` and `recon-x results RX-001` | Lists scans and shows one scan's results | 6, 15 |
| `recon-x report --scan-id RX-001 --format json` | Writes a JSON, TXT, CSV or HTML report | 15, 20 |
| `recon-x resume RX-001` | Continues an interrupted or paused scan | 10 |
| `recon-x audit RX-001` | Verifies the log chain, scope decisions and request rate | 15 |
| `recon-x diff RX-001 RX-002` and `recon-x monitor example.com` | Compares scans, and watches a target for changes | 19 |
| `recon-x export --scan-id RX-001 --type burp-scope` | Exports lists and Burp or Nuclei target files | 20 |
| `recon-x leads RX-001 --top 20` | Shows ranked leads for manual testing | 22 |
| `recon-x findings list \| set` and `recon-x notes add` | Tracks each finding from new to fixed | 22 |

**Options on `scan`**

| Option | Effect |
| --- | --- |
| `--profile cautious \| normal \| program-custom` | Selects request limits |
| `--scope FILE` | Uses a scope file other than `config/scope.yaml` |
| `--rate N`, `--concurrency N` | Lowers limits. Raising them needs `--confirm-rate` |
| `--max-requests N` | Hard request budget for the scan |
| `--dry-run` | Prints planned tasks and estimated budget, sends nothing |
| `--checks exposure,cors` | Turns on the optional checks from step 21 |

**Exit codes** (useful for cron and scripts): `0` finished, `2` paused by rate limiting or errors, `3` budget used up, `4` scope or configuration error.

**Bug bounty workflow**

1. Read the program policy and complete the checklist in section 2. Save a dated copy of the policy.
2. Write `config/scope.yaml` from the program's scope page, or import a downloaded scope file with `scope import`.
3. Test the scope with `recon-x scope check` on two hosts that must be allowed and two that must be denied.
4. Set the program name, User-Agent, extra headers and rate in `settings.yaml`.
5. Run `recon-x passive example.com` and review what it found.
6. Run `recon-x scan example.com --profile cautious --dry-run` and read the plan.
7. Run the first real scan with `--max-requests 100`. Then run `recon-x status` and `recon-x audit RX-001`.
8. Raise the budget in steps (500, then 1,000) only as far as the program allows.
9. Open `recon-x leads RX-001 --top 20` and review the reasons for each lead.
10. Export a Burp scope file with `export --type burp-scope` and test the top leads manually in Burp or Caido. Recon points you at targets. The testing is yours.
11. Record what you find with `findings set` and `notes add`. Search the program's disclosed reports for duplicates before you spend hours on one.
12. Write the report from the template, fill in the steps and impact yourself, and attach the stored evidence.
13. Schedule `monitor` daily and read its diffs first. New assets are where fewer hunters have looked.

**A first session, start to finish**

```bash
recon-x init
recon-x scope add example.com
recon-x scope check a.example.com        # expect ALLOWED
recon-x scope check evil.com             # expect DENIED
recon-x passive example.com
recon-x scan example.com --profile cautious --dry-run
recon-x scan example.com --profile cautious --max-requests 100
recon-x audit RX-001
recon-x report --scan-id RX-001 --format html
```

**If a scan pauses**

A pause means the target returned repeated 429 or 503 responses or several errors in a row. Do not override it. Check the program's allowed rate, lower the rate if needed, wait, and run `recon-x resume RX-001`. If the pauses continue, stop and ask the program's contact.

**Reading confidence levels**

| Asset level | Meaning | What to do |
| --- | --- | --- |
| Low | One passive source only | Ignore until verified |
| Medium | Two or more independent sources | Worth checking |
| High | DNS resolves | Real hostname, may not serve a website |
| Verified | Live HTTP response with stored evidence | Safe to test, if in scope |

Vulnerability confidence is a separate scale (section 12, step 23). A verified asset says nothing about whether it is vulnerable.

**Where files go**

- Database: `data/reconx.db`
- Reports: `reports/RX-001/`
- Logs: `logs/reconx.log` (secrets redacted)
- Scope and settings: `config/`

## 15. Features added to the original design

Your original design covers scope, request control, accuracy and reporting well. These additions close the gaps that matter most for winning bug bounty reports and for passing a client's review. Each one is already placed in the build plan.

**Safety and scope**

| Addition | Why it matters | Step |
| --- | --- | --- |
| Strict edge-case tests for host and URL parsing | Scope bugs are the most dangerous bugs in the tool | 3, 4 |
| Scope re-check after DNS resolution and after every redirect | A name inside scope can point to a third party | 4, 8, 13 |
| Default deny for loopback, link-local and private ranges | Stops requests to cloud metadata or internal hosts | 4 |
| Tamper-evident request log and the `audit` command | Proof of staying in scope and under the rate limit | 5, 15 |
| Program User-Agent, custom headers and proxy support | Many programs require them. A proxy lets you follow up in Burp | 2, 8 |
| CDN and WAF tagging, with port scans skipped | Scanning shared IPs hits other companies | 14, 24 |
| Safe handling of hostile servers: response caps, decompression limits, no JavaScript execution, escaped reports | Targets can send hostile data to your tool | 8, 17, 20 |
| Secret redaction in logs, reports and alerts | Candidate secrets must never leak further | 5, 17 |

**Discovery and accuracy**

| Addition | Why it matters | Step |
| --- | --- | --- |
| Wildcard DNS and soft-404 detection | Removes the largest source of fake assets and endpoints | 13, 14 |
| Response clustering by body hash and title | 500 identical login pages become one item to review | 14 |
| Takeover verification with a fingerprint list | Turns a dangling CNAME into a checked lead | 19 |
| ASN and RDAP pivots, Shodan and Censys passive lookups | Finds related infrastructure without touching the target | 24 |
| OpenAPI and GraphQL parsing into an endpoint inventory | Gives you a testable API map | 18 |
| JavaScript hashing and source map detection | Changed JavaScript often means a new feature to test | 17 |
| Authenticated crawling | Much of the attack surface sits behind login | 24 |
| Optional screenshots | Fastest way to triage hundreds of hosts visually | 20 |
| Virtual host awareness | Always request by hostname, and key port data by IP | 14, 24 |

**Bug bounty workflow**

| Addition | Why it matters | Step |
| --- | --- | --- |
| `monitor` and `diff` with alerts | Finding new assets first means fewer duplicate reports | 19 |
| Leads with priority scores and reasons | You test the best 20 assets first | 22 |
| Finding lifecycle and notes | Tracks what you have confirmed, reported and had marked duplicate | 22 |
| Report templates | Submission-ready layout with evidence filled in | 22 |
| Burp scope, host list and Nuclei target exports | Moves recon output into your testing tools | 20 |
| Platform scope import | Removes typing mistakes when copying scope | 20 |

**Design fixes**

| Change | Reason | Step |
| --- | --- | --- |
| Scan profiles instead of one fixed rate | One request per second with a budget of 100 is too tight for a real scan, and too loose for some programs | 2 |
| Separate limiters for passive sources and target traffic | Passive sources call third-party APIs, not the target | 8 |
| Async token bucket with an injected clock | Makes rate limits testable and avoids a rewrite later | 7 |
| Rate flags enforced on external tools | A Python limiter cannot slow down subprocesses | 11 |
| Concrete confidence rules | Scores need written criteria to be reproducible | 12 |
| Extra tables and commands | Support history, audit, JavaScript and findings | 5, 6 |
| Added dependencies `idna` and `defusedxml` | Correct internationalized names and safe XML parsing | 3, 16 |

**Ideas left out of the plan on purpose**

- A web dashboard. The design is CLI-only, and that keeps it light.
- DNS brute forcing and hidden-parameter fuzzing. They are active and intrusive, so add them only as opt-in modules with their own rate limits.
- Mobile app endpoint extraction from APK files. Valuable for programs with mobile scope, and a good candidate after V2.0.
- Public GitHub leak search for the target organization. It is passive and useful, and could be added as a module after V2.0.
- A plugin system for community modules, once the module interface has settled.

## 16. Troubleshooting, FAQ and checklists

**Troubleshooting**

| Problem | Likely cause | Fix |
| --- | --- | --- |
| `recon-x` command not found | Virtual environment not active, or project not installed | Activate `.venv`, then run `pip install -e .` |
| PowerShell refuses to run `Activate.ps1` | Execution policy | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| `subfinder: command not found` | Go bin folder not on PATH | Add `$(go env GOPATH)/bin` to PATH in `~/.zshrc` |
| `go install` says your Go version is too old | Kali's packaged Go is older than the tool needs | Install the current Go from go.dev |
| Two different `httpx` programs on Kali | Kali names ProjectDiscovery's tool `httpx-toolkit` | RECON-X uses only the Python library. Run `recon-x doctor` to see which is on PATH |
| Docker: cannot connect to the daemon in WSL | systemd not enabled or service not started | Enable systemd in `/etc/wsl.conf`, run `wsl --shutdown`, then `sudo systemctl start docker`. Add your user to the `docker` group and log in again |
| Repo is slow or file permissions look odd in WSL | Repo lives under `/mnt/c` | Clone it under `~` in the Linux filesystem |
| Tests pass on Kali but fail on Windows | Path separators or line endings in golden files | Use `pathlib`, and add a `.gitattributes` file with `* text=auto` |
| `pytest` runs lab or tools tests and fails | Markers not filtered | Run `pytest -m "not tools and not lab"` |
| Everything is denied by scope | Missing scope file, or a wildcard rule that does not cover the apex domain | Run `recon-x scope check <target>`. The reason is printed |
| Lab target on `localhost` is denied | Loopback is denied unless listed | Add `ips: [127.0.0.1]` to the lab scope file |
| Scan pauses right away | 429 or 503 responses, or repeated errors | Read `scan_events`, lower `--rate`, check the program's limit, then `resume` |
| Hundreds of fake subdomains | Wildcard DNS | They are flagged `wildcard_match` and held at low confidence |
| Ctrl+C seems to lose the last result | Pressing it repeatedly forces an exit | Press it once and wait for the current request to finish |
| `database is locked` | Two processes writing at once | Run one scan per database file at a time |
| Nmap scans fail or hang in WSL2 | Raw-socket limits | Use TCP connect scans, or use a Kali VM |

**FAQ**

*Can I use RECON-X on a site that has no bug bounty program?* Only with written permission from the owner. The tool enforces the scope you give it, but it cannot know whether you are authorized.

*Why only one request per second?* It is a safe starting point. Raise it only to what the program's policy allows, using `program-custom`.

*Will it find vulnerabilities by itself?* It finds and ranks attack surface and reports observations such as missing headers. Version matches and Nuclei results are leads until you verify them. Confirming a vulnerability is manual work.

*Can I run it from a VPS?* Yes, but check whether the program restricts source IP addresses, and keep the same limits.

**Setup checklist**

- [ ] Windows: Python 3.11 or newer, Git, VS Code, virtual environment, `pip install -r requirements-dev.txt` succeeds
- [ ] Kali: WSL2 or VM running, Go tools installed and on PATH, Docker works
- [ ] Repository created, private remote added, CI green on Windows and Ubuntu
- [ ] Juice Shop running on `localhost:3000`
- [ ] `recon-x doctor` shows no errors on both machines

**Release checklist (every version)**

- [ ] All unit and mock-server tests pass on Windows, Kali and CI
- [ ] No-bypass guard test passes
- [ ] `audit` shows zero scope violations and zero rate breaches on the lab run
- [ ] Metrics from section 13 recorded
- [ ] README and this guide updated
- [ ] Version tag created

**Verification note and references**

The install commands and tool flags in this guide come from my general knowledge of each tool and were not checked against live documentation while writing. Tool options change between releases, so confirm each flag with the tool's `-h` output and its project page before relying on it:

- [Subfinder](https://github.com/projectdiscovery/subfinder), [Katana](https://github.com/projectdiscovery/katana), [Naabu](https://github.com/projectdiscovery/naabu), [Nuclei](https://github.com/projectdiscovery/nuclei)
- [GAU](https://github.com/lc/gau) and [waybackurls](https://github.com/tomnomnom/waybackurls)
- [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) and [OWASP crAPI](https://github.com/OWASP/crAPI)
- [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) for takeover fingerprints
