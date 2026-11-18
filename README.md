# RECON-X

A lightweight, CLI-only, modular attack surface reconnaissance framework built for authorized bug bounty programs and penetration testing engagements.

RECON-X enforces strict default-deny scope validation, tamper-evident cryptographic request logging, automated rate limiting, and non-destructive heuristic intelligence gathering.

---

## Key Highlights

- **Unified Network Gateway**: Every outbound HTTP/HTTPS request flows through a centralized manager (`reconx/core/request_manager.py`). Bypasses are prevented via architectural AST lint guards.
- **Strict Scope Engine**: Validates every host, IP, CIDR, redirect target, and resolved DNS address against policy rules. Out-of-scope requests are blocked before hitting the network.
- **Tamper-Evident Audit Trail**: Outbound requests are recorded in SQLite using a continuous SHA-256 hash chain verified via `recon-x audit`.
- **Adaptive Rate Limiting**: Token-bucket rate limiter with automatic exponential backoff on HTTP `429` / `503` responses.
- **Heuristic Surface Ranking**: Highlights interesting endpoints, parameters, exposed configurations, and potential takeover candidates without making destructive payloads.
- **Multi-Format Reporting**: Generates standalone HTML dashboards, JSON data exports, CSV tables, and HackerOne submission templates.

---

## Installation

### Prerequisites
- Python 3.11 or higher
- Optional external tools: `subfinder`, `katana`, `nuclei`, `nmap`

### Setup

```bash
# Clone the repository
git clone https://github.com/Adyt3ch/Recon-x.git
cd Recon-x

# Create and activate virtual environment
python -m venv .venv

# On Linux / macOS:
source .venv/bin/activate

# On Windows PowerShell:
.\.venv\Scripts\Activate.ps1

# Install package and dependencies
pip install -r requirements-dev.txt
pip install -e .
```

Verify your environment setup:
```bash
recon-x doctor
```

---

## Quick Start Guide

```bash
# 1. Initialize configuration and SQLite database
recon-x init

# 2. Add authorized target domain to scope
recon-x scope add example.com

# 3. Check scope enforcement
recon-x scope check sub.example.com     # ALLOWED
recon-x scope check untrusted.com       # DENIED

# 4. Perform passive discovery (no packets sent to target)
recon-x passive example.com

# 5. Review planned requests with a dry run
recon-x scan example.com --dry-run

# 6. Execute bounded active reconnaissance
recon-x scan example.com --profile cautious --max-requests 100

# 7. Review ranked attack surface leads
recon-x leads RX-001 --top 20

# 8. Verify audit log integrity
recon-x audit RX-001

# 9. Generate reports
recon-x report --scan-id RX-001 --format html
recon-x report --scan-id RX-001 --format json
```

---

## CLI Command Reference

### Core Reconnaissance Commands

#### `recon-x init`
Initializes configuration files (`config/settings.yaml`, `config/scope.yaml`), storage directories, and SQLite database (`data/reconx.db`).

#### `recon-x doctor`
Validates Python runtime, required packages, local database schema, and external reconnaissance utilities found on `PATH`.

#### `recon-x status`
Lists all historical and current scans with execution status, target program, profile, and budget usage.

#### `recon-x passive <target>`
Executes passive subdomain gathering (e.g. Certificate Transparency via crt.sh and passive sources) with zero traffic dispatched to the target.

#### `recon-x scan <target> [OPTIONS]`
Executes the multi-stage active reconnaissance pipeline:
- Passive collection & subdomain deduplication
- DNS resolution, wildcard detection, and takeover verification
- HTTP service discovery, TLS details, and server fingerprinting
- Web endpoint extraction, robots/sitemap parsing, and JS endpoint discovery
- Security misconfiguration checks (CORS, security headers, tech profiling)

**Options:**
- `--profile, -p`: Rate profile (`cautious`, `normal`, `program-custom`). Default: `cautious`.
- `--scope, -s`: Path to scope configuration file. Default: `config/scope.yaml`.
- `--settings`: Path to settings configuration file. Default: `config/settings.yaml`.
- `--max-requests, -m`: Maximum request budget limit.
- `--rate, -r`: Override request rate (requests/sec).
- `--concurrency, -c`: Concurrent worker threads.
- `--confirm-rate`: Required when increasing rate limits above cautious defaults.
- `--dry-run`: Simulates tasks and calculates estimated budget without sending network traffic.

#### `recon-x resume <scan_id>`
Resumes an interrupted or paused scan from its last recorded checkpoint.

#### `recon-x results <scan_id>`
Displays verified assets, open services, endpoints, and observations for a scan.

#### `recon-x diff <scan_id_1> <scan_id_2>`
Calculates structural differences between two scans, highlighting new subdomains, removed assets, changed IP addresses, and newly identified endpoints.

#### `recon-x monitor <target>`
Executes periodic monitoring scans against a target, checks for newly exposed assets, and outputs alert diffs.

#### `recon-x leads <scan_id> [--top N]`
Applies heuristic priority scoring across discovered assets, flagging high-interest testing targets (auth panels, dev environments, parameter patterns, potential takeovers).

---

### Scope Management (`recon-x scope ...`)

- **`recon-x scope check <target>`**: Tests a domain, IP, or URL against scope rules and displays the allow/deny decision with the matching rule.
- **`recon-x scope add <target>`**: Appends a domain, IP, or CIDR to `in_scope` in `config/scope.yaml`.
- **`recon-x scope list`**: Displays loaded in-scope definitions, exclusions, and allowed web ports.
- **`recon-x scope import <filepath> --format (txt|csv|yaml|hackerone)`**: Imports structured scope targets with line-by-line syntax validation.

---

### Triage & Finding Lifecycle (`recon-x findings ...` / `recon-x notes ...`)

Tracks observations through a formal state machine:
`new` $\rightarrow$ `confirmed` | `false_positive` | `duplicate` $\rightarrow$ `reported` $\rightarrow$ `fixed`

- **`recon-x findings list [--scan-id ID]`**: Displays recorded findings and their triage status.
- **`recon-x findings set <finding_id> --status <status> [--note <text>]`**: Advances finding state while enforcing valid transitions.
- **`recon-x notes add <finding_id> "<text>"`**: Attaches analyst observation notes to findings or assets.

---

### Reporting & Tool Exports

#### `recon-x report`
Exports consolidated scan findings into standard file formats:
```bash
# Standalone offline HTML dashboard (zero external JS/CSS dependencies)
recon-x report --scan-id RX-001 --format html

# Structured JSON report
recon-x report --scan-id RX-001 --format json

# Tabular CSV export
recon-x report --scan-id RX-001 --format csv

# Bug bounty markdown report template pre-populated with evidence
recon-x report --scan-id RX-001 --finding F-001 --template hackerone
```

#### `recon-x export`
Generates target lists tailored for external testing suites:
```bash
# Burp Suite target scope JSON
recon-x export --scan-id RX-001 --type burp-scope --out burp_scope.json

# Plain lists of verified hostnames or URLs
recon-x export --scan-id RX-001 --type hosts --out hosts.txt
recon-x export --scan-id RX-001 --type urls --out urls.txt

# Target file for Nuclei
recon-x export --scan-id RX-001 --type nuclei-targets --out nuclei_targets.txt
```

---

### Audit & Quality Verification

#### `recon-x audit <scan_id>`
Verifies the tamper-evident SHA-256 hash chain of the request log, ensuring no records have been altered, zero out-of-scope requests were sent, and rate bounds were honored.

#### `recon-x metrics <scan_id>`
Computes Section 13 Quality Assurance benchmarks:
- Scope violations over the wire (Target: 0)
- Rate-limit breaches (Target: 0)
- Duplicate asset percentage (Target: 0.0%)
- Requests sent per verified asset (Target: $\le 3.0$)
- False-positive ratio tracking

#### `recon-x config show`
Prints active runtime settings, limits, and user-agent strings with sensitive API keys masked.

---

## Testing

Run the test suite:
```bash
# Run unit and mock integration tests
pytest -m "not tools and not lab"

# Code style and lint check
ruff check .
```

---

## Ethical Use & Legal Disclaimer

RECON-X is designed strictly for authorized security assessments, penetration testing, and legitimate bug bounty research. Users must obtain written permission from target owners before initiating active network requests. The authors assume no liability for misuse.
