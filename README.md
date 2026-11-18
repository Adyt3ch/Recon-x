# RECON-X

RECON-X is a lightweight, CLI-only, modular reconnaissance framework designed for authorized bug bounty and VAPT work.

## Core Principles

- **Single Gateway**: All active network requests flow strictly through a central request controller (`reconx/core/request_manager.py`).
- **Default-Deny Scope**: Scopes are enforced per request and re-checked on DNS resolution and redirects. Exclusions always override inclusions.
- **Strict Traffic Control**: Automatic rate limiting, delays, backoff, and budgets protect target infrastructure.
- **Evidence-Backed Tracking**: Every asset, DNS record, service, and observation is persisted with cryptographic audit trails.
- **Non-Destructive & Safe**: Observation-only leads, no exploitation, no brute forcing, and automatic secret redaction.

## Installation

```bash
# Clone the repository
git clone <repo-url> recon-x
cd recon-x

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\Activate.ps1

# Install dependencies and editable package
pip install -r requirements-dev.txt
pip install -e .
```

## Quick Start

```bash
recon-x init
recon-x scope add example.com
recon-x scope check a.example.com
recon-x doctor
recon-x scan example.com --profile cautious --dry-run
```
