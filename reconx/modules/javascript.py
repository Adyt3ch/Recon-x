"""JavaScript intelligence analysis: script extraction, route discovery, and secret scanning."""

from __future__ import annotations

import hashlib
import math
import re
import urllib.parse
from typing import Any

from bs4 import BeautifulSoup

from reconx.core.engine import ScanContext
from reconx.core.scheduler import Task
from reconx.database.storage import (
    insert_endpoint,
    insert_scan_event,
    insert_secret_candidate,
    upsert_js_file,
    upsert_technology,
    utc_now_iso,
)

# CDN library filename patterns (e.g. jquery-3.6.0.min.js)
CDN_LIB_PATTERNS = [
    (re.compile(r"jquery[-.]([0-9.]+)(?:\.min)?\.js", re.I), "jQuery", "javascript_library"),
    (re.compile(r"bootstrap[-.]([0-9.]+)(?:\.min)?\.js", re.I), "Bootstrap", "ui_library"),
    (re.compile(r"react[-.]([0-9.]+)(?:\.min)?\.js", re.I), "React", "javascript_framework"),
    (re.compile(r"vue[-.]([0-9.]+)(?:\.min)?\.js", re.I), "Vue.js", "javascript_framework"),
    (re.compile(r"angular[-.]([0-9.]+)(?:\.min)?\.js", re.I), "AngularJS", "javascript_framework"),
    (re.compile(r"lodash[-.]([0-9.]+)(?:\.min)?\.js", re.I), "Lodash", "javascript_library"),
    (re.compile(r"axios[-.]([0-9.]+)(?:\.min)?\.js", re.I), "Axios", "javascript_library"),
]

# Known secret patterns
SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
    ("Google API Key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{30,40})\b")),
    ("GitHub Token", re.compile(r"\b(ghp_[a-zA-Z0-9]{36})\b")),
    ("Slack Token", re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b")),
    ("Private Key", re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)")),
    ("JWT", re.compile(r"\b(eyJ[A-Za-z0-9-_]{10,}\.eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,})\b")),
]

# API route and call patterns
ROUTE_REGEX = re.compile(r"""['"`](/(?:api|v[0-9]+|rest|graphql|admin|auth|users?|login)[a-zA-Z0-9_/.-]*)['"`]""")
CALL_REGEX = re.compile(r"""(?:fetch|axios(?:\.get|\.post)?|\$\.(?:ajax|get|post))\s*\(\s*['"`]([^'"`\s)]+)['"`]""")
WEBSOCKET_REGEX = re.compile(r"""(?:ws|wss)://[^\s'"`]+""")
INTERNAL_IP_REGEX = re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b")
INTERNAL_HOST_REGEX = re.compile(r"\b[a-zA-Z0-9.-]+\.(?:internal|local|corp|lan)\b")
SOURCEMAP_REGEX = re.compile(r"//# sourceMappingURL=(\S+)")


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += -p_x * math.log2(p_x)
    return round(entropy, 3)


def redact_secret_preview(secret: str) -> str:
    """Redact secret value, showing only first 4 characters and overall length."""
    length = len(secret)
    prefix = secret[:4] if length >= 4 else secret
    return f"{prefix}... (length {length})"


def find_script_urls(html: str, base_url: str) -> list[str]:
    """Extract <script src="..."> URLs from HTML content."""
    soup = BeautifulSoup(html, "html.parser")
    urls: list[str] = []
    seen: set[str] = set()

    for script in soup.find_all("script", src=True):
        src = script.get("src", "").strip()
        if src:
            full_url = urllib.parse.urljoin(base_url, src)
            if full_url not in seen:
                seen.add(full_url)
                urls.append(full_url)
    return urls


def extract_cdn_library(url: str) -> tuple[str, str | None, str] | None:
    """Detect third-party library name and version from script URL.

    Returns (name, version, category) or None.
    """
    path = urllib.parse.urlsplit(url).path
    filename = path.split("/")[-1]

    # 1. Match filename directly
    for pattern, name, cat in CDN_LIB_PATTERNS:
        match = pattern.search(filename)
        if match:
            version = match.group(1) if match.groups() else None
            return name, version, cat

    # 2. Check if library name and version are in URL path structure (e.g. cdnjs: /react/17.0.2/...)
    for _, name, cat in CDN_LIB_PATTERNS:
        path_match = re.search(rf"/{re.escape(name.lower())}/([0-9.]+)/", path, re.I)
        if path_match:
            return name, path_match.group(1), cat
        if re.search(rf"/{re.escape(name.lower())}[/.]", path, re.I):
            ver_match = re.search(r"/([0-9]+\.[0-9]+(?:\.[0-9]+)?)/", path)
            version = ver_match.group(1) if ver_match else None
            return name, version, cat

    return None


def extract_endpoints_from_js(js_code: str) -> list[str]:
    """Extract API routes, endpoints, and calls from JavaScript source."""
    endpoints: set[str] = set()

    # 1. Quoted routes
    for match in ROUTE_REGEX.finditer(js_code):
        route = match.group(1).strip()
        if route and not route.endswith((".js", ".css", ".png", ".jpg")):
            endpoints.add(route)

    # 2. Function calls (fetch, axios, etc.)
    for match in CALL_REGEX.finditer(js_code):
        target = match.group(1).strip()
        if target.startswith("/"):
            endpoints.add(target)

    # 3. WebSockets
    for match in WEBSOCKET_REGEX.finditer(js_code):
        endpoints.add(match.group(0).strip())

    return sorted(endpoints)


def extract_secrets_from_js(js_code: str) -> list[tuple[str, str, float]]:
    """Scan JS for secret tokens. Returns (pattern_name, redacted_preview, entropy)."""
    candidates: list[tuple[str, str, float]] = []

    for pattern_name, regex in SECRET_PATTERNS:
        for match in regex.finditer(js_code):
            val = match.group(1).strip()
            entropy = shannon_entropy(val)
            # Private keys don't require entropy threshold; tokens require entropy >= 3.0
            if "Private Key" in pattern_name or entropy >= 3.0:
                preview = redact_secret_preview(val)
                candidates.append((pattern_name, preview, entropy))

    return candidates


class JavascriptModule:
    """Module for JavaScript intelligence: endpoint extraction and secret scanning."""

    name = "javascript"

    def plan(self, ctx: ScanContext) -> list[Task]:
        """Plan JS extraction tasks for verified assets having live services."""
        cursor = ctx.db.execute(
            """
            SELECT DISTINCT h.url
            FROM http_services h
            JOIN assets a ON h.asset_id = a.id
            WHERE a.program = ? AND a.confidence = 'verified'
            """,
            (ctx.program,),
        )
        live_urls = [row[0] for row in cursor.fetchall()]
        return [
            Task(scan_id=ctx.scan_id, module=self.name, target=u, estimated_requests=3)
            for u in live_urls
        ]

    async def run(self, ctx: ScanContext, task: Task) -> dict[str, Any]:
        """Discover and analyze JavaScript files for target page URL."""
        page_url = task.target
        parsed_page = urllib.parse.urlsplit(page_url)
        hostname = parsed_page.netloc.split(":")[0]

        cursor = ctx.db.execute(
            "SELECT id FROM assets WHERE program = ? AND hostname = ?",
            (ctx.program, hostname),
        )
        asset_row = cursor.fetchone()
        asset_id = asset_row["id"] if asset_row else None
        if not asset_id:
            return {"endpoints_found": 0, "secrets_found": 0}

        # 1. Fetch page to discover <script src="...">
        script_urls: list[str] = []
        try:
            resp = await ctx.requests.request("GET", page_url, module=self.name, purpose="find_scripts")
            if resp.status_code == 200 and resp.text:
                script_urls = find_script_urls(resp.text, page_url)
        except Exception as e:
            insert_scan_event(ctx.db, ctx.scan_id, "DEBUG", f"Failed fetching {page_url} for scripts: {e}")
            return {"endpoints_found": 0, "secrets_found": 0}

        endpoints_found = 0
        secrets_found = 0

        # 2. Process each discovered script URL
        for s_url in script_urls:
            # Scope check on script URL
            scope_decision = ctx.scope.check_url(s_url)
            if not scope_decision.allowed:
                # Third-party script: extract CDN library and version without fetching
                cdn_info = extract_cdn_library(s_url)
                if cdn_info:
                    lib_name, lib_ver, lib_cat = cdn_info
                    upsert_technology(
                        db=ctx.db,
                        asset_id=asset_id,
                        name=lib_name,
                        version=lib_ver,
                        category=lib_cat,
                        evidence=f"Detected from CDN script URL: {s_url}",
                    )
                continue

            # In-scope script: fetch and analyze
            try:
                js_resp = await ctx.requests.request("GET", s_url, module=self.name, purpose="analyze_js")
                if js_resp.status_code != 200 or not js_resp.content:
                    continue

                js_content = js_resp.text
                js_hash = hashlib.sha256(js_resp.content).hexdigest()
                size = len(js_resp.content)

                # Upsert js_files and check if changed
                js_file_id, is_new_or_changed = upsert_js_file(ctx.db, s_url, js_hash, size)
                if not is_new_or_changed:
                    # File unchanged since last scan; skip re-parsing
                    continue

                # 3. Extract endpoints
                routes = extract_endpoints_from_js(js_content)
                for route in routes:
                    insert_endpoint(
                        db=ctx.db,
                        url_id=None,
                        method="GET",
                        path=route,
                        parameters=None,
                        js_file_id=js_file_id,
                    )
                    endpoints_found += 1

                # 4. Extract secret candidates (stored as unverified with redacted preview)
                candidates = extract_secrets_from_js(js_content)
                for pattern_name, preview_redacted, entropy in candidates:
                    insert_secret_candidate(
                        db=ctx.db,
                        js_file_id=js_file_id,
                        pattern=pattern_name,
                        preview_redacted=preview_redacted,
                        entropy=entropy,
                    )
                    secrets_found += 1
                    # Record observation finding
                    finding_id = f"F-SECRET-{abs(hash((s_url, pattern_name, preview_redacted))) % 100000:05d}"
                    ctx.db.execute(
                        """
                        INSERT INTO findings (
                            id, scan_id, asset_id, type, title, severity_hint,
                            confidence, status, notes, created_at
                        ) VALUES (?, ?, ?, 'observation', ?, 'medium', 'low', 'new', ?, ?)
                        ON CONFLICT(id) DO NOTHING
                        """,
                        (
                            finding_id,
                            ctx.scan_id,
                            asset_id,
                            f"Unverified secret candidate: {pattern_name}",
                            f"Discovered in {s_url}: {preview_redacted}",
                            utc_now_iso(),
                        ),
                    )
                    ctx.db.commit()

            except Exception as e:
                insert_scan_event(ctx.db, ctx.scan_id, "DEBUG", f"Error analyzing script {s_url}: {e}")

        return {"endpoints_found": endpoints_found, "secrets_found": secrets_found}
