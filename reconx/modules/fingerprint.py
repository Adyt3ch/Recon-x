"""Technology fingerprinting and API discovery module."""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
from pathlib import Path
from typing import Any

import yaml
from bs4 import BeautifulSoup

from reconx.core.engine import ScanContext
from reconx.core.scheduler import Task
from reconx.database.storage import (
    insert_endpoint,
    insert_scan_event,
    upsert_technology,
    utc_now_iso,
)

DEFAULT_TECH_RULES = [
    {"name": "Nginx", "category": "web_server", "type": "header", "header": "server", "pattern": r"(?i)nginx(?:/([0-9.]+))?", "version_group": 1, "confidence": "high"},
    {"name": "Apache", "category": "web_server", "type": "header", "header": "server", "pattern": r"(?i)apache(?:/([0-9.]+))?", "version_group": 1, "confidence": "high"},
    {"name": "Microsoft-IIS", "category": "web_server", "type": "header", "header": "server", "pattern": r"(?i)microsoft-iis(?:/([0-9.]+))?", "version_group": 1, "confidence": "high"},
    {"name": "Cloudflare", "category": "cdn", "type": "header", "header": "server", "pattern": r"(?i)cloudflare", "confidence": "high"},
    {"name": "PHP", "category": "programming_language", "type": "header", "header": "x-powered-by", "pattern": r"(?i)php(?:/([0-9.]+))?", "version_group": 1, "confidence": "high"},
    {"name": "ASP.NET", "category": "web_framework", "type": "header", "header": "x-powered-by", "pattern": r"(?i)asp\.net", "confidence": "high"},
    {"name": "Express", "category": "web_framework", "type": "header", "header": "x-powered-by", "pattern": r"(?i)express", "confidence": "high"},
    {"name": "PHP", "category": "programming_language", "type": "cookie", "pattern": r"(?i)phpsessid", "confidence": "medium"},
    {"name": "Java", "category": "programming_language", "type": "cookie", "pattern": r"(?i)jsessionid", "confidence": "medium"},
    {"name": "Django", "category": "web_framework", "type": "cookie", "pattern": r"(?i)csrftoken|sessionid", "confidence": "medium"},
    {"name": "WordPress", "category": "cms", "type": "meta_generator", "pattern": r"(?i)wordpress(?: ([0-9.]+))?", "version_group": 1, "confidence": "high"},
    {"name": "Drupal", "category": "cms", "type": "meta_generator", "pattern": r"(?i)drupal(?: ([0-9.]+))?", "version_group": 1, "confidence": "high"},
    {"name": "WordPress", "category": "cms", "type": "body", "pattern": r"/wp-content/|/wp-includes/", "confidence": "high"},
    {"name": "React", "category": "javascript_framework", "type": "body", "pattern": r"data-reactroot|react-dom", "confidence": "medium"},
    {"name": "Vue.js", "category": "javascript_framework", "type": "body", "pattern": r"data-v-[a-f0-9]{8}|vue\.runtime", "confidence": "medium"},
]

API_PROBE_PATHS = [
    "/swagger.json",
    "/openapi.json",
    "/v3/api-docs",
    "/api-docs",
    "/swagger-ui/",
    "/graphql",
]


def parse_openapi_spec(spec_text: str) -> list[tuple[str, str, list[str]]]:
    """Parse OpenAPI v2/v3 specification (JSON or YAML).

    Returns list of (method, path, parameter_names).
    """
    try:
        try:
            data = json.loads(spec_text)
        except json.JSONDecodeError:
            data = yaml.safe_load(spec_text)

        if not isinstance(data, dict):
            return []

        paths_dict = data.get("paths", {})
        if not isinstance(paths_dict, dict):
            return []

        endpoints: list[tuple[str, str, list[str]]] = []
        for path_key, path_item in paths_dict.items():
            if not isinstance(path_item, dict):
                continue

            for method_key, method_item in path_item.items():
                if method_key.lower() in ("get", "post", "put", "delete", "patch", "options", "head"):
                    params: list[str] = []
                    if isinstance(method_item, dict):
                        # Extract parameter names
                        param_list = method_item.get("parameters", [])
                        if isinstance(param_list, list):
                            for p in param_list:
                                if isinstance(p, dict) and "name" in p:
                                    params.append(str(p["name"]))
                    endpoints.append((method_key.upper(), path_key, params))

        return endpoints
    except Exception:
        return []


def is_soft_404_match(status_code: int, content: bytes, soft_404_fp: str | None) -> bool:
    """Check if a response matches the established soft-404 fingerprint."""
    if not soft_404_fp:
        return False
    try:
        fp_dict = json.loads(soft_404_fp)
        fp_status = fp_dict.get("status_code")
        fp_len = fp_dict.get("length")
        fp_hash = fp_dict.get("body_hash")

        # If status code matches and length is within 10 bytes or hash matches
        if status_code == fp_status:
            b_hash = hashlib.sha256(content).hexdigest()
            if b_hash == fp_hash:
                return True
            if fp_len is not None and abs(len(content) - fp_len) <= 10:
                return True
    except Exception:
        pass
    return False


class FingerprintModule:
    """Technology fingerprinting (zero active requests) and API discovery module."""

    name = "fingerprint"

    def __init__(self, tech_rules_path: Path | str = "config/fingerprints/tech.yaml"):
        self.tech_rules_path = Path(tech_rules_path)
        self.rules = self._load_rules()

    def _load_rules(self) -> list[dict[str, Any]]:
        if self.tech_rules_path.exists():
            try:
                data = yaml.safe_load(self.tech_rules_path.read_text(encoding="utf-8"))
                if isinstance(data, dict) and "fingerprints" in data:
                    return data["fingerprints"]
            except Exception:
                pass
        return DEFAULT_TECH_RULES

    def plan(self, ctx: ScanContext) -> list[Task]:
        """Plan fingerprint and API discovery tasks for verified live assets."""
        cursor = ctx.db.execute(
            """
            SELECT DISTINCT h.url
            FROM http_services h
            JOIN assets a ON h.asset_id = a.id
            WHERE a.program = ? AND a.confidence = 'verified'
            """,
            (ctx.program,),
        )
        urls = [row[0] for row in cursor.fetchall()]
        return [
            Task(scan_id=ctx.scan_id, module=self.name, target=u, estimated_requests=6)
            for u in urls
        ]

    def _fingerprint_passive(
        self,
        ctx: ScanContext,
        asset_id: int,
        server_header: str | None,
        title: str | None,
        body_snippet: str | None,
    ) -> list[str]:
        """Perform zero-request passive fingerprinting on collected response data."""
        detected: list[str] = []

        # Parse meta generator if body snippet present
        meta_generator: str | None = None
        if body_snippet:
            soup = BeautifulSoup(body_snippet, "html.parser")
            meta_tag = soup.find("meta", attrs={"name": re.compile(r"generator", re.I)})
            if meta_tag and meta_tag.get("content"):
                meta_generator = str(meta_tag.get("content")).strip()

        for rule in self.rules:
            rule_type = rule.get("type")
            pattern = rule.get("pattern", "")
            name = rule.get("name", "")
            category = rule.get("category", "")
            version_grp = rule.get("version_group")

            matched = False
            version: str | None = None
            evidence = ""

            if rule_type == "header":
                hdr_name = rule.get("header", "").lower()
                target_val = server_header if hdr_name == "server" else None
                if target_val:
                    m = re.search(pattern, target_val)
                    if m:
                        matched = True
                        if version_grp and m.groups() and len(m.groups()) >= version_grp:
                            version = m.group(version_grp)
                        evidence = f"Header {hdr_name}: {target_val}"

            elif rule_type == "meta_generator" and meta_generator:
                m = re.search(pattern, meta_generator)
                if m:
                    matched = True
                    if version_grp and m.groups() and len(m.groups()) >= version_grp:
                        version = m.group(version_grp)
                    evidence = f"Meta generator: {meta_generator}"

            elif rule_type == "body" and body_snippet:
                m = re.search(pattern, body_snippet)
                if m:
                    matched = True
                    evidence = f"Body snippet matched pattern: {pattern}"

            if matched:
                upsert_technology(
                    db=ctx.db,
                    asset_id=asset_id,
                    name=name,
                    version=version,
                    category=category,
                    evidence=evidence,
                )
                detected.append(name)

        return detected

    async def run(self, ctx: ScanContext, task: Task) -> dict[str, Any]:
        """Execute passive technology detection and active API endpoint probing."""
        base_url = task.target
        parsed = urllib.parse.urlsplit(base_url)
        hostname = parsed.netloc.split(":")[0]

        cursor = ctx.db.execute(
            """
            SELECT a.id, h.server, h.title, h.soft_404_fingerprint
            FROM assets a
            JOIN http_services h ON h.asset_id = a.id
            WHERE a.program = ? AND a.hostname = ?
            ORDER BY h.id DESC LIMIT 1
            """,
            (ctx.program, hostname),
        )
        row = cursor.fetchone()
        if not row:
            return {"technologies": [], "api_endpoints": 0}

        asset_id = row["id"]
        server_header = row["server"]
        title = row["title"]
        soft_404_fp = row["soft_404_fingerprint"]

        # Fetch evidence snippet if available
        ev_cursor = ctx.db.execute(
            "SELECT raw_redacted FROM evidence WHERE asset_id = ? AND kind = 'http_response' ORDER BY id DESC LIMIT 1",
            (asset_id,),
        )
        ev_row = ev_cursor.fetchone()
        body_snippet = ev_row[0] if ev_row else None

        # 1. Passive technology fingerprinting (0 network requests)
        technologies = self._fingerprint_passive(
            ctx=ctx,
            asset_id=asset_id,
            server_header=server_header,
            title=title,
            body_snippet=body_snippet,
        )

        # 2. Active API Discovery (capped at 6 requests per host)
        api_endpoints_found = 0
        graphql_introspection_enabled = ctx.metadata.get("graphql_introspection", False)

        for path in API_PROBE_PATHS:
            probe_url = urllib.parse.urljoin(base_url, path)
            try:
                resp = await ctx.requests.request("GET", probe_url, module=self.name, purpose="api_probe")
                if resp.status_code == 200 and resp.content:
                    # Soft-404 check
                    if is_soft_404_match(resp.status_code, resp.content, soft_404_fp):
                        continue

                    if path == "/graphql":
                        # Record GraphQL lead
                        finding_id = f"F-GQL-{abs(hash((hostname, probe_url))) % 100000:05d}"
                        ctx.db.execute(
                            """
                            INSERT INTO findings (
                                id, scan_id, asset_id, type, title, severity_hint,
                                confidence, status, notes, created_at
                            ) VALUES (?, ?, ?, 'observation', 'GraphQL endpoint discovered', 'info', 'high', 'new', ?, ?)
                            ON CONFLICT(id) DO NOTHING
                            """,
                            (finding_id, ctx.scan_id, asset_id, f"GraphQL endpoint at {probe_url}", utc_now_iso()),
                        )
                        ctx.db.commit()

                        # Only run introspection if explicitly enabled
                        if graphql_introspection_enabled:
                            intro_query = {"query": "{__schema{types{name}}}"}
                            intro_resp = await ctx.requests.request(
                                "POST",
                                probe_url,
                                module=self.name,
                                purpose="graphql_introspection",
                                headers={"Content-Type": "application/json"},
                                data=json.dumps(intro_query),
                            )
                            if intro_resp.status_code == 200 and b"__schema" in intro_resp.content:
                                insert_scan_event(ctx.db, ctx.scan_id, "INFO", f"GraphQL introspection enabled on {probe_url}")

                    elif any(path.endswith(ext) for ext in (".json", "api-docs", "/api-docs")):
                        # OpenAPI / Swagger file discovered
                        specs = parse_openapi_spec(resp.text)
                        for method, ep_path, params in specs:
                            insert_endpoint(
                                db=ctx.db,
                                url_id=None,
                                method=method,
                                path=ep_path,
                                parameters=json.dumps(params) if params else None,
                            )
                            api_endpoints_found += 1

                        finding_id = f"F-API-{abs(hash((hostname, probe_url))) % 100000:05d}"
                        ctx.db.execute(
                            """
                            INSERT INTO findings (
                                id, scan_id, asset_id, type, title, severity_hint,
                                confidence, status, notes, created_at
                            ) VALUES (?, ?, ?, 'observation', 'API documentation exposed', 'info', 'high', 'new', ?, ?)
                            ON CONFLICT(id) DO NOTHING
                            """,
                            (finding_id, ctx.scan_id, asset_id, f"Found OpenAPI specification at {probe_url} with {len(specs)} endpoints", utc_now_iso()),
                        )
                        ctx.db.commit()

            except Exception as e:
                insert_scan_event(ctx.db, ctx.scan_id, "DEBUG", f"API probe failed for {probe_url}: {e}")

        return {
            "technologies": technologies,
            "api_endpoints": api_endpoints_found,
        }
