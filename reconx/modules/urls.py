"""URL discovery, normalization, categorization, robots/sitemap parsing, and crawling."""

from __future__ import annotations

import json
import urllib.parse
from pathlib import Path
from typing import Any

import defusedxml.ElementTree as ET
import yaml

from reconx.core.engine import ScanContext
from reconx.core.scheduler import Task
from reconx.database.storage import (
    insert_endpoint,
    insert_scan_event,
    upsert_url,
    utc_now_iso,
)
from reconx.integrations.gau import GauIntegration
from reconx.integrations.katana import KatanaIntegration

TRACKING_PARAMS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "gclid",
    "fbclid",
    "_ga",
    "_gl",
    "mc_cid",
    "mc_eid",
    "ref",
    "source",
}

DEFAULT_CATEGORIES = {
    "login": ["login", "signin", "auth", "session", "logout", "register", "signup"],
    "admin": ["admin", "dashboard", "manage", "portal", "cpanel", "console", "root"],
    "api": ["/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/json", "/rpc/"],
    "upload": ["upload", "file", "attach", "document", "image", "media"],
    "docs": ["docs", "documentation", "swagger", "openapi", "redoc", "manual", "api-docs"],
    "graphql": ["graphql", "graphiql", "gql"],
    "static": [".css", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".ico", ".pdf"],
}


def clean_url(url: str) -> str:
    """Normalize URL, drop fragments, strip tracking params, sort query parameters."""
    parsed = urllib.parse.urlsplit(url.strip())
    scheme = parsed.scheme.lower()
    if not scheme:
        scheme = "https"

    netloc = parsed.netloc.lower()
    # Strip default ports
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]

    path = parsed.path or "/"

    # Parse and filter query parameters
    query_items: list[tuple[str, str]] = []
    if parsed.query:
        for k, v in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
            if k.lower() not in TRACKING_PARAMS:
                query_items.append((k, v))

    # Sort query items alphabetically by key, then value
    query_items.sort(key=lambda item: (item[0], item[1]))
    cleaned_query = urllib.parse.urlencode(query_items)

    # Reconstruct URL without fragment
    return urllib.parse.urlunsplit((scheme, netloc, path, cleaned_query, ""))


def extract_parameters(url: str) -> list[str]:
    """Extract distinct parameter names from URL query string."""
    parsed = urllib.parse.urlsplit(url)
    if not parsed.query:
        return []
    names = {k for k, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)}
    return sorted(names)


def categorize_url(url: str, rules: dict[str, list[str]] | None = None) -> str | None:
    """Categorize URL by path and query according to configuration rules."""
    cat_rules = rules or DEFAULT_CATEGORIES
    url_lower = url.lower()
    parsed = urllib.parse.urlsplit(url_lower)
    target_str = parsed.path + ("?" + parsed.query if parsed.query else "")

    for category, patterns in cat_rules.items():
        for pattern in patterns:
            if pattern in target_str:
                return category
    return None


def parse_robots_txt(content: str, base_url: str) -> list[str]:
    """Parse Disallow and Allow directives from robots.txt content."""
    urls: list[str] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip().lower()
            val = val.strip()
            if key in ("disallow", "allow") and val:
                full = urllib.parse.urljoin(base_url, val)
                urls.append(full)
    return urls


def parse_sitemap_xml(xml_bytes: bytes, base_url: str) -> tuple[list[str], list[str]]:
    """Parse sitemap XML safely with defusedxml.

    Returns (page_urls, nested_sitemap_urls).
    """
    page_urls: list[str] = []
    nested_sitemaps: list[str] = []

    try:
        root = ET.fromstring(xml_bytes)
        # Strip XML namespace if present
        tag_name = root.tag.split("}")[-1] if "}" in root.tag else root.tag

        if tag_name == "sitemapindex":
            for sitemap in root.iter():
                subtag = sitemap.tag.split("}")[-1] if "}" in sitemap.tag else sitemap.tag
                if subtag == "loc" and sitemap.text:
                    nested_sitemaps.append(sitemap.text.strip())
        elif tag_name == "urlset":
            for url_node in root.iter():
                subtag = url_node.tag.split("}")[-1] if "}" in url_node.tag else url_node.tag
                if subtag == "loc" and url_node.text:
                    page_urls.append(url_node.text.strip())
    except Exception:
        pass

    return page_urls, nested_sitemaps


class UrlsModule:
    """Web endpoint and URL discovery module (Katana, GAU, robots.txt, sitemaps)."""

    name = "urls"

    def __init__(self, categories_path: Path | str = "config/categories.yaml"):
        self.categories_path = Path(categories_path)
        self.categories = self._load_categories()

    def _load_categories(self) -> dict[str, list[str]]:
        if self.categories_path.exists():
            try:
                data = yaml.safe_load(self.categories_path.read_text(encoding="utf-8"))
                if isinstance(data, dict) and "categories" in data:
                    return data["categories"]
            except Exception:
                pass
        return DEFAULT_CATEGORIES

    def plan(self, ctx: ScanContext) -> list[Task]:
        """Plan URL discovery tasks for verified assets having live HTTP services."""
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
            Task(scan_id=ctx.scan_id, module=self.name, target=u, estimated_requests=5)
            for u in urls
        ]

    async def _fetch_sitemaps_recursive(
        self,
        ctx: ScanContext,
        sitemap_url: str,
        depth: int = 0,
        max_depth: int = 2,
    ) -> list[str]:
        """Fetch sitemap XML and follow nested sitemaps up to max_depth."""
        if depth > max_depth:
            return []

        discovered: list[str] = []
        try:
            resp = await ctx.requests.request("GET", sitemap_url, module=self.name, purpose="sitemap")
            if resp.status_code == 200 and resp.content:
                pages, nested = parse_sitemap_xml(resp.content, sitemap_url)
                discovered.extend(pages)
                for sub_sitemap in nested:
                    sub_pages = await self._fetch_sitemaps_recursive(
                        ctx, sub_sitemap, depth=depth + 1, max_depth=max_depth
                    )
                    discovered.extend(sub_pages)
        except Exception:
            pass
        return discovered

    async def run(self, ctx: ScanContext, task: Task) -> dict[str, Any]:
        """Execute URL discovery for live base URL."""
        base_url = task.target
        parsed_base = urllib.parse.urlsplit(base_url)
        hostname = parsed_base.netloc.split(":")[0]

        cursor = ctx.db.execute(
            "SELECT id FROM assets WHERE program = ? AND hostname = ?",
            (ctx.program, hostname),
        )
        asset_row = cursor.fetchone()
        asset_id = asset_row["id"] if asset_row else None
        if not asset_id:
            return {"discovered_urls": 0}

        discovered_raw_urls: list[tuple[str, str]] = []  # (url, source)

        # 1. Fetch robots.txt
        robots_url = urllib.parse.urljoin(base_url, "/robots.txt")
        try:
            r_resp = await ctx.requests.request("GET", robots_url, module=self.name, purpose="robots_txt")
            if r_resp.status_code == 200 and r_resp.text:
                paths = parse_robots_txt(r_resp.text, base_url)
                for p in paths:
                    discovered_raw_urls.append((p, "robots.txt"))
                # Record robots.txt discovery observation
                if paths:
                    finding_id = f"F-ROBOTS-{abs(hash((hostname, robots_url))) % 100000:05d}"
                    ctx.db.execute(
                        """
                        INSERT INTO findings (
                            id, scan_id, asset_id, type, title, severity_hint,
                            confidence, status, notes, created_at
                        ) VALUES (?, ?, ?, 'observation', 'Disallowed paths found in robots.txt', 'info', 'high', 'new', ?, ?)
                        ON CONFLICT(id) DO NOTHING
                        """,
                        (finding_id, ctx.scan_id, asset_id, f"Discovered {len(paths)} disallowed paths in robots.txt", utc_now_iso()),
                    )
                    ctx.db.commit()
        except Exception as e:
            insert_scan_event(ctx.db, ctx.scan_id, "DEBUG", f"robots.txt fetch failed for {base_url}: {e}")

        # 2. Fetch sitemap.xml (with recursive limit)
        sitemap_url = urllib.parse.urljoin(base_url, "/sitemap.xml")
        sitemap_pages = await self._fetch_sitemaps_recursive(ctx, sitemap_url, depth=0, max_depth=2)
        for sp in sitemap_pages:
            discovered_raw_urls.append((sp, "sitemap.xml"))

        # 3. Active Katana crawl (if installed)
        from reconx.core.tool_runner import ToolRunner
        tool_runner = ToolRunner(scan_id=ctx.scan_id, db_path=ctx.settings.storage.database)
        katana = KatanaIntegration(tool_runner)
        k_urls, k_warn = katana.crawl(base_url, rate_limit=10, depth=2)
        if k_warn:
            insert_scan_event(ctx.db, ctx.scan_id, "INFO", k_warn)
        for ku in k_urls:
            discovered_raw_urls.append((ku, "katana"))

        # 4. GAU historical archive fetch (passive)
        gau = GauIntegration(tool_runner)
        g_urls, g_warn = gau.fetch(hostname)
        if g_warn:
            insert_scan_event(ctx.db, ctx.scan_id, "INFO", g_warn)
        for gu in g_urls:
            discovered_raw_urls.append((gu, "gau"))

        # 5. Normalize, scope-filter, categorize, and store
        saved_count = 0
        seen_normalized: set[str] = set()
        max_urls = 1000

        for raw_url, source in discovered_raw_urls:
            if saved_count >= max_urls:
                break

            decision = ctx.scope.check_url(raw_url)
            if not decision.allowed:
                continue

            norm_url = clean_url(raw_url)
            if norm_url in seen_normalized:
                continue
            seen_normalized.add(norm_url)

            category = categorize_url(norm_url, self.categories)
            url_id = upsert_url(
                db=ctx.db,
                asset_id=asset_id,
                url_normalized=norm_url,
                source=source,
                category=category,
            )

            # Extract parameter names and insert endpoint
            params = extract_parameters(norm_url)
            params_str = json.dumps(params) if params else None
            parsed_path = urllib.parse.urlsplit(norm_url).path or "/"
            insert_endpoint(
                db=ctx.db,
                url_id=url_id,
                method="GET",
                path=parsed_path,
                parameters=params_str,
            )
            saved_count += 1

        return {"discovered_urls": saved_count}
