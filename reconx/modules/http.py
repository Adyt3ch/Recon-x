"""HTTP service discovery, soft-404 fingerprinting, and CDN tagging module."""

from __future__ import annotations

import hashlib
import json
import random
import string
from typing import Any

from bs4 import BeautifulSoup

from reconx.core.engine import ScanContext
from reconx.core.logging import redact_secrets
from reconx.core.request_manager import ReconResponse, ScopeDenied
from reconx.core.scheduler import Task
from reconx.database.storage import (
    insert_scan_event,
    upsert_asset,
    upsert_http_service,
    utc_now_iso,
)
from reconx.intelligence.confidence import upgrade_confidence

CDN_MARKERS = [
    ("server", "cloudflare"),
    ("cf-ray", ""),
    ("cf-cache-status", ""),
    ("server", "cloudfront"),
    ("x-amz-cf-id", ""),
    ("x-amz-cf-pop", ""),
    ("server", "akamai"),
    ("x-akamai-transformed", ""),
    ("x-fastly-request-id", ""),
    ("server", "fastly"),
]


def extract_title(html_content: str | bytes) -> str | None:
    """Extract page title from HTML using BeautifulSoup, capped at 100 KB."""
    if isinstance(html_content, bytes):
        raw_slice = html_content[:100_000].decode("utf-8", errors="replace")
    else:
        raw_slice = html_content[:100_000]

    soup = BeautifulSoup(raw_slice, "html.parser")
    if soup.title and soup.title.string:
        return soup.title.string.strip()
    return None


def is_cdn_service(headers: dict[str, str]) -> bool:
    """Detect CDN and WAF presence from standard response headers."""
    lowered = {k.lower(): v.lower() for k, v in headers.items()}
    for hdr, marker in CDN_MARKERS:
        if hdr in lowered:
            if not marker or marker in lowered[hdr]:
                return True
    return False


class HttpModule:
    """Live HTTP service detection and fingerprinting module."""
    name = "http"

    def plan(self, ctx: ScanContext) -> list[Task]:
        """Plan HTTP probes for all resolved (high confidence) or active assets."""
        cursor = ctx.db.execute(
            "SELECT hostname FROM assets WHERE program = ? AND confidence IN ('high', 'medium', 'verified')",
            (ctx.program,),
        )
        hosts = [row[0] for row in cursor.fetchall()]
        # 2-3 requests planned per asset (HTTPS, fallback, soft-404)
        return [
            Task(scan_id=ctx.scan_id, module=self.name, target=h, estimated_requests=2)
            for h in hosts
        ]

    async def _probe_soft_404(self, ctx: ScanContext, host: str, base_scheme: str) -> str | None:
        """Probe a non-existent path to establish the host's soft-404 fingerprint."""
        rand_token = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        test_url = f"{base_scheme}://{host}/reconx-test-404-{rand_token}"
        try:
            resp = await ctx.requests.request("GET", test_url, module=self.name, purpose="soft_404")
            b_hash = hashlib.sha256(resp.content).hexdigest()
            fp = {
                "status_code": resp.status_code,
                "length": len(resp.content),
                "body_hash": b_hash,
            }
            return json.dumps(fp)
        except Exception:
            return None

    async def run(self, ctx: ScanContext, task: Task) -> dict[str, Any] | None:
        """Probe an asset on HTTPS (falling back to HTTP) and record live service data."""
        host = task.target

        # Fetch asset_id
        cursor = ctx.db.execute(
            "SELECT id, confidence FROM assets WHERE program = ? AND hostname = ?",
            (ctx.program, host),
        )
        asset_row = cursor.fetchone()
        if not asset_row:
            return None
        asset_id = asset_row["id"]
        current_conf = asset_row["confidence"]

        # 1. Probe HTTPS first
        https_url = f"https://{host}/"
        resp: ReconResponse | None = None
        scheme_used = "https"

        try:
            resp = await ctx.requests.request("GET", https_url, module=self.name, purpose="live_check")
        except ScopeDenied:
            return None
        except Exception:
            # 2. Fall back to plain HTTP if HTTPS fails
            http_url = f"http://{host}/"
            try:
                resp = await ctx.requests.request("GET", http_url, module=self.name, purpose="live_fallback")
                scheme_used = "http"
            except Exception as e:
                insert_scan_event(ctx.db, ctx.scan_id, "INFO", f"HTTP probing failed for {host}: {e}")
                return None

        if not resp:
            return None

        # Parse service properties
        title = extract_title(resp.content)
        headers_dict = resp.headers
        server = resp.header("server")
        content_type = resp.header("content-type")
        content_length = len(resp.content)
        body_hash = hashlib.sha256(resp.content).hexdigest()
        redirect_chain_json = json.dumps(resp.redirect_chain)
        cdn_flag = 1 if is_cdn_service(headers_dict) else 0

        # 3. Soft-404 fingerprinting probe
        soft_404_fp = await self._probe_soft_404(ctx, host, scheme_used)

        # 4. Upsert HTTP service row
        service_id = upsert_http_service(
            db=ctx.db,
            asset_id=asset_id,
            scan_id=ctx.scan_id,
            url=resp.url,
            status_code=resp.status_code,
            title=title,
            server=server,
            content_type=content_type,
            content_length=content_length,
            redirect_chain=redirect_chain_json,
            tls=None,
            body_hash=body_hash,
            is_cdn=cdn_flag,
            soft_404_fingerprint=soft_404_fp,
        )

        # 5. Store evidence snippet with redacted secrets
        evidence_snippet = redact_secrets(resp.text[:2000])
        ctx.db.execute(
            """
            INSERT INTO evidence (asset_id, kind, raw_redacted, source, captured_at)
            VALUES (?, 'http_response', ?, 'http_module', ?)
            """,
            (asset_id, evidence_snippet, utc_now_iso()),
        )
        ctx.db.commit()

        # 6. Upgrade asset confidence to 'verified'
        new_conf = upgrade_confidence(current_conf, "verified")
        upsert_asset(ctx.db, ctx.program, host, confidence=new_conf)

        return {
            "service_id": service_id,
            "url": resp.url,
            "status_code": resp.status_code,
            "title": title,
            "is_cdn": cdn_flag,
        }
