"""Central request controller for RECON-X.

The ONLY module authorized to initiate network connections or import network libraries
(httpx, socket, dns.resolver). All target requests are normalized, scope-verified,
rate-limited, budget-checked, and cryptographically audit-logged.
"""

from __future__ import annotations

import asyncio
import email.utils
import sqlite3
import time
import urllib.parse
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import dns.resolver
import httpx

from reconx.core.audit import log_request
from reconx.core.config import Settings
from reconx.core.normalizer import (
    NormalizationError,
    normalize_url,
)
from reconx.core.rate_limiter import AsyncRateLimiter
from reconx.core.scope import ScopeEngine


class ScopeDenied(Exception):
    """Raised when a request target or redirect is denied by scope."""
    pass


class BudgetExceeded(Exception):
    """Raised when a scan exceeds its allocated request budget."""
    pass


class ScanPaused(Exception):
    """Raised when a scan is paused due to repeated target errors or rate limits."""
    pass


@dataclass
class ReconResponse:
    """Standard response object returned by RequestManager."""
    status_code: int
    headers: dict[str, str]
    content: bytes
    text: str
    url: str
    is_truncated: bool = False
    redirect_chain: list[str] = field(default_factory=list)

    def header(self, key: str, default: str | None = None) -> str | None:
        """Case-insensitive header lookup."""
        k_lower = key.lower()
        for h_k, h_v in self.headers.items():
            if h_k.lower() == k_lower:
                return h_v
        return default


class RequestManager:
    """Central traffic controller enforcing safety, rate limits, budgets, and audit logging."""

    def __init__(
        self,
        scan_id: str,
        scope_engine: ScopeEngine,
        settings: Settings,
        db: sqlite3.Connection,
        rate_limiter: AsyncRateLimiter,
        clock: Callable[[], float] | None = None,
        sleep_func: Callable[[float], Coroutine[Any, Any, None]] | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        proxy: str | None = None,
    ):
        self.scan_id = scan_id
        self.scope_engine = scope_engine
        self.settings = settings
        self.db = db
        self.rate_limiter = rate_limiter
        self.clock = clock or time.monotonic
        self.sleep_func = sleep_func or asyncio.sleep
        self.transport = transport
        self.proxy = proxy

        # Request budget tracking
        self.requests_used = 0
        self.max_requests = settings.request_control.budget.max_requests

        # Error protection & backoff state
        self.consecutive_errors = 0
        self.error_threshold = settings.request_control.protection.repeated_error_threshold
        self.initial_backoff = settings.request_control.backoff.initial_delay
        self.max_backoff = settings.request_control.backoff.maximum_delay
        self.current_backoff = self.initial_backoff

        # DNS resolver configuration
        self.dns_resolver = dns.resolver.Resolver()

    def _parse_retry_after(self, header_val: str) -> float:
        """Parse Retry-After header as seconds or HTTP date."""
        val = header_val.strip()
        if val.isdigit():
            return float(val)
        try:
            parsed_date = email.utils.parsedate_to_datetime(val)
            now = datetime.now(timezone.utc)
            diff = (parsed_date - now).total_seconds()
            return max(1.0, diff)
        except Exception:
            return self.current_backoff

    async def _send_single(
        self,
        client: httpx.AsyncClient,
        method: str,
        norm_url: str,
        headers: dict[str, str] | None = None,
        data: Any = None,
        params: dict[str, Any] | None = None,
    ) -> ReconResponse:
        """Execute a single HTTP request, reading body up to max_response_bytes."""
        max_bytes = self.settings.request_control.limits.max_response_bytes
        req_headers = dict(self.settings.program.extra_headers)
        if headers:
            req_headers.update(headers)

        req = client.build_request(
            method=method,
            url=norm_url,
            headers=req_headers,
            content=data if isinstance(data, (bytes, str)) else None,
            params=params,
        )

        resp = await client.send(req, stream=True)
        body_chunks = []
        bytes_read = 0
        is_truncated = False

        try:
            async for chunk in resp.aiter_bytes():
                if bytes_read + len(chunk) > max_bytes:
                    allowed = max_bytes - bytes_read
                    if allowed > 0:
                        body_chunks.append(chunk[:allowed])
                        bytes_read += allowed
                    is_truncated = True
                    break
                body_chunks.append(chunk)
                bytes_read += len(chunk)
        finally:
            await resp.aclose()

        raw_content = b"".join(body_chunks)
        encoding = resp.encoding or "utf-8"
        text_content = raw_content.decode(encoding, errors="replace")

        return ReconResponse(
            status_code=resp.status_code,
            headers=dict(resp.headers),
            content=raw_content,
            text=text_content,
            url=str(resp.url),
            is_truncated=is_truncated,
        )

    async def request(
        self,
        method: str,
        url: str,
        module: str = "",
        purpose: str = "",
        headers: dict[str, str] | None = None,
        data: Any = None,
        params: dict[str, Any] | None = None,
    ) -> ReconResponse:
        """Main entry point for all active HTTP requests against scan targets."""
        # 1. Normalize URL
        try:
            norm_res = normalize_url(url)
            norm_url = norm_res.value
            host = norm_res.host
        except NormalizationError as e:
            raise ScopeDenied(f"Target URL normalization failed: {e}") from e

        # 2. Check scope
        decision = self.scope_engine.check(norm_url)
        if not decision.allowed:
            log_request(
                db=self.db,
                scan_id=self.scan_id,
                method=method,
                url=norm_url,
                host=host,
                status=None,
                bytes_count=0,
                duration_ms=0,
                scope_decision=f"denied: {decision.reason}",
            )
            raise ScopeDenied(f"Target {norm_url} is out of scope: {decision.reason}")

        # 3. Check budget
        if self.requests_used >= self.max_requests:
            raise BudgetExceeded(
                f"Scan request budget exhausted ({self.requests_used}/{self.max_requests})"
            )

        # Build client configuration
        client_kwargs: dict[str, Any] = {
            "headers": {"User-Agent": self.settings.program.user_agent},
            "timeout": httpx.Timeout(
                connect=self.settings.request_control.timeouts.connect,
                read=self.settings.request_control.timeouts.read,
                write=self.settings.request_control.timeouts.read,
                pool=self.settings.request_control.timeouts.connect,
            ),
            "follow_redirects": False,
        }
        if self.transport:
            client_kwargs["transport"] = self.transport
        if self.proxy:
            client_kwargs["proxy"] = self.proxy

        redirect_chain: list[str] = [norm_url]
        current_url = norm_url
        current_method = method
        max_redirects = self.settings.request_control.limits.max_redirects
        redirect_hops = 0
        final_resp: ReconResponse | None = None

        async with httpx.AsyncClient(**client_kwargs) as client:
            while True:
                # 4. Rate Limiting
                curr_norm = normalize_url(current_url)
                await self.rate_limiter.acquire(curr_norm.host)

                # Check budget before sending
                if self.requests_used >= self.max_requests:
                    raise BudgetExceeded(
                        f"Request budget exceeded ({self.requests_used}/{self.max_requests})"
                    )

                t_start = self.clock()
                attempts = 0
                max_attempts = self.settings.request_control.retry.max_attempts

                resp: ReconResponse | None = None

                while attempts <= max_attempts:
                    self.requests_used += 1
                    try:
                        resp = await self._send_single(
                            client=client,
                            method=current_method,
                            norm_url=current_url,
                            headers=headers,
                            data=data,
                            params=params,
                        )
                        t_end = self.clock()
                        duration_ms = int((t_end - t_start) * 1000)

                        # Audit log
                        log_request(
                            db=self.db,
                            scan_id=self.scan_id,
                            method=current_method,
                            url=current_url,
                            host=curr_norm.host,
                            status=resp.status_code,
                            bytes_count=len(resp.content),
                            duration_ms=duration_ms,
                            scope_decision="allowed",
                        )

                        # Handle 429 & 503 protection
                        if resp.status_code in (429, 503):
                            self.consecutive_errors += 1

                            retry_after_val = resp.headers.get("Retry-After")
                            if retry_after_val and self.settings.request_control.retry.respect_retry_after:
                                wait_sec = self._parse_retry_after(retry_after_val)
                            else:
                                wait_sec = self.current_backoff
                                self.current_backoff = min(self.max_backoff, self.current_backoff * 2)

                            if self.consecutive_errors >= self.error_threshold:
                                raise ScanPaused(
                                    f"Scan paused: {self.consecutive_errors} consecutive server errors ({resp.status_code})"
                                )

                            if attempts < max_attempts:
                                attempts += 1
                                await self.sleep_func(wait_sec)
                                continue
                            break
                        else:
                            # Successful response
                            self.consecutive_errors = 0
                            self.current_backoff = self.initial_backoff
                            break

                    except (httpx.RequestError, TimeoutError) as e:
                        t_end = self.clock()
                        duration_ms = int((t_end - t_start) * 1000)
                        log_request(
                            db=self.db,
                            scan_id=self.scan_id,
                            method=current_method,
                            url=current_url,
                            host=curr_norm.host,
                            status=None,
                            bytes_count=0,
                            duration_ms=duration_ms,
                            scope_decision="allowed",
                        )
                        self.consecutive_errors += 1
                        if self.consecutive_errors >= self.error_threshold:
                            raise ScanPaused(
                                f"Scan paused: {self.consecutive_errors} consecutive network failures"
                            ) from e

                        if attempts < max_attempts:
                            attempts += 1
                            await self.sleep_func(self.current_backoff)
                            self.current_backoff = min(self.max_backoff, self.current_backoff * 2)
                            continue
                        raise

                if resp is None:
                    raise httpx.RequestError(f"Failed to fetch {current_url}")

                # 6. Manual Redirect Handling
                if resp.status_code in (301, 302, 303, 307, 308) and "Location" in resp.headers:
                    raw_loc = resp.headers["Location"]
                    next_url = urllib.parse.urljoin(current_url, raw_loc)

                    # Re-check scope for redirect destination
                    redir_decision = self.scope_engine.check_redirect(current_url, next_url)
                    if not redir_decision.allowed:
                        # Log scope block and do not follow redirect
                        log_request(
                            db=self.db,
                            scan_id=self.scan_id,
                            method="GET",
                            url=next_url,
                            host=urllib.parse.urlsplit(next_url).hostname or "",
                            status=None,
                            bytes_count=0,
                            duration_ms=0,
                            scope_decision=f"denied: redirect blocked: {redir_decision.reason}",
                        )
                        final_resp = resp
                        final_resp.redirect_chain = redirect_chain
                        return final_resp

                    redirect_hops += 1
                    if redirect_hops > max_redirects:
                        final_resp = resp
                        final_resp.redirect_chain = redirect_chain
                        return final_resp

                    redirect_chain.append(next_url)
                    current_url = next_url
                    if resp.status_code == 303:
                        current_method = "GET"
                    continue

                final_resp = resp
                final_resp.redirect_chain = redirect_chain
                return final_resp

    async def passive_get(
        self,
        url: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> ReconResponse:
        """Query third-party OSINT sources without consuming target scan budget."""
        client_kwargs: dict[str, Any] = {
            "headers": {"User-Agent": "RECON-X/0.1 OSINT fetcher"},
            "timeout": httpx.Timeout(15.0),
            "follow_redirects": True,
        }
        if self.transport:
            client_kwargs["transport"] = self.transport

        async with httpx.AsyncClient(**client_kwargs) as client:
            resp = await client.get(url, params=params, headers=headers)
            return ReconResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                content=resp.content,
                text=resp.text,
                url=str(resp.url),
            )

    async def dns_query(self, qname: str, rdtype: str = "A") -> list[str]:
        """Execute a DNS query using dnspython through the request manager."""
        try:
            loop = asyncio.get_running_loop()
            answer = await loop.run_in_executor(
                None, lambda: self.dns_resolver.resolve(qname, rdtype)
            )
            return [r.to_text() for r in answer]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return []
        except Exception:
            return []

    async def send_webhook(self, url: str, payload: dict[str, Any]) -> bool:
        """Send notification webhook (Slack, Discord, Telegram) without consuming scan budget."""
        client_kwargs: dict[str, Any] = {
            "headers": {"Content-Type": "application/json", "User-Agent": "RECON-X/0.1 notifier"},
            "timeout": httpx.Timeout(10.0),
        }
        if self.transport:
            client_kwargs["transport"] = self.transport

        try:
            async with httpx.AsyncClient(**client_kwargs) as client:
                resp = await client.post(url, json=payload)
                return resp.status_code in (200, 201, 204)
        except Exception:
            return False
