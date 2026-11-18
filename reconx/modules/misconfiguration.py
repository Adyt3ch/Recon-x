"""Security misconfiguration analysis: headers, cookies, CORS, and sensitive file exposures."""

from __future__ import annotations

import re
import urllib.parse
from datetime import datetime, timezone
from typing import Any

from reconx.core.engine import ScanContext
from reconx.core.scheduler import Task
from reconx.database.storage import insert_scan_event, utc_now_iso
from reconx.modules.fingerprint import is_soft_404_match

# Exposure targets and verification signatures
EXPOSURE_SIGNATURES: list[tuple[str, re.Pattern[str], str]] = [
    (
        "/.git/HEAD",
        re.compile(r"^ref:\s+refs/", re.M),
        "Git repository metadata exposed (HEAD ref)",
    ),
    (
        "/.env",
        re.compile(r"(?i)\b(?:DB_PASSWORD|DATABASE_URL|SECRET_KEY|APP_KEY|API_KEY|AWS_SECRET)\s*=", re.M),
        "Environment file exposed (.env with credential definitions)",
    ),
    (
        "/server-status",
        re.compile(r"(?i)(?:<title>Apache Status</title>|Server Version:\s*Apache)", re.M),
        "Apache server-status page exposed",
    ),
    (
        "/actuator/health",
        re.compile(r"""(?i)["']status["']\s*:\s*["']UP["']"""),
        "Spring Boot Actuator health endpoint exposed",
    ),
]


def check_security_headers(url: str, headers: dict[str, str]) -> list[str]:
    """Examine response headers and return missing security header observations."""
    observations: list[str] = []
    lowered = {k.lower(): v for k, v in headers.items()}
    is_https = url.lower().startswith("https://")

    # 1. HSTS (Strict-Transport-Security) - only evaluate for HTTPS services
    if is_https and "strict-transport-security" not in lowered:
        observations.append("Strict-Transport-Security header missing")

    # 2. Content-Security-Policy
    if "content-security-policy" not in lowered:
        observations.append("Content-Security-Policy header missing")

    # 3. X-Frame-Options or frame-ancestors
    csp = lowered.get("content-security-policy", "")
    if "x-frame-options" not in lowered and "frame-ancestors" not in csp:
        observations.append("X-Frame-Options header missing")

    # 4. X-Content-Type-Options
    if "x-content-type-options" not in lowered:
        observations.append("X-Content-Type-Options header missing")

    # 5. Referrer-Policy
    if "referrer-policy" not in lowered:
        observations.append("Referrer-Policy header missing")

    # 6. Permissions-Policy
    if "permissions-policy" not in lowered:
        observations.append("Permissions-Policy header missing")

    return observations


def check_cookie_security(raw_cookies: list[str], is_https: bool) -> list[str]:
    """Evaluate Set-Cookie strings for Secure, HttpOnly, and SameSite attributes."""
    observations: list[str] = []

    for cookie in raw_cookies:
        parts = [p.strip().lower() for p in cookie.split(";")]
        name_val = parts[0] if parts else ""
        cookie_name = name_val.split("=")[0] if "=" in name_val else name_val

        has_secure = "secure" in parts
        has_httponly = "httponly" in parts
        has_samesite = any(p.startswith("samesite") for p in parts)

        if is_https and not has_secure:
            observations.append(f"Cookie {cookie_name!r} missing Secure attribute")

        # Session/Auth-like cookies should have HttpOnly
        if any(token in cookie_name for token in ("sess", "auth", "token", "id", "jwt")) and not has_httponly:
            observations.append(f"Sensitive cookie {cookie_name!r} missing HttpOnly attribute")

        if not has_samesite:
            observations.append(f"Cookie {cookie_name!r} missing SameSite attribute")

    return observations


def evaluate_cors_response(headers: dict[str, str]) -> tuple[str, str] | None:
    """Evaluate CORS headers for origin reflection and credential allowance.

    Returns (lead_title, severity) or None.
    """
    lowered = {k.lower(): v.strip() for k, v in headers.items()}
    acao = lowered.get("access-control-allow-origin")
    acac = lowered.get("access-control-allow-credentials", "").lower()

    if not acao:
        return None

    # Reflected arbitrary test origin with credentials
    if acao == "https://recon-x.invalid" and acac == "true":
        return (
            "CORS misconfiguration: arbitrary origin reflected with credentials allowed",
            "high",
        )

    # Wildcard origin
    if acao == "*":
        return ("CORS policy: wildcard origin allowed without credentials", "info")

    return None


def check_tls_certificate(cert_info: dict[str, Any], current_time: datetime | None = None) -> list[str]:
    """Flag certificate expiration within 30 days, expired status, or insecure protocol."""
    observations: list[str] = []
    if not cert_info:
        return observations

    now = current_time or datetime.now(timezone.utc)

    # 1. Check expiration date (supports ssl.getpeercert format "notAfter" or "not_after")
    not_after_raw = cert_info.get("notAfter") or cert_info.get("not_after")
    if not_after_raw:
        exp_dt = None
        if isinstance(not_after_raw, datetime):
            exp_dt = not_after_raw if not_after_raw.tzinfo else not_after_raw.replace(tzinfo=timezone.utc)
        elif isinstance(not_after_raw, str):
            # Try standard SSL format: "May 15 12:00:00 2026 GMT"
            try:
                exp_dt = datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            except Exception:
                try:
                    exp_dt = datetime.fromisoformat(not_after_raw.replace("Z", "+00:00"))
                except Exception:
                    pass

        if exp_dt:
            days_left = (exp_dt - now).total_seconds() / 86400.0
            if days_left < 0:
                observations.append("TLS certificate has expired")
            elif days_left <= 30:
                observations.append("TLS certificate expiring within 30 days")

    # 2. Protocol version check (flag old versions like TLSv1.0, TLSv1.1)
    proto = cert_info.get("protocol") or cert_info.get("version")
    if proto and isinstance(proto, str):
        p_clean = proto.strip().upper()
        if p_clean in ("TLSV1", "TLSV1.0", "TLSV1.1", "SSLV3", "SSLV2"):
            observations.append(f"Insecure TLS protocol version in use: {p_clean}")

    return observations


class MisconfigurationModule:
    """Security misconfiguration and sensitive exposure detection module."""

    name = "misconfiguration"

    def plan(self, ctx: ScanContext) -> list[Task]:
        """Plan misconfiguration tasks for verified live services."""
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

    async def run(self, ctx: ScanContext, task: Task) -> dict[str, Any]:
        """Execute passive header analysis, CORS probe, and exposure candidate checks."""
        base_url = task.target
        parsed = urllib.parse.urlsplit(base_url)
        hostname = parsed.netloc.split(":")[0]

        cursor = ctx.db.execute(
            """
            SELECT a.id, h.soft_404_fingerprint
            FROM assets a
            JOIN http_services h ON h.asset_id = a.id
            WHERE a.program = ? AND a.hostname = ?
            ORDER BY h.id DESC LIMIT 1
            """,
            (ctx.program, hostname),
        )
        row = cursor.fetchone()
        if not row:
            return {"observations": 0}

        asset_id = row["id"]
        soft_404_fp = row["soft_404_fingerprint"]
        observations_count = 0

        # 1. Fetch live base page to inspect headers, cookies, and directory listing
        try:
            resp = await ctx.requests.request("GET", base_url, module=self.name, purpose="misconfig_base")
            headers = resp.headers

            # A. Check missing security headers (0 extra requests)
            hdr_obs = check_security_headers(base_url, headers)
            for obs in hdr_obs:
                finding_id = f"F-HDR-{abs(hash((hostname, obs))) % 100000:05d}"
                ctx.db.execute(
                    """
                    INSERT INTO findings (
                        id, scan_id, asset_id, type, title, severity_hint,
                        confidence, status, notes, created_at
                    ) VALUES (?, ?, ?, 'observation', ?, 'info', 'high', 'new', ?, ?)
                    ON CONFLICT(id) DO NOTHING
                    """,
                    (finding_id, ctx.scan_id, asset_id, obs, f"Observed on {base_url}", utc_now_iso()),
                )
                observations_count += 1

            # B. Check cookies if Set-Cookie was received
            set_cookie = headers.get("set-cookie") or headers.get("Set-Cookie")
            if set_cookie:
                raw_cookies = [c.strip() for c in set_cookie.split(",") if "=" in c]
                cookie_obs = check_cookie_security(raw_cookies, base_url.startswith("https://"))
                for c_obs in cookie_obs:
                    finding_id = f"F-CK-{abs(hash((hostname, c_obs))) % 100000:05d}"
                    ctx.db.execute(
                        """
                        INSERT INTO findings (
                            id, scan_id, asset_id, type, title, severity_hint,
                            confidence, status, notes, created_at
                        ) VALUES (?, ?, ?, 'observation', ?, 'low', 'high', 'new', ?, ?)
                        ON CONFLICT(id) DO NOTHING
                        """,
                        (finding_id, ctx.scan_id, asset_id, c_obs, f"Observed on {base_url}", utc_now_iso()),
                    )
                    observations_count += 1

            # C. Directory listing pattern
            if "Index of /" in resp.text:
                finding_id = f"F-DIR-{abs(hash((hostname, base_url))) % 100000:05d}"
                ctx.db.execute(
                    """
                    INSERT INTO findings (
                        id, scan_id, asset_id, type, title, severity_hint,
                        confidence, status, notes, created_at
                    ) VALUES (?, ?, ?, 'observation', 'Directory listing enabled', 'medium', 'high', 'new', ?, ?)
                    ON CONFLICT(id) DO NOTHING
                    """,
                    (finding_id, ctx.scan_id, asset_id, f"Index listing pattern found on {base_url}", utc_now_iso()),
                )
                observations_count += 1

            ctx.db.commit()

        except Exception as e:
            insert_scan_event(ctx.db, ctx.scan_id, "DEBUG", f"Misconfig base probe failed for {base_url}: {e}")

        # 2. CORS check (1 request per host)
        cors_url = base_url
        try:
            cors_resp = await ctx.requests.request(
                "GET",
                cors_url,
                module=self.name,
                purpose="cors_check",
                headers={"Origin": "https://recon-x.invalid"},
            )
            cors_result = evaluate_cors_response(cors_resp.headers)
            if cors_result:
                lead_title, severity = cors_result
                finding_id = f"F-CORS-{abs(hash((hostname, lead_title))) % 100000:05d}"
                ctx.db.execute(
                    """
                    INSERT INTO findings (
                        id, scan_id, asset_id, type, title, severity_hint,
                        confidence, status, notes, created_at
                    ) VALUES (?, ?, ?, 'observation', ?, ?, 'high', 'new', ?, ?)
                    ON CONFLICT(id) DO NOTHING
                    """,
                    (finding_id, ctx.scan_id, asset_id, lead_title, severity, f"Origin reflected on {cors_url}", utc_now_iso()),
                )
                ctx.db.commit()
                observations_count += 1
        except Exception as e:
            insert_scan_event(ctx.db, ctx.scan_id, "DEBUG", f"CORS probe failed for {cors_url}: {e}")

        # 3. Exposure Candidates checks (max 512 bytes read, confirmed signature required)
        for path, sig_regex, desc in EXPOSURE_SIGNATURES:
            exp_url = urllib.parse.urljoin(base_url, path)
            try:
                exp_resp = await ctx.requests.request("GET", exp_url, module=self.name, purpose="exposure_probe")
                if exp_resp.status_code == 200 and exp_resp.content:
                    # Compare with soft-404
                    if is_soft_404_match(exp_resp.status_code, exp_resp.content, soft_404_fp):
                        continue

                    snippet = exp_resp.text[:512]
                    if sig_regex.search(snippet):
                        finding_id = f"F-EXP-{abs(hash((hostname, path))) % 100000:05d}"
                        # Note: We record ONLY that the signature matched, NOT the file content!
                        ctx.db.execute(
                            """
                            INSERT INTO findings (
                                id, scan_id, asset_id, type, title, severity_hint,
                                confidence, status, notes, created_at
                            ) VALUES (?, ?, ?, 'observation', ?, 'high', 'verified', 'new', ?, ?)
                            ON CONFLICT(id) DO NOTHING
                            """,
                            (
                                finding_id,
                                ctx.scan_id,
                                asset_id,
                                desc,
                                f"Confirmed signature match at {exp_url} (content omitted for safety)",
                                utc_now_iso(),
                            ),
                        )
                        ctx.db.commit()
                        observations_count += 1
            except Exception as e:
                insert_scan_event(ctx.db, ctx.scan_id, "DEBUG", f"Exposure probe failed for {exp_url}: {e}")

        return {"observations": observations_count}
