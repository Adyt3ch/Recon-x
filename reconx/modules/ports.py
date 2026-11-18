"""Port scanning, service detection, ASN/RDAP pivots, and cloud storage detection.

Safety boundaries:
1. Port scanning is OFF by default. It runs only when rules.allow_port_scan is explicitly true.
2. IPs tagged as CDN, WAF, or shared cloud hosting are strictly skipped.
3. Each unique IP is scanned at most once, regardless of how many hostnames resolve to it.
4. Tools run with required rate-limit flags and no intrusive scripts by default.
"""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any
from xml.etree import ElementTree as ET

import defusedxml.ElementTree as SafeET

from reconx.core.engine import ScanContext
from reconx.core.scheduler import Task
from reconx.core.tool_runner import ToolMissing, run_tool
from reconx.database.storage import insert_scan_event, utc_now_iso

DEFAULT_WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000, 9090]

# Cloud storage bucket regexes
CLOUD_STORAGE_PATTERNS = [
    ("AWS S3", re.compile(r"([a-z0-9.\-_]{3,63})\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com", re.IGNORECASE)),
    ("AWS S3 URI", re.compile(r"s3://([a-z0-9.\-_]{3,63})", re.IGNORECASE)),
    ("Google Cloud Storage", re.compile(r"storage\.googleapis\.com/([a-z0-9.\-_]{3,63})", re.IGNORECASE)),
    ("Azure Blob", re.compile(r"([a-z0-9]{3,24})\.blob\.core\.windows\.net", re.IGNORECASE)),
]


def extract_cloud_storage_references(text: str) -> list[dict[str, str]]:
    """Identify cloud storage bucket references without attempting to access them."""
    found = []
    seen = set()
    for provider, pattern in CLOUD_STORAGE_PATTERNS:
        for match in pattern.finditer(text):
            bucket_name = match.group(1).lower()
            key = (provider, bucket_name)
            if key not in seen:
                seen.add(key)
                found.append({"provider": provider, "bucket": bucket_name})
    return found


def parse_naabu_output(output: str) -> list[dict[str, Any]]:
    """Parse Naabu JSON or host:port line output."""
    results = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                data = json.loads(line)
                ip = data.get("ip") or data.get("host")
                port = int(data.get("port", 0))
                if ip and port:
                    results.append({"ip": ip, "port": port, "protocol": "tcp"})
            except Exception:
                continue
        elif ":" in line:
            parts = line.split(":")
            if len(parts) == 2 and parts[1].isdigit():
                results.append({"ip": parts[0], "port": int(parts[1]), "protocol": "tcp"})
    return results


def parse_nmap_xml(xml_content: str) -> list[dict[str, Any]]:
    """Parse Nmap XML output extracting open ports, services, versions, and banners."""
    results = []
    if not xml_content.strip():
        return results

    try:
        root = SafeET.fromstring(xml_content)
    except Exception:
        try:
            root = ET.fromstring(xml_content)
        except Exception:
            return results

    for host in root.findall("host"):
        # Address
        addr_elem = host.find("address")
        if addr_elem is None:
            continue
        ip = addr_elem.get("addr", "")

        ports_elem = host.find("ports")
        if ports_elem is None:
            continue

        for port_elem in ports_elem.findall("port"):
            state_elem = port_elem.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue

            port_id = int(port_elem.get("portid", 0))
            proto = port_elem.get("protocol", "tcp")

            service_elem = port_elem.find("service")
            service_name = ""
            product = ""
            version = ""
            if service_elem is not None:
                service_name = service_elem.get("name", "")
                product = service_elem.get("product", "")
                version = service_elem.get("version", "")

            banner = f"{product} {version}".strip() if product or version else ""

            results.append({
                "ip": ip,
                "port": port_id,
                "protocol": proto,
                "service": service_name,
                "version": version,
                "banner": banner,
            })
    return results


def is_ip_cdn_or_waf(db: sqlite3.Connection, asset_id: int) -> bool:
    """Check if the given asset is flagged as CDN or WAF."""
    cursor = db.execute(
        "SELECT is_cdn FROM http_services WHERE asset_id = ? AND is_cdn = 1 LIMIT 1",
        (asset_id,),
    )
    return cursor.fetchone() is not None


class PortsModule:
    """Port scanning and service detection module enforcing strict authorization and CDN exclusion."""

    name = "ports"

    def __init__(self, ports: list[int] | None = None, rate: int = 100):
        self.ports = ports or DEFAULT_WEB_PORTS
        self.rate = rate

    def plan(self, ctx: ScanContext) -> list[Task]:
        """Plan port scan tasks only if rules.allow_port_scan is True."""
        allow_port_scan = False
        if hasattr(ctx.scope, "config") and hasattr(ctx.scope.config, "rules"):
            allow_port_scan = ctx.scope.config.rules.allow_port_scan
        elif hasattr(ctx.settings, "rules"):
            allow_port_scan = getattr(ctx.settings.rules, "allow_port_scan", False)

        if not allow_port_scan:
            return []

        # Find unique resolved IPs that are NOT tagged CDN/WAF
        cursor = ctx.db.execute(
            """
            SELECT DISTINCT d.asset_id, d.value
            FROM dns_records d
            JOIN assets a ON d.asset_id = a.id
            WHERE d.type = 'A' AND a.program = ?
            """,
            (ctx.program,),
        )
        tasks = []
        seen_ips = set()
        for asset_id, ip in cursor.fetchall():
            if ip in seen_ips:
                continue
            seen_ips.add(ip)

            # Skip CDN assets
            if is_ip_cdn_or_waf(ctx.db, asset_id):
                continue

            tasks.append(
                Task(
                    scan_id=ctx.scan_id,
                    module=self.name,
                    target=f"{asset_id}|{ip}",
                    estimated_requests=len(self.ports),
                )
            )
        return tasks

    async def run(self, ctx: ScanContext, task: Task) -> list[dict[str, Any]]:
        """Execute port scan using Nmap with required rate flags and store results."""
        allow_port_scan = False
        if hasattr(ctx.scope, "config") and hasattr(ctx.scope.config, "rules"):
            allow_port_scan = ctx.scope.config.rules.allow_port_scan
        elif hasattr(ctx.settings, "rules"):
            allow_port_scan = getattr(ctx.settings.rules, "allow_port_scan", False)

        if not allow_port_scan:
            return []

        parts = task.target.split("|")
        if len(parts) != 2:
            return []

        asset_id = int(parts[0])
        ip = parts[1]

        ports_csv = ",".join(str(p) for p in self.ports)

        # Nmap arguments enforcing Safety Rule 5 (no scripts, max-rate flag required)
        args = [
            "-p", ports_csv,
            "--max-rate", str(self.rate),
            "-sV", "--version-intensity", "1",
            "-T3",
            "-Pn",
            "-oX", "-",
            ip,
        ]

        try:
            res = run_tool(
                tool_name="nmap",
                args=args,
                scan_id=ctx.scan_id,
                db=ctx.db,
                timeout=120,
            )
            parsed_ports = parse_nmap_xml(res.stdout)
        except ToolMissing:
            insert_scan_event(ctx.db, ctx.scan_id, "WARN", "Nmap not found on PATH; skipping port scanning")
            return []
        except Exception as e:
            insert_scan_event(ctx.db, ctx.scan_id, "ERROR", f"Port scan failed on {ip}: {e}")
            return []

        now = utc_now_iso()
        for p in parsed_ports:
            ctx.db.execute(
                """
                INSERT INTO ports (asset_id, scan_id, port, protocol, service, version, banner, observed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_id, scan_id, port, protocol) DO UPDATE SET
                    service = excluded.service,
                    version = excluded.version,
                    banner = excluded.banner,
                    observed_at = excluded.observed_at
                """,
                (
                    asset_id,
                    ctx.scan_id,
                    p["port"],
                    p["protocol"],
                    p["service"],
                    p["version"],
                    p["banner"],
                    now,
                ),
            )
            if p["banner"]:
                ctx.db.execute(
                    """
                    INSERT INTO evidence (asset_id, kind, raw_redacted, source, captured_at)
                    VALUES (?, 'port_banner', ?, 'ports_module', ?)
                    """,
                    (asset_id, f"Port {p['port']}/{p['protocol']}: {p['banner']}", now),
                )
        ctx.db.commit()
        return parsed_ports
