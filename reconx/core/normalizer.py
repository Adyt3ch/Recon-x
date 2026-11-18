"""Normalizer module for hostnames, URLs, IPs, and ports.

Provides rigorous normalization, homoglyph handling via IDNA, obfuscated IP detection,
and URL canonicalization with security flag tracking.
"""

from __future__ import annotations

import ipaddress
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import idna


class NormalizationError(ValueError):
    """Raised when an input cannot be normalized or is malformed."""
    pass


@dataclass
class NormalizedResult:
    """Represents a normalized network identifier with metadata flags."""
    value: str
    host: str = ""
    port: int | None = None
    scheme: str = ""
    path: str = ""
    query: str = ""
    flags: dict[str, Any] = field(default_factory=dict)


def normalize_port(port: int | str) -> int:
    """Validate and normalize a port number (1-65535)."""
    try:
        p = int(port)
    except (ValueError, TypeError) as e:
        raise NormalizationError(f"Invalid port: {port}") from e

    if not (1 <= p <= 65535):
        raise NormalizationError(f"Port out of valid range (1-65535): {p}")
    return p


def _try_parse_obfuscated_ipv4(host: str) -> tuple[str | None, bool]:
    """Attempt to decode integer, octal, or hex obfuscated IPv4 addresses."""
    # Strip any brackets
    raw = host.strip("[]")

    # 1. Check for single DWORD / integer IP (e.g. 2130706433 or 0x7f000001)
    if raw.isdigit():
        try:
            val = int(raw)
            if 0 <= val <= 0xFFFFFFFF:
                ip_obj = ipaddress.IPv4Address(val)
                return str(ip_obj), True
        except (ValueError, ipaddress.AddressValueError):
            pass

    # 2. Check for hex DWORD (0x...)
    if raw.lower().startswith("0x") and not any(sep in raw for sep in [".", ":"]):
        try:
            val = int(raw, 16)
            if 0 <= val <= 0xFFFFFFFF:
                ip_obj = ipaddress.IPv4Address(val)
                return str(ip_obj), True
        except ValueError:
            pass

    # 3. Check for dotted octal or hex parts (e.g. 0177.0.0.1 or 0x7f.0.0.1)
    if "." in raw and ":" not in raw:
        parts = raw.split(".")
        if len(parts) == 4:
            parsed_octets = []
            obfuscated = False
            for part in parts:
                if not part:
                    return None, False
                try:
                    if part.lower().startswith("0x"):
                        val = int(part, 16)
                        obfuscated = True
                    elif part.startswith("0") and len(part) > 1 and part.isdigit():
                        val = int(part, 8)
                        obfuscated = True
                    elif part.isdigit():
                        val = int(part, 10)
                    else:
                        return None, False
                    if not (0 <= val <= 255):
                        return None, False
                    parsed_octets.append(str(val))
                except ValueError:
                    return None, False

            if obfuscated and len(parsed_octets) == 4:
                return ".".join(parsed_octets), True

    return None, False


def normalize_ip(ip_str: str) -> NormalizedResult:
    """Normalize IPv4 or IPv6 address and flag any obfuscations."""
    cleaned = ip_str.strip().strip("[]")
    if not cleaned:
        raise NormalizationError("Empty IP address string")

    flags: dict[str, Any] = {}

    # Check for obfuscated representations first
    obf_ip, is_obfuscated = _try_parse_obfuscated_ipv4(cleaned)
    if is_obfuscated and obf_ip:
        flags["obfuscated_ip"] = True
        cleaned = obf_ip

    try:
        ip_obj = ipaddress.ip_address(cleaned)
    except ValueError as e:
        raise NormalizationError(f"Invalid IP address: {ip_str}") from e

    # Handle IPv4-mapped IPv6 (e.g., ::ffff:192.0.2.1)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        ipv4 = str(ip_obj.ipv4_mapped)
        flags["ipv4_mapped"] = True
        return NormalizedResult(value=ipv4, host=ipv4, flags=flags)

    canon = str(ip_obj)
    return NormalizedResult(value=canon, host=canon, flags=flags)


def normalize_hostname(host: str) -> NormalizedResult:
    """Normalize a hostname using IDNA (punycode) and strip trailing dots.

    Validates whole labels, rejects spaces, double dots, and invalid characters.
    """
    raw = host.strip()
    if not raw:
        raise NormalizationError("Empty hostname")

    flags: dict[str, Any] = {}

    # Check trailing dot
    if raw.endswith("."):
        flags["trailing_dot"] = True
        raw = raw[:-1]

    if not raw or " " in raw or ".." in raw or raw.startswith(".") or raw.endswith("."):
        raise NormalizationError(f"Malformed hostname: {host!r}")

    # Process each label with IDNA encoding
    labels = raw.split(".")
    encoded_labels = []
    has_idna = False

    for label in labels:
        if not label:
            raise NormalizationError(f"Empty label in hostname: {host!r}")
        # RFC 1035 label length <= 63
        try:
            enc = idna.encode(label, uts46=True).decode("ascii").lower()
            if enc.startswith("xn--"):
                has_idna = True
            # Reject invalid characters in encoded label
            if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", enc):
                raise NormalizationError(f"Invalid characters in hostname label: {label!r}")
            encoded_labels.append(enc)
        except (idna.IDNAError, UnicodeError) as e:
            raise NormalizationError(f"IDNA normalization failed for {label!r}: {e}") from e

    if has_idna:
        flags["is_idna"] = True

    canonical = ".".join(encoded_labels)
    if len(canonical) > 253:
        raise NormalizationError(f"Hostname exceeds maximum 253 characters: {canonical}")

    return NormalizedResult(value=canonical, host=canonical, flags=flags)


def normalize_url(raw_url: str) -> NormalizedResult:
    """Canonicalize a URL: check scheme, extract userinfo, normalize host and port,

    strip fragments, and format path.
    """
    url_str = raw_url.strip()
    if not url_str:
        raise NormalizationError("Empty URL")

    # If scheme missing, we only allow parsing with explicit scheme or raise
    parsed = urllib.parse.urlsplit(url_str)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise NormalizationError(f"Scheme {scheme!r} not supported (must be http or https)")

    netloc = parsed.netloc
    if not netloc and not parsed.hostname:
        raise NormalizationError(f"No host present in URL: {raw_url}")

    flags: dict[str, Any] = {}

    # Extract userinfo if present
    if "@" in netloc:
        flags["userinfo_present"] = True
        _, _, host_port = netloc.rpartition("@")
    else:
        host_port = netloc

    # Extract host and port
    if host_port.startswith("[") and "]" in host_port:
        # IPv6 URL: [::1]:8080 or [::1]
        host_part, _, port_part = host_port.partition("]")
        host_part = host_part + "]"
        if port_part.startswith(":"):
            port_str = port_part[1:]
        else:
            port_str = ""
    elif ":" in host_port:
        host_part, _, port_str = host_port.rpartition(":")
    else:
        host_part = host_port
        port_str = ""

    # Normalize host: check if it's an IP or hostname
    normalized_host: str
    is_ipv6 = False

    # Check if host_part is an IP (including obfuscated)
    try:
        ip_res = normalize_ip(host_part)
        normalized_host = ip_res.value
        if ip_res.flags:
            flags.update(ip_res.flags)
        try:
            ip_obj = ipaddress.ip_address(normalized_host)
            if isinstance(ip_obj, ipaddress.IPv6Address):
                is_ipv6 = True
        except ValueError:
            pass
    except NormalizationError:
        # Not an IP; normalize as hostname
        host_res = normalize_hostname(host_part)
        normalized_host = host_res.value
        if host_res.flags:
            flags.update(host_res.flags)

    # Normalize port
    port: int
    if port_str:
        port = normalize_port(port_str)
    else:
        port = 443 if scheme == "https" else 80

    # Build canonical netloc
    include_port = not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80))
    if is_ipv6:
        canonical_netloc = f"[{normalized_host}]:{port}" if include_port else f"[{normalized_host}]"
    else:
        canonical_netloc = f"{normalized_host}:{port}" if include_port else normalized_host

    # Canonical path and query (strip fragment)
    path = parsed.path
    if not path:
        path = "/"
    query = parsed.query

    # Reassemble canonical URL
    canon_url = urllib.parse.urlunsplit((scheme, canonical_netloc, path, query, ""))

    return NormalizedResult(
        value=canon_url,
        host=normalized_host,
        port=port,
        scheme=scheme,
        path=path,
        query=query,
        flags=flags,
    )
