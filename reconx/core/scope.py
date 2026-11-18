"""Scope engine for RECON-X.

Enforces default-deny scoping, whole-label domain matching, CIDR and IP checks,
port verification, automatic exclusion precedence, and redirect/DNS verification.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Sequence

from reconx.core.config import ScopeConfig
from reconx.core.normalizer import (
    NormalizationError,
    normalize_hostname,
    normalize_ip,
    normalize_port,
    normalize_url,
)


@dataclass
class ScopeDecision:
    """Represents a scope evaluation decision."""
    allowed: bool
    rule: str | None = None
    reason: str = ""


class ScopeEngine:
    """Engine that validates targets, URLs, redirects, and resolved IPs against scope."""

    def __init__(self, config: ScopeConfig):
        self.config = config
        self._init_rules()

    def _init_rules(self) -> None:
        """Parse and prepare domain, IP, and CIDR rules for fast, accurate matching."""
        # 1. In-scope domains
        self.in_exact_domains: set[str] = set()
        self.in_wildcard_domains: list[str] = []

        for d in self.config.in_scope.domains:
            d = d.strip().lower()
            if not d:
                continue
            if d.startswith("*."):
                wild_suffix = d[2:]
                try:
                    norm = normalize_hostname(wild_suffix).value
                    self.in_wildcard_domains.append(norm)
                except NormalizationError:
                    pass
            else:
                try:
                    norm = normalize_hostname(d).value
                    self.in_exact_domains.add(norm)
                except NormalizationError:
                    pass

        # 2. Out-of-scope domains (exclusions)
        self.out_exact_domains: set[str] = set()
        self.out_wildcard_domains: list[str] = []

        for d in self.config.out_of_scope.domains:
            d = d.strip().lower()
            if not d:
                continue
            if d.startswith("*."):
                wild_suffix = d[2:]
                try:
                    norm = normalize_hostname(wild_suffix).value
                    self.out_wildcard_domains.append(norm)
                except NormalizationError:
                    pass
            else:
                try:
                    norm = normalize_hostname(d).value
                    self.out_exact_domains.add(norm)
                except NormalizationError:
                    pass

        # 3. CIDRs and IPs
        self.in_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for c in self.config.in_scope.cidrs:
            c = c.strip()
            if c:
                try:
                    self.in_cidrs.append(ipaddress.ip_network(c, strict=False))
                except ValueError:
                    pass

        self.in_ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        for ip in self.config.in_scope.ips:
            ip = ip.strip()
            if ip:
                try:
                    norm = normalize_ip(ip).value
                    self.in_ips.add(ipaddress.ip_address(norm))
                except (ValueError, NormalizationError):
                    pass

        self.out_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for c in self.config.out_of_scope.cidrs:
            c = c.strip()
            if c:
                try:
                    self.out_cidrs.append(ipaddress.ip_network(c, strict=False))
                except ValueError:
                    pass

        self.out_ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        for ip in self.config.out_of_scope.ips:
            ip = ip.strip()
            if ip:
                try:
                    norm = normalize_ip(ip).value
                    self.out_ips.add(ipaddress.ip_address(norm))
                except (ValueError, NormalizationError):
                    pass

        # 4. Web ports
        self.web_ports = set(self.config.in_scope.web_ports or [80, 443, 8080, 8443])

    def _is_ip(self, host: str) -> bool:
        """Check if a string represents an IP address."""
        try:
            normalize_ip(host)
            return True
        except NormalizationError:
            return False

    def _matches_domain_exclusion(self, hostname: str) -> tuple[bool, str]:
        """Check if hostname matches any out-of-scope domain rule."""
        if hostname in self.out_exact_domains:
            return True, f"Excluded exact domain rule {hostname}"

        labels = hostname.split(".")
        for wild in self.out_wildcard_domains:
            wild_labels = wild.split(".")
            if len(labels) > len(wild_labels):
                if labels[-len(wild_labels):] == wild_labels:
                    return True, f"Excluded wildcard domain rule *.{wild}"

        return False, ""

    def _matches_domain_inclusion(self, hostname: str) -> tuple[bool, str | None, str]:
        """Check if hostname matches any in-scope domain rule."""
        if hostname in self.in_exact_domains:
            return True, hostname, f"Matches in-scope domain {hostname}"

        labels = hostname.split(".")
        for wild in self.in_wildcard_domains:
            wild_labels = wild.split(".")
            if len(labels) > len(wild_labels):
                if labels[-len(wild_labels):] == wild_labels:
                    return True, f"*.{wild}", f"Matches in-scope wildcard *.{wild}"

        return False, None, "No in-scope domain rule matched"

    def _check_ip_address(self, ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ScopeDecision:
        """Check an IP address against exclusions, private/loopback defaults, and inclusions."""
        # Unmap IPv4-mapped IPv6
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
            ip_obj = ip_obj.ipv4_mapped

        # 1. Out-of-scope exclusions always win
        if ip_obj in self.out_ips:
            return ScopeDecision(
                allowed=False,
                reason=f"IP {ip_obj} matches out-of-scope IP rule",
            )
        for c in self.out_cidrs:
            if ip_obj in c:
                return ScopeDecision(
                    allowed=False,
                    rule=str(c),
                    reason=f"IP {ip_obj} is inside out-of-scope CIDR {c}",
                )

        # 2. Check if explicitly allowed in scope
        explicitly_allowed = False
        allowed_rule = None
        if ip_obj in self.in_ips:
            explicitly_allowed = True
            allowed_rule = str(ip_obj)
        else:
            for c in self.in_cidrs:
                if ip_obj in c:
                    explicitly_allowed = True
                    allowed_rule = str(c)
                    break

        if explicitly_allowed:
            return ScopeDecision(
                allowed=True,
                rule=allowed_rule,
                reason=f"IP {ip_obj} matches in-scope rule {allowed_rule}",
            )

        # 3. Deny loopback, private, link-local, multicast, reserved by default
        if (
            ip_obj.is_loopback
            or ip_obj.is_private
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
        ):
            return ScopeDecision(
                allowed=False,
                reason=f"IP {ip_obj} is private, loopback, or link-local and not explicitly in scope",
            )

        return ScopeDecision(
            allowed=False,
            reason=f"IP {ip_obj} is not covered by any in-scope IP/CIDR rule",
        )

    def check(self, target: str) -> ScopeDecision:
        """Check whether a URL, hostname, or IP target is inside scope."""
        raw = target.strip()
        if not raw:
            return ScopeDecision(allowed=False, reason="Empty target")

        host = ""
        port: int | None = None

        # Check if target is a full URL or contains a scheme
        if "://" in raw:
            try:
                norm_url = normalize_url(raw)
                host = norm_url.host
                port = norm_url.port
                if norm_url.scheme not in ("http", "https"):
                    return ScopeDecision(
                        allowed=False,
                        reason=f"Unsupported scheme {norm_url.scheme!r} (only http/https allowed)",
                    )
            except NormalizationError as e:
                return ScopeDecision(allowed=False, reason=f"Invalid URL: {e}")
        else:
            # Check for host:port format
            if ":" in raw and not raw.startswith("[") and not raw.count(":") > 1:
                h, _, p = raw.partition(":")
                try:
                    port = normalize_port(p)
                    raw = h
                except NormalizationError:
                    pass

            # Try normalizing as IP or Hostname
            try:
                ip_norm = normalize_ip(raw)
                host = ip_norm.value
            except NormalizationError:
                try:
                    host_norm = normalize_hostname(raw)
                    host = host_norm.value
                except NormalizationError as e:
                    return ScopeDecision(allowed=False, reason=f"Invalid host: {e}")

        # Port validation if port was determined
        if port is not None and self.web_ports:
            if port not in self.web_ports:
                return ScopeDecision(
                    allowed=False,
                    reason=f"Port {port} is not in allowed web ports {sorted(self.web_ports)}",
                )

        # Evaluate IP address
        if self._is_ip(host):
            ip_val = normalize_ip(host).value
            ip_obj = ipaddress.ip_address(ip_val)
            return self._check_ip_address(ip_obj)

        # Evaluate Hostname
        # 1. Out-of-scope exclusions
        is_excluded, excl_reason = self._matches_domain_exclusion(host)
        if is_excluded:
            return ScopeDecision(allowed=False, reason=excl_reason)

        # 2. In-scope inclusions
        is_included, rule, incl_reason = self._matches_domain_inclusion(host)
        if is_included:
            return ScopeDecision(allowed=True, rule=rule, reason=incl_reason)

        return ScopeDecision(
            allowed=False,
            reason=f"Hostname {host} is not covered by any in-scope domain rule",
        )

    def check_redirect(self, from_url: str, to_url: str) -> ScopeDecision:
        """Check whether following a redirect to `to_url` is permitted by scope."""
        decision = self.check(to_url)
        if not decision.allowed:
            return ScopeDecision(
                allowed=False,
                reason=f"Redirect to out-of-scope destination {to_url} blocked: {decision.reason}",
            )
        return decision

    def recheck_after_dns(self, host: str, ips: Sequence[str]) -> ScopeDecision:
        """Verify that resolved IP addresses for an in-scope host do not violate scope.

        Blocks DNS rebinding to loopback, private ranges, or out-of-scope IP blocks.
        """
        # First verify the host itself
        host_decision = self.check(host)
        if not host_decision.allowed:
            return host_decision

        if not ips:
            return ScopeDecision(allowed=False, reason=f"Host {host} resolved to no IP addresses")

        for ip_str in ips:
            try:
                ip_val = normalize_ip(ip_str).value
                ip_obj = ipaddress.ip_address(ip_val)
                if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
                    ip_obj = ip_obj.ipv4_mapped

                # 1. Out-of-scope exclusions always win
                if ip_obj in self.out_ips:
                    return ScopeDecision(
                        allowed=False,
                        reason=f"Host {host} resolved to excluded out-of-scope IP {ip_obj}",
                    )
                for c in self.out_cidrs:
                    if ip_obj in c:
                        return ScopeDecision(
                            allowed=False,
                            reason=f"Host {host} resolved to IP {ip_obj} inside excluded CIDR {c}",
                        )

                # 2. Check if private / loopback / link-local / reserved
                if (
                    ip_obj.is_loopback
                    or ip_obj.is_private
                    or ip_obj.is_link_local
                    or ip_obj.is_multicast
                    or ip_obj.is_reserved
                ):
                    in_explicit = (ip_obj in self.in_ips) or any(ip_obj in c for c in self.in_cidrs)
                    if not in_explicit:
                        return ScopeDecision(
                            allowed=False,
                            reason=f"Host {host} resolved to private/loopback/metadata IP {ip_obj} not explicitly in scope",
                        )

            except NormalizationError as e:
                return ScopeDecision(
                    allowed=False,
                    reason=f"Host {host} resolved to invalid IP {ip_str}: {e}",
                )

        return ScopeDecision(
            allowed=True,
            reason=f"Host {host} and all {len(ips)} resolved IPs are authorized in scope",
        )
