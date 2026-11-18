"""Unit tests for the ScopeEngine."""

import random
import string

import pytest

from reconx.core.config import ScopeConfig, ScopeInScope, ScopeOutOfScope, ScopeRules
from reconx.core.scope import ScopeEngine


@pytest.fixture
def base_scope():
    return ScopeConfig(
        program="test-program",
        authorized_by="Security team policy",
        in_scope=ScopeInScope(
            domains=["example.com", "*.example.com", "target.org"],
            cidrs=["10.0.0.0/24"],
            ips=["192.168.1.10"],
            web_ports=[80, 443, 8080, 8443],
        ),
        out_of_scope=ScopeOutOfScope(
            domains=["mail.example.com", "*.internal.example.com"],
            cidrs=["10.0.0.128/25"],
            ips=["192.168.1.100"],
        ),
        rules=ScopeRules(
            allow_port_scan=False,
            allow_nuclei=False,
            max_requests=1000,
        ),
    )


def test_scope_exact_domain_match(base_scope):
    engine = ScopeEngine(base_scope)
    decision = engine.check("example.com")
    assert decision.allowed is True
    assert "example.com" in decision.reason.lower()


def test_scope_wildcard_domain_match(base_scope):
    engine = ScopeEngine(base_scope)
    decision = engine.check("a.example.com")
    assert decision.allowed is True
    assert decision.rule == "*.example.com"


def test_scope_wildcard_does_not_match_apex():
    scope = ScopeConfig(
        program="wildcard-only",
        authorized_by="Policy",
        in_scope=ScopeInScope(domains=["*.example.com"]),
        out_of_scope=ScopeOutOfScope(),
        rules=ScopeRules(),
    )
    engine = ScopeEngine(scope)
    decision = engine.check("example.com")
    assert decision.allowed is False
    assert "apex" in decision.reason.lower() or "not covered" in decision.reason.lower()


def test_scope_evilexample_substring_denied(base_scope):
    engine = ScopeEngine(base_scope)
    assert engine.check("evilexample.com").allowed is False
    assert engine.check("example.com.evil.com").allowed is False
    assert engine.check("notexample.com").allowed is False


def test_scope_exclusion_wins(base_scope):
    engine = ScopeEngine(base_scope)
    decision = engine.check("mail.example.com")
    assert decision.allowed is False
    assert "out-of-scope" in decision.reason.lower() or "excluded" in decision.reason.lower()

    decision_sub = engine.check("sub.internal.example.com")
    assert decision_sub.allowed is False


def test_scope_userinfo_check(base_scope):
    engine = ScopeEngine(base_scope)
    decision = engine.check("http://example.com@evil.com/")
    assert decision.allowed is False
    assert "evil.com" in decision.reason.lower() or not decision.allowed


def test_scope_homoglyph_cyrillic(base_scope):
    engine = ScopeEngine(base_scope)
    # Cyrillic 'а' (U+0430) instead of latin 'a'
    cyrillic_host = "exаmple.com"
    decision = engine.check(cyrillic_host)
    assert decision.allowed is False


def test_scope_cidr_match(base_scope):
    engine = ScopeEngine(base_scope)
    assert engine.check("10.0.0.5").allowed is True
    assert engine.check("10.0.1.5").allowed is False
    # Excluded subnet inside in-scope CIDR
    assert engine.check("10.0.0.130").allowed is False


def test_scope_private_and_loopback_denied_by_default():
    scope = ScopeConfig(
        program="clean",
        authorized_by="Policy",
        in_scope=ScopeInScope(domains=["example.com"]),
        out_of_scope=ScopeOutOfScope(),
        rules=ScopeRules(),
    )
    engine = ScopeEngine(scope)
    assert engine.check("127.0.0.1").allowed is False
    assert engine.check("169.254.169.254").allowed is False
    assert engine.check("10.0.0.1").allowed is False
    assert engine.check("::1").allowed is False


def test_scope_ipv4_mapped_ipv6(base_scope):
    engine = ScopeEngine(base_scope)
    decision = engine.check("::ffff:10.0.0.5")
    assert decision.allowed is True


def test_scope_port_restriction(base_scope):
    engine = ScopeEngine(base_scope)
    assert engine.check("http://example.com:80").allowed is True
    assert engine.check("https://example.com:443").allowed is True
    assert engine.check("http://example.com:8080").allowed is True
    assert engine.check("http://example.com:22").allowed is False


def test_scope_redirect_check(base_scope):
    engine = ScopeEngine(base_scope)
    decision = engine.check_redirect("https://example.com/login", "https://evil.com/phish")
    assert decision.allowed is False

    decision_ok = engine.check_redirect("https://example.com/old", "https://a.example.com/new")
    assert decision_ok.allowed is True


def test_scope_recheck_after_dns(base_scope):
    engine = ScopeEngine(base_scope)
    # Host resolves to private metadata or loopback
    decision = engine.recheck_after_dns("a.example.com", ["169.254.169.254"])
    assert decision.allowed is False

    decision_ok = engine.recheck_after_dns("a.example.com", ["93.184.216.34"])
    assert decision_ok.allowed is True


def test_scope_empty():
    empty_scope = ScopeConfig(
        program="empty",
        authorized_by="None",
        in_scope=ScopeInScope(),
        out_of_scope=ScopeOutOfScope(),
        rules=ScopeRules(),
    )
    engine = ScopeEngine(empty_scope)
    assert engine.check("example.com").allowed is False
    assert engine.check("https://example.com/").allowed is False
    assert engine.check("10.0.0.1").allowed is False


def test_scope_fuzz_random_hosts(base_scope):
    engine = ScopeEngine(base_scope)
    rng = random.Random(42)
    for _ in range(200):
        length = rng.randint(5, 15)
        rand_name = "".join(rng.choices(string.ascii_lowercase + string.digits, k=length))
        rand_tld = rng.choice(["org", "net", "io", "co", "xyz"])
        host = f"{rand_name}.{rand_tld}"
        assert engine.check(host).allowed is False


def test_scope_edge_cases_and_coverage(base_scope):
    engine = ScopeEngine(base_scope)

    # Empty target
    assert engine.check("").allowed is False
    assert engine.check("   ").allowed is False

    # Unsupported scheme and invalid URLs
    assert engine.check("ftp://example.com").allowed is False
    assert engine.check("gopher://example.com:70/").allowed is False
    assert engine.check("http:///no-host").allowed is False

    # Invalid host
    assert engine.check("bad..host..").allowed is False

    # Host:port format without scheme
    assert engine.check("example.com:80").allowed is True
    assert engine.check("example.com:22").allowed is False

    # Out of scope exact IP and CIDR
    assert engine.check("192.168.1.100").allowed is False
    assert engine.check("10.0.0.200").allowed is False

    # In scope explicit IP
    assert engine.check("192.168.1.10").allowed is True

    # Reserved and multicast IPs
    assert engine.check("224.0.0.1").allowed is False
    assert engine.check("240.0.0.1").allowed is False

    # recheck_after_dns edges
    assert engine.recheck_after_dns("out-of-scope.com", ["93.184.216.34"]).allowed is False
    assert engine.recheck_after_dns("example.com", []).allowed is False
    assert engine.recheck_after_dns("example.com", ["192.168.1.100"]).allowed is False  # out_ips
    assert engine.recheck_after_dns("example.com", ["10.0.0.200"]).allowed is False  # out_cidrs
    assert engine.recheck_after_dns("example.com", ["invalid-ip"]).allowed is False


def test_scope_config_parsing_invalid_entries():
    bad_cfg = ScopeConfig(
        program="bad-entries",
        authorized_by="Test",
        in_scope=ScopeInScope(
            domains=["*.valid.com", "*.invalid..domain", "valid.com", "invalid..name"],
            cidrs=["10.0.0.0/24", "not-a-cidr"],
            ips=["192.168.1.1", "not-an-ip"],
        ),
        out_of_scope=ScopeOutOfScope(
            domains=["*.out.com", "*.invalid..out", "out.com", "invalid..out"],
            cidrs=["172.16.0.0/16", "bad-out-cidr"],
            ips=["10.0.0.99", "bad-out-ip"],
        ),
        rules=ScopeRules(),
    )
    engine = ScopeEngine(bad_cfg)
    assert engine.check("sub.valid.com").allowed is True
    assert engine.check("valid.com").allowed is True
    assert engine.check("192.168.1.1").allowed is True
    assert engine.check("out.com").allowed is False
    assert engine.check("10.0.0.99").allowed is False
