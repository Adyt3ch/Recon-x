"""Unit tests for URL, hostname, IP, and port normalization."""

import pytest

from reconx.core.normalizer import (
    NormalizationError,
    normalize_hostname,
    normalize_ip,
    normalize_port,
    normalize_url,
)


def test_normalize_hostname_trailing_dot_and_case():
    res = normalize_hostname("EXAMPLE.com.")
    assert res.value == "example.com"
    assert res.flags.get("trailing_dot") is True


def test_normalize_hostname_punycode_and_idna():
    res = normalize_hostname("bücher.example")
    assert res.value == "xn--bcher-kva.example"
    assert res.flags.get("is_idna") is True


def test_normalize_hostname_rejections():
    for bad in ["exa mple.com", "a..b.com", ".example.com", "example..com", ""]:
        with pytest.raises(NormalizationError):
            normalize_hostname(bad)


def test_normalize_url_default_port_and_fragment():
    res = normalize_url("https://example.com:443/a#x")
    assert res.value == "https://example.com/a"
    assert res.port == 443
    assert res.scheme == "https"
    assert res.host == "example.com"


def test_normalize_url_http_default_port():
    res = normalize_url("http://example.com:80/path?q=1#frag")
    assert res.value == "http://example.com/path?q=1"
    assert res.port == 80


def test_normalize_url_userinfo():
    res = normalize_url("http://example.com@evil.com/")
    assert res.host == "evil.com"
    assert res.flags.get("userinfo_present") is True
    assert res.value == "http://evil.com/"


def test_normalize_url_obfuscated_ip_decimal():
    res = normalize_url("http://2130706433/")
    assert res.host == "127.0.0.1"
    assert res.flags.get("obfuscated_ip") is True
    assert res.value == "http://127.0.0.1/"


def test_normalize_url_obfuscated_ip_octal():
    res = normalize_url("http://0177.0.0.1/")
    assert res.host == "127.0.0.1"
    assert res.flags.get("obfuscated_ip") is True
    assert res.value == "http://127.0.0.1/"


def test_normalize_url_ipv6():
    res = normalize_url("http://[::1]:8080/")
    assert res.host == "::1"
    assert res.port == 8080
    assert res.value == "http://[::1]:8080/"


def test_normalize_url_invalid_schemes():
    for bad in ["ftp://example.com", "file:///etc/passwd", "javascript:alert(1)"]:
        with pytest.raises(NormalizationError):
            normalize_url(bad)


def test_normalize_ip():
    assert normalize_ip("127.0.0.1").value == "127.0.0.1"
    assert normalize_ip("2130706433").value == "127.0.0.1"
    assert normalize_ip("2130706433").flags.get("obfuscated_ip") is True
    assert normalize_ip("0177.0.0.1").value == "127.0.0.1"
    assert normalize_ip("::ffff:127.0.0.1").value == "127.0.0.1"
    assert normalize_ip("::1").value == "::1"

    with pytest.raises(NormalizationError):
        normalize_ip("999.999.999.999")


def test_normalize_port():
    assert normalize_port(80) == 80
    assert normalize_port("443") == 443

    for bad in [0, 65536, -1, "abc"]:
        with pytest.raises(NormalizationError):
            normalize_port(bad)


def test_normalizer_idempotence():
    test_urls = [
        "https://EXAMPLE.COM/foo/bar?b=2&a=1#section",
        "http://[::1]:8080/test",
        "http://127.0.0.1:80/",
        "https://bücher.example:443/",
        "http://admin:pass@test.example.com/login",
    ]
    for raw in test_urls:
        norm1 = normalize_url(raw)
        norm2 = normalize_url(norm1.value)
        assert norm1.value == norm2.value
        assert norm1.host == norm2.host
        assert norm1.port == norm2.port
        assert norm1.scheme == norm2.scheme
