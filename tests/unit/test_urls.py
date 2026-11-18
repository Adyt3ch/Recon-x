"""Unit tests for URL discovery, normalization, categorization, robots, and sitemap parsing."""

from pathlib import Path

from reconx.integrations.gau import parse_gau_output
from reconx.integrations.katana import parse_katana_jsonl
from reconx.modules.urls import (
    categorize_url,
    clean_url,
    extract_parameters,
    parse_robots_txt,
    parse_sitemap_xml,
)


def test_clean_url_deduplication_and_sorting():
    # 1. Query param ordering: ?b=1&a=2 equals ?a=2&b=1
    u1 = clean_url("https://example.com/search?b=1&a=2")
    u2 = clean_url("https://example.com/search?a=2&b=1")
    assert u1 == u2
    assert u1 == "https://example.com/search?a=2&b=1"

    # 2. Fragment dropping
    u3 = clean_url("https://example.com/page#section2")
    assert u3 == "https://example.com/page"

    # 3. Default port stripping
    u4 = clean_url("https://example.com:443/home")
    u5 = clean_url("http://example.com:80/home")
    assert u4 == "https://example.com/home"
    assert u5 == "http://example.com/home"

    # 4. Tracking parameter stripping
    u6 = clean_url("https://example.com/product?id=123&utm_source=twitter&utm_medium=cpc&gclid=xyz")
    assert u6 == "https://example.com/product?id=123"


def test_categorize_url():
    cases = [
        ("https://example.com/auth/login", "login"),
        ("https://example.com/admin/dashboard", "admin"),
        ("https://example.com/api/v1/users", "api"),
        ("https://example.com/upload/avatar.png", "upload"),
        ("https://example.com/swagger/index.html", "docs"),
        ("https://example.com/graphql", "graphql"),
        ("https://example.com/static/style.css", "static"),
        ("https://example.com/about-us", None),
    ]
    for url, expected_cat in cases:
        assert categorize_url(url) == expected_cat


def test_extract_parameters():
    params = extract_parameters("https://example.com/api?token=secret123&user_id=456&role=admin")
    assert params == ["role", "token", "user_id"]
    # Empty query
    assert extract_parameters("https://example.com/home") == []


def test_parse_robots_txt():
    robots_content = """
    User-agent: *
    Disallow: /admin/
    Disallow: /private/data
    Allow: /public/
    # Comment line
    Disallow: /secret.txt
    """
    paths = parse_robots_txt(robots_content, "https://example.com")
    assert "https://example.com/admin/" in paths
    assert "https://example.com/private/data" in paths
    assert "https://example.com/public/" in paths
    assert "https://example.com/secret.txt" in paths


def test_parse_sitemap_xml():
    xml = b"""<?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
      <url>
        <loc>https://example.com/page1</loc>
        <lastmod>2026-01-01</lastmod>
      </url>
      <url>
        <loc>https://example.com/page2</loc>
      </url>
    </urlset>
    """
    pages, nested = parse_sitemap_xml(xml, "https://example.com/sitemap.xml")
    assert pages == ["https://example.com/page1", "https://example.com/page2"]
    assert nested == []

    # Sitemap index test
    index_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
    <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
      <sitemap>
        <loc>https://example.com/sub-sitemap.xml</loc>
      </sitemap>
    </sitemapindex>
    """
    p2, n2 = parse_sitemap_xml(index_xml, "https://example.com/sitemap.xml")
    assert p2 == []
    assert n2 == ["https://example.com/sub-sitemap.xml"]


def test_katana_parser_fixture():
    fixture_path = Path("tests/fixtures/katana_sample.jsonl")
    urls = parse_katana_jsonl(fixture_path.read_text(encoding="utf-8"))
    assert "https://example.com/" in urls
    assert "https://example.com/about" in urls
    assert "https://example.com/login?redirect=/dashboard" in urls
    assert "https://example.com/api/v1/users?page=1&limit=10" in urls
    assert "https://evil.com/out-of-scope" in urls


def test_gau_parser_fixture():
    fixture_path = Path("tests/fixtures/gau_sample.txt")
    urls = parse_gau_output(fixture_path.read_text(encoding="utf-8"))
    assert "https://example.com/" in urls
    assert "https://example.com/index.html" in urls
    assert "https://example.com/old-login" in urls
    assert "https://out-of-scope.net/page" in urls
