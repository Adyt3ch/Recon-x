"""Unit tests for JavaScript intelligence, endpoint extraction, and secret scanning."""

import json
from pathlib import Path

from reconx.modules.javascript import (
    extract_cdn_library,
    extract_endpoints_from_js,
    extract_secrets_from_js,
    find_script_urls,
    redact_secret_preview,
    shannon_entropy,
)


def test_find_script_urls():
    html = """
    <html>
      <head>
        <script src="/static/js/main.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"></script>
      </head>
      <body>
        <script>console.log("inline");</script>
        <script src="/app.bundle.js"></script>
      </body>
    </html>
    """
    scripts = find_script_urls(html, "https://example.com/dashboard")
    assert "https://example.com/static/js/main.js" in scripts
    assert "https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js" in scripts
    assert "https://example.com/app.bundle.js" in scripts
    assert len(scripts) == 3


def test_extract_cdn_library():
    res1 = extract_cdn_library("https://cdn.example.com/libs/jquery-3.6.0.min.js")
    assert res1 is not None
    assert res1[0] == "jQuery"
    assert res1[1] == "3.6.0"

    res2 = extract_cdn_library("https://cdnjs.cloudflare.com/ajax/libs/react/17.0.2/react.production.min.js")
    assert res2 is not None
    assert res2[0] == "React"

    res3 = extract_cdn_library("https://example.com/custom-app.js")
    assert res3 is None


def test_extract_endpoints_and_record_metrics(tmp_path):
    js_sample = """
    // API endpoints in application JS
    const apiBase = "/api/v1/auth/login";
    fetch("/api/v2/products/search?q=test");
    axios.get("/api/v1/users/profile");
    $.post("/rest/checkout");
    const ws = new WebSocket("wss://example.com/ws/notifications");
    let normalVar = "not an endpoint";
    """
    endpoints = extract_endpoints_from_js(js_sample)
    expected_endpoints = {
        "/api/v1/auth/login",
        "/api/v2/products/search?q=test",
        "/api/v1/users/profile",
        "/rest/checkout",
        "wss://example.com/ws/notifications",
    }

    found_set = set(endpoints)
    true_positives = len(found_set.intersection(expected_endpoints))
    false_positives = len(found_set - expected_endpoints)
    false_negatives = len(expected_endpoints - found_set)

    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) else 0.0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) else 0.0

    assert precision >= 0.9
    assert recall >= 0.9

    # Record metrics to tests/metrics/js_endpoints.json
    metrics_dir = Path("tests/metrics")
    metrics_dir.mkdir(parents=True, exist_ok=True)
    metrics_file = metrics_dir / "js_endpoints.json"
    metrics_data = {
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
    }
    metrics_file.write_text(json.dumps(metrics_data, indent=2), encoding="utf-8")
    assert metrics_file.exists()


def test_secret_detection_and_redaction():
    # AWS documentation example key (AKIAIOSFODNN7EXAMPLE)
    raw_aws = "AKIAIOSFODNN7EXAMPLE"
    # Google API Key example
    raw_google = "AIzaSyD-1234567890abcdefghijklmnopqrst"

    js_code = f"""
    const awsKey = "{raw_aws}";
    const gKey = "{raw_google}";
    const randomHex = "0123456789abcdef"; // Low entropy or non-matching token
    """

    secrets = extract_secrets_from_js(js_code)
    assert len(secrets) >= 2

    patterns_found = [s[0] for s in secrets]
    previews = [s[1] for s in secrets]
    assert len(previews) >= 2

    assert "AWS Access Key" in patterns_found
    assert "Google API Key" in patterns_found

    # Gate: secret candidates must never appear in full anywhere
    for _, preview, _ in secrets:
        assert raw_aws not in preview
        assert raw_google not in preview
        assert "..." in preview
        assert "length" in preview

    # Verify preview helper
    assert redact_secret_preview(raw_aws) == "AKIA... (length 20)"


def test_shannon_entropy():
    # Uniform high-entropy string vs repeated low-entropy
    low_ent = shannon_entropy("aaaaaaaaaaaa")
    high_ent = shannon_entropy("abcdefghijklmnopqrstuvwxyz0123456789!@#$%^")
    assert low_ent == 0.0
    assert high_ent > 4.5
