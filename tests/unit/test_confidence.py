"""Unit tests for asset confidence progression rules."""

from reconx.intelligence.confidence import calculate_asset_confidence, upgrade_confidence


def test_confidence_transitions():
    # 1 source -> low
    assert calculate_asset_confidence(sources=["crtsh"]) == "low"

    # >= 2 sources -> medium
    assert calculate_asset_confidence(sources=["crtsh", "subfinder"]) == "medium"

    # DNS resolves -> high
    assert calculate_asset_confidence(sources=["crtsh"], dns_resolved=True) == "high"
    assert calculate_asset_confidence(sources=["crtsh", "subfinder"], dns_resolved=True) == "high"

    # HTTP live -> verified
    assert calculate_asset_confidence(sources=["crtsh"], dns_resolved=True, http_live=True) == "verified"

    # Wildcard zones -> held at low
    assert calculate_asset_confidence(sources=["crtsh"], dns_resolved=True, is_wildcard=True) == "low"


def test_confidence_never_downgrades():
    assert upgrade_confidence("low", "medium") == "medium"
    assert upgrade_confidence("medium", "high") == "high"
    assert upgrade_confidence("high", "verified") == "verified"

    # Attempted downgrade
    assert upgrade_confidence("high", "low") == "high"
    assert upgrade_confidence("verified", "high") == "verified"
