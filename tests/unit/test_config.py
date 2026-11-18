"""Unit tests for configuration manager and validation."""

import os

import pytest

from reconx.core.config import (
    ProfileType,
    TelegramNotificationConfig,
    load_settings,
)


def test_load_settings_defaults(tmp_path):
    # Non-existent file should fall back to cautious defaults
    settings = load_settings(settings_path=tmp_path / "nonexistent.yaml")
    assert settings.profile == ProfileType.CAUTIOUS
    assert settings.request_control.concurrency == 1
    assert settings.request_control.global_rate.requests_per_second == 1.0
    assert settings.request_control.per_host.requests_per_second == 1.0
    assert settings.request_control.delay.minimum == 1.0
    assert settings.request_control.delay.maximum == 2.0


def test_load_settings_normal_profile(tmp_path):
    settings = load_settings(
        settings_path=tmp_path / "nonexistent.yaml",
        profile_override="normal",
    )
    assert settings.profile == ProfileType.NORMAL
    assert settings.request_control.concurrency == 3
    assert settings.request_control.global_rate.requests_per_second == 5.0
    assert settings.request_control.per_host.requests_per_second == 2.0


def test_program_custom_requires_policy_url(tmp_path):
    with pytest.raises(ValueError, match="policy_url"):
        load_settings(
            settings_path=tmp_path / "nonexistent.yaml",
            profile_override="program-custom",
        )


def test_invalid_yaml_fails(tmp_path):
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("profile: [unclosed list", encoding="utf-8")
    with pytest.raises(ValueError, match="Failed to parse"):
        load_settings(settings_path=bad_yaml)


def test_invalid_delays_fail(tmp_path):
    bad_yaml = tmp_path / "bad_delay.yaml"
    bad_yaml.write_text(
        """
request_control:
  delay:
    minimum: 5.0
    maximum: 1.0
""",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="minimum delay .* cannot exceed maximum delay"):
        load_settings(settings_path=bad_yaml)


def test_rate_lowering_and_raising_with_confirm():
    # Lowering rate from 1.0 to 0.5 without confirm_rate is allowed
    s_lowered = load_settings(cli_overrides={"rate": 0.5}, confirm_rate=False)
    assert s_lowered.request_control.global_rate.requests_per_second == 0.5

    # Raising rate from 1.0 to 10.0 without confirm_rate must fail
    with pytest.raises(ValueError, match="--confirm-rate"):
        load_settings(cli_overrides={"rate": 10.0}, confirm_rate=False)

    # Raising rate with confirm_rate=True succeeds
    s_raised = load_settings(cli_overrides={"rate": 10.0}, confirm_rate=True)
    assert s_raised.request_control.global_rate.requests_per_second == 10.0


def test_concurrency_raising_with_confirm():
    with pytest.raises(ValueError, match="--confirm-rate"):
        load_settings(cli_overrides={"concurrency": 5}, confirm_rate=False)

    s = load_settings(cli_overrides={"concurrency": 5}, confirm_rate=True)
    assert s.request_control.concurrency == 5


def test_secrets_masked_in_repr():
    os.environ["TEST_SECRET_TOKEN"] = "super-secret-telegram-token"
    cfg = TelegramNotificationConfig(
        enabled=True,
        token_env="TEST_SECRET_TOKEN",
        chat_id_env="NON_EXISTENT",
    )
    token = cfg.token
    assert token is not None
    assert token.get_secret_value() == "super-secret-telegram-token"
    assert "super-secret" not in repr(token)
    assert "**********" in repr(token)
