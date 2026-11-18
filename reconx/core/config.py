"""Configuration management and Pydantic models for RECON-X."""

from __future__ import annotations

import copy
import os
from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator


class ProfileType(str, Enum):
    CAUTIOUS = "cautious"
    NORMAL = "normal"
    PROGRAM_CUSTOM = "program-custom"


class ProgramConfig(BaseModel):
    name: str = "example-program"
    policy_url: str = ""
    user_agent: str = "RECON-X/0.1 (authorized security assessment)"
    extra_headers: dict[str, str] = Field(default_factory=dict)


class GlobalRateConfig(BaseModel):
    requests_per_second: float = Field(default=1.0, gt=0)
    requests_per_minute: int = Field(default=30, gt=0)


class HostRateConfig(BaseModel):
    requests_per_second: float = Field(default=1.0, gt=0)
    requests_per_minute: int = Field(default=30, gt=0)


class DelayConfig(BaseModel):
    minimum: float = Field(default=1.0, ge=0)
    maximum: float = Field(default=2.0, ge=0)

    @model_validator(mode="after")
    def validate_delays(self) -> DelayConfig:
        if self.minimum > self.maximum:
            raise ValueError(f"minimum delay ({self.minimum}) cannot exceed maximum delay ({self.maximum})")
        return self


class BudgetConfig(BaseModel):
    max_requests: int = Field(default=1000, gt=0)


class TimeoutConfig(BaseModel):
    connect: float = Field(default=5.0, gt=0)
    read: float = Field(default=10.0, gt=0)


class LimitsConfig(BaseModel):
    max_response_bytes: int = Field(default=2_000_000, gt=0)
    max_redirects: int = Field(default=3, ge=0)


class RetryConfig(BaseModel):
    max_attempts: int = Field(default=1, ge=0)
    respect_retry_after: bool = True


class BackoffConfig(BaseModel):
    enabled: bool = True
    initial_delay: float = Field(default=30.0, gt=0)
    maximum_delay: float = Field(default=300.0, gt=0)


class ProtectionConfig(BaseModel):
    pause_on_429: bool = True
    pause_on_503: bool = True
    pause_on_repeated_errors: bool = True
    repeated_error_threshold: int = Field(default=5, gt=0)
    preserve_results_on_stop: bool = True


class RequestControlConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    concurrency: int = Field(default=1, ge=1)
    global_rate: GlobalRateConfig = Field(default_factory=GlobalRateConfig, alias="global")
    per_host: HostRateConfig = Field(default_factory=HostRateConfig)
    delay: DelayConfig = Field(default_factory=DelayConfig)
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    timeouts: TimeoutConfig = Field(default_factory=TimeoutConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    retry: RetryConfig = Field(default_factory=RetryConfig)
    backoff: BackoffConfig = Field(default_factory=BackoffConfig)
    protection: ProtectionConfig = Field(default_factory=ProtectionConfig)


class ExternalToolSettings(BaseModel):
    path: str = "auto"
    rate_limit: int | None = None
    rate: int | None = None
    depth: int | None = None
    timeout: int = 300
    enabled: bool = True


class ExternalToolsConfig(BaseModel):
    subfinder: ExternalToolSettings = Field(
        default_factory=lambda: ExternalToolSettings(rate_limit=10, timeout=300)
    )
    katana: ExternalToolSettings = Field(
        default_factory=lambda: ExternalToolSettings(rate_limit=1, depth=2, timeout=600)
    )
    naabu: ExternalToolSettings = Field(
        default_factory=lambda: ExternalToolSettings(rate=100, enabled=False)
    )
    nuclei: ExternalToolSettings = Field(
        default_factory=lambda: ExternalToolSettings(rate_limit=1, enabled=False)
    )


class StorageConfig(BaseModel):
    database: str = "data/reconx.db"
    reports_dir: str = "reports"
    logs_dir: str = "logs"


class TelegramNotificationConfig(BaseModel):
    enabled: bool = False
    token_env: str = "RECONX_TELEGRAM_TOKEN"
    chat_id_env: str = "RECONX_TELEGRAM_CHAT"

    @property
    def token(self) -> SecretStr | None:
        val = os.environ.get(self.token_env)
        return SecretStr(val) if val else None

    @property
    def chat_id(self) -> str | None:
        return os.environ.get(self.chat_id_env)


class NotificationsConfig(BaseModel):
    telegram: TelegramNotificationConfig = Field(default_factory=TelegramNotificationConfig)


class AuthProfileConfig(BaseModel):
    hosts: list[str] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)


class Settings(BaseModel):
    profile: ProfileType = ProfileType.CAUTIOUS
    program: ProgramConfig = Field(default_factory=ProgramConfig)
    request_control: RequestControlConfig = Field(default_factory=RequestControlConfig)
    external_tools: ExternalToolsConfig = Field(default_factory=ExternalToolsConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    notifications: NotificationsConfig = Field(default_factory=NotificationsConfig)
    auth_profiles: dict[str, AuthProfileConfig] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_profile_rules(self) -> Settings:
        if self.profile == ProfileType.PROGRAM_CUSTOM:
            if not self.program.policy_url.strip():
                raise ValueError(
                    "Profile 'program-custom' requires program.policy_url to be specified."
                )
        return self


# Scope Config Models
class ScopeInScope(BaseModel):
    domains: list[str] = Field(default_factory=list)
    cidrs: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    web_ports: list[int] = Field(default_factory=lambda: [80, 443, 8080, 8443])


class ScopeOutOfScope(BaseModel):
    domains: list[str] = Field(default_factory=list)
    cidrs: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)


class ScopeRules(BaseModel):
    allow_port_scan: bool = False
    allow_nuclei: bool = False
    max_requests: int = 1000


class ScopeConfig(BaseModel):
    program: str = "example-program"
    authorized_by: str = ""
    in_scope: ScopeInScope = Field(default_factory=ScopeInScope)
    out_of_scope: ScopeOutOfScope = Field(default_factory=ScopeOutOfScope)
    rules: ScopeRules = Field(default_factory=ScopeRules)


# Profile Defaults
PROFILE_DEFAULTS: dict[ProfileType, dict[str, Any]] = {
    ProfileType.CAUTIOUS: {
        "request_control": {
            "concurrency": 1,
            "global": {"requests_per_second": 1.0, "requests_per_minute": 30},
            "per_host": {"requests_per_second": 1.0, "requests_per_minute": 30},
            "delay": {"minimum": 1.0, "maximum": 2.0},
        },
        "external_tools": {
            "naabu": {"enabled": False},
            "nuclei": {"enabled": False},
        },
    },
    ProfileType.NORMAL: {
        "request_control": {
            "concurrency": 3,
            "global": {"requests_per_second": 5.0, "requests_per_minute": 150},
            "per_host": {"requests_per_second": 2.0, "requests_per_minute": 60},
            "delay": {"minimum": 0.5, "maximum": 1.5},
        },
    },
    ProfileType.PROGRAM_CUSTOM: {},
}


def load_settings(
    settings_path: Path | str | None = None,
    profile_override: ProfileType | str | None = None,
    cli_overrides: dict[str, Any] | None = None,
    confirm_rate: bool = False,
) -> Settings:
    """Load settings by merging Profile defaults, then settings.yaml, then CLI overrides.

    Enforces that raising rate limits above profile defaults requires confirm_rate=True.
    """
    raw_data: dict[str, Any] = {}

    # 1. Determine profile
    resolved_profile = ProfileType.CAUTIOUS
    if profile_override:
        resolved_profile = ProfileType(profile_override)

    # 2. Load settings file if exists
    path = Path(settings_path) if settings_path else Path("config/settings.yaml")
    if path.is_file():
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = yaml.safe_load(f) or {}
                if isinstance(content, dict):
                    raw_data = content
        except Exception as e:
            raise ValueError(f"Failed to parse settings file {path}: {e}") from e

    # Profile in file overrides default if not CLI provided
    if not profile_override and "profile" in raw_data:
        resolved_profile = ProfileType(raw_data["profile"])

    # 3. Base on profile defaults
    profile_defaults = copy.deepcopy(PROFILE_DEFAULTS.get(resolved_profile, {}))
    merged: dict[str, Any] = {
        "profile": resolved_profile.value,
        **profile_defaults,
    }

    # Deep merge raw_data into merged
    def deep_update(base: dict, update: dict) -> dict:
        for k, v in update.items():
            if isinstance(v, dict) and k in base and isinstance(base[k], dict):
                deep_update(base[k], v)
            else:
                base[k] = v
        return base

    deep_update(merged, raw_data)

    # 4. Apply CLI overrides
    if cli_overrides:
        baseline_rate = merged.get("request_control", {}).get("global", {}).get("requests_per_second", 1.0)
        baseline_concurrency = merged.get("request_control", {}).get("concurrency", 1)

        req_ctrl = merged.setdefault("request_control", {})

        if "rate" in cli_overrides and cli_overrides["rate"] is not None:
            new_rate = float(cli_overrides["rate"])
            if new_rate <= 0:
                raise ValueError("Rate must be greater than 0")
            if new_rate > baseline_rate and not confirm_rate:
                raise ValueError(
                    f"Raising rate from {baseline_rate} to {new_rate} requires --confirm-rate"
                )
            req_ctrl.setdefault("global", {})["requests_per_second"] = new_rate
            req_ctrl.setdefault("per_host", {})["requests_per_second"] = min(
                new_rate, req_ctrl.get("per_host", {}).get("requests_per_second", new_rate)
            )

        if "concurrency" in cli_overrides and cli_overrides["concurrency"] is not None:
            new_conc = int(cli_overrides["concurrency"])
            if new_conc < 1:
                raise ValueError("Concurrency must be at least 1")
            if new_conc > baseline_concurrency and not confirm_rate:
                raise ValueError(
                    f"Raising concurrency from {baseline_concurrency} to {new_conc} requires --confirm-rate"
                )
            req_ctrl["concurrency"] = new_conc

        if "max_requests" in cli_overrides and cli_overrides["max_requests"] is not None:
            new_budget = int(cli_overrides["max_requests"])
            if new_budget <= 0:
                raise ValueError("max_requests must be greater than 0")
            req_ctrl.setdefault("budget", {})["max_requests"] = new_budget

    return Settings.model_validate(merged)


def load_scope(scope_path: Path | str | None = None) -> ScopeConfig:
    """Load and validate scope.yaml."""
    path = Path(scope_path) if scope_path else Path("config/scope.yaml")
    if not path.is_file():
        # Return default empty scope
        return ScopeConfig()

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            if not isinstance(data, dict):
                raise ValueError(f"Scope file {path} must contain a YAML dictionary")
            return ScopeConfig.model_validate(data)
    except Exception as e:
        raise ValueError(f"Failed to load scope from {path}: {e}") from e
