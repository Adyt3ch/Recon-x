"""Unit tests for tool_runner subprocess execution security."""

import pytest

from reconx.core.tool_runner import (
    OptionInjectionError,
    ToolExecutionError,
    ToolMissing,
    ToolRunner,
)


def test_tool_runner_rejects_leading_hyphen_target():
    runner = ToolRunner(scan_id="RX-TEST")
    with pytest.raises(OptionInjectionError):
        runner.run("subfinder", args=["-rl", "10"], target="-d evil.com")


def test_tool_runner_requires_rate_limit_flag():
    runner = ToolRunner(scan_id="RX-TEST")
    # Subfinder requires -rl or -rate-limit
    with pytest.raises(ToolExecutionError, match="rate limit flag"):
        runner.run("subfinder", args=["-silent"], target="example.com")


def test_tool_runner_missing_binary():
    runner = ToolRunner(scan_id="RX-TEST")
    with pytest.raises(ToolMissing):
        runner.run("nonexistent_binary_xyz_123", args=["-rl", "10"], target="example.com")
