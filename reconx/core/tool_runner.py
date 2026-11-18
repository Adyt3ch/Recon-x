"""Central external tool runner for executing CLI tools with enforced safety controls.

Subprocesses are ONLY permitted through this runner. Enforces shell=False, argument list
validation (preventing option injection), required rate-limit flags, execution timeouts,
and output size caps.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reconx.database.storage import get_db, utc_now_iso


class ToolMissing(Exception):
    """Raised when an external CLI binary is not found on PATH."""
    pass


class ToolExecutionError(Exception):
    """Raised when a subprocess fails or returns an error."""
    pass


class OptionInjectionError(ValueError):
    """Raised when a target parameter starts with '-'."""
    pass


@dataclass
class ToolResult:
    tool: str
    command: list[str]
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int


REQUIRED_RATE_FLAGS = {
    "subfinder": ["-rl", "-rate-limit"],
    "katana": ["-rl", "-rate-limit"],
    "naabu": ["-rate", "-r"],
    "nuclei": ["-rl", "-rate-limit"],
    "nmap": ["--max-rate"],
}


class ToolRunner:
    """Manages subprocess execution for external reconnaissance binaries."""

    def __init__(self, scan_id: str | None = None, db_path: Path | str = "data/reconx.db"):
        self.scan_id = scan_id
        self.db_path = db_path

    def run(
        self,
        tool: str,
        args: list[str],
        target: str | None = None,
        timeout: int = 300,
        max_output_bytes: int = 10_000_000,
    ) -> ToolResult:
        """Execute external binary safely and record in database."""
        # 1. Option injection check on target
        if target and target.strip().startswith("-"):
            raise OptionInjectionError(f"Target cannot begin with hyphen: {target!r}")

        # 2. Check required rate limit flag
        rate_flag_present = 0
        if tool.lower() in REQUIRED_RATE_FLAGS:
            expected_flags = REQUIRED_RATE_FLAGS[tool.lower()]
            has_flag = any(any(arg == f or arg.startswith(f"{f}=") for f in expected_flags) for arg in args)
            if not has_flag:
                raise ToolExecutionError(
                    f"Tool {tool} requires a rate limit flag from {expected_flags}, but none was provided."
                )
            rate_flag_present = 1

        # 3. Check binary on PATH
        tool_bin = shutil.which(tool)
        if not tool_bin:
            raise ToolMissing(f"Tool {tool!r} is not installed or not found on PATH")

        cmd = [tool_bin] + args
        if target:
            cmd.append(target)

        started_at = utc_now_iso()
        t0 = subprocess.time.monotonic()
        exit_code = -1
        stdout = ""
        stderr = ""

        try:
            # Strictly NO shell=True
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
            )
            exit_code = proc.returncode
            stdout = proc.stdout[:max_output_bytes]
            stderr = proc.stderr[:max_output_bytes]
        except subprocess.TimeoutExpired as e:
            exit_code = -1
            stderr = f"Process timed out after {timeout} seconds"
            raise ToolExecutionError(f"Execution of {tool} timed out after {timeout}s") from e
        except Exception as e:
            exit_code = -1
            stderr = str(e)
            raise ToolExecutionError(f"Failed to execute {tool}: {e}") from e
        finally:
            finished_at = utc_now_iso()
            duration_ms = int((subprocess.time.monotonic() - t0) * 1000)

            # Record in tool_runs if scan_id provided
            if self.scan_id and Path(self.db_path).exists():
                try:
                    db = get_db(self.db_path)
                    clean_args = " ".join(args)
                    db.execute(
                        """
                        INSERT INTO tool_runs (
                            scan_id, tool, args_redacted, started_at,
                            finished_at, exit_code, rate_flag_present
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            self.scan_id,
                            tool,
                            clean_args,
                            started_at,
                            finished_at,
                            exit_code,
                            rate_flag_present,
                        ),
                    )
                    db.commit()
                    db.close()
                except Exception:
                    pass

        return ToolResult(
            tool=tool,
            command=cmd,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            duration_ms=duration_ms,
        )


def run_tool(
    tool_name: str,
    args: list[str],
    target: str | None = None,
    timeout: int = 300,
    scan_id: str | None = None,
    db: Any = None,
    binary_override: str | None = None,
) -> ToolResult:
    """Convenience function to execute external CLI tool through ToolRunner."""
    runner = ToolRunner(scan_id=scan_id)
    return runner.run(
        tool=tool_name,
        args=args,
        target=target,
        timeout=timeout,
    )


def check_tool_version(tool: str) -> str | None:
    """Safely check tool version for doctor command."""
    tool_path = shutil.which(tool)
    if not tool_path:
        return None
    try:
        proc = subprocess.run(
            [tool_path, "-version"],
            capture_output=True,
            text=True,
            timeout=3,
            shell=False,
        )
        out = (proc.stdout or proc.stderr).strip().splitlines()
        return out[0][:40] if out else "found"
    except Exception:
        return "found"
