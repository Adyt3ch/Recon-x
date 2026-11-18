"""AST-based security guard ensuring no module bypasses the central request controller

or tool runner.

Rule:
1. No module in reconx/ except reconx/core/request_manager.py may import httpx, requests,
   aiohttp, urllib.request, socket, or dns.resolver.
2. No module in reconx/ except reconx/core/tool_runner.py may import subprocess.
"""

import ast
from pathlib import Path

FORBIDDEN_NETWORK_MODULES = {
    "httpx",
    "requests",
    "aiohttp",
    "urllib.request",
    "socket",
    "dns.resolver",
    "dns",
}

ALLOWED_NETWORK_FILES = {
    Path("reconx/core/request_manager.py"),
}

ALLOWED_SUBPROCESS_FILES = {
    Path("reconx/core/tool_runner.py"),
}


def test_no_network_bypass_ast_guard():
    root = Path("reconx")
    py_files = list(root.rglob("*.py"))
    assert len(py_files) > 0, "No python files found in reconx package"

    violations = []

    for file_path in py_files:
        norm_path = file_path.as_posix()
        tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))

        for node in ast.walk(tree):
            # Check `import X`
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.name
                    # Network imports
                    for forbidden in FORBIDDEN_NETWORK_MODULES:
                        if name == forbidden or name.startswith(f"{forbidden}."):
                            if Path(norm_path) not in ALLOWED_NETWORK_FILES:
                                violations.append(
                                    f"Illegal network import {name!r} in {norm_path} (line {node.lineno})"
                                )
                    # Subprocess import
                    if name == "subprocess" or name.startswith("subprocess."):
                        if Path(norm_path) not in ALLOWED_SUBPROCESS_FILES:
                            violations.append(
                                f"Illegal subprocess import {name!r} in {norm_path} (line {node.lineno})"
                            )

            # Check `from X import Y`
            elif isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                # Network imports
                for forbidden in FORBIDDEN_NETWORK_MODULES:
                    if mod == forbidden or mod.startswith(f"{forbidden}."):
                        if Path(norm_path) not in ALLOWED_NETWORK_FILES:
                            violations.append(
                                f"Illegal network import from {mod!r} in {norm_path} (line {node.lineno})"
                            )
                # Subprocess import
                if mod == "subprocess" or mod.startswith("subprocess."):
                    if Path(norm_path) not in ALLOWED_SUBPROCESS_FILES:
                        violations.append(
                            f"Illegal subprocess import from {mod!r} in {norm_path} (line {node.lineno})"
                        )

    assert not violations, "Security Bypass Violations Found:\n" + "\n".join(violations)
