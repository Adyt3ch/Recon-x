"""Pytest configuration and global fixtures for RECON-X."""

import os
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


def pytest_configure(config):
    config.addinivalue_line("markers", "integration: mark test as requiring mock server")
    config.addinivalue_line("markers", "tools: mark test as requiring external tools on PATH (Kali)")
    config.addinivalue_line("markers", "lab: mark test as requiring Docker lab targets")


def pytest_runtest_setup(item):
    if "lab" in item.keywords and not os.environ.get("RECONX_LAB"):
        pytest.skip("Skipping lab test: RECONX_LAB=1 not set")

    if "tools" in item.keywords:
        # Check if external tools are present
        required_tools = ["subfinder", "katana", "nuclei", "nmap"]
        missing = [t for t in required_tools if shutil.which(t) is None]
        if missing:
            pytest.skip(f"Skipping tools test: missing binaries on PATH: {', '.join(missing)}")


@pytest.fixture(scope="session")
def mock_server():
    """Start local threaded HTTP mock server for integration tests."""
    from tests.mock_server.server import ThreadedMockServer

    server = ThreadedMockServer(host="127.0.0.1", port=0)
    server.start()
    yield server
    server.stop()
