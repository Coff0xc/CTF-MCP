"""
pytest configuration and shared fixtures for CTF-MCP tests
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


@pytest.fixture
def crypto_tools():
    """Fixture for CryptoTools instance"""
    from ctf_mcp.tools.crypto import CryptoTools
    return CryptoTools()


@pytest.fixture
def web_tools():
    """Fixture for WebTools instance"""
    from ctf_mcp.tools.web import WebTools
    return WebTools()


@pytest.fixture
def pwn_tools():
    """Fixture for PwnTools instance"""
    from ctf_mcp.tools.pwn import PwnTools
    return PwnTools()


@pytest.fixture
def reverse_tools():
    """Fixture for ReverseTools instance"""
    from ctf_mcp.tools.reverse import ReverseTools
    return ReverseTools()


@pytest.fixture
def forensics_tools():
    """Fixture for ForensicsTools instance"""
    from ctf_mcp.tools.forensics import ForensicsTools
    return ForensicsTools()


@pytest.fixture
def misc_tools():
    """Fixture for MiscTools instance"""
    from ctf_mcp.tools.misc import MiscTools
    return MiscTools()


@pytest.fixture
def sample_data():
    """Common test data"""
    return {
        "plaintext": "Hello CTF",
        "base64": "SGVsbG8gQ1RG",
        "hex": "48656c6c6f20435446",
        "rot13": "Uryyb PGS",
        "test_url": "http://example.com",
        "test_ip": "127.0.0.1",
    }
