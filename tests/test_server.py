"""
Tests for server module and dynamic tool registration
"""

import pytest
from unittest.mock import Mock, patch


class TestToolRegistry:
    """Test dynamic tool registration system"""

    def test_registry_initialization(self):
        """Test that tool registry initializes correctly"""
        from ctf_mcp.server import TOOL_REGISTRY, register_tools

        # Clear registry first
        TOOL_REGISTRY.clear()

        # Register tools
        register_tools()

        # Verify tools are registered
        assert len(TOOL_REGISTRY) > 0
        assert "crypto_base64_encode" in TOOL_REGISTRY
        assert "web_sql_payloads" in TOOL_REGISTRY

    def test_all_modules_registered(self):
        """Test that all tool modules are registered"""
        from ctf_mcp.server import TOOL_REGISTRY, register_tools

        TOOL_REGISTRY.clear()
        register_tools()

        # Check for tools from each module
        prefixes = ["crypto_", "web_", "pwn_", "reverse_", "forensics_", "misc_"]
        for prefix in prefixes:
            tools_with_prefix = [k for k in TOOL_REGISTRY.keys() if k.startswith(prefix)]
            assert len(tools_with_prefix) > 0, f"No tools found with prefix {prefix}"


class TestToolModules:
    """Test that all tool modules can be imported"""

    def test_crypto_tools_import(self):
        """Test CryptoTools can be imported"""
        from ctf_mcp.tools.crypto import CryptoTools
        tools = CryptoTools()
        assert tools is not None
        assert hasattr(tools, 'get_tools')

    def test_web_tools_import(self):
        """Test WebTools can be imported"""
        from ctf_mcp.tools.web import WebTools
        tools = WebTools()
        assert tools is not None
        assert hasattr(tools, 'get_tools')

    def test_pwn_tools_import(self):
        """Test PwnTools can be imported"""
        from ctf_mcp.tools.pwn import PwnTools
        tools = PwnTools()
        assert tools is not None
        assert hasattr(tools, 'get_tools')

    def test_reverse_tools_import(self):
        """Test ReverseTools can be imported"""
        from ctf_mcp.tools.reverse import ReverseTools
        tools = ReverseTools()
        assert tools is not None
        assert hasattr(tools, 'get_tools')

    def test_forensics_tools_import(self):
        """Test ForensicsTools can be imported"""
        from ctf_mcp.tools.forensics import ForensicsTools
        tools = ForensicsTools()
        assert tools is not None
        assert hasattr(tools, 'get_tools')

    def test_misc_tools_import(self):
        """Test MiscTools can be imported"""
        from ctf_mcp.tools.misc import MiscTools
        tools = MiscTools()
        assert tools is not None
        assert hasattr(tools, 'get_tools')


class TestToolListing:
    """Test MCP tool listing functionality"""

    @pytest.mark.asyncio
    async def test_list_tools_returns_tools(self):
        """Test that list_tools returns a list of Tool objects"""
        from ctf_mcp.server import list_tools

        # Call the list_tools function directly
        tools = await list_tools()

        assert isinstance(tools, list)
        assert len(tools) > 0

        # Check first tool has required attributes
        first_tool = tools[0]
        assert hasattr(first_tool, 'name')
        assert hasattr(first_tool, 'description')
        assert hasattr(first_tool, 'inputSchema')

    @pytest.mark.asyncio
    async def test_list_tools_includes_all_categories(self):
        """Test that list_tools includes tools from all categories"""
        from ctf_mcp.server import list_tools

        tools = await list_tools()
        tool_names = [t.name for t in tools]

        # Check for at least one tool from each category
        assert any(name.startswith("crypto_") for name in tool_names)
        assert any(name.startswith("web_") for name in tool_names)
        assert any(name.startswith("pwn_") for name in tool_names)
        assert any(name.startswith("misc_") for name in tool_names)


class TestToolExecution:
    """Test tool execution through call_tool"""

    @pytest.mark.asyncio
    async def test_call_tool_crypto_base64(self):
        """Test calling crypto_base64_encode tool"""
        from ctf_mcp.server import call_tool, register_tools

        register_tools()

        # Call the tool directly
        result = await call_tool(
            name="crypto_base64_encode",
            arguments={"data": "Hello"}
        )

        assert len(result) > 0
        assert result[0].type == "text"
        assert "SGVsbG8" in result[0].text or "base64" in result[0].text.lower()

    @pytest.mark.asyncio
    async def test_call_tool_unknown(self):
        """Test calling unknown tool returns error"""
        from ctf_mcp.server import call_tool, register_tools

        register_tools()

        result = await call_tool(
            name="unknown_tool_xyz",
            arguments={}
        )

        assert len(result) > 0
        assert "unknown" in result[0].text.lower() or "error" in result[0].text.lower()

    @pytest.mark.asyncio
    async def test_call_tool_with_error(self):
        """Test that tool errors are handled gracefully"""
        from ctf_mcp.server import call_tool, register_tools

        register_tools()

        # Call tool with invalid arguments
        result = await call_tool(
            name="crypto_base64_encode",
            arguments={}  # Missing required 'data' argument
        )

        assert len(result) > 0
        assert "error" in result[0].text.lower()
