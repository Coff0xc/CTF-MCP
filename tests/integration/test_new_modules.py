"""
Integration Tests for CTF-MCP New Modules
Tests for engines, adapters, network, mcp, and core modules
"""

import pytest


class TestEnginesIntegration:
    """Integration tests for solving engines"""

    def test_all_engines_import(self):
        """All engines should import successfully"""
        from ctf_mcp.engines import (
            SolvingEngine,
            EngineResult,
            EngineCapability,
            CryptoEngine,
            WebEngine,
            PwnEngine,
            ReverseEngine,
            ForensicsEngine,
            MiscEngine,
            get_engine_for_type,
        )

        assert SolvingEngine is not None
        assert EngineResult is not None
        assert EngineCapability is not None

    def test_engine_routing(self):
        """Engine routing should return correct engine type"""
        from ctf_mcp.engines import get_engine_for_type

        assert get_engine_for_type("crypto").name == "crypto"
        assert get_engine_for_type("web").name == "web"
        assert get_engine_for_type("pwn").name == "pwn"
        assert get_engine_for_type("reverse").name == "reverse"
        assert get_engine_for_type("forensics").name == "forensics"
        assert get_engine_for_type("misc").name == "misc"
        # Unknown type should fallback to misc
        assert get_engine_for_type("unknown").name == "misc"

    def test_engine_capabilities(self):
        """Each engine should have defined capabilities"""
        from ctf_mcp.engines import (
            CryptoEngine,
            WebEngine,
            PwnEngine,
            ReverseEngine,
            ForensicsEngine,
            MiscEngine,
            EngineCapability,
        )

        engines = [
            CryptoEngine(),
            WebEngine(),
            PwnEngine(),
            ReverseEngine(),
            ForensicsEngine(),
            MiscEngine(),
        ]

        for engine in engines:
            caps = engine.capabilities
            assert isinstance(caps, list)
            assert len(caps) > 0
            assert all(isinstance(c, EngineCapability) for c in caps)

    def test_engine_result_dataclass(self):
        """EngineResult should work correctly"""
        from ctf_mcp.engines import EngineResult

        result = EngineResult()
        assert result.success is False
        assert result.flag is None
        assert result.steps == []

        result.add_step("Test step")
        assert len(result.steps) == 1
        assert result.steps[0] == "Test step"

        result_dict = result.to_dict()
        assert "success" in result_dict
        assert "flag" in result_dict
        assert "steps" in result_dict


class TestAdaptersIntegration:
    """Integration tests for external tool adapters"""

    def test_all_adapters_import(self):
        """All adapters should import successfully"""
        from ctf_mcp.adapters import (
            ToolAdapter,
            PythonLibraryAdapter,
            AdapterResult,
            AdapterStatus,
            PwntoolsAdapter,
            AngrAdapter,
            SqlmapAdapter,
            HashcatAdapter,
            BinwalkAdapter,
            NmapAdapter,
        )

        assert ToolAdapter is not None
        assert AdapterResult is not None

    def test_adapter_registry(self):
        """Adapter registry should work correctly"""
        from ctf_mcp.adapters import (
            list_adapters,
            list_available_adapters,
            get_adapter_status,
        )

        all_adapters = list_adapters()
        assert isinstance(all_adapters, list)
        assert "pwntools" in all_adapters
        assert "nmap" in all_adapters

        available = list_available_adapters()
        assert isinstance(available, list)

        status = get_adapter_status()
        assert isinstance(status, dict)
        for name, info in status.items():
            assert "status" in info
            assert "available" in info

    def test_adapter_result_dataclass(self):
        """AdapterResult should work correctly"""
        from ctf_mcp.adapters import AdapterResult

        result = AdapterResult()
        assert result.success is False
        assert result.output == ""
        assert result.error is None

        result = AdapterResult(success=True, output="test output")
        result_dict = result.to_dict()
        assert result_dict["success"] is True
        assert "test output" in result_dict["output"]


class TestNetworkIntegration:
    """Integration tests for network module"""

    def test_all_network_import(self):
        """All network components should import"""
        from ctf_mcp.network import (
            RemoteConnection,
            ConnectionResult,
            RemotePool,
            HTTPClient,
            AsyncHTTPClient,
            HTTPResponse,
            ExploitRunner,
            AsyncExploitRunner,
            ExploitResult,
            ExploitStatus,
            ExploitTemplate,
        )

        assert RemoteConnection is not None
        assert HTTPClient is not None
        assert ExploitRunner is not None

    def test_remote_connection_init(self):
        """RemoteConnection should initialize correctly"""
        from ctf_mcp.network import RemoteConnection

        conn = RemoteConnection("localhost", 8080)
        assert conn.host == "localhost"
        assert conn.port == 8080
        assert conn.protocol == "tcp"
        assert conn.connected is False

    def test_http_client_init(self):
        """HTTPClient should initialize correctly"""
        from ctf_mcp.network import HTTPClient

        client = HTTPClient(
            base_url="http://example.com",
            timeout=30.0,
            verify_ssl=False,
        )
        assert client.base_url == "http://example.com"
        assert client.timeout == 30.0
        assert client.verify_ssl is False

    def test_exploit_runner_flag_patterns(self):
        """ExploitRunner should have flag patterns"""
        from ctf_mcp.network import ExploitRunner

        runner = ExploitRunner()
        assert len(runner.FLAG_PATTERNS) > 0

        # Test flag finding
        flags = runner.find_flags("The flag is flag{test_flag_123}")
        assert len(flags) == 1
        assert flags[0] == "flag{test_flag_123}"

    def test_exploit_template_generation(self):
        """ExploitTemplate should generate code"""
        from ctf_mcp.network import ExploitTemplate

        template = ExploitTemplate.buffer_overflow(
            target="127.0.0.1",
            port=1234,
            offset=64,
            payload=b"\x90" * 4,
        )
        assert "pwntools" in template.lower() or "pwn" in template
        assert "127.0.0.1" in template
        assert "1234" in template


class TestMCPIntegration:
    """Integration tests for MCP enhancement module"""

    def test_all_mcp_import(self):
        """All MCP components should import"""
        from ctf_mcp.mcp import (
            ToolsRegistry,
            ToolDefinition,
            ToolParameter,
            ToolCategory,
            TaskManager,
            Task,
            TaskState,
            StreamManager,
            StreamEvent,
            StreamEventType,
        )

        assert ToolsRegistry is not None
        assert TaskManager is not None
        assert StreamManager is not None

    def test_tools_registry(self):
        """ToolsRegistry should work correctly"""
        from ctf_mcp.mcp import ToolsRegistry, ToolCategory

        registry = ToolsRegistry()

        # Register a test tool
        def test_handler(x: str) -> str:
            return f"Result: {x}"

        registry.register(
            name="test_tool",
            handler=test_handler,
            description="A test tool",
            category=ToolCategory.MISC,
        )

        assert "test_tool" in registry.list_all()

        tool = registry.get("test_tool")
        assert tool is not None
        assert tool.name == "test_tool"
        assert tool.category == ToolCategory.MISC

        # Test MCP schema generation
        schema = tool.to_mcp_schema()
        assert "name" in schema
        assert "description" in schema
        assert "inputSchema" in schema

    def test_task_manager(self):
        """TaskManager should work correctly"""
        from ctf_mcp.mcp import TaskManager, TaskState

        manager = TaskManager(max_workers=2)

        task = manager.create_task("test_task", timeout=60)
        assert task.state == TaskState.PENDING
        assert task.name == "test_task"

        # Test listing
        tasks = manager.list_tasks()
        assert len(tasks) >= 1

        # Test stats
        stats = manager.get_stats()
        assert "total" in stats
        assert "by_state" in stats

        manager.shutdown(wait=False)

    def test_stream_manager(self):
        """StreamManager should work correctly"""
        from ctf_mcp.mcp import StreamManager, StreamEventType

        manager = StreamManager()

        emitter = manager.get_emitter("test_stream")

        # Emit events
        event = emitter.progress(50, 100, "Half done")
        assert event.type == StreamEventType.PROGRESS
        assert event.data["current"] == 50
        assert event.data["total"] == 100

        event = emitter.step("Analysis complete")
        assert event.type == StreamEventType.STEP
        assert event.message == "Analysis complete"

        # Test recent events
        events = manager.get_recent_events("test_stream", count=10)
        assert len(events) >= 2


class TestCoreIntegration:
    """Integration tests for core module"""

    def test_knowledge_base_import(self):
        """KnowledgeBase should import correctly"""
        from ctf_mcp.core import (
            KnowledgeBase,
            SolvePattern,
            SolutionCache,
            get_knowledge_base,
        )

        assert KnowledgeBase is not None
        assert SolvePattern is not None

    def test_knowledge_base_patterns(self):
        """KnowledgeBase should have built-in patterns"""
        from ctf_mcp.core import get_knowledge_base

        kb = get_knowledge_base()

        # Check patterns loaded
        patterns = kb.list_patterns()
        assert len(patterns) > 0

        # Check categories
        stats = kb.get_stats()
        assert stats["total_patterns"] > 0
        assert "crypto" in stats["by_category"]
        assert "web" in stats["by_category"]
        assert "pwn" in stats["by_category"]

    def test_knowledge_base_pattern_matching(self):
        """Pattern matching should work"""
        from ctf_mcp.core import get_knowledge_base

        kb = get_knowledge_base()

        # Test RSA pattern matching
        test_content = "Given RSA parameters: n = 12345, e = 65537, c = 9999"
        matches = kb.find_patterns(test_content, category="crypto", min_match=0.2)
        assert len(matches) > 0

        # Test SQL injection pattern matching
        test_content = "Login form with SQL query and database"
        matches = kb.find_patterns(test_content, category="web", min_match=0.2)
        assert len(matches) > 0

    def test_solution_caching(self):
        """Solution caching should work"""
        from ctf_mcp.core import KnowledgeBase

        kb = KnowledgeBase()  # Memory-only

        # Cache a solution
        kb.cache_solution(
            challenge_desc="Test RSA challenge",
            flag="flag{test123}",
            method="factorization",
            steps=["Factor n", "Compute d", "Decrypt"],
        )

        # Lookup
        solution = kb.lookup_solution("Test RSA challenge")
        assert solution is not None
        assert solution.flag == "flag{test123}"
        assert solution.method == "factorization"


class TestFullStackIntegration:
    """Full stack integration tests"""

    def test_engine_with_knowledge_base(self):
        """Engine should work with knowledge base"""
        from ctf_mcp.engines import CryptoEngine
        from ctf_mcp.core import get_knowledge_base

        engine = CryptoEngine()
        kb = get_knowledge_base()

        challenge_desc = """
        RSA Challenge:
        n = 123456789
        e = 65537
        c = 987654321
        """

        # Knowledge base recommendation
        recommendation = kb.get_recommendation(challenge_desc)
        # Should recommend an RSA-related pattern
        if recommendation:
            assert "rsa" in recommendation.id.lower() or "crypto" in recommendation.category

        # Create a mock challenge (use category_hint, not category)
        from ctf_mcp.core import Challenge
        challenge = Challenge(
            name="test",
            description=challenge_desc,
            category_hint="crypto",
        )
        analysis = engine.analyze(challenge)
        assert "crypto_type" in analysis

    def test_module_interoperability(self):
        """All new modules should work together"""
        from ctf_mcp.engines import get_engine_for_type
        from ctf_mcp.adapters import list_adapters
        from ctf_mcp.network import ExploitRunner
        from ctf_mcp.mcp import get_registry, get_task_manager, get_stream_manager
        from ctf_mcp.core import get_knowledge_base

        # All should return valid objects
        assert get_engine_for_type("crypto") is not None
        assert len(list_adapters()) > 0
        assert ExploitRunner() is not None
        assert get_registry() is not None
        assert get_task_manager() is not None
        assert get_stream_manager() is not None
        assert get_knowledge_base() is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
