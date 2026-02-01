"""
Tool Bindings for ReAct Agent

Connects CTF-MCP tools to the LLM agent.
"""

import inspect
import json
import logging
from typing import Any, Callable, Optional

logger = logging.getLogger("ctf-mcp.llm.agent.tools")


class ToolRegistry:
    """
    Registry for tools available to the agent.

    Tools are registered with:
    - Name: Unique identifier
    - Function: The callable to execute
    - Description: Human-readable description
    - Parameters: JSON schema for parameters
    """

    def __init__(self):
        self._tools: dict[str, dict] = {}

    def register(
        self,
        name: str,
        func: Callable,
        description: str = "",
        parameters: Optional[dict] = None,
    ) -> None:
        """
        Register a tool.

        Args:
            name: Tool name
            func: Callable to execute
            description: Description for LLM
            parameters: JSON schema for parameters (auto-generated if not provided)
        """
        if parameters is None:
            parameters = self._generate_schema(func)

        self._tools[name] = {
            "function": func,
            "description": description or func.__doc__ or "No description",
            "parameters": parameters,
        }

    def get(self, name: str) -> Optional[dict]:
        """Get tool by name"""
        return self._tools.get(name)

    def call(self, name: str, **kwargs) -> Any:
        """Call a tool by name"""
        tool = self._tools.get(name)
        if not tool:
            raise ValueError(f"Unknown tool: {name}")
        return tool["function"](**kwargs)

    async def acall(self, name: str, **kwargs) -> Any:
        """Async call a tool by name"""
        tool = self._tools.get(name)
        if not tool:
            raise ValueError(f"Unknown tool: {name}")

        result = tool["function"](**kwargs)
        if hasattr(result, "__await__"):
            result = await result
        return result

    def get_openai_tools(self) -> list[dict]:
        """Get tools in OpenAI function format"""
        tools = []
        for name, tool in self._tools.items():
            tools.append({
                "type": "function",
                "function": {
                    "name": name,
                    "description": tool["description"],
                    "parameters": tool["parameters"],
                }
            })
        return tools

    def get_tools_dict(self) -> dict[str, Callable]:
        """Get tools as name -> callable dictionary"""
        return {name: tool["function"] for name, tool in self._tools.items()}

    def get_descriptions(self) -> str:
        """Get formatted tool descriptions"""
        lines = []
        for name, tool in self._tools.items():
            desc = tool["description"].split("\n")[0][:100]
            lines.append(f"- {name}: {desc}")
        return "\n".join(lines)

    def _generate_schema(self, func: Callable) -> dict:
        """Generate JSON schema from function signature"""
        sig = inspect.signature(func)
        properties = {}
        required = []

        for param_name, param in sig.parameters.items():
            if param_name == "self":
                continue

            # Determine type from annotation
            param_type = "string"
            if param.annotation != inspect.Parameter.empty:
                anno = param.annotation
                if anno == int:
                    param_type = "integer"
                elif anno == float:
                    param_type = "number"
                elif anno == bool:
                    param_type = "boolean"
                elif anno == list:
                    param_type = "array"
                elif anno == dict:
                    param_type = "object"

            properties[param_name] = {"type": param_type}

            # Check if required
            if param.default == inspect.Parameter.empty:
                required.append(param_name)

        return {
            "type": "object",
            "properties": properties,
            "required": required,
        }

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def __len__(self) -> int:
        return len(self._tools)


class CTFToolBinder:
    """
    Binds CTF-MCP tool modules to a ToolRegistry.

    Automatically discovers and registers tools from:
    - CryptoTools
    - WebTools
    - PwnTools
    - ReverseTools
    - ForensicsTools
    - MiscTools
    """

    # Methods to exclude from registration
    EXCLUDE_METHODS = {"get_tools", "__init__", "__class__"}

    def __init__(self, registry: Optional[ToolRegistry] = None):
        self.registry = registry or ToolRegistry()

    def bind_all(self) -> ToolRegistry:
        """Bind all CTF-MCP tools to the registry"""
        from ctf_mcp.tools.crypto import CryptoTools
        from ctf_mcp.tools.web import WebTools
        from ctf_mcp.tools.pwn import PwnTools
        from ctf_mcp.tools.reverse import ReverseTools
        from ctf_mcp.tools.forensics import ForensicsTools
        from ctf_mcp.tools.misc import MiscTools

        modules = [
            ("crypto", CryptoTools()),
            ("web", WebTools()),
            ("pwn", PwnTools()),
            ("reverse", ReverseTools()),
            ("forensics", ForensicsTools()),
            ("misc", MiscTools()),
        ]

        for prefix, module in modules:
            self._bind_module(prefix, module)

        return self.registry

    def _bind_module(self, prefix: str, module: Any) -> None:
        """Bind all tools from a module"""
        # Get tool descriptions from get_tools()
        tool_descriptions = {}
        if hasattr(module, "get_tools"):
            tool_descriptions = module.get_tools()

        # Register each tool
        for method_name in dir(module):
            if method_name.startswith("_") or method_name in self.EXCLUDE_METHODS:
                continue

            method = getattr(module, method_name, None)
            if not callable(method):
                continue

            # Build tool name
            tool_name = f"{prefix}_{method_name}"

            # Get description
            description = tool_descriptions.get(method_name, method.__doc__ or "")

            try:
                self.registry.register(
                    name=tool_name,
                    func=method,
                    description=description,
                )
                logger.debug("Registered tool: %s", tool_name)
            except Exception as e:
                logger.warning("Failed to register %s: %s", tool_name, e)

    def bind_custom(self, name: str, func: Callable, description: str = "") -> None:
        """Bind a custom tool"""
        self.registry.register(name, func, description)


def create_ctf_agent_tools() -> ToolRegistry:
    """Create a ToolRegistry with all CTF-MCP tools bound"""
    binder = CTFToolBinder()
    return binder.bind_all()
