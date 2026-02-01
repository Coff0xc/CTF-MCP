"""
MCP Dynamic Tools Registry
Automatic tool discovery, registration, and schema generation
"""

import inspect
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Type, get_type_hints
from enum import Enum

logger = logging.getLogger("ctf-mcp.mcp.registry")


class ToolCategory(Enum):
    """Tool categories for organization"""
    CRYPTO = "crypto"
    WEB = "web"
    PWN = "pwn"
    REVERSE = "reverse"
    FORENSICS = "forensics"
    MISC = "misc"
    NETWORK = "network"
    ORCHESTRATION = "orchestration"


@dataclass
class ToolParameter:
    """Tool parameter definition"""
    name: str
    type: str
    description: str = ""
    required: bool = True
    default: Any = None
    enum: Optional[list[str]] = None


@dataclass
class ToolDefinition:
    """Complete tool definition"""
    name: str
    description: str
    category: ToolCategory
    handler: Callable
    parameters: list[ToolParameter] = field(default_factory=list)
    returns: str = "string"
    enabled: bool = True
    tags: list[str] = field(default_factory=list)

    def to_mcp_schema(self) -> dict:
        """Generate MCP-compatible tool schema"""
        properties = {}
        required = []

        for param in self.parameters:
            prop = {"type": param.type}
            if param.description:
                prop["description"] = param.description
            if param.enum:
                prop["enum"] = param.enum
            if param.default is not None:
                prop["default"] = param.default

            properties[param.name] = prop

            if param.required:
                required.append(param.name)

        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        }


class ToolsRegistry:
    """
    Dynamic registry for MCP tools.

    Features:
    - Auto-discovery from modules
    - Schema generation
    - Hot registration/unregistration
    - Category management
    - Tool enable/disable
    """

    def __init__(self):
        self._tools: dict[str, ToolDefinition] = {}
        self._categories: dict[ToolCategory, list[str]] = {cat: [] for cat in ToolCategory}
        self._modules: dict[str, Any] = {}

    def register(
        self,
        name: str,
        handler: Callable,
        description: str = "",
        category: ToolCategory = ToolCategory.MISC,
        parameters: Optional[list[ToolParameter]] = None,
        tags: Optional[list[str]] = None,
    ) -> ToolDefinition:
        """
        Register a tool.

        Args:
            name: Tool name
            handler: Tool handler function
            description: Tool description
            category: Tool category
            parameters: Parameter definitions (auto-detected if None)
            tags: Search tags

        Returns:
            ToolDefinition
        """
        if parameters is None:
            parameters = self._extract_parameters(handler)

        if not description:
            description = handler.__doc__ or f"Execute {name}"

        tool = ToolDefinition(
            name=name,
            description=description,
            category=category,
            handler=handler,
            parameters=parameters,
            tags=tags or [],
        )

        self._tools[name] = tool
        self._categories[category].append(name)

        logger.debug("Registered tool: %s (%s)", name, category.value)
        return tool

    def unregister(self, name: str) -> bool:
        """
        Unregister a tool.

        Args:
            name: Tool name

        Returns:
            True if tool was removed
        """
        if name not in self._tools:
            return False

        tool = self._tools.pop(name)
        self._categories[tool.category].remove(name)

        logger.debug("Unregistered tool: %s", name)
        return True

    def get(self, name: str) -> Optional[ToolDefinition]:
        """Get tool by name"""
        return self._tools.get(name)

    def list_all(self) -> list[str]:
        """List all registered tool names"""
        return list(self._tools.keys())

    def list_enabled(self) -> list[str]:
        """List only enabled tools"""
        return [name for name, tool in self._tools.items() if tool.enabled]

    def list_by_category(self, category: ToolCategory) -> list[str]:
        """List tools in category"""
        return self._categories.get(category, [])

    def enable(self, name: str) -> bool:
        """Enable a tool"""
        if name in self._tools:
            self._tools[name].enabled = True
            return True
        return False

    def disable(self, name: str) -> bool:
        """Disable a tool"""
        if name in self._tools:
            self._tools[name].enabled = False
            return True
        return False

    def get_mcp_tools(self) -> list[dict]:
        """Get all enabled tools as MCP schemas"""
        return [
            tool.to_mcp_schema()
            for tool in self._tools.values()
            if tool.enabled
        ]

    def discover_from_module(
        self,
        module: Any,
        prefix: str,
        category: ToolCategory,
    ) -> int:
        """
        Auto-discover and register tools from a module.

        Args:
            module: Module to scan
            prefix: Tool name prefix
            category: Category for discovered tools

        Returns:
            Number of tools registered
        """
        count = 0

        # Look for get_tools() method
        if hasattr(module, 'get_tools'):
            tools_dict = module.get_tools()
            for tool_name, description in tools_dict.items():
                full_name = f"{prefix}_{tool_name}"

                # Get handler
                handler = getattr(module, tool_name, None)
                if handler and callable(handler):
                    self.register(
                        name=full_name,
                        handler=handler,
                        description=description,
                        category=category,
                    )
                    count += 1

        self._modules[prefix] = module
        logger.info("Discovered %d tools from %s", count, prefix)
        return count

    def discover_from_class(
        self,
        cls: Type,
        prefix: str,
        category: ToolCategory,
        instance: Optional[Any] = None,
    ) -> int:
        """
        Auto-discover tools from a class.

        Args:
            cls: Class to scan
            prefix: Tool name prefix
            category: Category
            instance: Class instance (created if None)

        Returns:
            Number of tools registered
        """
        if instance is None:
            instance = cls()

        count = 0

        # Look for get_tools() method
        if hasattr(instance, 'get_tools'):
            tools_dict = instance.get_tools()
            for tool_name, description in tools_dict.items():
                full_name = f"{prefix}_{tool_name}"

                handler = getattr(instance, tool_name, None)
                if handler and callable(handler):
                    self.register(
                        name=full_name,
                        handler=handler,
                        description=description,
                        category=category,
                    )
                    count += 1

        return count

    def _extract_parameters(self, func: Callable) -> list[ToolParameter]:
        """Extract parameters from function signature"""
        params = []
        sig = inspect.signature(func)

        # Try to get type hints
        try:
            hints = get_type_hints(func)
        except Exception:
            hints = {}

        for name, param in sig.parameters.items():
            if name == 'self':
                continue

            # Determine type
            type_hint = hints.get(name, param.annotation)
            param_type = self._python_type_to_json(type_hint)

            # Check if required
            required = param.default == inspect.Parameter.empty

            # Get default
            default = None if required else param.default

            params.append(ToolParameter(
                name=name,
                type=param_type,
                required=required,
                default=default,
            ))

        return params

    def _python_type_to_json(self, type_hint) -> str:
        """Convert Python type hint to JSON schema type"""
        if type_hint == inspect.Parameter.empty:
            return "string"

        type_map = {
            str: "string",
            int: "integer",
            float: "number",
            bool: "boolean",
            list: "array",
            dict: "object",
            bytes: "string",
        }

        # Handle Optional, Union, etc.
        origin = getattr(type_hint, '__origin__', None)
        if origin is not None:
            if origin is list:
                return "array"
            if origin is dict:
                return "object"

        return type_map.get(type_hint, "string")

    async def execute(self, name: str, arguments: dict) -> Any:
        """
        Execute a tool.

        Args:
            name: Tool name
            arguments: Tool arguments

        Returns:
            Tool result
        """
        tool = self.get(name)
        if not tool:
            raise ValueError(f"Unknown tool: {name}")

        if not tool.enabled:
            raise ValueError(f"Tool disabled: {name}")

        # Execute handler
        result = tool.handler(**arguments)

        # Handle async
        if inspect.iscoroutine(result):
            result = await result

        return result

    def search(self, query: str) -> list[ToolDefinition]:
        """
        Search tools by name, description, or tags.

        Args:
            query: Search query

        Returns:
            List of matching tools
        """
        query = query.lower()
        results = []

        for tool in self._tools.values():
            if (query in tool.name.lower() or
                query in tool.description.lower() or
                any(query in tag.lower() for tag in tool.tags)):
                results.append(tool)

        return results

    def get_stats(self) -> dict:
        """Get registry statistics"""
        return {
            "total": len(self._tools),
            "enabled": len(self.list_enabled()),
            "by_category": {
                cat.value: len(tools)
                for cat, tools in self._categories.items()
            },
        }


# Global registry instance
_registry = ToolsRegistry()


def get_registry() -> ToolsRegistry:
    """Get global registry instance"""
    return _registry


def register_tool(
    name: str,
    category: ToolCategory = ToolCategory.MISC,
    description: str = "",
    tags: Optional[list[str]] = None,
):
    """
    Decorator to register a function as a tool.

    Usage:
        @register_tool("my_tool", ToolCategory.CRYPTO)
        def my_tool(arg1: str, arg2: int = 10) -> str:
            ...
    """
    def decorator(func: Callable) -> Callable:
        _registry.register(
            name=name,
            handler=func,
            description=description or func.__doc__ or "",
            category=category,
            tags=tags,
        )
        return func
    return decorator
