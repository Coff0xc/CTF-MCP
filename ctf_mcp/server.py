#!/usr/bin/env python3
"""
CTF-MCP Server - MCP Server for CTF Challenges
Provides tools for Crypto, Web, Pwn, Reverse, Forensics, and Misc challenges

Dynamically registers all tools from tool modules using introspection.
"""

import asyncio
import inspect
import json
import logging
import re
from typing import Any, get_type_hints, get_origin, get_args, Union

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from .tools.crypto import CryptoTools
from .tools.web import WebTools
from .tools.pwn import PwnTools
from .tools.reverse import ReverseTools
from .tools.forensics import ForensicsTools
from .tools.misc import MiscTools
from .core.orchestrator import CTFOrchestrator, Challenge, SolveResult

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("ctf-mcp")

# Initialize MCP server
app = Server("ctf-mcp")

# Initialize tool modules
crypto_tools = CryptoTools()
web_tools = WebTools()
pwn_tools = PwnTools()
reverse_tools = ReverseTools()
forensics_tools = ForensicsTools()
misc_tools = MiscTools()

# Module registry
MODULES = [
    ("crypto", crypto_tools),
    ("web", web_tools),
    ("pwn", pwn_tools),
    ("reverse", reverse_tools),
    ("forensics", forensics_tools),
    ("misc", misc_tools),
]

# Tool registry - maps tool names to their handlers
TOOL_REGISTRY: dict[str, tuple[Any, str]] = {}

# Tool schema cache
TOOL_SCHEMAS: dict[str, Tool] = {}


def python_type_to_json_schema(py_type: Any) -> dict:
    """Convert Python type annotation to JSON Schema type"""
    if py_type is None or py_type is type(None):
        return {"type": "null"}

    origin = get_origin(py_type)
    args = get_args(py_type)

    # Handle Optional[X] (Union[X, None])
    if origin is Union:
        non_none_args = [a for a in args if a is not type(None)]
        if len(non_none_args) == 1:
            # Optional[X] -> X with nullable
            return python_type_to_json_schema(non_none_args[0])
        # Union of multiple types - use anyOf
        return {"anyOf": [python_type_to_json_schema(a) for a in non_none_args]}

    # Handle List[X]
    if origin is list:
        if args:
            return {"type": "array", "items": python_type_to_json_schema(args[0])}
        return {"type": "array"}

    # Handle Dict[K, V]
    if origin is dict:
        return {"type": "object"}

    # Basic types
    type_map = {
        str: {"type": "string"},
        int: {"type": "integer"},
        float: {"type": "number"},
        bool: {"type": "boolean"},
        bytes: {"type": "string", "description": "Hex-encoded bytes"},
        list: {"type": "array"},
        dict: {"type": "object"},
    }

    return type_map.get(py_type, {"type": "string"})


def generate_input_schema(module: Any, method_name: str) -> dict:
    """Generate JSON Schema for a method's input parameters"""
    method = getattr(module, method_name)
    sig = inspect.signature(method)

    # Try to get type hints
    try:
        hints = get_type_hints(method)
    except Exception:
        hints = {}

    properties = {}
    required = []

    for param_name, param in sig.parameters.items():
        # Skip 'self' parameter
        if param_name == "self":
            continue

        # Get type from hints or default to string
        param_type = hints.get(param_name, str)
        schema = python_type_to_json_schema(param_type)

        # Add description from docstring if available
        doc = method.__doc__ or ""
        # Try to extract parameter description from docstring
        # Format: :param name: description or name: description
        param_doc_match = re.search(
            rf':param\s+{param_name}:\s*(.+?)(?=\n\s*:|$)',
            doc,
            re.DOTALL
        )
        if param_doc_match:
            schema["description"] = param_doc_match.group(1).strip()

        # Handle default values
        if param.default is not inspect.Parameter.empty:
            schema["default"] = param.default
        else:
            # No default = required
            required.append(param_name)

        properties[param_name] = schema

    return {
        "type": "object",
        "properties": properties,
        "required": required
    }


def register_tools():
    """Register all tools from all modules dynamically"""
    for prefix, module in MODULES:
        # Get tool definitions from module
        tools_dict = module.get_tools()

        for tool_name, description in tools_dict.items():
            full_name = f"{prefix}_{tool_name}"

            # Verify method exists
            if not hasattr(module, tool_name):
                logger.warning("Method %s not found in %s module, skipping", tool_name, prefix)
                continue

            # Register in tool registry
            TOOL_REGISTRY[full_name] = (module, tool_name)

            # Generate schema
            try:
                input_schema = generate_input_schema(module, tool_name)
            except Exception as e:
                logger.warning("Failed to generate schema for %s: %s", full_name, e)
                input_schema = {"type": "object", "properties": {}, "required": []}

            # Create Tool object
            TOOL_SCHEMAS[full_name] = Tool(
                name=full_name,
                description=description,
                inputSchema=input_schema
            )

            logger.debug("Registered tool: %s", full_name)

    logger.info("Registered %d tools", len(TOOL_REGISTRY))

    # Register orchestrator tools
    _register_orchestrator_tools()


def _register_orchestrator_tools():
    """Register orchestrator-specific tools"""
    # Auto-solve tool
    TOOL_SCHEMAS["auto_solve"] = Tool(
        name="auto_solve",
        description="Automatically solve a CTF challenge. Analyzes the challenge, plans strategies, and executes them.",
        inputSchema={
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Challenge name/identifier"
                },
                "description": {
                    "type": "string",
                    "description": "Challenge description text",
                    "default": ""
                },
                "files": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of file paths associated with the challenge",
                    "default": []
                },
                "remote": {
                    "type": "string",
                    "description": "Remote connection info (host:port or URL)",
                    "default": ""
                },
                "flag_format": {
                    "type": "string",
                    "description": "Expected flag format regex",
                    "default": "flag\\{[^}]+\\}"
                },
                "category": {
                    "type": "string",
                    "description": "Category hint (crypto, web, pwn, reverse, forensics, misc)",
                    "default": ""
                },
                "timeout": {
                    "type": "number",
                    "description": "Maximum time in seconds",
                    "default": 300
                }
            },
            "required": ["name"]
        }
    )
    TOOL_REGISTRY["auto_solve"] = (None, "_auto_solve")

    # Classify tool
    TOOL_SCHEMAS["classify_challenge"] = Tool(
        name="classify_challenge",
        description="Classify a CTF challenge type without solving it. Returns likely categories and confidence scores.",
        inputSchema={
            "type": "object",
            "properties": {
                "description": {
                    "type": "string",
                    "description": "Challenge description text",
                    "default": ""
                },
                "files": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of file paths",
                    "default": []
                },
                "remote": {
                    "type": "string",
                    "description": "Remote connection info",
                    "default": ""
                }
            },
            "required": []
        }
    )
    TOOL_REGISTRY["classify_challenge"] = (None, "_classify_challenge")

    logger.info("Registered orchestrator tools: auto_solve, classify_challenge")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List all available CTF tools dynamically"""
    return list(TOOL_SCHEMAS.values())


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Handle tool calls"""
    try:
        # Handle orchestrator tools
        if name == "auto_solve":
            return await _handle_auto_solve(arguments)
        elif name == "classify_challenge":
            return await _handle_classify(arguments)

        # Dynamic tool dispatch using registry
        if name not in TOOL_REGISTRY:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]

        # Get module and method name from registry
        module, method_name = TOOL_REGISTRY[name]

        # Guard against None module (orchestrator tools that weren't handled above)
        if module is None:
            return [TextContent(type="text", text=f"Tool {name} not properly configured")]

        # Get the actual method using getattr
        method = getattr(module, method_name)

        # Call the method with arguments, handling async methods
        result = method(**arguments)

        # Handle async tool handlers
        if inspect.iscoroutine(result):
            result = await result

        return [TextContent(type="text", text=str(result))]

    except TypeError as e:
        logger.error("Tool %s argument error: %s", name, e)
        return [TextContent(type="text", text=f"Argument error: {str(e)}")]
    except Exception as e:
        logger.error("Tool %s failed: %s", name, e)
        return [TextContent(type="text", text=f"Error: {str(e)}")]


async def _handle_auto_solve(arguments: dict) -> list[TextContent]:
    """Handle auto_solve tool call"""
    challenge = Challenge(
        name=arguments.get("name", "unknown"),
        description=arguments.get("description", ""),
        files=arguments.get("files", []),
        remote=arguments.get("remote") or None,
        flag_format=arguments.get("flag_format", r"flag\{[^}]+\}"),
        category_hint=arguments.get("category") or None,
    )

    timeout = arguments.get("timeout", 300)
    orchestrator = CTFOrchestrator(timeout=timeout)
    result = await orchestrator.solve(challenge)

    output = json.dumps(result.to_dict(), indent=2, ensure_ascii=False)
    return [TextContent(type="text", text=output)]


async def _handle_classify(arguments: dict) -> list[TextContent]:
    """Handle classify_challenge tool call"""
    from .core.classifier import ChallengeClassifier

    classifier = ChallengeClassifier()
    result = classifier.classify(
        description=arguments.get("description", ""),
        files=arguments.get("files", []),
        remote=arguments.get("remote") or None,
    )

    output = json.dumps(result.to_dict(), indent=2, ensure_ascii=False)
    return [TextContent(type="text", text=output)]


def main():
    """Main entry point"""
    logger.info("Starting CTF-MCP Server...")
    register_tools()
    asyncio.run(stdio_server(app))


if __name__ == "__main__":
    main()
