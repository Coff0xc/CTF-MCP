#!/usr/bin/env python3
"""
CTF-MCP Server - MCP Server for CTF Challenges
Provides tools for Crypto, Web, Pwn, Reverse, Forensics, and Misc challenges
"""

import asyncio
import logging
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from .tools.crypto import CryptoTools
from .tools.web import WebTools
from .tools.pwn import PwnTools
from .tools.reverse import ReverseTools
from .tools.forensics import ForensicsTools
from .tools.misc import MiscTools

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

# Tool registry - maps tool names to their handlers
TOOL_REGISTRY: dict[str, tuple[Any, str]] = {}


def register_tools():
    """Register all tools from all modules"""
    modules = [
        ("crypto", crypto_tools),
        ("web", web_tools),
        ("pwn", pwn_tools),
        ("reverse", reverse_tools),
        ("forensics", forensics_tools),
        ("misc", misc_tools),
    ]

    for prefix, module in modules:
        for tool_name, tool_info in module.get_tools().items():
            full_name = f"{prefix}_{tool_name}"
            TOOL_REGISTRY[full_name] = (module, tool_name)
            logger.debug(f"Registered tool: {full_name}")

    logger.info(f"Registered {len(TOOL_REGISTRY)} tools")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List all available CTF tools"""
    tools = []

    # Crypto tools
    tools.extend([
        Tool(
            name="crypto_base64_encode",
            description="Base64 encode data",
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {"type": "string", "description": "Data to encode"}
                },
                "required": ["data"]
            }
        ),
        Tool(
            name="crypto_base64_decode",
            description="Base64 decode data",
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {"type": "string", "description": "Base64 encoded data"}
                },
                "required": ["data"]
            }
        ),
        Tool(
            name="crypto_rot13",
            description="ROT13 cipher encode/decode",
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Text to encode/decode"}
                },
                "required": ["text"]
            }
        ),
        Tool(
            name="crypto_caesar",
            description="Caesar cipher with custom shift",
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Text to encrypt/decrypt"},
                    "shift": {"type": "integer", "description": "Shift value (1-25)", "default": 3}
                },
                "required": ["text"]
            }
        ),
        Tool(
            name="crypto_caesar_bruteforce",
            description="Bruteforce all Caesar cipher shifts",
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Ciphertext to bruteforce"}
                },
                "required": ["text"]
            }
        ),
        Tool(
            name="crypto_vigenere",
            description="Vigenere cipher encrypt/decrypt",
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Text to process"},
                    "key": {"type": "string", "description": "Cipher key"},
                    "decrypt": {"type": "boolean", "description": "Decrypt mode", "default": False}
                },
                "required": ["text", "key"]
            }
        ),
        Tool(
            name="crypto_xor",
            description="XOR data with a key",
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {"type": "string", "description": "Data (hex or string)"},
                    "key": {"type": "string", "description": "XOR key"},
                    "input_hex": {"type": "boolean", "description": "Input is hex", "default": False}
                },
                "required": ["data", "key"]
            }
        ),
        Tool(
            name="crypto_hash",
            description="Calculate hash of data (MD5, SHA1, SHA256, SHA512)",
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {"type": "string", "description": "Data to hash"},
                    "algorithm": {"type": "string", "description": "Hash algorithm", "enum": ["md5", "sha1", "sha256", "sha512"], "default": "sha256"}
                },
                "required": ["data"]
            }
        ),
        Tool(
            name="crypto_rsa_factor",
            description="Factor RSA modulus n using various methods",
            inputSchema={
                "type": "object",
                "properties": {
                    "n": {"type": "string", "description": "RSA modulus n (decimal)"},
                    "e": {"type": "string", "description": "Public exponent e", "default": "65537"}
                },
                "required": ["n"]
            }
        ),
        Tool(
            name="crypto_rsa_decrypt",
            description="Decrypt RSA ciphertext given p, q, e, c",
            inputSchema={
                "type": "object",
                "properties": {
                    "p": {"type": "string", "description": "Prime p"},
                    "q": {"type": "string", "description": "Prime q"},
                    "e": {"type": "string", "description": "Public exponent"},
                    "c": {"type": "string", "description": "Ciphertext"}
                },
                "required": ["p", "q", "e", "c"]
            }
        ),
        Tool(
            name="crypto_freq_analysis",
            description="Frequency analysis on ciphertext",
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Ciphertext to analyze"}
                },
                "required": ["text"]
            }
        ),
    ])

    # Misc tools
    tools.extend([
        Tool(
            name="misc_hex_encode",
            description="Encode string to hexadecimal",
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {"type": "string", "description": "Data to encode"}
                },
                "required": ["data"]
            }
        ),
        Tool(
            name="misc_hex_decode",
            description="Decode hexadecimal to string",
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {"type": "string", "description": "Hex data to decode"}
                },
                "required": ["data"]
            }
        ),
        Tool(
            name="misc_url_encode",
            description="URL encode string",
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {"type": "string", "description": "Data to encode"}
                },
                "required": ["data"]
            }
        ),
        Tool(
            name="misc_url_decode",
            description="URL decode string",
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {"type": "string", "description": "URL encoded data"}
                },
                "required": ["data"]
            }
        ),
        Tool(
            name="misc_binary_convert",
            description="Convert between binary, decimal, hex, and string",
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {"type": "string", "description": "Data to convert"},
                    "from_base": {"type": "string", "description": "Source format", "enum": ["bin", "dec", "hex", "str"]},
                    "to_base": {"type": "string", "description": "Target format", "enum": ["bin", "dec", "hex", "str"]}
                },
                "required": ["data", "from_base", "to_base"]
            }
        ),
        Tool(
            name="misc_find_flag",
            description="Search for flag patterns in text",
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Text to search"},
                    "prefix": {"type": "string", "description": "Flag prefix", "default": "flag"}
                },
                "required": ["text"]
            }
        ),
        Tool(
            name="misc_strings_extract",
            description="Extract printable strings from binary data",
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {"type": "string", "description": "Hex-encoded binary data"},
                    "min_length": {"type": "integer", "description": "Minimum string length", "default": 4}
                },
                "required": ["data"]
            }
        ),
    ])

    # Web tools
    tools.extend([
        Tool(
            name="web_sql_payloads",
            description="Generate SQL injection payloads",
            inputSchema={
                "type": "object",
                "properties": {
                    "dbms": {"type": "string", "description": "Database type", "enum": ["mysql", "postgresql", "mssql", "oracle", "sqlite"], "default": "mysql"},
                    "technique": {"type": "string", "description": "Injection technique", "enum": ["union", "error", "blind", "time"], "default": "union"}
                },
                "required": []
            }
        ),
        Tool(
            name="web_xss_payloads",
            description="Generate XSS payloads",
            inputSchema={
                "type": "object",
                "properties": {
                    "context": {"type": "string", "description": "Injection context", "enum": ["html", "attribute", "script", "url"], "default": "html"},
                    "bypass": {"type": "boolean", "description": "Include WAF bypass variants", "default": False}
                },
                "required": []
            }
        ),
        Tool(
            name="web_lfi_payloads",
            description="Generate Local File Inclusion payloads",
            inputSchema={
                "type": "object",
                "properties": {
                    "os": {"type": "string", "description": "Target OS", "enum": ["linux", "windows"], "default": "linux"},
                    "wrapper": {"type": "boolean", "description": "Include PHP wrappers", "default": True}
                },
                "required": []
            }
        ),
        Tool(
            name="web_ssti_payloads",
            description="Generate Server-Side Template Injection payloads",
            inputSchema={
                "type": "object",
                "properties": {
                    "engine": {"type": "string", "description": "Template engine", "enum": ["jinja2", "twig", "freemarker", "velocity", "auto"], "default": "auto"}
                },
                "required": []
            }
        ),
        Tool(
            name="web_jwt_decode",
            description="Decode and analyze JWT token",
            inputSchema={
                "type": "object",
                "properties": {
                    "token": {"type": "string", "description": "JWT token to decode"}
                },
                "required": ["token"]
            }
        ),
        Tool(
            name="web_jwt_forge",
            description="Forge JWT token with none algorithm or weak secret",
            inputSchema={
                "type": "object",
                "properties": {
                    "token": {"type": "string", "description": "Original JWT token"},
                    "payload_changes": {"type": "object", "description": "Payload modifications"},
                    "attack": {"type": "string", "description": "Attack type", "enum": ["none", "weak_secret"], "default": "none"}
                },
                "required": ["token"]
            }
        ),
    ])

    # Forensics tools
    tools.extend([
        Tool(
            name="forensics_file_magic",
            description="Identify file type by magic bytes",
            inputSchema={
                "type": "object",
                "properties": {
                    "data": {"type": "string", "description": "Hex-encoded file header (first 32 bytes)"}
                },
                "required": ["data"]
            }
        ),
        Tool(
            name="forensics_exif_extract",
            description="Extract EXIF metadata from image",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to image file"}
                },
                "required": ["file_path"]
            }
        ),
        Tool(
            name="forensics_steghide_detect",
            description="Detect potential steganography in image",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to image file"}
                },
                "required": ["file_path"]
            }
        ),
        Tool(
            name="forensics_lsb_extract",
            description="Extract LSB hidden data from image",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to image file"},
                    "bits": {"type": "integer", "description": "Number of LSB bits", "default": 1}
                },
                "required": ["file_path"]
            }
        ),
        Tool(
            name="forensics_strings_file",
            description="Extract strings from a file",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to file"},
                    "min_length": {"type": "integer", "description": "Minimum string length", "default": 4},
                    "encoding": {"type": "string", "description": "String encoding", "enum": ["ascii", "utf-8", "utf-16"], "default": "ascii"}
                },
                "required": ["file_path"]
            }
        ),
        Tool(
            name="forensics_binwalk_scan",
            description="Scan file for embedded files and data",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to file"}
                },
                "required": ["file_path"]
            }
        ),
    ])

    # Pwn tools
    tools.extend([
        Tool(
            name="pwn_shellcode_gen",
            description="Generate shellcode for various architectures",
            inputSchema={
                "type": "object",
                "properties": {
                    "arch": {"type": "string", "description": "Architecture", "enum": ["x86", "x64", "arm", "arm64"], "default": "x64"},
                    "os": {"type": "string", "description": "Operating system", "enum": ["linux", "windows"], "default": "linux"},
                    "type": {"type": "string", "description": "Shellcode type", "enum": ["execve", "reverse_shell", "bind_shell", "read_flag"], "default": "execve"}
                },
                "required": []
            }
        ),
        Tool(
            name="pwn_pattern_create",
            description="Create cyclic pattern for buffer overflow",
            inputSchema={
                "type": "object",
                "properties": {
                    "length": {"type": "integer", "description": "Pattern length", "default": 100}
                },
                "required": []
            }
        ),
        Tool(
            name="pwn_pattern_offset",
            description="Find offset in cyclic pattern",
            inputSchema={
                "type": "object",
                "properties": {
                    "value": {"type": "string", "description": "Value to find (hex or string)"}
                },
                "required": ["value"]
            }
        ),
        Tool(
            name="pwn_rop_gadgets",
            description="Common ROP gadget patterns",
            inputSchema={
                "type": "object",
                "properties": {
                    "arch": {"type": "string", "description": "Architecture", "enum": ["x86", "x64"], "default": "x64"},
                    "gadget_type": {"type": "string", "description": "Gadget type", "enum": ["pop_rdi", "pop_rsi", "pop_rdx", "syscall", "ret", "all"], "default": "all"}
                },
                "required": []
            }
        ),
        Tool(
            name="pwn_format_string",
            description="Generate format string exploit payload",
            inputSchema={
                "type": "object",
                "properties": {
                    "target_addr": {"type": "string", "description": "Target address to write (hex)"},
                    "value": {"type": "string", "description": "Value to write (hex)"},
                    "offset": {"type": "integer", "description": "Format string offset"},
                    "arch": {"type": "string", "description": "Architecture", "enum": ["x86", "x64"], "default": "x64"}
                },
                "required": ["target_addr", "value", "offset"]
            }
        ),
        Tool(
            name="pwn_libc_offset",
            description="Calculate libc base from leaked address",
            inputSchema={
                "type": "object",
                "properties": {
                    "leaked_addr": {"type": "string", "description": "Leaked address (hex)"},
                    "symbol": {"type": "string", "description": "Symbol name (e.g., puts, printf)"},
                    "libc_version": {"type": "string", "description": "Libc version hint", "default": "2.31"}
                },
                "required": ["leaked_addr", "symbol"]
            }
        ),
    ])

    # Reverse tools
    tools.extend([
        Tool(
            name="reverse_disasm",
            description="Disassemble hex-encoded machine code",
            inputSchema={
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "Hex-encoded machine code"},
                    "arch": {"type": "string", "description": "Architecture", "enum": ["x86", "x64", "arm", "arm64"], "default": "x64"}
                },
                "required": ["code"]
            }
        ),
        Tool(
            name="reverse_asm",
            description="Assemble instructions to machine code",
            inputSchema={
                "type": "object",
                "properties": {
                    "instructions": {"type": "string", "description": "Assembly instructions (one per line)"},
                    "arch": {"type": "string", "description": "Architecture", "enum": ["x86", "x64", "arm", "arm64"], "default": "x64"}
                },
                "required": ["instructions"]
            }
        ),
        Tool(
            name="reverse_elf_info",
            description="Parse ELF file header information",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to ELF file"}
                },
                "required": ["file_path"]
            }
        ),
        Tool(
            name="reverse_pe_info",
            description="Parse PE file header information",
            inputSchema={
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "Path to PE file"}
                },
                "required": ["file_path"]
            }
        ),
        Tool(
            name="reverse_deobfuscate",
            description="Attempt to deobfuscate simple obfuscation",
            inputSchema={
                "type": "object",
                "properties": {
                    "code": {"type": "string", "description": "Obfuscated code or data"},
                    "type": {"type": "string", "description": "Obfuscation type", "enum": ["xor", "base64", "rot13", "auto"], "default": "auto"}
                },
                "required": ["code"]
            }
        ),
    ])

    return tools


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Handle tool calls"""
    try:
        # Dynamic tool dispatch using registry
        if name not in TOOL_REGISTRY:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]

        # Get module and method name from registry
        module, method_name = TOOL_REGISTRY[name]

        # Get the actual method using getattr
        method = getattr(module, method_name)

        # Call the method with arguments
        result = method(**arguments)

        return [TextContent(type="text", text=str(result))]

    except Exception as e:
        logger.error(f"Tool {name} failed: {e}")
        return [TextContent(type="text", text=f"Error: {str(e)}")]


def main():
    """Main entry point"""
    logger.info("Starting CTF-MCP Server...")
    register_tools()
    asyncio.run(stdio_server(app))


if __name__ == "__main__":
    main()
