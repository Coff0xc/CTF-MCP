"""
Reverse Engineering Solving Engine
Specialized engine for reverse engineering challenges
"""

import re
import struct
import time
from typing import Any, Optional, TYPE_CHECKING

from .base import SolvingEngine, EngineResult, EngineCapability

if TYPE_CHECKING:
    from ..core.orchestrator import Challenge

# Optional analysis tools
try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False


class ReverseEngine(SolvingEngine):
    """
    Reverse engineering challenge solving engine.

    Handles:
    - Static binary analysis
    - Disassembly and decompilation
    - String extraction
    - Anti-debugging bypass
    - Algorithm reversing
    - Packer/obfuscation detection
    """

    # File magic signatures
    FILE_SIGNATURES = {
        'elf32': (b'\x7fELF\x01', 'ELF 32-bit'),
        'elf64': (b'\x7fELF\x02', 'ELF 64-bit'),
        'pe': (b'MZ', 'PE executable'),
        'macho': (b'\xfe\xed\xfa\xce', 'Mach-O 32-bit'),
        'macho64': (b'\xfe\xed\xfa\xcf', 'Mach-O 64-bit'),
        'java_class': (b'\xca\xfe\xba\xbe', 'Java class'),
        'dex': (b'dex\n', 'Android DEX'),
        'pyc': (b'\x03\xf3\r\n', 'Python bytecode'),
    }

    # Packer/protector signatures
    PACKER_PATTERNS = {
        'upx': [b'UPX!', b'UPX0', b'UPX1'],
        'vmprotect': [b'VMProtect'],
        'themida': [b'Themida'],
        'aspack': [b'ASPack'],
        'petite': [b'petite'],
    }

    # Anti-debugging patterns
    ANTI_DEBUG_PATTERNS = [
        r'IsDebuggerPresent', r'CheckRemoteDebuggerPresent',
        r'NtQueryInformationProcess', r'ptrace',
        r'PTRACE_TRACEME', r'anti.?debug',
    ]

    @property
    def name(self) -> str:
        return "reverse"

    @property
    def capabilities(self) -> list[EngineCapability]:
        caps = [
            EngineCapability.ANALYZE,
            EngineCapability.FILE_ANALYSIS,
            EngineCapability.DECODE,
        ]
        if CAPSTONE_AVAILABLE:
            caps.append(EngineCapability.EXPLOIT)
        return caps

    def analyze(self, challenge: "Challenge") -> dict[str, Any]:
        """Analyze a reverse engineering challenge"""
        analysis = {
            "file_types": [],
            "packers": [],
            "strings": [],
            "anti_debug": False,
            "recommendations": [],
        }

        content = challenge.description.lower()

        # Analyze binary files
        for file_path in challenge.files:
            file_info = self._analyze_file(file_path)
            if file_info:
                analysis["file_types"].append(file_info)

                # Check for packers
                packer = self._detect_packer(file_path)
                if packer:
                    analysis["packers"].append(packer)
                    analysis["recommendations"].append(f"Unpack with {packer} before analysis")

                # Extract interesting strings
                strings = self._extract_strings(file_path)
                analysis["strings"].extend(strings[:20])

        # Check for anti-debugging mentions
        if any(re.search(p, content) for p in self.ANTI_DEBUG_PATTERNS):
            analysis["anti_debug"] = True
            analysis["recommendations"].append("Contains anti-debugging - patch or bypass")

        # Generate recommendations based on file type
        for ft in analysis["file_types"]:
            if 'ELF' in ft.get('type', ''):
                analysis["recommendations"].append("Use Ghidra/IDA for static analysis")
            elif 'PE' in ft.get('type', ''):
                analysis["recommendations"].append("Use x64dbg/IDA for Windows binary")
            elif 'Python' in ft.get('type', ''):
                analysis["recommendations"].append("Use uncompyle6/pycdc to decompile")
            elif 'Java' in ft.get('type', ''):
                analysis["recommendations"].append("Use jadx/jd-gui for decompilation")
            elif 'DEX' in ft.get('type', ''):
                analysis["recommendations"].append("Use jadx/apktool for Android analysis")

        return analysis

    def solve(self, challenge: "Challenge", **kwargs) -> EngineResult:
        """Attempt to solve a reverse engineering challenge"""
        start_time = time.time()
        result = EngineResult()

        try:
            tools = self._get_tools()["reverse"]

            result.add_step("Analyzing reverse engineering challenge")

            # Analyze challenge
            analysis = self.analyze(challenge)
            result.analysis = analysis

            # Process each binary file
            for file_path in challenge.files:
                binary_content = self._read_file(file_path, binary=True)
                if not binary_content:
                    continue

                result.add_step(f"Analyzing file: {file_path}")

                # Check for packed files
                packer = self._detect_packer(file_path)
                if packer:
                    result.add_step(f"Detected packer: {packer}")
                    if packer.lower() == 'upx':
                        unpack_result = self._try_upx_unpack(file_path, tools, result)
                        if unpack_result:
                            binary_content = unpack_result

                # Extract and analyze strings
                strings = self._extract_strings(file_path)
                for s in strings:
                    flags = self.find_flags(s, challenge.flag_format)
                    if flags:
                        result.success = True
                        result.flag = flags[0]
                        result.confidence = 0.95
                        result.add_step(f"Found flag in strings!")
                        result.duration = time.time() - start_time
                        return result

                # Try to disassemble and find patterns
                disasm_result = self._try_disassemble(file_path, tools, result)
                if disasm_result:
                    result.data = result.data or {}
                    result.data["disassembly"] = disasm_result[:2000]

                    # Look for XOR operations (common obfuscation)
                    xor_result = self._detect_xor_pattern(disasm_result, result)
                    if xor_result:
                        result.data["xor_key"] = xor_result

            # If we have analysis data but no flag
            if analysis["file_types"] or analysis["strings"]:
                result.success = True
                result.confidence = 0.5
                result.data = result.data or {}
                result.data.update({
                    "file_types": [f.get('type') for f in analysis["file_types"]],
                    "interesting_strings": analysis["strings"][:10],
                    "recommendations": analysis["recommendations"],
                })
                result.add_step("Analysis complete - manual review required")
            else:
                result.success = False
                result.error = "Could not analyze challenge"

        except Exception as e:
            result.success = False
            result.error = str(e)

        result.duration = time.time() - start_time
        return result

    def can_handle(self, challenge: "Challenge") -> float:
        """Check if this looks like a reverse engineering challenge"""
        score = 0.0
        content = challenge.description.lower()

        # Keyword matching
        reverse_keywords = [
            'reverse', 'reversing', 'binary', 'disassemble', 'decompile',
            'analysis', 'elf', 'executable', 'crack', 'keygen',
            'patch', 'debug', 'algorithm', 'obfuscate',
        ]

        for keyword in reverse_keywords:
            if keyword in content:
                score += 0.1

        # Check for executable files
        for file_path in challenge.files:
            if self._is_executable(file_path):
                score += 0.3
                break

        # Check file extensions
        exe_extensions = ['.exe', '.elf', '.bin', '.so', '.dll', '.pyc', '.class']
        for file_path in challenge.files:
            if any(file_path.lower().endswith(ext) for ext in exe_extensions):
                score += 0.2
                break

        return min(score, 1.0)

    def _is_executable(self, file_path: str) -> bool:
        """Check if file is an executable"""
        content = self._read_file(file_path, binary=True)
        if not content or len(content) < 4:
            return False

        for sig, _ in self.FILE_SIGNATURES.values():
            if content.startswith(sig):
                return True
        return False

    def _analyze_file(self, file_path: str) -> Optional[dict]:
        """Analyze file type and basic info"""
        content = self._read_file(file_path, binary=True)
        if not content:
            return None

        info = {"path": file_path, "size": len(content)}

        # Detect file type
        for type_name, (sig, desc) in self.FILE_SIGNATURES.items():
            if content.startswith(sig):
                info["type"] = desc
                info["type_id"] = type_name
                break
        else:
            info["type"] = "Unknown"

        return info

    def _detect_packer(self, file_path: str) -> Optional[str]:
        """Detect if binary is packed"""
        content = self._read_file(file_path, binary=True)
        if not content:
            return None

        for packer_name, signatures in self.PACKER_PATTERNS.items():
            for sig in signatures:
                if sig in content:
                    return packer_name

        return None

    def _extract_strings(self, file_path: str, min_length: int = 6) -> list[str]:
        """Extract printable strings from binary"""
        content = self._read_file(file_path, binary=True)
        if not content:
            return []

        # ASCII strings
        ascii_pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
        strings = [s.decode('ascii', errors='ignore')
                   for s in re.findall(ascii_pattern, content)]

        # UTF-16 strings (Windows)
        utf16_pattern = rb'(?:[\x20-\x7e]\x00){' + str(min_length).encode() + rb',}'
        utf16_matches = re.findall(utf16_pattern, content)
        strings.extend([s.decode('utf-16-le', errors='ignore')
                       for s in utf16_matches])

        # Filter out common noise
        filtered = []
        noise_patterns = [r'^\.', r'^_', r'^\s*$']
        for s in strings:
            if not any(re.match(p, s) for p in noise_patterns):
                filtered.append(s)

        return filtered[:100]  # Limit results

    def _try_upx_unpack(self, file_path: str, tools, result: EngineResult) -> Optional[bytes]:
        """Try to unpack UPX packed binary"""
        result.add_step("Attempting UPX unpack")

        try:
            unpack_result = tools.upx_unpack(file_path)
            result.add_step(f"UPX unpack: {unpack_result[:100]}")
            # Return unpacked content if successful
            return self._read_file(file_path, binary=True)
        except Exception as ex:
            result.add_step(f"UPX unpack failed: {ex}")
            return None

    def _try_disassemble(self, file_path: str, tools, result: EngineResult) -> Optional[str]:
        """Try to disassemble binary"""
        result.add_step("Disassembling binary")

        try:
            disasm_result = tools.disassemble(file_path)
            result.add_step(f"Disassembly: {len(disasm_result)} bytes of output")
            return disasm_result
        except Exception as ex:
            result.add_step(f"Disassembly failed: {ex}")
            return None

    def _detect_xor_pattern(self, disasm: str, result: EngineResult) -> Optional[int]:
        """Detect XOR obfuscation patterns"""
        # Look for XOR with constant
        xor_pattern = r'xor\s+\w+,\s*0x([0-9a-fA-F]+)'
        matches = re.findall(xor_pattern, disasm)

        if matches:
            # Find most common XOR key
            key_counts = {}
            for match in matches:
                key = int(match, 16)
                if 0 < key < 256:  # Single byte key
                    key_counts[key] = key_counts.get(key, 0) + 1

            if key_counts:
                most_common = max(key_counts, key=key_counts.get)
                result.add_step(f"Detected XOR key: 0x{most_common:02x}")
                return most_common

        return None
