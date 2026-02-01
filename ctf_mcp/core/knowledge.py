"""
CTF Knowledge Base
Pattern storage, solution caching, and CTF technique library
"""

import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
from pathlib import Path

logger = logging.getLogger("ctf-mcp.core.knowledge")


@dataclass
class SolvePattern:
    """A known solving pattern/technique"""
    id: str
    name: str
    category: str
    description: str
    indicators: list[str] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    difficulty: str = "medium"
    success_rate: float = 0.0
    usage_count: int = 0
    tags: list[str] = field(default_factory=list)

    def matches(self, content: str) -> float:
        """Check how well this pattern matches content"""
        content_lower = content.lower()
        matched = sum(1 for ind in self.indicators if ind.lower() in content_lower)
        return matched / len(self.indicators) if self.indicators else 0.0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "indicators": self.indicators,
            "steps": self.steps,
            "tools": self.tools,
            "difficulty": self.difficulty,
            "success_rate": self.success_rate,
            "usage_count": self.usage_count,
            "tags": self.tags,
        }


@dataclass
class SolutionCache:
    """Cached solution for a challenge"""
    challenge_hash: str
    flag: str
    method: str
    steps: list[str] = field(default_factory=list)
    confidence: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "challenge_hash": self.challenge_hash,
            "flag": self.flag,
            "method": self.method,
            "steps": self.steps,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
        }


class KnowledgeBase:
    """
    CTF Knowledge Base.

    Features:
    - Pre-built solving patterns for common CTF challenges
    - Solution caching
    - Pattern matching for challenge classification
    - Technique recommendations
    - Persistent storage
    """

    def __init__(self, storage_path: Optional[str] = None):
        """
        Initialize knowledge base.

        Args:
            storage_path: Path for persistent storage (None for memory-only)
        """
        self._patterns: dict[str, SolvePattern] = {}
        self._cache: dict[str, SolutionCache] = {}
        self._storage_path = storage_path

        # Load built-in patterns
        self._load_builtin_patterns()

        # Load persistent data
        if storage_path:
            self._load_from_disk()

    # ------------------------------------------------------------------ #
    #  Pattern management                                                 #
    # ------------------------------------------------------------------ #

    def add_pattern(self, pattern: SolvePattern) -> None:
        """Add a solving pattern"""
        self._patterns[pattern.id] = pattern

    def get_pattern(self, pattern_id: str) -> Optional[SolvePattern]:
        """Get pattern by ID"""
        return self._patterns.get(pattern_id)

    def find_patterns(
        self,
        content: str,
        category: Optional[str] = None,
        min_match: float = 0.3,
    ) -> list[tuple[SolvePattern, float]]:
        """
        Find matching patterns for given content.

        Args:
            content: Challenge description/content
            category: Filter by category
            min_match: Minimum match score (0-1)

        Returns:
            List of (pattern, score) sorted by score descending
        """
        matches = []

        for pattern in self._patterns.values():
            if category and pattern.category != category:
                continue

            score = pattern.matches(content)
            if score >= min_match:
                matches.append((pattern, score))

        matches.sort(key=lambda x: x[1], reverse=True)
        return matches

    def get_recommendation(self, content: str) -> Optional[SolvePattern]:
        """Get best pattern recommendation for content"""
        matches = self.find_patterns(content, min_match=0.2)
        return matches[0][0] if matches else None

    def list_patterns(self, category: Optional[str] = None) -> list[SolvePattern]:
        """List all patterns"""
        patterns = list(self._patterns.values())
        if category:
            patterns = [p for p in patterns if p.category == category]
        return patterns

    def record_usage(self, pattern_id: str, success: bool) -> None:
        """Record pattern usage and update success rate"""
        pattern = self._patterns.get(pattern_id)
        if pattern:
            old_count = pattern.usage_count
            old_rate = pattern.success_rate

            pattern.usage_count += 1
            if old_count > 0:
                pattern.success_rate = (
                    (old_rate * old_count + (1.0 if success else 0.0))
                    / pattern.usage_count
                )
            else:
                pattern.success_rate = 1.0 if success else 0.0

    # ------------------------------------------------------------------ #
    #  Solution caching                                                   #
    # ------------------------------------------------------------------ #

    def cache_solution(
        self,
        challenge_desc: str,
        flag: str,
        method: str,
        steps: Optional[list[str]] = None,
        confidence: float = 1.0,
    ) -> SolutionCache:
        """
        Cache a challenge solution.

        Args:
            challenge_desc: Challenge description (hashed for lookup)
            flag: Found flag
            method: Method used
            steps: Solving steps
            confidence: Confidence level

        Returns:
            Cached solution
        """
        challenge_hash = self._hash_challenge(challenge_desc)

        solution = SolutionCache(
            challenge_hash=challenge_hash,
            flag=flag,
            method=method,
            steps=steps or [],
            confidence=confidence,
        )

        self._cache[challenge_hash] = solution
        self._save_to_disk()

        return solution

    def lookup_solution(self, challenge_desc: str) -> Optional[SolutionCache]:
        """Look up cached solution"""
        challenge_hash = self._hash_challenge(challenge_desc)
        return self._cache.get(challenge_hash)

    def clear_cache(self) -> int:
        """Clear solution cache"""
        count = len(self._cache)
        self._cache.clear()
        return count

    # ------------------------------------------------------------------ #
    #  Persistence                                                        #
    # ------------------------------------------------------------------ #

    def _save_to_disk(self) -> None:
        """Save knowledge base to disk"""
        if not self._storage_path:
            return

        try:
            data = {
                "patterns": {pid: p.to_dict() for pid, p in self._patterns.items()},
                "cache": {ch: s.to_dict() for ch, s in self._cache.items()},
                "timestamp": datetime.now().isoformat(),
            }

            path = Path(self._storage_path)
            path.parent.mkdir(parents=True, exist_ok=True)

            with open(path, 'w') as f:
                json.dump(data, f, indent=2)

        except Exception as e:
            logger.warning("Failed to save knowledge base: %s", e)

    def _load_from_disk(self) -> None:
        """Load knowledge base from disk"""
        if not self._storage_path or not os.path.exists(self._storage_path):
            return

        try:
            with open(self._storage_path, 'r') as f:
                data = json.load(f)

            # Load cached solutions
            for ch, sol_dict in data.get("cache", {}).items():
                self._cache[ch] = SolutionCache(
                    challenge_hash=sol_dict["challenge_hash"],
                    flag=sol_dict["flag"],
                    method=sol_dict["method"],
                    steps=sol_dict.get("steps", []),
                    confidence=sol_dict.get("confidence", 1.0),
                )

            logger.info("Loaded %d cached solutions", len(self._cache))

        except Exception as e:
            logger.warning("Failed to load knowledge base: %s", e)

    def _hash_challenge(self, description: str) -> str:
        """Create hash for challenge lookup"""
        normalized = re.sub(r'\s+', ' ', description.strip().lower())
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]

    # ------------------------------------------------------------------ #
    #  Built-in patterns                                                  #
    # ------------------------------------------------------------------ #

    def _load_builtin_patterns(self) -> None:
        """Load built-in CTF solving patterns"""

        # ==================== CRYPTO ====================
        self.add_pattern(SolvePattern(
            id="crypto_rsa_small_e",
            name="RSA Small Public Exponent",
            category="crypto",
            description="RSA with small e (e=3): take eth root of ciphertext",
            indicators=["rsa", "e = 3", "e=3", "small exponent", "cube root"],
            steps=[
                "Extract n, e, c from challenge",
                "If e=3, compute c^(1/3) directly",
                "Convert result integer to bytes",
            ],
            tools=["crypto_rsa_factor", "crypto_rsa_decrypt"],
            difficulty="easy",
            tags=["rsa", "small_e"],
        ))

        self.add_pattern(SolvePattern(
            id="crypto_rsa_factor",
            name="RSA Factorization",
            category="crypto",
            description="RSA with factorable N: use factordb, Fermat, or Pollard rho",
            indicators=["rsa", "n =", "e =", "c =", "factor", "prime"],
            steps=[
                "Extract n, e, c",
                "Try factordb.com for known factorizations",
                "Try Fermat factorization if p and q are close",
                "Compute d = inverse(e, phi(n))",
                "Decrypt: m = pow(c, d, n)",
            ],
            tools=["crypto_rsa_factor", "crypto_rsa_decrypt"],
            difficulty="medium",
            tags=["rsa", "factorization"],
        ))

        self.add_pattern(SolvePattern(
            id="crypto_rsa_common_n",
            name="RSA Common Modulus Attack",
            category="crypto",
            description="Two ciphertexts with same N but different e values",
            indicators=["rsa", "common modulus", "same n", "two ciphertext", "e1", "e2"],
            steps=[
                "Extract n, e1, c1, e2, c2",
                "Compute gcd(e1, e2) - should be 1",
                "Use extended Euclidean: s*e1 + t*e2 = 1",
                "m = (c1^s * c2^t) mod n",
            ],
            tools=["crypto_rsa_decrypt"],
            difficulty="medium",
            tags=["rsa", "common_modulus"],
        ))

        self.add_pattern(SolvePattern(
            id="crypto_caesar",
            name="Caesar Cipher / ROT-N",
            category="crypto",
            description="Simple letter shift cipher",
            indicators=["caesar", "rot", "shift", "alphabet"],
            steps=[
                "Try all 26 shifts",
                "Look for readable English / flag format",
            ],
            tools=["crypto_caesar_bruteforce", "crypto_rot_n"],
            difficulty="easy",
            tags=["classical", "caesar", "rot13"],
        ))

        self.add_pattern(SolvePattern(
            id="crypto_vigenere",
            name="Vigenere Cipher",
            category="crypto",
            description="Polyalphabetic cipher with repeating key",
            indicators=["vigenere", "polyalphabetic", "key", "repeating"],
            steps=[
                "Find key length using Kasiski / Index of Coincidence",
                "Split text into key-length groups",
                "Frequency analysis on each group",
            ],
            tools=["crypto_freq_analysis", "crypto_vigenere_decrypt"],
            difficulty="medium",
            tags=["classical", "vigenere"],
        ))

        self.add_pattern(SolvePattern(
            id="crypto_xor",
            name="XOR Cipher",
            category="crypto",
            description="XOR encryption with single or repeating key",
            indicators=["xor", "^", "exclusive or", "0x"],
            steps=[
                "Try single-byte XOR bruteforce (256 keys)",
                "Try known-plaintext attack if partial plaintext known",
                "For repeating key: find key length then per-byte bruteforce",
            ],
            tools=["crypto_xor_decrypt", "crypto_xor_bruteforce"],
            difficulty="easy",
            tags=["xor", "bruteforce"],
        ))

        self.add_pattern(SolvePattern(
            id="crypto_base_chain",
            name="Base Encoding Chain",
            category="crypto",
            description="Multiple layers of base encoding (base64, hex, etc.)",
            indicators=["base64", "base32", "hex", "encode", "decode"],
            steps=[
                "Detect encoding type (base64, hex, base32, etc.)",
                "Decode iteratively until plaintext",
                "Check for flag format at each step",
            ],
            tools=["crypto_base64_decode", "crypto_hex_decode"],
            difficulty="easy",
            tags=["encoding", "base64", "hex"],
        ))

        self.add_pattern(SolvePattern(
            id="crypto_aes_ecb",
            name="AES-ECB Mode Attack",
            category="crypto",
            description="AES in ECB mode: identical blocks produce identical ciphertext",
            indicators=["aes", "ecb", "block cipher", "identical blocks", "penguin"],
            steps=[
                "Detect ECB mode by looking for repeated ciphertext blocks",
                "Use byte-at-a-time oracle attack if oracle available",
                "Feed controlled input and observe block boundaries",
            ],
            tools=["crypto_aes_decrypt"],
            difficulty="medium",
            tags=["aes", "ecb", "block_cipher"],
        ))

        # ==================== WEB ====================
        self.add_pattern(SolvePattern(
            id="web_sqli_union",
            name="SQL Injection (UNION-based)",
            category="web",
            description="UNION-based SQL injection to extract data",
            indicators=["sql", "login", "query", "database", "select", "union"],
            steps=[
                "Find injection point (single quote test)",
                "Determine number of columns with ORDER BY",
                "UNION SELECT to extract data",
                "Enumerate tables and columns",
            ],
            tools=["web_sql_payloads", "web_sqli_test"],
            difficulty="medium",
            tags=["sqli", "union", "database"],
        ))

        self.add_pattern(SolvePattern(
            id="web_sqli_blind",
            name="SQL Injection (Blind)",
            category="web",
            description="Boolean or time-based blind SQL injection",
            indicators=["sql", "blind", "boolean", "time-based", "login"],
            steps=[
                "Identify blind injection point",
                "Use boolean conditions to extract bit by bit",
                "Alternative: use time-based (SLEEP/BENCHMARK)",
                "Automate with sqlmap",
            ],
            tools=["web_sql_payloads", "web_sqli_test"],
            difficulty="hard",
            tags=["sqli", "blind"],
        ))

        self.add_pattern(SolvePattern(
            id="web_ssti",
            name="Server-Side Template Injection",
            category="web",
            description="Template engine code execution via user input",
            indicators=["template", "jinja", "twig", "flask", "render", "ssti", "{{"],
            steps=[
                "Test with {{7*7}} to confirm SSTI",
                "Identify template engine",
                "Jinja2 RCE: {{config.__class__.__init__.__globals__['os'].popen('cmd').read()}}",
                "Twig RCE: {{_self.env.registerUndefinedFilterCallback('exec')}}",
            ],
            tools=["web_ssti_payloads", "web_ssti_detect"],
            difficulty="medium",
            tags=["ssti", "jinja", "rce"],
        ))

        self.add_pattern(SolvePattern(
            id="web_lfi",
            name="Local File Inclusion",
            category="web",
            description="Read local files via path traversal",
            indicators=["file", "include", "path", "lfi", "directory", "../"],
            steps=[
                "Test with ../../../../etc/passwd",
                "Try PHP wrappers: php://filter/convert.base64-encode/resource=",
                "Read source code, config files, /flag",
            ],
            tools=["web_lfi_payloads", "web_path_traversal"],
            difficulty="easy",
            tags=["lfi", "path_traversal"],
        ))

        self.add_pattern(SolvePattern(
            id="web_jwt_none",
            name="JWT None Algorithm Attack",
            category="web",
            description="Bypass JWT verification using alg:none",
            indicators=["jwt", "token", "bearer", "auth", "header"],
            steps=[
                "Decode JWT (base64 header.payload.signature)",
                "Change alg to 'none' in header",
                "Modify payload claims (e.g. admin=true)",
                "Re-encode with empty signature",
            ],
            tools=["web_jwt_decode", "web_jwt_forge"],
            difficulty="easy",
            tags=["jwt", "none_algorithm"],
        ))

        self.add_pattern(SolvePattern(
            id="web_ssrf",
            name="Server-Side Request Forgery",
            category="web",
            description="Make server send requests to internal resources",
            indicators=["ssrf", "url", "fetch", "request", "internal", "127.0.0.1"],
            steps=[
                "Identify URL input parameter",
                "Test with http://127.0.0.1 and http://localhost",
                "Try cloud metadata: http://169.254.169.254/",
                "Use protocol wrappers: file://, gopher://",
            ],
            tools=["web_ssrf_payloads"],
            difficulty="medium",
            tags=["ssrf", "internal"],
        ))

        # ==================== PWN ====================
        self.add_pattern(SolvePattern(
            id="pwn_bof_ret2win",
            name="Buffer Overflow ret2win",
            category="pwn",
            description="Stack overflow to jump to existing win function",
            indicators=["overflow", "buffer", "gets", "win", "flag", "stack"],
            steps=[
                "Find buffer size with cyclic pattern",
                "Locate win/flag function address",
                "Overwrite return address with win function",
                "Account for alignment (ret gadget on x64)",
            ],
            tools=["pwn_checksec", "pwn_find_gadgets", "pwn_cyclic"],
            difficulty="easy",
            tags=["bof", "ret2win", "stack"],
        ))

        self.add_pattern(SolvePattern(
            id="pwn_bof_shellcode",
            name="Buffer Overflow Shellcode Injection",
            category="pwn",
            description="Inject and execute shellcode via stack overflow",
            indicators=["overflow", "nx disabled", "shellcode", "rwx", "executable stack"],
            steps=[
                "Confirm NX is disabled (checksec)",
                "Find buffer address (gdb/leak)",
                "Craft shellcode + NOP sled",
                "Overwrite return address with buffer address",
            ],
            tools=["pwn_checksec", "pwn_shellcode_generate"],
            difficulty="easy",
            tags=["bof", "shellcode", "nx_disabled"],
        ))

        self.add_pattern(SolvePattern(
            id="pwn_bof_rop",
            name="ROP Chain Attack",
            category="pwn",
            description="Return-oriented programming to bypass NX",
            indicators=["overflow", "rop", "gadget", "nx", "libc", "ret2libc"],
            steps=[
                "Find buffer overflow offset",
                "Collect gadgets (pop rdi; ret, etc.)",
                "Leak libc address via puts/printf GOT",
                "Calculate system() and /bin/sh addresses",
                "Build ROP chain: pop rdi; /bin/sh; system",
            ],
            tools=["pwn_checksec", "pwn_find_gadgets", "pwn_rop_chain"],
            difficulty="hard",
            tags=["rop", "ret2libc", "nx"],
        ))

        self.add_pattern(SolvePattern(
            id="pwn_format_string",
            name="Format String Exploit",
            category="pwn",
            description="Format string vulnerability for read/write",
            indicators=["printf", "format", "%p", "%n", "%x", "format string"],
            steps=[
                "Find format string offset (send %p.%p.%p...)",
                "Leak stack/libc addresses with %N$p",
                "Write with %n or pwntools fmtstr_payload",
                "Overwrite GOT entry or return address",
            ],
            tools=["pwn_format_string", "pwn_checksec"],
            difficulty="medium",
            tags=["format_string", "printf"],
        ))

        self.add_pattern(SolvePattern(
            id="pwn_heap_tcache",
            name="Heap Tcache Poisoning",
            category="pwn",
            description="Tcache poisoning for arbitrary write (glibc 2.27+)",
            indicators=["heap", "tcache", "malloc", "free", "double free", "uaf"],
            steps=[
                "Create two chunks in same tcache bin",
                "Free both (or double-free if no check)",
                "Overwrite fd pointer in freed chunk",
                "Allocate twice to get arbitrary write",
            ],
            tools=["pwn_checksec", "pwn_heap_analysis"],
            difficulty="hard",
            tags=["heap", "tcache", "glibc"],
        ))

        # ==================== REVERSE ====================
        self.add_pattern(SolvePattern(
            id="rev_strings",
            name="Flag in Strings",
            category="reverse",
            description="Flag is directly embedded as string in binary",
            indicators=["reverse", "binary", "strings", "flag"],
            steps=[
                "Run strings on binary",
                "Grep for flag format",
            ],
            tools=["reverse_find_strings", "reverse_disassemble"],
            difficulty="easy",
            tags=["strings", "easy"],
        ))

        self.add_pattern(SolvePattern(
            id="rev_xor_obfuscation",
            name="XOR Obfuscated Flag",
            category="reverse",
            description="Flag XORed with static key in binary",
            indicators=["xor", "obfuscate", "decrypt", "key", "reverse"],
            steps=[
                "Find XOR loop in disassembly",
                "Extract encrypted data and key",
                "XOR decrypt to get flag",
            ],
            tools=["reverse_disassemble", "crypto_xor_decrypt"],
            difficulty="easy",
            tags=["xor", "obfuscation"],
        ))

        self.add_pattern(SolvePattern(
            id="rev_angr",
            name="Symbolic Execution Solve",
            category="reverse",
            description="Use angr to find correct input via symbolic execution",
            indicators=["reverse", "crackme", "password", "correct", "angr"],
            steps=[
                "Identify success/fail addresses in binary",
                "Set up angr with find=success, avoid=fail",
                "Run symbolic execution",
                "Extract stdin solution",
            ],
            tools=["reverse_disassemble"],
            difficulty="medium",
            tags=["angr", "symbolic"],
        ))

        # ==================== FORENSICS ====================
        self.add_pattern(SolvePattern(
            id="forensics_stego_lsb",
            name="LSB Steganography",
            category="forensics",
            description="Data hidden in least significant bits of image",
            indicators=["stego", "image", "lsb", "hidden", "png", "bmp"],
            steps=[
                "Use zsteg (PNG/BMP) or stegsolve",
                "Check LSB of each color channel",
                "Try different bit planes",
            ],
            tools=["forensics_lsb_extract", "forensics_strings_extract"],
            difficulty="easy",
            tags=["stego", "lsb", "image"],
        ))

        self.add_pattern(SolvePattern(
            id="forensics_binwalk",
            name="Embedded File Extraction",
            category="forensics",
            description="Files embedded/appended within other files",
            indicators=["hidden", "embedded", "file", "binwalk", "carve"],
            steps=[
                "Run binwalk to detect signatures",
                "Extract with binwalk -e",
                "Check extracted files for flags",
            ],
            tools=["forensics_binwalk_scan", "forensics_file_carve"],
            difficulty="easy",
            tags=["binwalk", "carving"],
        ))

        self.add_pattern(SolvePattern(
            id="forensics_exif",
            name="EXIF Metadata Flag",
            category="forensics",
            description="Flag hidden in image EXIF metadata",
            indicators=["exif", "metadata", "gps", "comment", "image", "photo"],
            steps=[
                "Extract EXIF data with exiftool",
                "Check Comment, Artist, Description fields",
                "Check GPS coordinates if OSINT",
            ],
            tools=["forensics_exif_extract"],
            difficulty="easy",
            tags=["exif", "metadata"],
        ))

        self.add_pattern(SolvePattern(
            id="forensics_pcap",
            name="PCAP Network Analysis",
            category="forensics",
            description="Extract data from network capture",
            indicators=["pcap", "wireshark", "network", "packet", "capture", "tcp"],
            steps=[
                "Open in Wireshark, follow TCP streams",
                "Look for HTTP requests with flag",
                "Check DNS queries for exfiltration",
                "Extract files from streams",
            ],
            tools=["forensics_pcap_analyze"],
            difficulty="medium",
            tags=["pcap", "network", "wireshark"],
        ))

        # ==================== MISC ====================
        self.add_pattern(SolvePattern(
            id="misc_encoding_chain",
            name="Multi-layer Encoding",
            category="misc",
            description="Data encoded through multiple layers",
            indicators=["decode", "encode", "base64", "hex", "binary", "layers"],
            steps=[
                "Identify first encoding layer",
                "Decode iteratively",
                "Common chains: base64->hex->ascii, binary->decimal->ascii",
            ],
            tools=["misc_base64_decode", "misc_hex_decode"],
            difficulty="easy",
            tags=["encoding", "multilayer"],
        ))

        self.add_pattern(SolvePattern(
            id="misc_pyjail",
            name="Python Jail Escape",
            category="misc",
            description="Escape restricted Python execution environment",
            indicators=["pyjail", "python", "eval", "exec", "restricted", "sandbox"],
            steps=[
                "Test available builtins: __builtins__",
                "Try: ().__class__.__bases__[0].__subclasses__()",
                "Find os/subprocess via subclass chain",
                "Bypass filters with string concatenation / chr()",
            ],
            tools=[],
            difficulty="medium",
            tags=["pyjail", "sandbox_escape"],
        ))

    # ------------------------------------------------------------------ #
    #  Statistics                                                          #
    # ------------------------------------------------------------------ #

    def get_stats(self) -> dict:
        """Get knowledge base statistics"""
        categories = {}
        for p in self._patterns.values():
            categories[p.category] = categories.get(p.category, 0) + 1

        return {
            "total_patterns": len(self._patterns),
            "cached_solutions": len(self._cache),
            "by_category": categories,
        }


# Global knowledge base
_kb: Optional[KnowledgeBase] = None


def get_knowledge_base(storage_path: Optional[str] = None) -> KnowledgeBase:
    """Get global knowledge base"""
    global _kb
    if _kb is None:
        _kb = KnowledgeBase(storage_path)
    return _kb
