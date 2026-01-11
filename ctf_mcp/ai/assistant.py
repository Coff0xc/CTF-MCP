"""
AI-assisted decision making for CTF-MCP
Inspired by hexstrike-ai's autonomous security testing capabilities

Provides intelligent suggestions for next steps in CTF challenges
"""

from typing import Dict, List, Any, Optional
from enum import Enum
from dataclasses import dataclass


class CTFCategory(Enum):
    """CTF challenge categories"""
    WEB = "web"
    CRYPTO = "crypto"
    PWN = "pwn"
    REVERSE = "reverse"
    FORENSICS = "forensics"
    MISC = "misc"


@dataclass
class AnalysisResult:
    """Result of AI analysis"""
    category: CTFCategory
    confidence: float
    suggested_tools: List[str]
    reasoning: str
    next_steps: List[str]


class AIAssistant:
    """
    AI-powered CTF assistant

    Features inspired by hexstrike-ai:
    - Intelligent tool selection
    - Context-aware suggestions
    - Automated decision making
    """

    def __init__(self):
        self.context_history: List[Dict[str, Any]] = []

    def analyze_challenge(self, challenge_info: Dict[str, Any]) -> AnalysisResult:
        """
        Analyze a CTF challenge and suggest approach

        Args:
            challenge_info: Information about the challenge
                - description: Challenge description
                - files: List of provided files
                - hints: Any hints provided
                - category: Optional category hint

        Returns:
            Analysis result with suggestions
        """
        description = challenge_info.get("description", "").lower()
        files = challenge_info.get("files", [])
        category_hint = challenge_info.get("category")

        # Detect category
        category = self._detect_category(description, files, category_hint)

        # Suggest tools based on category and context
        tools = self._suggest_tools(category, description, files)

        # Generate reasoning
        reasoning = self._generate_reasoning(category, description, files)

        # Suggest next steps
        next_steps = self._suggest_next_steps(category, tools)

        return AnalysisResult(
            category=category,
            confidence=0.8,  # Simplified confidence
            suggested_tools=tools,
            reasoning=reasoning,
            next_steps=next_steps
        )

    def _detect_category(
        self,
        description: str,
        files: List[str],
        hint: Optional[str]
    ) -> CTFCategory:
        """Detect challenge category"""

        # Use hint if provided
        if hint:
            try:
                return CTFCategory(hint.lower())
            except ValueError:
                pass

        # Web indicators
        web_keywords = ["http", "url", "website", "web", "sql", "xss", "cookie", "session"]
        if any(kw in description for kw in web_keywords):
            return CTFCategory.WEB

        # Crypto indicators
        crypto_keywords = ["encrypt", "decrypt", "cipher", "hash", "rsa", "aes", "base64"]
        if any(kw in description for kw in crypto_keywords):
            return CTFCategory.CRYPTO

        # Pwn indicators
        pwn_keywords = ["binary", "overflow", "shellcode", "rop", "exploit"]
        if any(kw in description for kw in pwn_keywords):
            return CTFCategory.PWN

        # File extension analysis
        for file in files:
            if file.endswith((".exe", ".elf", ".bin")):
                return CTFCategory.PWN
            elif file.endswith((".pcap", ".png", ".jpg", ".zip")):
                return CTFCategory.FORENSICS

        return CTFCategory.MISC

    def _suggest_tools(
        self,
        category: CTFCategory,
        description: str,
        files: List[str]
    ) -> List[str]:
        """Suggest appropriate tools"""

        tool_map = {
            CTFCategory.WEB: [
                "web_tech_detect",
                "web_sql_payloads",
                "web_xss_payloads",
                "web_dir_bruteforce"
            ],
            CTFCategory.CRYPTO: [
                "crypto_identify",
                "crypto_base64_decode",
                "crypto_frequency_analysis",
                "crypto_rsa_attack"
            ],
            CTFCategory.PWN: [
                "pwn_checksec",
                "pwn_pattern_create",
                "pwn_rop_gadgets",
                "pwn_shellcode_gen"
            ],
            CTFCategory.REVERSE: [
                "reverse_disasm",
                "reverse_strings",
                "reverse_deobfuscate"
            ],
            CTFCategory.FORENSICS: [
                "forensics_file_magic",
                "forensics_exif_extract",
                "forensics_strings_file",
                "forensics_binwalk_scan"
            ],
            CTFCategory.MISC: [
                "misc_hex_decode",
                "misc_binary_convert",
                "misc_find_flag"
            ]
        }

        base_tools = tool_map.get(category, [])

        # Add context-specific tools
        if "base64" in description:
            base_tools.insert(0, "crypto_base64_decode")
        if "sql" in description:
            base_tools.insert(0, "web_sql_payloads")
        if "xss" in description:
            base_tools.insert(0, "web_xss_payloads")

        return base_tools[:5]  # Return top 5 tools

    def _generate_reasoning(
        self,
        category: CTFCategory,
        description: str,
        files: List[str]
    ) -> str:
        """Generate reasoning for the analysis"""

        reasoning_parts = [
            f"Challenge appears to be in the {category.value.upper()} category."
        ]

        # Add specific observations
        if "encrypt" in description or "cipher" in description:
            reasoning_parts.append("Keywords suggest cryptographic challenge.")
        if "web" in description or "http" in description:
            reasoning_parts.append("Web-related keywords detected.")
        if files:
            reasoning_parts.append(f"Provided files: {', '.join(files)}")

        return " ".join(reasoning_parts)

    def _suggest_next_steps(
        self,
        category: CTFCategory,
        tools: List[str]
    ) -> List[str]:
        """Suggest next steps"""

        steps_map = {
            CTFCategory.WEB: [
                "Identify web technologies and frameworks",
                "Check for common vulnerabilities (SQLi, XSS)",
                "Enumerate directories and endpoints",
                "Test authentication mechanisms"
            ],
            CTFCategory.CRYPTO: [
                "Identify encryption/encoding method",
                "Analyze ciphertext patterns",
                "Try common cryptographic attacks",
                "Check for weak keys or implementation flaws"
            ],
            CTFCategory.PWN: [
                "Analyze binary protections (checksec)",
                "Identify vulnerability type",
                "Calculate offsets if buffer overflow",
                "Craft exploit payload"
            ],
            CTFCategory.REVERSE: [
                "Disassemble the binary",
                "Extract strings and analyze",
                "Identify key functions",
                "Understand program logic"
            ],
            CTFCategory.FORENSICS: [
                "Identify file type",
                "Extract metadata",
                "Search for hidden data",
                "Analyze file structure"
            ],
            CTFCategory.MISC: [
                "Analyze provided data",
                "Try common encoding schemes",
                "Search for flag patterns",
                "Experiment with different approaches"
            ]
        }

        return steps_map.get(category, ["Analyze the challenge", "Try suggested tools"])

    def suggest_next_action(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Suggest next action based on current context

        Args:
            context: Current challenge context
                - category: Challenge category
                - completed_steps: List of completed steps
                - findings: Current findings
                - stuck: Whether user is stuck

        Returns:
            Suggested action
        """
        category = context.get("category")
        completed = context.get("completed_steps", [])
        findings = context.get("findings", {})
        stuck = context.get("stuck", False)

        # If stuck, suggest alternative approaches
        if stuck:
            return {
                "action": "try_alternative",
                "suggestion": "Consider a different approach or tool",
                "alternatives": self._get_alternatives(category, completed)
            }

        # Suggest next logical step
        all_steps = self._suggest_next_steps(
            CTFCategory(category) if category else CTFCategory.MISC,
            []
        )

        # Find first uncompleted step
        for step in all_steps:
            if step not in completed:
                return {
                    "action": "next_step",
                    "suggestion": step,
                    "tools": self._tools_for_step(step)
                }

        return {
            "action": "review",
            "suggestion": "Review findings and look for missed clues"
        }

    def _get_alternatives(
        self,
        category: Optional[str],
        completed: List[str]
    ) -> List[str]:
        """Get alternative approaches"""
        alternatives = [
            "Try a different tool from the same category",
            "Re-examine the challenge description for hints",
            "Look for hidden data or steganography",
            "Check if multiple vulnerabilities need to be chained"
        ]
        return alternatives

    def _tools_for_step(self, step: str) -> List[str]:
        """Get tools for a specific step"""
        # Simplified mapping
        step_lower = step.lower()

        if "identify" in step_lower or "analyze" in step_lower:
            return ["tech_detect", "file_magic", "identify"]
        elif "enumerate" in step_lower or "scan" in step_lower:
            return ["dir_bruteforce", "port_scan", "subdomain_enum"]
        elif "exploit" in step_lower or "attack" in step_lower:
            return ["sql_payloads", "xss_payloads", "exploit_gen"]

        return []

    def analyze_vulnerability(
        self,
        vuln_type: str,
        target: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Analyze a vulnerability and suggest exploitation strategy

        Args:
            vuln_type: Type of vulnerability (sqli, xss, etc.)
            target: Target URL or system
            context: Additional context

        Returns:
            Exploitation strategy
        """
        strategies = {
            "sqli": {
                "steps": [
                    "Test for SQL injection with basic payloads",
                    "Determine number of columns (UNION)",
                    "Extract database information",
                    "Dump sensitive data"
                ],
                "tools": ["sql_payloads", "exploit_sqli_extract"],
                "payloads": ["union", "error", "blind", "time"]
            },
            "xss": {
                "steps": [
                    "Identify injection context (HTML, attribute, script)",
                    "Test basic XSS payloads",
                    "Bypass filters if present",
                    "Craft final payload"
                ],
                "tools": ["xss_payloads", "xss_detect"],
                "contexts": ["html", "attribute", "script", "url"]
            },
            "rce": {
                "steps": [
                    "Identify command injection point",
                    "Test basic command injection",
                    "Bypass filters",
                    "Execute desired commands"
                ],
                "tools": ["cmd_injection", "reverse_shell_gen"],
                "techniques": ["semicolon", "pipe", "backtick", "dollar"]
            }
        }

        return strategies.get(vuln_type, {
            "steps": ["Analyze vulnerability", "Research exploitation techniques"],
            "tools": [],
            "note": "No specific strategy available for this vulnerability type"
        })
