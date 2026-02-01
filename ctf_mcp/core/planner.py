"""
CTF Solving Strategy Planner
Generates and prioritizes solving strategies based on challenge type
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from .classifier import ChallengeType

logger = logging.getLogger("ctf-mcp.planner")


class StepType(Enum):
    """Type of strategy step"""
    TOOL = "tool"           # Call a CTF-MCP tool
    ANALYZE = "analyze"     # Analyze output
    EXTRACT = "extract"     # Extract flag from output
    VALIDATE = "validate"   # Validate result
    REMOTE = "remote"       # Remote interaction
    MANUAL = "manual"       # Requires manual intervention


@dataclass
class StrategyStep:
    """
    A single step in a solving strategy.

    Attributes:
        step_type: Type of step
        tool_name: Name of tool to call (for TOOL type)
        params: Parameters for the tool
        description: Human-readable description
        depends_on: List of step indices this step depends on
        on_success: Next step index on success
        on_failure: Next step index on failure (or None to continue)
        timeout: Step-specific timeout in seconds
    """
    step_type: StepType
    tool_name: Optional[str] = None
    params: dict[str, Any] = field(default_factory=dict)
    description: str = ""
    depends_on: list[int] = field(default_factory=list)
    on_success: Optional[int] = None
    on_failure: Optional[int] = None
    timeout: float = 60.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.step_type.value,
            "tool": self.tool_name,
            "params": self.params,
            "description": self.description,
        }


@dataclass
class SolvingStrategy:
    """
    A complete solving strategy for a challenge.

    Attributes:
        name: Strategy name
        description: Strategy description
        challenge_types: Applicable challenge types
        priority: Priority (higher = try first)
        steps: List of strategy steps
        requirements: Required tools/capabilities
        estimated_time: Estimated time in seconds
    """
    name: str
    description: str = ""
    challenge_types: list[ChallengeType] = field(default_factory=list)
    priority: int = 0
    steps: list[StrategyStep] = field(default_factory=list)
    requirements: list[str] = field(default_factory=list)
    estimated_time: float = 60.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "types": [t.value for t in self.challenge_types],
            "priority": self.priority,
            "steps": [s.to_dict() for s in self.steps],
        }


class SolvingPlanner:
    """
    Plans solving strategies for CTF challenges.

    Generates strategies based on:
    - Challenge type
    - Available files
    - Remote endpoints
    - Content analysis results
    """

    def __init__(self):
        """Initialize the planner with strategy templates"""
        self.strategy_templates = self._build_strategy_templates()

    def plan(
        self,
        challenge_types: list[ChallengeType],
        files: list[str] = None,
        remote: Optional[str] = None,
        analysis: dict[str, Any] = None,
    ) -> list[SolvingStrategy]:
        """
        Generate solving strategies for a challenge.

        Args:
            challenge_types: Classified challenge types (ordered by confidence)
            files: Associated file paths
            remote: Remote connection info
            analysis: Additional analysis data

        Returns:
            List of strategies ordered by priority
        """
        files = files or []
        analysis = analysis or {}
        strategies: list[SolvingStrategy] = []

        # Get strategies for each possible type
        for ctype in challenge_types:
            type_strategies = self._get_strategies_for_type(ctype, files, remote, analysis)
            strategies.extend(type_strategies)

        # Sort by priority (descending)
        strategies.sort(key=lambda s: s.priority, reverse=True)

        logger.info("Generated %d strategies for types: %s", len(strategies), [t.value for t in challenge_types])

        return strategies

    def _get_strategies_for_type(
        self,
        ctype: ChallengeType,
        files: list[str],
        remote: Optional[str],
        analysis: dict[str, Any],
    ) -> list[SolvingStrategy]:
        """Get applicable strategies for a challenge type"""
        strategies = []

        # Get templates for this type
        templates = self.strategy_templates.get(ctype, [])

        for template in templates:
            # Customize template based on challenge specifics
            strategy = self._customize_strategy(template, files, remote, analysis)
            if strategy:
                strategies.append(strategy)

        return strategies

    def _customize_strategy(
        self,
        template: SolvingStrategy,
        files: list[str],
        remote: Optional[str],
        analysis: dict[str, Any],
    ) -> Optional[SolvingStrategy]:
        """Customize a strategy template for specific challenge"""
        # Create a copy of the template
        strategy = SolvingStrategy(
            name=template.name,
            description=template.description,
            challenge_types=template.challenge_types.copy(),
            priority=template.priority,
            requirements=template.requirements.copy(),
            estimated_time=template.estimated_time,
        )

        # Customize steps
        for step in template.steps:
            customized = StrategyStep(
                step_type=step.step_type,
                tool_name=step.tool_name,
                params=step.params.copy(),
                description=step.description,
                depends_on=step.depends_on.copy(),
                on_success=step.on_success,
                on_failure=step.on_failure,
                timeout=step.timeout,
            )

            # Replace placeholders in params
            for key, value in customized.params.items():
                if isinstance(value, str):
                    if value == "{file}" and files:
                        customized.params[key] = files[0]
                    elif value == "{files}":
                        customized.params[key] = files
                    elif value == "{remote}":
                        customized.params[key] = remote

            strategy.steps.append(customized)

        return strategy

    def _build_strategy_templates(self) -> dict[ChallengeType, list[SolvingStrategy]]:
        """Build strategy templates for each challenge type"""
        templates: dict[ChallengeType, list[SolvingStrategy]] = {}

        # Crypto strategies
        templates[ChallengeType.CRYPTO] = [
            # RSA attack strategies
            SolvingStrategy(
                name="RSA Factor Attack",
                description="Try to factor RSA modulus using various methods",
                challenge_types=[ChallengeType.CRYPTO],
                priority=90,
                steps=[
                    StrategyStep(
                        step_type=StepType.ANALYZE,
                        description="Extract RSA parameters from challenge",
                    ),
                    StrategyStep(
                        step_type=StepType.TOOL,
                        tool_name="crypto_rsa_factor",
                        params={"n": "{n}", "e": "{e}"},
                        description="Attempt to factor n",
                    ),
                    StrategyStep(
                        step_type=StepType.TOOL,
                        tool_name="crypto_rsa_decrypt",
                        params={"p": "{p}", "q": "{q}", "e": "{e}", "c": "{c}"},
                        description="Decrypt ciphertext",
                        depends_on=[1],
                    ),
                    StrategyStep(
                        step_type=StepType.EXTRACT,
                        description="Extract flag from plaintext",
                    ),
                ],
                estimated_time=120.0,
            ),
            # Classical cipher bruteforce
            SolvingStrategy(
                name="Classical Cipher Bruteforce",
                description="Try common classical cipher attacks",
                challenge_types=[ChallengeType.CRYPTO],
                priority=80,
                steps=[
                    StrategyStep(
                        step_type=StepType.TOOL,
                        tool_name="crypto_caesar_bruteforce",
                        params={"text": "{ciphertext}"},
                        description="Try all Caesar shifts",
                    ),
                    StrategyStep(
                        step_type=StepType.TOOL,
                        tool_name="crypto_freq_analysis",
                        params={"text": "{ciphertext}"},
                        description="Frequency analysis",
                    ),
                    StrategyStep(
                        step_type=StepType.EXTRACT,
                        description="Look for flag in results",
                    ),
                ],
                estimated_time=30.0,
            ),
            # Base encoding chain
            SolvingStrategy(
                name="Encoding Chain Decode",
                description="Try common encoding chains (base64, hex, etc.)",
                challenge_types=[ChallengeType.CRYPTO],
                priority=95,
                steps=[
                    StrategyStep(
                        step_type=StepType.TOOL,
                        tool_name="crypto_base64_decode",
                        params={"data": "{data}"},
                        description="Try base64 decode",
                    ),
                    StrategyStep(
                        step_type=StepType.TOOL,
                        tool_name="misc_hex_decode",
                        params={"data": "{data}"},
                        description="Try hex decode",
                    ),
                    StrategyStep(
                        step_type=StepType.EXTRACT,
                        description="Extract flag from decoded data",
                    ),
                ],
                estimated_time=15.0,
            ),
        ]

        # Web strategies
        templates[ChallengeType.WEB] = [
            SolvingStrategy(
                name="SQL Injection Test",
                description="Test for SQL injection vulnerabilities",
                challenge_types=[ChallengeType.WEB],
                priority=85,
                steps=[
                    StrategyStep(
                        step_type=StepType.TOOL,
                        tool_name="web_sql_payloads",
                        params={"dbms": "mysql", "technique": "union"},
                        description="Generate SQLi payloads",
                    ),
                    StrategyStep(
                        step_type=StepType.REMOTE,
                        description="Test payloads against target",
                    ),
                    StrategyStep(
                        step_type=StepType.EXTRACT,
                        description="Extract flag from response",
                    ),
                ],
                estimated_time=120.0,
            ),
            SolvingStrategy(
                name="SSTI Detection",
                description="Test for Server-Side Template Injection",
                challenge_types=[ChallengeType.WEB],
                priority=80,
                steps=[
                    StrategyStep(
                        step_type=StepType.TOOL,
                        tool_name="web_ssti_identify",
                        params={},
                        description="Generate SSTI detection payloads",
                    ),
                    StrategyStep(
                        step_type=StepType.TOOL,
                        tool_name="web_ssti_payloads",
                        params={"engine": "auto"},
                        description="Generate exploitation payloads",
                    ),
                    StrategyStep(
                        step_type=StepType.EXTRACT,
                        description="Extract flag from response",
                    ),
                ],
                estimated_time=90.0,
            ),
            SolvingStrategy(
                name="JWT Attack",
                description="Analyze and attack JWT tokens",
                challenge_types=[ChallengeType.WEB],
                priority=75,
                steps=[
                    StrategyStep(
                        step_type=StepType.TOOL,
                        tool_name="web_jwt_decode",
                        params={"token": "{token}"},
                        description="Decode JWT token",
                    ),
                    StrategyStep(
                        step_type=StepType.TOOL,
                        tool_name="web_jwt_forge",
                        params={"token": "{token}", "attack": "none"},
                        description="Forge JWT with none algorithm",
                    ),
                    StrategyStep(
                        step_type=StepType.EXTRACT,
                        description="Use forged token to get flag",
                    ),
                ],
                estimated_time=60.0,
            ),
        ]

        # PWN strategies
        templates[ChallengeType.PWN] = [
            SolvingStrategy(
                name="Buffer Overflow Exploit",
                description="Classic buffer overflow exploitation",
                challenge_types=[ChallengeType.PWN],
                priority=90,
                steps=[
                    StrategyStep(
                        step_type=StepType.TOOL,
                        tool_name="pwn_pattern_create",
                        params={"length": 500},
                        description="Create cyclic pattern",
                    ),
                    StrategyStep(
                        step_type=StepType.TOOL,
                        tool_name="pwn_pattern_offset",
                        params={"value": "{crash_value}"},
                        description="Find offset",
                        depends_on=[0],
                    ),
                    StrategyStep(
                        step_type=StepType.TOOL,
                        tool_name="pwn_rop_gadgets",
                        params={"arch": "x64"},
                        description="Find ROP gadgets",
                    ),
                    StrategyStep(
                        step_type=StepType.TOOL,
                        tool_name="pwn_ret2libc",
                        params={"arch": "x64"},
                        description="Generate ret2libc template",
                    ),
                    StrategyStep(
                        step_type=StepType.REMOTE,
                        description="Execute exploit against remote",
                    ),
                ],
                estimated_time=300.0,
            ),
            SolvingStrategy(
                name="Format String Attack",
                description="Format string vulnerability exploitation",
                challenge_types=[ChallengeType.PWN],
                priority=85,
                steps=[
                    StrategyStep(
                        step_type=StepType.TOOL,
                        tool_name="pwn_format_string_leak",
                        params={},
                        description="Generate format string leak payload",
                    ),
                    StrategyStep(
                        step_type=StepType.TOOL,
                        tool_name="pwn_format_string",
                        params={"target_addr": "{got_addr}", "value": "{system}", "offset": "{offset}"},
                        description="Generate write payload",
                        depends_on=[0],
                    ),
                    StrategyStep(
                        step_type=StepType.REMOTE,
                        description="Execute exploit",
                    ),
                ],
                estimated_time=240.0,
            ),
        ]

        # Reverse strategies
        templates[ChallengeType.REVERSE] = [
            SolvingStrategy(
                name="Static Analysis",
                description="Static binary analysis",
                challenge_types=[ChallengeType.REVERSE],
                priority=90,
                steps=[
                    StrategyStep(
                        step_type=StepType.TOOL,
                        tool_name="reverse_elf_info",
                        params={"file_path": "{file}"},
                        description="Analyze ELF header",
                    ),
                    StrategyStep(
                        step_type=StepType.TOOL,
                        tool_name="reverse_find_strings",
                        params={"file_path": "{file}", "min_length": 4},
                        description="Extract strings",
                    ),
                    StrategyStep(
                        step_type=StepType.EXTRACT,
                        description="Look for flag in strings",
                    ),
                ],
                estimated_time=60.0,
            ),
            SolvingStrategy(
                name="Deobfuscation",
                description="Try various deobfuscation techniques",
                challenge_types=[ChallengeType.REVERSE],
                priority=70,
                steps=[
                    StrategyStep(
                        step_type=StepType.TOOL,
                        tool_name="reverse_deobfuscate",
                        params={"code": "{data}", "obf_type": "auto"},
                        description="Attempt deobfuscation",
                    ),
                    StrategyStep(
                        step_type=StepType.EXTRACT,
                        description="Extract flag from deobfuscated data",
                    ),
                ],
                estimated_time=45.0,
            ),
        ]

        # Forensics strategies
        templates[ChallengeType.FORENSICS] = [
            SolvingStrategy(
                name="File Analysis",
                description="Analyze file type and embedded data",
                challenge_types=[ChallengeType.FORENSICS],
                priority=95,
                steps=[
                    StrategyStep(
                        step_type=StepType.TOOL,
                        tool_name="forensics_binwalk_scan",
                        params={"file_path": "{file}"},
                        description="Scan for embedded files",
                    ),
                    StrategyStep(
                        step_type=StepType.TOOL,
                        tool_name="forensics_strings_file",
                        params={"file_path": "{file}", "min_length": 4},
                        description="Extract strings",
                    ),
                    StrategyStep(
                        step_type=StepType.EXTRACT,
                        description="Search for flag",
                    ),
                ],
                estimated_time=60.0,
            ),
            SolvingStrategy(
                name="Image Steganography",
                description="Check image for hidden data",
                challenge_types=[ChallengeType.FORENSICS],
                priority=85,
                steps=[
                    StrategyStep(
                        step_type=StepType.TOOL,
                        tool_name="forensics_exif_extract",
                        params={"file_path": "{file}"},
                        description="Extract EXIF metadata",
                    ),
                    StrategyStep(
                        step_type=StepType.TOOL,
                        tool_name="forensics_steghide_detect",
                        params={"file_path": "{file}"},
                        description="Detect steganography",
                    ),
                    StrategyStep(
                        step_type=StepType.TOOL,
                        tool_name="forensics_lsb_extract",
                        params={"file_path": "{file}", "bits": 1},
                        description="Extract LSB data",
                    ),
                    StrategyStep(
                        step_type=StepType.EXTRACT,
                        description="Search for flag in extracted data",
                    ),
                ],
                estimated_time=90.0,
            ),
        ]

        # Misc strategies
        templates[ChallengeType.MISC] = [
            SolvingStrategy(
                name="Encoding Detection",
                description="Detect and decode various encodings",
                challenge_types=[ChallengeType.MISC],
                priority=90,
                steps=[
                    StrategyStep(
                        step_type=StepType.TOOL,
                        tool_name="misc_detect_encoding",
                        params={"data": "{data}"},
                        description="Detect encoding type",
                    ),
                    StrategyStep(
                        step_type=StepType.TOOL,
                        tool_name="misc_find_flag",
                        params={"text": "{decoded}"},
                        description="Search for flag pattern",
                    ),
                ],
                estimated_time=30.0,
            ),
        ]

        # Add empty lists for types without templates
        for ctype in ChallengeType:
            if ctype not in templates:
                templates[ctype] = []

        return templates
