"""
Base Solving Engine
Abstract base class for all CTF solving engines
"""

import logging
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from ..core.orchestrator import Challenge

logger = logging.getLogger("ctf-mcp.engine")


class EngineCapability(Enum):
    """Capabilities that an engine may have"""
    ANALYZE = auto()       # Can analyze challenge files
    DECODE = auto()        # Can decode/decrypt data
    EXPLOIT = auto()       # Can generate exploits
    REMOTE = auto()        # Can interact with remote targets
    FILE_ANALYSIS = auto() # Can analyze binary files
    BRUTEFORCE = auto()    # Can perform bruteforce attacks
    EXTRACT = auto()       # Can extract hidden data


@dataclass
class EngineResult:
    """
    Result from an engine operation.

    Attributes:
        success: Whether the operation succeeded
        flag: Extracted flag (if found)
        data: Processed/decoded data
        analysis: Analysis results
        steps: Steps taken during solving
        confidence: Confidence in the result (0-1)
        error: Error message if failed
        duration: Time taken in seconds
    """
    success: bool = False
    flag: Optional[str] = None
    data: Any = None
    analysis: dict[str, Any] = field(default_factory=dict)
    steps: list[str] = field(default_factory=list)
    confidence: float = 0.0
    error: Optional[str] = None
    duration: float = 0.0

    def add_step(self, step: str):
        """Add a step to the solving history"""
        self.steps.append(step)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "flag": self.flag,
            "data": str(self.data)[:500] if self.data else None,
            "steps": self.steps,
            "confidence": self.confidence,
            "error": self.error,
            "duration": self.duration,
        }


class SolvingEngine(ABC):
    """
    Abstract base class for CTF solving engines.

    Each engine specializes in a specific category (crypto, web, pwn, etc.)
    and provides methods to analyze and solve challenges in that category.
    """

    # Flag patterns to search for
    FLAG_PATTERNS = [
        r'flag\{[^}]+\}',
        r'FLAG\{[^}]+\}',
        r'ctf\{[^}]+\}',
        r'CTF\{[^}]+\}',
        r'picoCTF\{[^}]+\}',
        r'HTB\{[^}]+\}',
        r'FLAG-[A-Za-z0-9_-]+',
    ]

    def __init__(self):
        """Initialize the engine"""
        self._tools = None
        self.logger = logging.getLogger(f"ctf-mcp.engine.{self.name}")

    @property
    @abstractmethod
    def name(self) -> str:
        """Engine name"""
        pass

    @property
    @abstractmethod
    def capabilities(self) -> list[EngineCapability]:
        """List of engine capabilities"""
        pass

    @abstractmethod
    def analyze(self, challenge: "Challenge") -> dict[str, Any]:
        """
        Analyze a challenge without solving it.

        Args:
            challenge: The challenge to analyze

        Returns:
            Analysis results including detected patterns and recommendations
        """
        pass

    @abstractmethod
    def solve(self, challenge: "Challenge", **kwargs) -> EngineResult:
        """
        Attempt to solve a challenge.

        Args:
            challenge: The challenge to solve
            **kwargs: Additional parameters

        Returns:
            EngineResult with flag if found
        """
        pass

    def can_handle(self, challenge: "Challenge") -> float:
        """
        Check if this engine can handle a challenge.

        Args:
            challenge: The challenge to check

        Returns:
            Confidence score (0-1) that this engine can handle the challenge
        """
        return 0.0

    def find_flags(self, text: str, custom_pattern: Optional[str] = None) -> list[str]:
        """
        Find flag patterns in text.

        Args:
            text: Text to search
            custom_pattern: Additional pattern to search

        Returns:
            List of found flags
        """
        flags = []
        patterns = self.FLAG_PATTERNS.copy()
        if custom_pattern:
            patterns.append(custom_pattern)

        for pattern in patterns:
            try:
                matches = re.findall(pattern, text, re.IGNORECASE)
                flags.extend(matches)
            except re.error:
                pass

        return list(set(flags))

    def _get_tools(self):
        """Get the tools module (lazy load)"""
        if self._tools is None:
            from ..tools.crypto import CryptoTools
            from ..tools.web import WebTools
            from ..tools.pwn import PwnTools
            from ..tools.reverse import ReverseTools
            from ..tools.forensics import ForensicsTools
            from ..tools.misc import MiscTools

            self._tools = {
                "crypto": CryptoTools(),
                "web": WebTools(),
                "pwn": PwnTools(),
                "reverse": ReverseTools(),
                "forensics": ForensicsTools(),
                "misc": MiscTools(),
            }
        return self._tools

    def _read_file(self, file_path: str, binary: bool = False) -> Optional[Any]:
        """Safely read a file"""
        try:
            mode = 'rb' if binary else 'r'
            with open(file_path, mode, errors='ignore' if not binary else None) as f:
                return f.read()
        except (IOError, PermissionError) as e:
            self.logger.warning("Failed to read file %s: %s", file_path, e)
            return None

    def _timed_operation(self, func, *args, **kwargs) -> tuple[Any, float]:
        """Execute a function and return result with duration"""
        start = time.time()
        result = func(*args, **kwargs)
        duration = time.time() - start
        return result, duration
