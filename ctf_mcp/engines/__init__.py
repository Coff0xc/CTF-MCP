"""
CTF-MCP Solving Engines
Specialized engines for each challenge category
"""

from .base import SolvingEngine, EngineResult, EngineCapability
from .crypto_engine import CryptoEngine
from .web_engine import WebEngine
from .pwn_engine import PwnEngine
from .reverse_engine import ReverseEngine
from .forensics_engine import ForensicsEngine
from .misc_engine import MiscEngine

__all__ = [
    # Base
    "SolvingEngine",
    "EngineResult",
    "EngineCapability",
    # Engines
    "CryptoEngine",
    "WebEngine",
    "PwnEngine",
    "ReverseEngine",
    "ForensicsEngine",
    "MiscEngine",
]


def get_engine_for_type(challenge_type: str) -> SolvingEngine:
    """Get the appropriate engine for a challenge type"""
    engines = {
        "crypto": CryptoEngine,
        "web": WebEngine,
        "pwn": PwnEngine,
        "reverse": ReverseEngine,
        "forensics": ForensicsEngine,
        "misc": MiscEngine,
    }
    engine_class = engines.get(challenge_type.lower(), MiscEngine)
    return engine_class()
