"""
CTF-MCP External Tool Adapters
Unified interface for external security tools
"""

from .base import (
    ToolAdapter,
    PythonLibraryAdapter,
    AdapterResult,
    AdapterStatus,
    AdapterRegistry,
    get_adapter,
    register_adapter,
    list_adapters,
    list_available_adapters,
    get_adapter_status,
)
from .pwntools_adapter import PwntoolsAdapter
from .angr_adapter import AngrAdapter
from .sqlmap_adapter import SqlmapAdapter
from .hashcat_adapter import HashcatAdapter
from .binwalk_adapter import BinwalkAdapter
from .nmap_adapter import NmapAdapter

__all__ = [
    # Base classes
    "ToolAdapter",
    "PythonLibraryAdapter",
    "AdapterResult",
    "AdapterStatus",
    "AdapterRegistry",
    # Registry functions
    "get_adapter",
    "register_adapter",
    "list_adapters",
    "list_available_adapters",
    "get_adapter_status",
    # Adapters
    "PwntoolsAdapter",
    "AngrAdapter",
    "SqlmapAdapter",
    "HashcatAdapter",
    "BinwalkAdapter",
    "NmapAdapter",
]


def register_all_adapters() -> None:
    """Register all available adapters to the global registry"""
    adapters = [
        PwntoolsAdapter(),
        AngrAdapter(),
        SqlmapAdapter(),
        HashcatAdapter(),
        BinwalkAdapter(),
        NmapAdapter(),
    ]
    for adapter in adapters:
        register_adapter(adapter)


# Auto-register on import
register_all_adapters()
