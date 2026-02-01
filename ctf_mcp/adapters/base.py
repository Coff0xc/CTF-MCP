"""
External Tool Adapter Base
Abstract base class for all external tool adapters
"""

import logging
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional


logger = logging.getLogger("ctf-mcp.adapter")


class AdapterStatus(Enum):
    """Status of an adapter"""
    AVAILABLE = auto()      # Tool is available and working
    NOT_INSTALLED = auto()  # Tool is not installed
    VERSION_MISMATCH = auto()  # Tool version doesn't meet requirements
    DISABLED = auto()       # Adapter is disabled by configuration
    ERROR = auto()          # Error checking status


@dataclass
class AdapterResult:
    """
    Result from an adapter operation.

    Attributes:
        success: Whether the operation succeeded
        output: Command output or result data
        error: Error message if failed
        duration: Time taken in seconds
        return_code: Command return code (if applicable)
        data: Parsed/structured data from the output
    """
    success: bool = False
    output: str = ""
    error: Optional[str] = None
    duration: float = 0.0
    return_code: int = 0
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "output": self.output[:2000] if self.output else None,
            "error": self.error,
            "duration": self.duration,
            "return_code": self.return_code,
            "data": self.data,
        }


class ToolAdapter(ABC):
    """
    Abstract base class for external tool adapters.

    Provides a unified interface for interacting with external
    security tools like pwntools, sqlmap, nmap, etc.
    """

    def __init__(self):
        """Initialize the adapter"""
        self._status: Optional[AdapterStatus] = None
        self._version: Optional[str] = None
        self.logger = logging.getLogger(f"ctf-mcp.adapter.{self.name}")
        self._timeout = 300  # Default 5 minute timeout

    @property
    @abstractmethod
    def name(self) -> str:
        """Adapter/tool name"""
        pass

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """The actual tool binary/command name"""
        pass

    @property
    def description(self) -> str:
        """Tool description"""
        return f"{self.name} adapter"

    @property
    def min_version(self) -> Optional[str]:
        """Minimum required version (if any)"""
        return None

    @property
    def status(self) -> AdapterStatus:
        """Get adapter status (cached)"""
        if self._status is None:
            self._status = self._check_status()
        return self._status

    @property
    def version(self) -> Optional[str]:
        """Get tool version (cached)"""
        if self._version is None:
            self._version = self._get_version()
        return self._version

    @property
    def is_available(self) -> bool:
        """Check if tool is available"""
        return self.status == AdapterStatus.AVAILABLE

    def refresh_status(self) -> AdapterStatus:
        """Force refresh of adapter status"""
        self._status = None
        self._version = None
        return self.status

    def _check_status(self) -> AdapterStatus:
        """Check if the tool is available and meets requirements"""
        # Check if binary exists
        if not self._find_binary():
            return AdapterStatus.NOT_INSTALLED

        # Get version
        version = self._get_version()
        if version is None:
            return AdapterStatus.ERROR

        # Check minimum version if required
        if self.min_version:
            if not self._version_meets_requirement(version, self.min_version):
                return AdapterStatus.VERSION_MISMATCH

        return AdapterStatus.AVAILABLE

    def _find_binary(self) -> bool:
        """Check if tool binary exists in PATH"""
        return shutil.which(self.tool_name) is not None

    @abstractmethod
    def _get_version(self) -> Optional[str]:
        """Get the tool version"""
        pass

    def _version_meets_requirement(self, current: str, required: str) -> bool:
        """Compare version strings"""
        try:
            from packaging import version
            return version.parse(current) >= version.parse(required)
        except ImportError:
            # Fallback to tuple comparison for proper semantic versioning
            try:
                cur_parts = [int(x) for x in current.split('.')]
                req_parts = [int(x) for x in required.split('.')]
                return cur_parts >= req_parts
            except ValueError:
                return True
        except Exception:
            return True

    def _run_command(
        self,
        args: list[str],
        timeout: Optional[float] = None,
        input_data: Optional[str] = None,
        cwd: Optional[str] = None,
    ) -> AdapterResult:
        """
        Run a command and return the result.

        Args:
            args: Command arguments (including the command itself)
            timeout: Command timeout in seconds
            input_data: Data to send to stdin
            cwd: Working directory

        Returns:
            AdapterResult with command output
        """
        result = AdapterResult()
        start_time = time.time()

        try:
            process = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout or self._timeout,
                input=input_data,
                cwd=cwd,
            )

            result.output = process.stdout
            result.return_code = process.returncode
            result.success = process.returncode == 0

            if process.stderr and not result.success:
                result.error = process.stderr

        except subprocess.TimeoutExpired:
            result.success = False
            result.error = f"Command timed out after {timeout or self._timeout}s"
            result.return_code = -1

        except FileNotFoundError:
            result.success = False
            result.error = f"Command not found: {args[0]}"
            result.return_code = -1

        except Exception as e:
            result.success = False
            result.error = str(e)
            result.return_code = -1

        result.duration = time.time() - start_time
        return result

    def _run_command_async(
        self,
        args: list[str],
        cwd: Optional[str] = None,
    ) -> subprocess.Popen:
        """
        Start a command asynchronously.

        Args:
            args: Command arguments
            cwd: Working directory

        Returns:
            Popen object for the running process
        """
        return subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=cwd,
        )


class PythonLibraryAdapter(ToolAdapter):
    """
    Base class for adapters that wrap Python libraries
    instead of external binaries.
    """

    @property
    def tool_name(self) -> str:
        """For Python libraries, this is the import name"""
        return self.name

    def _find_binary(self) -> bool:
        """Check if the Python library is importable"""
        try:
            __import__(self.tool_name)
            return True
        except ImportError:
            return False

    def _get_version(self) -> Optional[str]:
        """Get library version"""
        try:
            module = __import__(self.tool_name)
            return getattr(module, '__version__', 'unknown')
        except Exception:
            return None


class AdapterRegistry:
    """
    Registry for managing tool adapters.

    Provides methods to discover, register, and query adapters.
    """

    def __init__(self):
        self._adapters: dict[str, ToolAdapter] = {}

    def register(self, adapter: ToolAdapter) -> None:
        """Register an adapter"""
        self._adapters[adapter.name] = adapter

    def unregister(self, name: str) -> None:
        """Unregister an adapter"""
        self._adapters.pop(name, None)

    def get(self, name: str) -> Optional[ToolAdapter]:
        """Get an adapter by name"""
        return self._adapters.get(name)

    def list_all(self) -> list[str]:
        """List all registered adapters"""
        return list(self._adapters.keys())

    def list_available(self) -> list[str]:
        """List only available adapters"""
        return [
            name for name, adapter in self._adapters.items()
            if adapter.is_available
        ]

    def get_status_report(self) -> dict[str, dict]:
        """Get status report for all adapters"""
        return {
            name: {
                "status": adapter.status.name,
                "version": adapter.version,
                "available": adapter.is_available,
            }
            for name, adapter in self._adapters.items()
        }


# Global registry
_registry = AdapterRegistry()


def get_adapter(name: str) -> Optional[ToolAdapter]:
    """Get an adapter from the global registry"""
    return _registry.get(name)


def register_adapter(adapter: ToolAdapter) -> None:
    """Register an adapter to the global registry"""
    _registry.register(adapter)


def list_adapters() -> list[str]:
    """List all registered adapters"""
    return _registry.list_all()


def list_available_adapters() -> list[str]:
    """List available adapters"""
    return _registry.list_available()


def get_adapter_status() -> dict[str, dict]:
    """Get status of all adapters"""
    return _registry.get_status_report()
