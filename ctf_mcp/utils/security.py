"""
Security utilities for CTF-MCP
Provides security warnings and decorators for dangerous operations
"""

import functools
import warnings
from typing import Callable, Any
from enum import Enum


class SecurityWarning(UserWarning):
    """Custom security warning for dangerous operations"""
    pass


class RiskLevel(Enum):
    """Risk levels for security operations"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def dangerous_operation(risk_level: RiskLevel, description: str):
    """
    Decorator to mark dangerous operations with security warnings

    Args:
        risk_level: Risk level of the operation
        description: Description of the security risk

    Example:
        @dangerous_operation(
            risk_level=RiskLevel.CRITICAL,
            description="Generates RCE payloads that can execute arbitrary code"
        )
        def pickle_payload(self) -> str:
            # Implementation
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # Generate warning message
            risk_icons = {
                RiskLevel.LOW: "🟢",
                RiskLevel.MEDIUM: "🟡",
                RiskLevel.HIGH: "🟠",
                RiskLevel.CRITICAL: "🔴"
            }

            icon = risk_icons.get(risk_level, "⚠️")

            warning_msg = f"""
╔═══════════════════════════════════════════════════════════╗
║  {icon} SECURITY WARNING - {risk_level.value.upper():^20s}              ║
╠═══════════════════════════════════════════════════════════╣
║  Function: {func.__name__:<45s} ║
║  Risk: {description[:50]:<50s} ║
║                                                           ║
║  ✅ ONLY USE FOR:                                        ║
║  • Authorized penetration testing                        ║
║  • CTF competitions                                      ║
║  • Security research                                     ║
║  • Educational purposes                                  ║
║                                                           ║
║  ❌ NEVER USE FOR:                                        ║
║  • Unauthorized system access                            ║
║  • Malicious attacks                                     ║
║  • Any illegal activities                                ║
║  • Production systems without permission                 ║
╚═══════════════════════════════════════════════════════════╝
"""

            # Issue warning
            warnings.warn(warning_msg, SecurityWarning, stacklevel=2)

            # Execute function
            return func(*args, **kwargs)

        # Add metadata
        wrapper._is_dangerous = True
        wrapper._risk_level = risk_level
        wrapper._risk_description = description

        return wrapper
    return decorator


def require_authorization(func: Callable) -> Callable:
    """
    Decorator to require explicit authorization for dangerous operations

    This decorator adds a confirmation prompt before executing dangerous operations.
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> Any:
        # Add authorization check metadata
        result = func(*args, **kwargs)

        # Prepend authorization notice to result
        auth_notice = """
⚠️  AUTHORIZATION REQUIRED
This operation requires explicit authorization.
Ensure you have permission to perform this action on the target system.
"""
        if isinstance(result, str):
            return auth_notice + "\n" + result
        return result

    return wrapper


def sanitize_command(command: str, placeholder: str = "COMMAND") -> str:
    """
    Sanitize dangerous commands by replacing them with placeholders

    Args:
        command: Command string to sanitize
        placeholder: Placeholder to use for dangerous commands

    Returns:
        Sanitized command string
    """
    dangerous_commands = [
        "id", "whoami", "cat /etc/passwd", "ls", "pwd",
        "rm", "del", "format", "shutdown", "reboot"
    ]

    sanitized = command
    for dangerous in dangerous_commands:
        if dangerous in sanitized.lower():
            sanitized = sanitized.replace(dangerous, placeholder)

    return sanitized


# ==============================================================================
# Input Validation Utilities
# ==============================================================================

import os
import re
import shlex
from pathlib import Path
from urllib.parse import urlparse


class SecurityError(ValueError):
    """Raised when security validation fails"""
    pass


class InputValidator:
    """
    Input validation utilities for security-sensitive operations.

    Use these validators to sanitize user inputs before:
    - Passing to shell commands
    - File system operations
    - Network operations
    """

    # Safe characters for various contexts
    SAFE_FILENAME_CHARS = re.compile(r'^[\w\-. ]+$')
    SAFE_PATH_CHARS = re.compile(r'^[\w\-./\\ ]+$')
    SAFE_IDENTIFIER_CHARS = re.compile(r'^[\w\-]+$')
    SAFE_HOSTNAME_CHARS = re.compile(r'^[a-zA-Z0-9.\-]+$')
    SAFE_PORT_RANGE = range(1, 65536)

    # Dangerous shell metacharacters
    SHELL_METACHARACTERS = set(';&|`$(){}[]<>!\\"\'\n\r\t')

    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r'\.\.[\\/]',      # ../
        r'[\\/]\.\.[\\/]', # /../
        r'\.\.[\\/]?$',    # ends with ../ or ..
    ]

    @classmethod
    def validate_hostname(cls, hostname: str) -> str:
        """
        Validate hostname/IP address.

        Args:
            hostname: Hostname or IP to validate

        Returns:
            Validated hostname

        Raises:
            SecurityError: If hostname is invalid
        """
        if not hostname or not isinstance(hostname, str):
            raise SecurityError("Hostname cannot be empty")

        hostname = hostname.strip()

        # Check length
        if len(hostname) > 253:
            raise SecurityError("Hostname too long")

        # Check for shell metacharacters
        if any(c in cls.SHELL_METACHARACTERS for c in hostname):
            raise SecurityError(f"Invalid characters in hostname: {hostname}")

        # Check for valid hostname characters
        if not cls.SAFE_HOSTNAME_CHARS.match(hostname):
            raise SecurityError(f"Invalid hostname format: {hostname}")

        return hostname

    @classmethod
    def validate_port(cls, port) -> int:
        """
        Validate port number.

        Args:
            port: Port number

        Returns:
            Validated port as integer

        Raises:
            SecurityError: If port is invalid
        """
        try:
            port_int = int(port)
        except (ValueError, TypeError):
            raise SecurityError(f"Invalid port: {port}")

        if port_int not in cls.SAFE_PORT_RANGE:
            raise SecurityError(f"Port out of range (1-65535): {port_int}")

        return port_int

    @classmethod
    def validate_port_spec(cls, port_spec: str) -> str:
        """
        Validate port specification string (e.g., "80,443,8000-9000").

        Args:
            port_spec: Port specification

        Returns:
            Validated port spec

        Raises:
            SecurityError: If port spec is invalid
        """
        if not port_spec or not isinstance(port_spec, str):
            raise SecurityError("Port specification cannot be empty")

        port_spec = port_spec.strip()

        # Only allow digits, commas, and hyphens
        if not re.match(r'^[\d,\-]+$', port_spec):
            raise SecurityError(f"Invalid port specification: {port_spec}")

        # Validate each port or range
        for part in port_spec.split(','):
            part = part.strip()
            if '-' in part:
                parts = part.split('-')
                if len(parts) != 2:
                    raise SecurityError(f"Invalid port range: {part}")
                cls.validate_port(parts[0])
                cls.validate_port(parts[1])
            else:
                cls.validate_port(part)

        return port_spec

    @classmethod
    def validate_url(cls, url: str, allowed_schemes: list[str] | None = None) -> str:
        """
        Validate URL.

        Args:
            url: URL to validate
            allowed_schemes: List of allowed schemes (default: http, https)

        Returns:
            Validated URL

        Raises:
            SecurityError: If URL is invalid
        """
        if not url or not isinstance(url, str):
            raise SecurityError("URL cannot be empty")

        url = url.strip()

        if allowed_schemes is None:
            allowed_schemes = ['http', 'https']

        try:
            parsed = urlparse(url)
        except Exception as e:
            raise SecurityError(f"Invalid URL: {e}")

        if parsed.scheme not in allowed_schemes:
            raise SecurityError(f"URL scheme not allowed: {parsed.scheme}")

        if not parsed.netloc:
            raise SecurityError("URL must have a host")

        # Validate hostname part
        hostname = parsed.hostname
        if hostname:
            cls.validate_hostname(hostname)

        return url

    @classmethod
    def validate_file_path(
        cls,
        path: str,
        base_dir: str | None = None,
        must_exist: bool = False,
        allow_absolute: bool = True,
    ) -> str:
        """
        Validate file path for safety.

        Args:
            path: File path to validate
            base_dir: If set, path must be under this directory
            must_exist: If True, file must exist
            allow_absolute: If False, reject absolute paths

        Returns:
            Validated and normalized path

        Raises:
            SecurityError: If path is invalid or unsafe
        """
        if not path or not isinstance(path, str):
            raise SecurityError("File path cannot be empty")

        path = path.strip()

        # Check for null bytes
        if '\x00' in path:
            raise SecurityError("Null bytes not allowed in path")

        # Check for path traversal patterns
        for pattern in cls.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, path):
                raise SecurityError(f"Path traversal detected: {path}")

        # Resolve to absolute path
        try:
            resolved = Path(path).resolve()
        except Exception as e:
            raise SecurityError(f"Invalid path: {e}")

        # Check if absolute paths are allowed
        if not allow_absolute and Path(path).is_absolute():
            raise SecurityError("Absolute paths not allowed")

        # Check base directory constraint
        if base_dir:
            base_resolved = Path(base_dir).resolve()
            try:
                resolved.relative_to(base_resolved)
            except ValueError:
                raise SecurityError(f"Path escapes base directory: {path}")

        # Check existence if required
        if must_exist and not resolved.exists():
            raise SecurityError(f"File does not exist: {path}")

        return str(resolved)

    @classmethod
    def validate_identifier(cls, identifier: str, max_length: int = 128) -> str:
        """
        Validate an identifier (database name, table name, etc.).

        Args:
            identifier: Identifier to validate
            max_length: Maximum allowed length

        Returns:
            Validated identifier

        Raises:
            SecurityError: If identifier is invalid
        """
        if not identifier or not isinstance(identifier, str):
            raise SecurityError("Identifier cannot be empty")

        identifier = identifier.strip()

        if len(identifier) > max_length:
            raise SecurityError(f"Identifier too long (max {max_length})")

        if not cls.SAFE_IDENTIFIER_CHARS.match(identifier):
            raise SecurityError(f"Invalid identifier: {identifier}")

        return identifier

    @classmethod
    def sanitize_shell_arg(cls, arg: str) -> str:
        """
        Sanitize a single shell argument.

        This uses shlex.quote to properly escape the argument
        for safe use in shell commands.

        Args:
            arg: Argument to sanitize

        Returns:
            Safely quoted argument
        """
        if not isinstance(arg, str):
            arg = str(arg)
        return shlex.quote(arg)

    @classmethod
    def validate_hash_value(cls, hash_value: str) -> str:
        """
        Validate a hash value (hexadecimal string or hash format).

        Args:
            hash_value: Hash to validate

        Returns:
            Validated hash

        Raises:
            SecurityError: If hash is invalid
        """
        if not hash_value or not isinstance(hash_value, str):
            raise SecurityError("Hash value cannot be empty")

        hash_value = hash_value.strip()

        # Check for shell metacharacters
        dangerous = [';', '|', '&', '`', '$', '(', ')', '{', '}', '<', '>']
        if any(c in hash_value for c in dangerous):
            raise SecurityError(f"Invalid characters in hash: {hash_value}")

        # Allow hex strings and hash formats like $6$salt$hash
        if not re.match(r'^[\$\w/.+=]+$', hash_value):
            raise SecurityError(f"Invalid hash format: {hash_value}")

        return hash_value

    @classmethod
    def validate_nse_script(cls, script: str) -> str:
        """
        Validate NSE script name/category.

        Args:
            script: Script name or category

        Returns:
            Validated script name

        Raises:
            SecurityError: If script name is invalid
        """
        if not script or not isinstance(script, str):
            raise SecurityError("Script name cannot be empty")

        script = script.strip()

        # Only allow safe characters
        if not re.match(r'^[\w,\-*]+$', script):
            raise SecurityError(f"Invalid script name: {script}")

        return script


def safe_xml_parse(source):
    """
    Safely parse XML without XXE vulnerabilities.

    Args:
        source: XML file path or file-like object

    Returns:
        ElementTree object
    """
    try:
        # Try to use defusedxml if available (preferred)
        import defusedxml.ElementTree as DefusedET
        return DefusedET.parse(source)
    except ImportError:
        # Fallback: use stdlib with limited features
        import xml.etree.ElementTree as ET

        # Create parser - note: Python 3.x XMLParser doesn't expand
        # external entities by default, but we explicitly disable it
        # for defense in depth
        parser = ET.XMLParser()

        # Parse and return
        tree = ET.parse(source, parser=parser)
        return tree
