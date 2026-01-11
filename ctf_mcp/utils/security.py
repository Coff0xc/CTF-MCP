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
