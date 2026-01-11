"""
Input validation utilities for CTF-MCP
Provides comprehensive input validation to prevent security issues
"""

import re
import os
from typing import Any, Optional, Union
from pathlib import Path


class ValidationError(Exception):
    """Custom exception for validation errors"""
    pass


class InputValidator:
    """Unified input validation for all CTF-MCP tools"""

    @staticmethod
    def validate_integer(
        value: Union[str, int],
        min_val: Optional[int] = None,
        max_val: Optional[int] = None,
        name: str = "value"
    ) -> int:
        """
        Validate and convert integer input

        Args:
            value: Value to validate
            min_val: Minimum allowed value
            max_val: Maximum allowed value
            name: Parameter name for error messages

        Returns:
            Validated integer

        Raises:
            ValidationError: If validation fails
        """
        try:
            num = int(value)
        except (ValueError, TypeError):
            raise ValidationError(f"{name} must be a valid integer, got: {value}")

        if min_val is not None and num < min_val:
            raise ValidationError(f"{name} must be >= {min_val}, got: {num}")

        if max_val is not None and num > max_val:
            raise ValidationError(f"{name} must be <= {max_val}, got: {num}")

        return num

    @staticmethod
    def validate_hex_string(value: str, name: str = "value") -> str:
        """
        Validate hexadecimal string

        Args:
            value: Hex string to validate
            name: Parameter name for error messages

        Returns:
            Cleaned hex string

        Raises:
            ValidationError: If not valid hex
        """
        if not isinstance(value, str):
            raise ValidationError(f"{name} must be a string")

        # Clean common hex prefixes and separators
        cleaned = value.replace(" ", "").replace("\\x", "").replace("0x", "")

        if not re.match(r'^[0-9a-fA-F]*$', cleaned):
            raise ValidationError(
                f"{name} must be valid hexadecimal string, got: {value[:50]}"
            )

        return cleaned

    @staticmethod
    def validate_base64(value: str, name: str = "value") -> str:
        """
        Validate base64 string

        Args:
            value: Base64 string to validate
            name: Parameter name for error messages

        Returns:
            Validated base64 string

        Raises:
            ValidationError: If not valid base64
        """
        if not isinstance(value, str):
            raise ValidationError(f"{name} must be a string")

        # Base64 pattern
        if not re.match(r'^[A-Za-z0-9+/]*={0,2}$', value):
            raise ValidationError(f"{name} must be valid base64 string")

        return value

    @staticmethod
    def validate_url(value: str, name: str = "url") -> str:
        """
        Validate URL format

        Args:
            value: URL to validate
            name: Parameter name for error messages

        Returns:
            Validated URL

        Raises:
            ValidationError: If not valid URL
        """
        if not isinstance(value, str):
            raise ValidationError(f"{name} must be a string")

        # Basic URL pattern
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
            r'localhost|'  # localhost
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE
        )

        if not url_pattern.match(value):
            raise ValidationError(f"{name} must be a valid URL, got: {value}")

        return value

    @staticmethod
    def validate_file_path(
        path: str,
        must_exist: bool = False,
        max_size_mb: int = 100,
        allowed_extensions: Optional[list] = None
    ) -> str:
        """
        Validate file path with security checks

        Args:
            path: File path to validate
            must_exist: Whether file must exist
            max_size_mb: Maximum file size in MB
            allowed_extensions: List of allowed file extensions

        Returns:
            Validated absolute path

        Raises:
            ValidationError: If validation fails
        """
        if not isinstance(path, str):
            raise ValidationError("Path must be a string")

        # Normalize path
        try:
            abs_path = os.path.abspath(path)
        except Exception as e:
            raise ValidationError(f"Invalid path: {e}")

        # Check for path traversal
        if ".." in path:
            raise ValidationError("Path traversal detected (..))")

        # Check sensitive paths (platform-specific)
        sensitive_paths = [
            "/etc", "/sys", "/proc", "/root",
            "C:\\Windows", "C:\\Program Files"
        ]

        for sensitive in sensitive_paths:
            if abs_path.startswith(sensitive):
                raise ValidationError(f"Access to sensitive path denied: {sensitive}")

        # Check if file exists
        if must_exist and not os.path.exists(abs_path):
            raise ValidationError(f"File not found: {abs_path}")

        # Check file size
        if os.path.exists(abs_path) and os.path.isfile(abs_path):
            size_mb = os.path.getsize(abs_path) / (1024 * 1024)
            if size_mb > max_size_mb:
                raise ValidationError(
                    f"File too large: {size_mb:.2f}MB (max {max_size_mb}MB)"
                )

        # Check file extension
        if allowed_extensions:
            ext = Path(abs_path).suffix.lower()
            if ext not in allowed_extensions:
                raise ValidationError(
                    f"File extension {ext} not allowed. "
                    f"Allowed: {', '.join(allowed_extensions)}"
                )

        return abs_path

    @staticmethod
    def validate_port(value: Union[str, int], name: str = "port") -> int:
        """
        Validate port number

        Args:
            value: Port number to validate
            name: Parameter name for error messages

        Returns:
            Validated port number

        Raises:
            ValidationError: If not valid port
        """
        port = InputValidator.validate_integer(
            value, min_val=1, max_val=65535, name=name
        )
        return port

    @staticmethod
    def validate_ip_address(value: str, name: str = "ip") -> str:
        """
        Validate IP address format

        Args:
            value: IP address to validate
            name: Parameter name for error messages

        Returns:
            Validated IP address

        Raises:
            ValidationError: If not valid IP
        """
        if not isinstance(value, str):
            raise ValidationError(f"{name} must be a string")

        # IPv4 pattern
        ipv4_pattern = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )

        if not ipv4_pattern.match(value):
            raise ValidationError(f"{name} must be a valid IPv4 address, got: {value}")

        return value

    @staticmethod
    def validate_enum(
        value: str,
        allowed_values: list,
        name: str = "value"
    ) -> str:
        """
        Validate value against allowed list

        Args:
            value: Value to validate
            allowed_values: List of allowed values
            name: Parameter name for error messages

        Returns:
            Validated value

        Raises:
            ValidationError: If value not in allowed list
        """
        if value not in allowed_values:
            raise ValidationError(
                f"{name} must be one of {allowed_values}, got: {value}"
            )

        return value

    @staticmethod
    def validate_length(
        value: str,
        min_length: Optional[int] = None,
        max_length: Optional[int] = None,
        name: str = "value"
    ) -> str:
        """
        Validate string length

        Args:
            value: String to validate
            min_length: Minimum length
            max_length: Maximum length
            name: Parameter name for error messages

        Returns:
            Validated string

        Raises:
            ValidationError: If length invalid
        """
        if not isinstance(value, str):
            raise ValidationError(f"{name} must be a string")

        length = len(value)

        if min_length is not None and length < min_length:
            raise ValidationError(
                f"{name} must be at least {min_length} characters, got: {length}"
            )

        if max_length is not None and length > max_length:
            raise ValidationError(
                f"{name} must be at most {max_length} characters, got: {length}"
            )

        return value
