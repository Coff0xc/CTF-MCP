"""Helper utilities for CTF-MCP"""

import base64
import binascii
from typing import Union


def to_bytes(data: Union[str, bytes], encoding: str = "utf-8") -> bytes:
    """Convert string or bytes to bytes"""
    if isinstance(data, bytes):
        return data
    return data.encode(encoding)


def to_str(data: Union[str, bytes], encoding: str = "utf-8") -> str:
    """Convert bytes or string to string"""
    if isinstance(data, str):
        return data
    return data.decode(encoding)


def clean_hex(hex_str: str) -> str:
    """
    Clean hex string by removing common prefixes and whitespace.
    Handles: spaces, '0x', '\\x', '0X', newlines
    """
    return (
        hex_str.replace(" ", "")
        .replace("\n", "")
        .replace("\t", "")
        .replace("0x", "")
        .replace("0X", "")
        .replace("\\x", "")
    )


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes, auto-cleaning common formats"""
    return bytes.fromhex(clean_hex(hex_str))


def hex_to_bytes_safe(hex_str: str) -> tuple[bytes | None, str | None]:
    """
    Safe hex to bytes conversion with error handling.
    Returns (bytes, None) on success, (None, error_message) on failure.
    """
    try:
        return bytes.fromhex(clean_hex(hex_str)), None
    except ValueError as e:
        return None, f"Invalid hex string: {e}"


def bytes_to_hex(data: bytes, prefix: str = "") -> str:
    """Convert bytes to hex string"""
    return prefix + data.hex()


def int_to_bytes(n: int, length: int | None = None, byteorder: str = "big") -> bytes:
    """
    Convert integer to bytes.
    If length is None, uses minimum required bytes.
    """
    if n == 0:
        return b"\x00" if length is None else b"\x00" * length
    if length is None:
        length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, byteorder=byteorder)


def b64_encode(data: Union[str, bytes]) -> str:
    """Base64 encode"""
    return base64.b64encode(to_bytes(data)).decode()


def b64_decode(data: str) -> bytes:
    """Base64 decode"""
    return base64.b64decode(data)


def xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR two byte sequences"""
    return bytes(a ^ b for a, b in zip(data, key * (len(data) // len(key) + 1)))


def rot_n(text: str, n: int = 13) -> str:
    """ROT-N cipher"""
    result = []
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result.append(chr((ord(char) - base + n) % 26 + base))
        else:
            result.append(char)
    return ''.join(result)


def find_flag(text: str, prefix: str = "flag") -> list[str]:
    """Find flags in text with common formats"""
    import re
    patterns = [
        rf"{prefix}\{{[^}}]+\}}",  # flag{...}
        rf"{prefix}\[[^\]]+\]",     # flag[...]
        rf"{prefix}\([^)]+\)",      # flag(...)
        r"CTF\{[^}]+\}",            # CTF{...}
        r"FLAG\{[^}]+\}",           # FLAG{...}
    ]
    flags = []
    for pattern in patterns:
        flags.extend(re.findall(pattern, text, re.IGNORECASE))
    return list(set(flags))
