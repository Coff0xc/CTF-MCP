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


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes"""
    hex_str = hex_str.replace(" ", "").replace("0x", "").replace("\\x", "")
    return bytes.fromhex(hex_str)


def bytes_to_hex(data: bytes, prefix: str = "") -> str:
    """Convert bytes to hex string"""
    return prefix + data.hex()


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
