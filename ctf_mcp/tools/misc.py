"""
Misc Tools Module for CTF-MCP
Encoding conversions, string operations, and utility tools
"""

import re
import string
import urllib.parse
from typing import Optional


class MiscTools:
    """Miscellaneous tools for CTF challenges"""

    def get_tools(self) -> dict:
        """Return available tools and their descriptions"""
        return {
            "hex_encode": "Encode string to hex",
            "hex_decode": "Decode hex to string",
            "url_encode": "URL encode string",
            "url_decode": "URL decode string",
            "binary_convert": "Convert between bases",
            "find_flag": "Find flag patterns",
            "strings_extract": "Extract printable strings",
        }

    # === Hex Encoding ===

    def hex_encode(self, data: str) -> str:
        """Encode string to hexadecimal"""
        hex_str = data.encode().hex()
        return f"Hex: {hex_str}\nWith spaces: {' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))}"

    def hex_decode(self, data: str) -> str:
        """Decode hexadecimal to string"""
        try:
            # Clean up hex string
            data = data.replace(' ', '').replace('0x', '').replace('\\x', '')
            decoded = bytes.fromhex(data)
            return f"String: {decoded.decode('utf-8', errors='replace')}\nRaw bytes: {decoded}"
        except Exception as e:
            return f"Decode error: {e}"

    # === URL Encoding ===

    def url_encode(self, data: str) -> str:
        """URL encode string"""
        encoded = urllib.parse.quote(data, safe='')
        double_encoded = urllib.parse.quote(encoded, safe='')
        return f"URL encoded: {encoded}\nDouble encoded: {double_encoded}"

    def url_decode(self, data: str) -> str:
        """URL decode string"""
        try:
            decoded = urllib.parse.unquote(data)
            double_decoded = urllib.parse.unquote(decoded)
            return f"Decoded: {decoded}\nDouble decoded: {double_decoded}"
        except Exception as e:
            return f"Decode error: {e}"

    # === HTML Encoding ===

    def html_encode(self, data: str) -> str:
        """HTML encode string"""
        import html
        return html.escape(data)

    def html_decode(self, data: str) -> str:
        """HTML decode string"""
        import html
        return html.unescape(data)

    # === Base Conversion ===

    def binary_convert(self, data: str, from_base: str, to_base: str) -> str:
        """Convert between binary, decimal, hex, and string"""
        try:
            # First convert to integer
            if from_base == "bin":
                value = int(data.replace(' ', ''), 2)
            elif from_base == "dec":
                value = int(data)
            elif from_base == "hex":
                value = int(data.replace(' ', '').replace('0x', ''), 16)
            elif from_base == "str":
                value = int.from_bytes(data.encode(), 'big')
            else:
                return f"Unknown source format: {from_base}"

            # Then convert to target format
            if to_base == "bin":
                result = bin(value)[2:]
                result = f"Binary: {result}\nWith spaces: {' '.join(result[i:i+8] for i in range(0, len(result), 8))}"
            elif to_base == "dec":
                result = f"Decimal: {value}"
            elif to_base == "hex":
                hex_str = hex(value)[2:]
                result = f"Hex: {hex_str}\nWith 0x: 0x{hex_str}"
            elif to_base == "str":
                byte_len = (value.bit_length() + 7) // 8
                result = value.to_bytes(byte_len, 'big').decode('utf-8', errors='replace')
                result = f"String: {result}"
            else:
                return f"Unknown target format: {to_base}"

            return result

        except Exception as e:
            return f"Conversion error: {e}"

    # === String Operations ===

    def find_flag(self, text: str, prefix: str = "flag") -> str:
        """Search for flag patterns in text"""
        patterns = [
            rf"{prefix}\{{[^}}]+\}}",      # flag{...}
            rf"{prefix}\[[^\]]+\]",        # flag[...]
            rf"{prefix}\([^)]+\)",         # flag(...)
            r"CTF\{[^}]+\}",               # CTF{...}
            r"FLAG\{[^}]+\}",              # FLAG{...}
            r"flag\{[^}]+\}",              # flag{...}
            r"[A-Za-z0-9+/=]{20,}",        # Potential Base64
            r"[0-9a-fA-F]{32,}",           # Potential hex/hash
        ]

        found = []
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            found.extend(matches)

        if found:
            return "Found potential flags:\n" + '\n'.join(f"  - {f}" for f in set(found))
        return "No flags found"

    def strings_extract(self, data: str, min_length: int = 4) -> str:
        """Extract printable strings from hex-encoded binary data"""
        try:
            binary_data = bytes.fromhex(data.replace(' ', ''))
        except:
            binary_data = data.encode()

        printable = set(string.printable.encode()) - set(b'\t\n\r\x0b\x0c')
        strings = []
        current = []

        for byte in binary_data:
            if byte in printable:
                current.append(chr(byte))
            else:
                if len(current) >= min_length:
                    strings.append(''.join(current))
                current = []

        if len(current) >= min_length:
            strings.append(''.join(current))

        if strings:
            return f"Found {len(strings)} strings (min length {min_length}):\n" + '\n'.join(strings)
        return "No printable strings found"

    # === Encoding Detection ===

    def detect_encoding(self, data: str) -> str:
        """Try to detect encoding type of data"""
        results = ["Encoding Detection Results:", "-" * 40]

        # Check Base64
        base64_pattern = r'^[A-Za-z0-9+/]+=*$'
        if re.match(base64_pattern, data.replace('\n', '').replace(' ', '')):
            results.append("Possibly Base64 encoded")
            try:
                import base64
                decoded = base64.b64decode(data).decode('utf-8', errors='replace')
                results.append(f"  Decoded: {decoded[:100]}...")
            except:
                pass

        # Check Hex
        hex_pattern = r'^[0-9a-fA-F]+$'
        clean_data = data.replace(' ', '').replace('0x', '').replace('\\x', '')
        if re.match(hex_pattern, clean_data) and len(clean_data) % 2 == 0:
            results.append("Possibly Hex encoded")
            try:
                decoded = bytes.fromhex(clean_data).decode('utf-8', errors='replace')
                results.append(f"  Decoded: {decoded[:100]}...")
            except:
                pass

        # Check URL encoded
        if '%' in data:
            results.append("Possibly URL encoded")
            try:
                decoded = urllib.parse.unquote(data)
                results.append(f"  Decoded: {decoded[:100]}...")
            except:
                pass

        # Check Binary
        if re.match(r'^[01\s]+$', data):
            results.append("Possibly Binary encoded")
            try:
                bits = data.replace(' ', '')
                decoded = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))
                results.append(f"  Decoded: {decoded[:100]}...")
            except:
                pass

        # Check ROT13/Caesar
        if data.isalpha():
            results.append("Alphabetic only - possibly ROT13/Caesar cipher")

        return '\n'.join(results)

    # === Math Operations ===

    def gcd(self, a: int, b: int) -> int:
        """Calculate GCD"""
        while b:
            a, b = b, a % b
        return a

    def lcm(self, a: int, b: int) -> int:
        """Calculate LCM"""
        return abs(a * b) // self.gcd(a, b)

    def mod_inverse(self, a: int, m: int) -> str:
        """Calculate modular inverse"""
        try:
            result = pow(a, -1, m)
            return f"{a}^(-1) mod {m} = {result}"
        except ValueError:
            return f"No modular inverse exists for {a} mod {m}"

    def chinese_remainder_theorem(self, remainders: list, moduli: list) -> str:
        """Solve system of congruences using CRT"""
        if len(remainders) != len(moduli):
            return "Error: remainders and moduli must have same length"

        # Check pairwise coprime
        from math import gcd
        for i in range(len(moduli)):
            for j in range(i + 1, len(moduli)):
                if gcd(moduli[i], moduli[j]) != 1:
                    return f"Error: {moduli[i]} and {moduli[j]} are not coprime"

        M = 1
        for m in moduli:
            M *= m

        result = 0
        for a, m in zip(remainders, moduli):
            Mi = M // m
            yi = pow(Mi, -1, m)
            result += a * Mi * yi

        result = result % M
        return f"Solution: x ≡ {result} (mod {M})"

    # === Text Manipulation ===

    def reverse_string(self, text: str) -> str:
        """Reverse string"""
        return text[::-1]

    def reverse_words(self, text: str) -> str:
        """Reverse word order"""
        return ' '.join(text.split()[::-1])

    def char_swap(self, text: str) -> str:
        """Swap adjacent characters"""
        result = list(text)
        for i in range(0, len(result) - 1, 2):
            result[i], result[i + 1] = result[i + 1], result[i]
        return ''.join(result)

    def remove_whitespace(self, text: str) -> str:
        """Remove all whitespace"""
        return ''.join(text.split())

    def to_leetspeak(self, text: str) -> str:
        """Convert to leetspeak"""
        leet = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7', 'l': '1'}
        return ''.join(leet.get(c.lower(), c) for c in text)

    # === Morse Code ===

    MORSE_CODE = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
        'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
        'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
        'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..',
        '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
        '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
        ' ': '/'
    }

    def morse_encode(self, text: str) -> str:
        """Encode text to Morse code"""
        return ' '.join(self.MORSE_CODE.get(c.upper(), c) for c in text)

    def morse_decode(self, morse: str) -> str:
        """Decode Morse code to text"""
        reverse_morse = {v: k for k, v in self.MORSE_CODE.items()}
        words = morse.split(' / ')
        result = []
        for word in words:
            chars = word.split(' ')
            result.append(''.join(reverse_morse.get(c, c) for c in chars))
        return ' '.join(result)
