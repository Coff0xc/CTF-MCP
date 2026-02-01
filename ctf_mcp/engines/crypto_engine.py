"""
Crypto Solving Engine
Specialized engine for cryptography challenges
"""

import base64
import re
import time
from typing import Any, Optional, TYPE_CHECKING

from .base import SolvingEngine, EngineResult, EngineCapability

if TYPE_CHECKING:
    from ..core.orchestrator import Challenge


class CryptoEngine(SolvingEngine):
    """
    Cryptography challenge solving engine.

    Handles:
    - Classical ciphers (Caesar, Vigenere, substitution, etc.)
    - Modern ciphers (RSA, AES, DES, etc.)
    - Encoding schemes (Base64, hex, etc.)
    - Hash cracking
    - Custom/CTF-specific crypto
    """

    # Patterns for crypto detection
    RSA_PATTERNS = [
        r'n\s*[=:]\s*(\d{10,})',
        r'e\s*[=:]\s*(\d+)',
        r'c\s*[=:]\s*(\d{10,})',
        r'p\s*[=:]\s*(\d{10,})',
        r'q\s*[=:]\s*(\d{10,})',
        r'd\s*[=:]\s*(\d{10,})',
    ]

    BASE64_PATTERN = r'^[A-Za-z0-9+/]+={0,2}$'
    HEX_PATTERN = r'^[0-9a-fA-F]+$'
    BINARY_PATTERN = r'^[01\s]+$'

    @property
    def name(self) -> str:
        return "crypto"

    @property
    def capabilities(self) -> list[EngineCapability]:
        return [
            EngineCapability.ANALYZE,
            EngineCapability.DECODE,
            EngineCapability.BRUTEFORCE,
        ]

    def analyze(self, challenge: "Challenge") -> dict[str, Any]:
        """Analyze a crypto challenge"""
        analysis = {
            "crypto_type": [],
            "detected_data": {},
            "recommendations": [],
        }

        # Combine description and file contents
        content = challenge.description

        for file_path in challenge.files:
            file_content = self._read_file(file_path)
            if file_content:
                content += "\n" + file_content

        # Detect RSA parameters
        rsa_params = self._detect_rsa(content)
        if rsa_params:
            analysis["crypto_type"].append("RSA")
            analysis["detected_data"]["rsa"] = rsa_params
            analysis["recommendations"].append("Try RSA factorization attacks")

        # Detect encoding
        encoding = self._detect_encoding(content)
        if encoding:
            analysis["crypto_type"].append(f"Encoding: {encoding}")
            analysis["recommendations"].append(f"Decode {encoding}")

        # Detect classical cipher patterns
        if self._looks_like_classical_cipher(content):
            analysis["crypto_type"].append("Classical Cipher")
            analysis["recommendations"].append("Try frequency analysis and bruteforce")

        # Detect hash
        hash_type = self._detect_hash(content)
        if hash_type:
            analysis["crypto_type"].append(f"Hash: {hash_type}")
            analysis["recommendations"].append("Try hash cracking or lookup")

        return analysis

    def solve(self, challenge: "Challenge", **kwargs) -> EngineResult:
        """Attempt to solve a crypto challenge"""
        start_time = time.time()
        result = EngineResult()

        try:
            # Get all content
            content = challenge.description
            for file_path in challenge.files:
                file_content = self._read_file(file_path)
                if file_content:
                    content += "\n" + file_content

            result.add_step("Collected challenge content")

            # Try encoding chains first (most common)
            decoded = self._try_decode_chain(content, result)
            if decoded:
                flags = self.find_flags(decoded, challenge.flag_format)
                if flags:
                    result.success = True
                    result.flag = flags[0]
                    result.confidence = 0.9
                    result.duration = time.time() - start_time
                    return result

            # Try RSA attack
            rsa_params = self._detect_rsa(content)
            if rsa_params:
                rsa_result = self._try_rsa_attack(rsa_params, result)
                if rsa_result:
                    flags = self.find_flags(rsa_result, challenge.flag_format)
                    if flags:
                        result.success = True
                        result.flag = flags[0]
                        result.confidence = 0.95
                        result.duration = time.time() - start_time
                        return result

            # Try classical cipher bruteforce
            classical_result = self._try_classical_attacks(content, result)
            if classical_result:
                flags = self.find_flags(classical_result, challenge.flag_format)
                if flags:
                    result.success = True
                    result.flag = flags[0]
                    result.confidence = 0.8
                    result.duration = time.time() - start_time
                    return result

            # No solution found
            result.success = False
            result.error = "Could not solve crypto challenge"

        except Exception as e:
            result.success = False
            result.error = str(e)

        result.duration = time.time() - start_time
        return result

    def can_handle(self, challenge: "Challenge") -> float:
        """Check if this looks like a crypto challenge"""
        score = 0.0
        content = challenge.description.lower()

        # Keyword matching
        crypto_keywords = [
            'encrypt', 'decrypt', 'cipher', 'rsa', 'aes', 'des',
            'hash', 'md5', 'sha', 'base64', 'xor', 'key',
            'caesar', 'vigenere', 'substitution', 'modulus',
        ]

        for keyword in crypto_keywords:
            if keyword in content:
                score += 0.1

        # Check for RSA parameters
        if self._detect_rsa(challenge.description):
            score += 0.3

        # Check for encoded data
        if self._detect_encoding(challenge.description):
            score += 0.2

        return min(score, 1.0)

    def _detect_rsa(self, content: str) -> Optional[dict[str, int]]:
        """Detect RSA parameters in content"""
        params = {}

        for pattern in self.RSA_PATTERNS:
            match = re.search(pattern, content)
            if match:
                param_name = pattern.split('\\')[0].strip()
                try:
                    params[param_name] = int(match.group(1))
                except (ValueError, IndexError):
                    pass

        # Also try direct extraction
        n_match = re.search(r'n\s*[=:]\s*(\d+)', content)
        e_match = re.search(r'e\s*[=:]\s*(\d+)', content)
        c_match = re.search(r'c\s*[=:]\s*(\d+)', content)

        if n_match:
            params['n'] = int(n_match.group(1))
        if e_match:
            params['e'] = int(e_match.group(1))
        if c_match:
            params['c'] = int(c_match.group(1))

        return params if params else None

    def _detect_encoding(self, content: str) -> Optional[str]:
        """Detect encoding type"""
        # Clean content
        clean = content.strip().replace('\n', '').replace(' ', '')

        # Check base64
        if re.match(self.BASE64_PATTERN, clean) and len(clean) > 10:
            try:
                decoded = base64.b64decode(clean)
                if self._is_printable(decoded):
                    return "base64"
            except Exception:
                pass

        # Check hex
        if re.match(self.HEX_PATTERN, clean) and len(clean) % 2 == 0:
            try:
                decoded = bytes.fromhex(clean)
                if self._is_printable(decoded):
                    return "hex"
            except Exception:
                pass

        # Check binary
        if re.match(self.BINARY_PATTERN, content):
            return "binary"

        return None

    def _detect_hash(self, content: str) -> Optional[str]:
        """Detect hash type"""
        # Common hash patterns
        patterns = {
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b',
            'sha512': r'\b[a-fA-F0-9]{128}\b',
        }

        for hash_type, pattern in patterns.items():
            if re.search(pattern, content):
                return hash_type

        return None

    def _looks_like_classical_cipher(self, content: str) -> bool:
        """Check if content looks like a classical cipher"""
        # Extract only alphabetic content
        alpha_only = re.sub(r'[^a-zA-Z]', '', content)

        if len(alpha_only) < 20:
            return False

        # Check for unusual letter distribution
        freq = {}
        for c in alpha_only.lower():
            freq[c] = freq.get(c, 0) + 1

        if not freq:
            return False

        # Calculate variance from expected English distribution
        avg = len(alpha_only) / 26
        variance = sum((v - avg) ** 2 for v in freq.values()) / len(freq)

        # English text typically has high variance (common letters like E, T, A)
        # Perfectly uniform distribution (variance=0) suggests some ciphers
        # Very high variance might indicate substitution cipher
        # Threshold: variance below 5% of avg^2 is suspiciously uniform
        # or variance above certain threshold indicates unusual distribution
        normalized_variance = variance / (avg * avg) if avg > 0 else 0

        # Low variance (< 0.5) = very uniform = likely transposition/polyalphabetic
        # High variance (> 2.0) = unusual peaks = likely substitution
        # Normal English text typically falls in 0.8-1.5 range
        return normalized_variance < 0.5 or normalized_variance > 2.0

    def _is_printable(self, data: bytes) -> bool:
        """Check if bytes are mostly printable"""
        try:
            text = data.decode('utf-8', errors='strict')
            printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
            return printable / len(text) > 0.8 if text else False
        except (UnicodeDecodeError, ZeroDivisionError):
            return False

    def _try_decode_chain(self, content: str, result: EngineResult) -> Optional[str]:
        """Try to decode through various encoding chains"""
        tools = self._get_tools()["crypto"]

        # Find potential encoded strings
        encoded_strings = self._extract_encoded_strings(content)

        for encoded in encoded_strings:
            decoded = encoded

            # Try multiple decode passes
            for _ in range(5):  # Max 5 layers
                prev = decoded

                # Try base64
                try:
                    attempt = base64.b64decode(decoded).decode('utf-8', errors='ignore')
                    if self._is_printable(attempt.encode()):
                        decoded = attempt
                        result.add_step(f"Base64 decoded: {decoded[:50]}...")
                        continue
                except Exception:
                    pass

                # Try hex
                try:
                    clean = decoded.replace(' ', '').replace('0x', '')
                    if re.match(r'^[0-9a-fA-F]+$', clean) and len(clean) % 2 == 0:
                        attempt = bytes.fromhex(clean).decode('utf-8', errors='ignore')
                        if self._is_printable(attempt.encode()):
                            decoded = attempt
                            result.add_step(f"Hex decoded: {decoded[:50]}...")
                            continue
                except Exception:
                    pass

                # No progress
                if decoded == prev:
                    break

            # Check for flag
            if decoded != encoded:
                flags = self.find_flags(decoded)
                if flags:
                    result.data = decoded
                    return decoded

        return None

    def _extract_encoded_strings(self, content: str) -> list[str]:
        """Extract potential encoded strings from content"""
        strings = []

        # Base64-like strings
        b64_matches = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', content)
        strings.extend(b64_matches)

        # Hex strings
        hex_matches = re.findall(r'(?:0x)?[0-9a-fA-F]{20,}', content)
        strings.extend(hex_matches)

        # The whole content if it looks encoded
        clean = content.strip()
        if len(clean) > 10 and clean not in strings:
            strings.append(clean)

        return strings

    def _try_rsa_attack(self, params: dict[str, int], result: EngineResult) -> Optional[str]:
        """Try various RSA attacks"""
        tools = self._get_tools()["crypto"]

        n = params.get('n')
        e = params.get('e', 65537)
        c = params.get('c')

        if not n or not c:
            return None

        result.add_step(f"Attempting RSA attack with n={str(n)[:30]}..., e={e}")

        # Try factorization
        try:
            factor_result = tools.rsa_factor(str(n), str(e))
            result.add_step(f"Factorization result: {factor_result[:100]}...")

            # Extract p and q from result
            p_match = re.search(r'p\s*=\s*(\d+)', factor_result)
            q_match = re.search(r'q\s*=\s*(\d+)', factor_result)

            if p_match and q_match:
                p = int(p_match.group(1))
                q = int(q_match.group(1))

                # Decrypt
                decrypt_result = tools.rsa_decrypt(str(p), str(q), str(e), str(c))
                result.add_step(f"Decryption result: {decrypt_result[:100]}...")

                return decrypt_result

        except Exception as ex:
            result.add_step(f"RSA attack failed: {ex}")

        return None

    def _try_classical_attacks(self, content: str, result: EngineResult) -> Optional[str]:
        """Try classical cipher attacks"""
        tools = self._get_tools()["crypto"]

        # Extract potential ciphertext
        ciphertext = re.sub(r'[^a-zA-Z]', '', content)
        if len(ciphertext) < 10:
            return None

        result.add_step(f"Trying classical cipher attacks on: {ciphertext[:50]}...")

        # Try Caesar bruteforce
        try:
            caesar_result = tools.caesar_bruteforce(ciphertext)
            result.add_step("Caesar bruteforce completed")

            # Check all shifts for flag
            for line in caesar_result.split('\n'):
                flags = self.find_flags(line)
                if flags:
                    result.data = line
                    return line

        except Exception as ex:
            result.add_step(f"Caesar attack failed: {ex}")

        # Try ROT13
        try:
            rot_result = tools.rot_n(ciphertext, 13)
            flags = self.find_flags(rot_result)
            if flags:
                result.add_step("ROT13 found flag")
                result.data = rot_result
                return rot_result
        except Exception:
            pass

        # Try frequency analysis
        try:
            freq_result = tools.freq_analysis(ciphertext)
            result.add_step(f"Frequency analysis: {freq_result[:100]}...")
        except Exception:
            pass

        return None
