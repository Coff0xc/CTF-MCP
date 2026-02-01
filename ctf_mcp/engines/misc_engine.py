"""
Misc Solving Engine
Specialized engine for miscellaneous challenges
"""

import base64
import re
import time
from typing import Any, Optional, TYPE_CHECKING

from .base import SolvingEngine, EngineResult, EngineCapability

if TYPE_CHECKING:
    from ..core.orchestrator import Challenge


class MiscEngine(SolvingEngine):
    """
    Miscellaneous challenge solving engine.

    Handles challenges that don't fit other categories:
    - Encoding/decoding puzzles
    - Trivia and OSINT
    - Programming challenges
    - Logic puzzles
    - QR codes
    - Audio/video analysis
    - Mixed-category challenges
    """

    # Common encodings to try
    ENCODINGS = [
        'base64', 'base32', 'base16', 'base58', 'base85',
        'rot13', 'hex', 'binary', 'url', 'html',
        'morse', 'braille', 'nato',
    ]

    # OSINT indicators
    OSINT_INDICATORS = [
        r'osint', r'find', r'locate', r'search',
        r'google', r'social', r'username', r'email',
        r'geolocation', r'exif', r'metadata',
    ]

    # Programming challenge indicators
    PROGRAMMING_INDICATORS = [
        r'algorithm', r'optimize', r'implement',
        r'solve', r'calculate', r'compute',
        r'dynamic programming', r'recursive',
    ]

    @property
    def name(self) -> str:
        return "misc"

    @property
    def capabilities(self) -> list[EngineCapability]:
        return [
            EngineCapability.ANALYZE,
            EngineCapability.DECODE,
            EngineCapability.BRUTEFORCE,
        ]

    def analyze(self, challenge: "Challenge") -> dict[str, Any]:
        """Analyze a misc challenge"""
        analysis = {
            "challenge_type": [],
            "detected_encodings": [],
            "potential_data": [],
            "recommendations": [],
        }

        content = challenge.description

        # Detect challenge type
        if any(re.search(p, content.lower()) for p in self.OSINT_INDICATORS):
            analysis["challenge_type"].append("osint")
            analysis["recommendations"].append("Use OSINT tools: Google, Shodan, social media")

        if any(re.search(p, content.lower()) for p in self.PROGRAMMING_INDICATORS):
            analysis["challenge_type"].append("programming")
            analysis["recommendations"].append("Implement the algorithm or solve the puzzle")

        if re.search(r'qr|barcode', content.lower()):
            analysis["challenge_type"].append("qr_code")
            analysis["recommendations"].append("Decode QR code with zbarimg or online tools")

        if re.search(r'audio|wav|mp3|spectrogram', content.lower()):
            analysis["challenge_type"].append("audio")
            analysis["recommendations"].append("Check spectrogram with Audacity/Sonic Visualizer")

        # Detect potential encoded data
        encodings = self._detect_encodings(content)
        analysis["detected_encodings"] = encodings

        # Extract potential data blocks
        data_blocks = self._extract_data_blocks(content)
        analysis["potential_data"] = data_blocks

        if not analysis["challenge_type"]:
            analysis["challenge_type"].append("mixed")
            analysis["recommendations"].append("Try various decoding techniques")

        return analysis

    def solve(self, challenge: "Challenge", **kwargs) -> EngineResult:
        """Attempt to solve a misc challenge"""
        start_time = time.time()
        result = EngineResult()

        try:
            tools = self._get_tools()["misc"]

            result.add_step("Analyzing miscellaneous challenge")

            # Analyze challenge
            analysis = self.analyze(challenge)
            result.analysis = analysis

            # Combine all content
            content = challenge.description
            for file_path in challenge.files:
                file_content = self._read_file(file_path)
                if file_content:
                    content += "\n" + file_content

            # Check for flags directly
            flags = self.find_flags(content, challenge.flag_format)
            if flags:
                result.success = True
                result.flag = flags[0]
                result.confidence = 0.95
                result.add_step("Found flag directly in content!")
                result.duration = time.time() - start_time
                return result

            # Try decoding chains
            decoded = self._try_decode_chain(content, tools, result)
            if decoded:
                flags = self.find_flags(decoded, challenge.flag_format)
                if flags:
                    result.success = True
                    result.flag = flags[0]
                    result.confidence = 0.9
                    result.add_step("Found flag after decoding!")
                    result.duration = time.time() - start_time
                    return result

            # Try ROT bruteforce
            rot_result = self._try_rot_bruteforce(content, tools, result)
            if rot_result:
                flags = self.find_flags(rot_result, challenge.flag_format)
                if flags:
                    result.success = True
                    result.flag = flags[0]
                    result.confidence = 0.85
                    result.add_step("Found flag via ROT bruteforce!")
                    result.duration = time.time() - start_time
                    return result

            # Try XOR bruteforce on potential encoded data
            for data in analysis.get("potential_data", []):
                xor_result = self._try_xor_bruteforce(data, tools, result)
                if xor_result:
                    flags = self.find_flags(xor_result, challenge.flag_format)
                    if flags:
                        result.success = True
                        result.flag = flags[0]
                        result.confidence = 0.8
                        result.add_step("Found flag via XOR bruteforce!")
                        result.duration = time.time() - start_time
                        return result

            # No flag found but analysis done
            if analysis["detected_encodings"] or analysis["potential_data"]:
                result.success = True
                result.confidence = 0.4
                result.data = {
                    "challenge_type": analysis["challenge_type"],
                    "detected_encodings": analysis["detected_encodings"],
                    "recommendations": analysis["recommendations"],
                }
                result.add_step("Analysis complete - manual solving required")
            else:
                result.success = False
                result.error = "Could not solve misc challenge"

        except Exception as e:
            result.success = False
            result.error = str(e)

        result.duration = time.time() - start_time
        return result

    def can_handle(self, challenge: "Challenge") -> float:
        """Misc engine is a fallback - always returns low score"""
        return 0.1  # Low priority, acts as fallback

    def _detect_encodings(self, content: str) -> list[str]:
        """Detect potential encodings in content"""
        detected = []

        # Base64
        if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', content):
            detected.append("base64")

        # Hex
        if re.search(r'(?:0x)?[0-9a-fA-F]{20,}', content):
            detected.append("hex")

        # Binary
        if re.search(r'[01]{20,}', content):
            detected.append("binary")

        # Morse
        if re.search(r'[\.\-\s]{10,}', content):
            detected.append("morse")

        # URL encoding
        if re.search(r'%[0-9a-fA-F]{2}', content):
            detected.append("url")

        # Base32
        if re.search(r'[A-Z2-7]{20,}={0,6}', content):
            detected.append("base32")

        return detected

    def _extract_data_blocks(self, content: str) -> list[str]:
        """Extract potential encoded data blocks"""
        blocks = []

        # Base64-like blocks
        b64_matches = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', content)
        blocks.extend(b64_matches[:5])

        # Hex blocks
        hex_matches = re.findall(r'(?:0x)?[0-9a-fA-F]{20,}', content)
        blocks.extend(hex_matches[:5])

        # Binary blocks
        bin_matches = re.findall(r'[01]{20,}', content)
        blocks.extend(bin_matches[:5])

        return blocks

    def _try_decode_chain(self, content: str, tools, result: EngineResult) -> Optional[str]:
        """Try various decode chains"""
        data_blocks = self._extract_data_blocks(content)

        for block in data_blocks:
            decoded = block

            # Try up to 5 decode layers
            for _ in range(5):
                prev = decoded

                # Try base64
                try:
                    attempt = base64.b64decode(decoded).decode('utf-8', errors='ignore')
                    if self._is_printable(attempt):
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
                        if self._is_printable(attempt):
                            decoded = attempt
                            result.add_step(f"Hex decoded: {decoded[:50]}...")
                            continue
                except Exception:
                    pass

                # Try binary
                try:
                    clean = decoded.replace(' ', '')
                    if re.match(r'^[01]+$', clean) and len(clean) % 8 == 0:
                        chars = [chr(int(clean[i:i+8], 2)) for i in range(0, len(clean), 8)]
                        attempt = ''.join(chars)
                        if self._is_printable(attempt):
                            decoded = attempt
                            result.add_step(f"Binary decoded: {decoded[:50]}...")
                            continue
                except Exception:
                    pass

                # No progress
                if decoded == prev:
                    break

            if decoded != block:
                return decoded

        return None

    def _try_rot_bruteforce(self, content: str, tools, result: EngineResult) -> Optional[str]:
        """Try ROT bruteforce"""
        result.add_step("Trying ROT bruteforce")

        # Extract alphabetic content
        alpha = re.sub(r'[^a-zA-Z]', '', content)
        if len(alpha) < 10:
            return None

        try:
            # Try all ROT shifts
            for shift in range(1, 26):
                rotated = self._rot_n(content, shift)
                if self.find_flags(rotated):
                    result.add_step(f"ROT{shift} found potential flag")
                    return rotated
        except Exception:
            pass

        return None

    def _try_xor_bruteforce(self, data: str, tools, result: EngineResult) -> Optional[str]:
        """Try single-byte XOR bruteforce"""
        result.add_step("Trying XOR bruteforce")

        # Convert to bytes
        try:
            if re.match(r'^[0-9a-fA-F]+$', data.replace(' ', '')):
                data_bytes = bytes.fromhex(data.replace(' ', ''))
            else:
                data_bytes = data.encode()
        except Exception:
            return None

        # Try single byte XOR
        for key in range(256):
            try:
                decrypted = bytes([b ^ key for b in data_bytes])
                text = decrypted.decode('utf-8', errors='ignore')

                if self._is_printable(text) and self.find_flags(text):
                    result.add_step(f"XOR key 0x{key:02x} found potential flag")
                    return text
            except Exception:
                continue

        return None

    def _rot_n(self, text: str, n: int) -> str:
        """Apply ROT-N cipher"""
        result = []
        for char in text:
            if 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + n) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + n) % 26 + ord('A')))
            else:
                result.append(char)
        return ''.join(result)

    def _is_printable(self, text: str) -> bool:
        """Check if text is mostly printable"""
        if not text:
            return False
        printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
        return printable / len(text) > 0.8
