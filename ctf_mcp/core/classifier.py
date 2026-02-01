"""
CTF Challenge Classifier
Identifies challenge type based on files, description, and content analysis
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("ctf-mcp.classifier")


class ChallengeType(Enum):
    """CTF challenge categories"""
    CRYPTO = "crypto"
    WEB = "web"
    PWN = "pwn"
    REVERSE = "reverse"
    FORENSICS = "forensics"
    MISC = "misc"
    OSINT = "osint"
    BLOCKCHAIN = "blockchain"
    UNKNOWN = "unknown"


@dataclass
class ClassificationResult:
    """
    Result of challenge classification.

    Attributes:
        types: List of possible challenge types (ordered by confidence)
        confidence: Confidence scores for each type
        analysis: Detailed analysis results
        file_types: Detected file types
        indicators: Key indicators that led to classification
    """
    types: list[ChallengeType] = field(default_factory=list)
    confidence: dict[ChallengeType, float] = field(default_factory=dict)
    analysis: dict[str, Any] = field(default_factory=dict)
    file_types: dict[str, str] = field(default_factory=dict)
    indicators: list[str] = field(default_factory=list)

    @property
    def primary_type(self) -> Optional[ChallengeType]:
        """Get the most likely challenge type"""
        return self.types[0] if self.types else None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary"""
        return {
            "types": [t.value for t in self.types],
            "confidence": {k.value: v for k, v in self.confidence.items()},
            "file_types": self.file_types,
            "indicators": self.indicators,
        }


class ChallengeClassifier:
    """
    Classifies CTF challenges by analyzing:
    - File types and contents
    - Description keywords
    - Network endpoints
    - Content patterns
    """

    # File extension to type mapping
    FILE_TYPE_HINTS = {
        # Crypto
        ".pem": ChallengeType.CRYPTO,
        ".key": ChallengeType.CRYPTO,
        ".pub": ChallengeType.CRYPTO,
        ".enc": ChallengeType.CRYPTO,
        ".crypt": ChallengeType.CRYPTO,

        # PWN/Reverse
        ".elf": ChallengeType.PWN,
        ".exe": ChallengeType.REVERSE,
        ".dll": ChallengeType.REVERSE,
        ".so": ChallengeType.PWN,
        ".o": ChallengeType.REVERSE,
        ".bin": ChallengeType.PWN,

        # Web
        ".php": ChallengeType.WEB,
        ".js": ChallengeType.WEB,
        ".html": ChallengeType.WEB,
        ".css": ChallengeType.WEB,
        ".sql": ChallengeType.WEB,

        # Forensics
        ".pcap": ChallengeType.FORENSICS,
        ".pcapng": ChallengeType.FORENSICS,
        ".mem": ChallengeType.FORENSICS,
        ".raw": ChallengeType.FORENSICS,
        ".img": ChallengeType.FORENSICS,
        ".dd": ChallengeType.FORENSICS,
        ".e01": ChallengeType.FORENSICS,

        # Images (could be forensics or misc)
        ".png": ChallengeType.FORENSICS,
        ".jpg": ChallengeType.FORENSICS,
        ".jpeg": ChallengeType.FORENSICS,
        ".gif": ChallengeType.FORENSICS,
        ".bmp": ChallengeType.FORENSICS,

        # Archives
        ".zip": ChallengeType.MISC,
        ".tar": ChallengeType.MISC,
        ".gz": ChallengeType.MISC,
        ".7z": ChallengeType.MISC,

        # Python (could be crypto or misc)
        ".py": ChallengeType.CRYPTO,
        ".sage": ChallengeType.CRYPTO,
    }

    # Magic bytes signatures
    MAGIC_SIGNATURES = {
        b'\x7fELF': ("ELF", ChallengeType.PWN),
        b'MZ': ("PE/DOS", ChallengeType.REVERSE),
        b'\x89PNG': ("PNG", ChallengeType.FORENSICS),
        b'\xff\xd8\xff': ("JPEG", ChallengeType.FORENSICS),
        b'GIF8': ("GIF", ChallengeType.FORENSICS),
        b'PK\x03\x04': ("ZIP", ChallengeType.MISC),
        b'\x1f\x8b': ("GZIP", ChallengeType.MISC),
        b'Rar!': ("RAR", ChallengeType.MISC),
        b'%PDF': ("PDF", ChallengeType.FORENSICS),
        b'SQLite': ("SQLite", ChallengeType.FORENSICS),
        b'\xd0\xcf\x11\xe0': ("OLE/MS Office", ChallengeType.FORENSICS),
        b'\xca\xfe\xba\xbe': ("Mach-O", ChallengeType.REVERSE),
        b'\xfe\xed\xfa\xce': ("Mach-O 32", ChallengeType.REVERSE),
        b'\xfe\xed\xfa\xcf': ("Mach-O 64", ChallengeType.REVERSE),
    }

    # Description keyword patterns
    KEYWORD_PATTERNS = {
        ChallengeType.CRYPTO: [
            r'\b(rsa|aes|des|cipher|encrypt|decrypt|hash|md5|sha|xor|base64)\b',
            r'\b(modulus|exponent|prime|factor|key|iv|nonce)\b',
            r'\b(caesar|vigenere|substitution|transposition)\b',
            r'\b(diffie|hellman|ecc|elliptic|curve)\b',
            r'\b(ciphertext|plaintext|padding|oracle)\b',
        ],
        ChallengeType.WEB: [
            r'\b(sql|injection|xss|csrf|ssrf|lfi|rfi)\b',
            r'\b(cookie|session|jwt|token|auth)\b',
            r'\b(http|https|url|web|api|rest|graphql)\b',
            r'\b(php|javascript|node|flask|django)\b',
            r'\b(login|admin|upload|download)\b',
            r'\b(ssti|template|serializ|deserializ)\b',
        ],
        ChallengeType.PWN: [
            r'\b(buffer|overflow|bof|stack|heap)\b',
            r'\b(rop|ret2|gadget|shellcode)\b',
            r'\b(format|string|printf|scanf)\b',
            r'\b(libc|got|plt|canary|aslr|pie|nx)\b',
            r'\b(exploit|pwn|binary|elf)\b',
            r'\b(tcache|fastbin|unsorted|malloc|free)\b',
        ],
        ChallengeType.REVERSE: [
            r'\b(reverse|disassembl|decompil|debug)\b',
            r'\b(assembly|asm|ida|ghidra|radare)\b',
            r'\b(obfuscat|pack|unpack|upx)\b',
            r'\b(keygen|crack|license|serial)\b',
            r'\b(android|apk|ios|mobile)\b',
        ],
        ChallengeType.FORENSICS: [
            r'\b(forensic|memory|disk|image)\b',
            r'\b(pcap|wireshark|network|packet)\b',
            r'\b(steganography|stego|hidden|lsb)\b',
            r'\b(exif|metadata|carv|recover)\b',
            r'\b(volatility|autopsy|sleuth)\b',
            r'\b(file|system|deleted|artifact)\b',
        ],
        ChallengeType.MISC: [
            r'\b(misc|trivia|programming|code)\b',
            r'\b(ppc|coding|algorithm)\b',
            r'\b(qr|barcode|morse|braille)\b',
            r'\b(escape|jail|sandbox)\b',
        ],
        ChallengeType.OSINT: [
            r'\b(osint|geolocation|social|recon)\b',
            r'\b(google|search|dork|metadata)\b',
        ],
        ChallengeType.BLOCKCHAIN: [
            r'\b(blockchain|ethereum|solidity|smart\s*contract)\b',
            r'\b(web3|defi|nft|token|wallet)\b',
        ],
    }

    # Content patterns for file analysis
    CONTENT_PATTERNS = {
        ChallengeType.CRYPTO: [
            rb'-----BEGIN.*KEY-----',
            rb'-----BEGIN.*CERTIFICATE-----',
            rb'n\s*=\s*\d{10,}',  # Large numbers (RSA n)
            rb'e\s*=\s*\d+',
            rb'p\s*=\s*\d{10,}',
            rb'c\s*=\s*\d{10,}',
        ],
        ChallengeType.WEB: [
            rb'<\?php',
            rb'SELECT.*FROM',
            rb'INSERT.*INTO',
            rb'document\.cookie',
            rb'eval\s*\(',
            rb'exec\s*\(',
        ],
        ChallengeType.PWN: [
            rb'gets\s*\(',
            rb'strcpy\s*\(',
            rb'sprintf\s*\(',
            rb'system\s*\(',
            rb'execve\s*\(',
            rb'/bin/sh',
        ],
    }

    def __init__(self):
        """Initialize the classifier"""
        pass

    def classify(
        self,
        description: str = "",
        files: list[str] = None,
        remote: Optional[str] = None,
        hint: Optional[str] = None,
    ) -> ClassificationResult:
        """
        Classify a CTF challenge.

        Args:
            description: Challenge description text
            files: List of file paths
            remote: Remote connection info
            hint: Category hint from CTF platform

        Returns:
            ClassificationResult with types and confidence
        """
        files = files or []
        scores: dict[ChallengeType, float] = {t: 0.0 for t in ChallengeType}
        indicators: list[str] = []
        file_types: dict[str, str] = {}
        analysis: dict[str, Any] = {}

        # Use hint if provided
        if hint:
            hint_type = self._parse_hint(hint)
            if hint_type != ChallengeType.UNKNOWN:
                scores[hint_type] += 5.0
                indicators.append(f"Category hint: {hint}")

        # Remote endpoint suggests web or pwn
        if remote:
            if any(proto in remote.lower() for proto in ['http://', 'https://']):
                scores[ChallengeType.WEB] += 3.0
                indicators.append("HTTP(S) remote endpoint")
            else:
                scores[ChallengeType.PWN] += 2.0
                indicators.append("TCP remote endpoint (likely PWN)")

        # Analyze description
        desc_analysis = self._analyze_description(description)
        for ctype, score in desc_analysis.items():
            scores[ctype] += score
        if desc_analysis:
            indicators.append("Description keyword matches")
        analysis["description_scores"] = {k.value: v for k, v in desc_analysis.items() if v > 0}

        # Analyze files
        for file_path in files:
            file_result = self._analyze_file(file_path)
            file_types[file_path] = file_result.get("type_name", "unknown")

            if file_result.get("challenge_type"):
                ctype = file_result["challenge_type"]
                scores[ctype] += file_result.get("score", 1.0)
                indicators.append(f"File {Path(file_path).name}: {file_result.get('type_name')}")

            # Content analysis
            if file_result.get("content_hints"):
                for ctype, hint_score in file_result["content_hints"].items():
                    scores[ctype] += hint_score

        analysis["file_analysis"] = file_types

        # Sort types by score
        sorted_types = sorted(
            [(t, s) for t, s in scores.items() if s > 0],
            key=lambda x: x[1],
            reverse=True
        )

        types = [t for t, s in sorted_types]
        confidence = {t: min(s / 10.0, 1.0) for t, s in sorted_types}

        # If no types identified, mark as unknown
        if not types:
            types = [ChallengeType.UNKNOWN]
            confidence[ChallengeType.UNKNOWN] = 0.0

        return ClassificationResult(
            types=types,
            confidence=confidence,
            analysis=analysis,
            file_types=file_types,
            indicators=indicators,
        )

    def _parse_hint(self, hint: str) -> ChallengeType:
        """Parse category hint to ChallengeType"""
        hint_lower = hint.lower().strip()
        mapping = {
            "crypto": ChallengeType.CRYPTO,
            "cryptography": ChallengeType.CRYPTO,
            "web": ChallengeType.WEB,
            "pwn": ChallengeType.PWN,
            "pwnable": ChallengeType.PWN,
            "binary": ChallengeType.PWN,
            "exploit": ChallengeType.PWN,
            "reverse": ChallengeType.REVERSE,
            "reversing": ChallengeType.REVERSE,
            "rev": ChallengeType.REVERSE,
            "forensics": ChallengeType.FORENSICS,
            "forensic": ChallengeType.FORENSICS,
            "dfir": ChallengeType.FORENSICS,
            "misc": ChallengeType.MISC,
            "miscellaneous": ChallengeType.MISC,
            "osint": ChallengeType.OSINT,
            "blockchain": ChallengeType.BLOCKCHAIN,
            "smart contract": ChallengeType.BLOCKCHAIN,
        }
        return mapping.get(hint_lower, ChallengeType.UNKNOWN)

    def _analyze_description(self, description: str) -> dict[ChallengeType, float]:
        """Analyze description text for keywords"""
        scores: dict[ChallengeType, float] = {}
        desc_lower = description.lower()

        for ctype, patterns in self.KEYWORD_PATTERNS.items():
            score = 0.0
            for pattern in patterns:
                matches = re.findall(pattern, desc_lower, re.IGNORECASE)
                score += len(matches) * 0.5
            if score > 0:
                scores[ctype] = min(score, 5.0)  # Cap at 5

        return scores

    def _analyze_file(self, file_path: str) -> dict[str, Any]:
        """Analyze a file for type identification"""
        result: dict[str, Any] = {}
        path = Path(file_path)

        if not path.exists():
            return {"error": "File not found"}

        # Check extension
        ext = path.suffix.lower()
        if ext in self.FILE_TYPE_HINTS:
            result["challenge_type"] = self.FILE_TYPE_HINTS[ext]
            result["score"] = 1.5
            result["type_name"] = f"Extension: {ext}"

        # Check magic bytes
        try:
            with open(file_path, 'rb') as f:
                header = f.read(32)

            for magic, (type_name, ctype) in self.MAGIC_SIGNATURES.items():
                if header.startswith(magic):
                    result["challenge_type"] = ctype
                    result["type_name"] = type_name
                    result["score"] = 2.0
                    break

            # Content pattern analysis (for text files)
            if self._is_text_file(header):
                content_hints = self._analyze_content(file_path)
                if content_hints:
                    result["content_hints"] = content_hints

        except (IOError, PermissionError) as e:
            result["error"] = str(e)

        return result

    def _is_text_file(self, header: bytes) -> bool:
        """Check if file appears to be text"""
        # Simple heuristic: check if header is mostly printable ASCII
        try:
            text_chars = sum(1 for b in header if 32 <= b < 127 or b in (9, 10, 13))
            return text_chars / len(header) > 0.7 if header else False
        except ZeroDivisionError:
            return False

    def _analyze_content(self, file_path: str) -> dict[ChallengeType, float]:
        """Analyze file content for patterns"""
        scores: dict[ChallengeType, float] = {}

        try:
            with open(file_path, 'rb') as f:
                # Read first 64KB
                content = f.read(65536)

            for ctype, patterns in self.CONTENT_PATTERNS.items():
                score = 0.0
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        score += 1.0
                if score > 0:
                    scores[ctype] = min(score, 3.0)

        except (IOError, PermissionError):
            pass

        return scores
