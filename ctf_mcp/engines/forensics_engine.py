"""
Forensics Solving Engine
Specialized engine for forensics challenges
"""

import os
import re
import struct
import time
from typing import Any, Optional, TYPE_CHECKING

from .base import SolvingEngine, EngineResult, EngineCapability

if TYPE_CHECKING:
    from ..core.orchestrator import Challenge


class ForensicsEngine(SolvingEngine):
    """
    Digital forensics challenge solving engine.

    Handles:
    - File carving and recovery
    - Memory forensics
    - Disk image analysis
    - Network packet analysis
    - Steganography detection
    - Metadata extraction
    - Log analysis
    """

    # File signatures for carving
    FILE_SIGNATURES = {
        'png': (b'\x89PNG\r\n\x1a\n', b'IEND\xaeB`\x82'),
        'jpg': (b'\xff\xd8\xff', b'\xff\xd9'),
        'gif': (b'GIF87a', None),
        'gif89': (b'GIF89a', b'\x00\x3b'),
        'pdf': (b'%PDF', b'%%EOF'),
        'zip': (b'PK\x03\x04', b'PK\x05\x06'),
        'rar': (b'Rar!\x1a\x07', None),
        '7z': (b'7z\xbc\xaf\x27\x1c', None),
        'sqlite': (b'SQLite format 3', None),
        'pcap': (b'\xd4\xc3\xb2\xa1', None),
        'pcapng': (b'\x0a\x0d\x0d\x0a', None),
    }

    # Steganography indicators
    STEGO_INDICATORS = [
        r'stego', r'hidden', r'secret', r'lsb', r'steghide',
        r'zsteg', r'outguess', r'invisible',
    ]

    # Memory forensics indicators
    MEMORY_INDICATORS = [
        r'memory', r'dump', r'volatility', r'ram', r'memdump',
        r'\.raw$', r'\.mem$', r'\.vmem$',
    ]

    @property
    def name(self) -> str:
        return "forensics"

    @property
    def capabilities(self) -> list[EngineCapability]:
        return [
            EngineCapability.ANALYZE,
            EngineCapability.FILE_ANALYSIS,
            EngineCapability.EXTRACT,
            EngineCapability.DECODE,
        ]

    def analyze(self, challenge: "Challenge") -> dict[str, Any]:
        """Analyze a forensics challenge"""
        analysis = {
            "forensics_type": [],
            "file_types": [],
            "embedded_files": [],
            "metadata": {},
            "recommendations": [],
        }

        content = challenge.description.lower()

        # Detect forensics type
        if any(re.search(p, content) for p in self.STEGO_INDICATORS):
            analysis["forensics_type"].append("steganography")
            analysis["recommendations"].append("Try stegsolve, zsteg, steghide, binwalk")

        if any(re.search(p, content) for p in self.MEMORY_INDICATORS):
            analysis["forensics_type"].append("memory")
            analysis["recommendations"].append("Use Volatility for memory analysis")

        if re.search(r'pcap|packet|wireshark|network', content):
            analysis["forensics_type"].append("network")
            analysis["recommendations"].append("Analyze with Wireshark/tshark")

        if re.search(r'disk|image|partition|deleted', content):
            analysis["forensics_type"].append("disk")
            analysis["recommendations"].append("Use Autopsy/FTK for disk analysis")

        # Analyze files
        for file_path in challenge.files:
            file_info = self._analyze_file_type(file_path)
            if file_info:
                analysis["file_types"].append(file_info)

            # Check for embedded files
            embedded = self._detect_embedded_files(file_path)
            analysis["embedded_files"].extend(embedded)

            # Extract metadata
            metadata = self._extract_metadata(file_path)
            if metadata:
                analysis["metadata"][file_path] = metadata

        return analysis

    def solve(self, challenge: "Challenge", **kwargs) -> EngineResult:
        """Attempt to solve a forensics challenge"""
        start_time = time.time()
        result = EngineResult()

        try:
            tools = self._get_tools()["forensics"]

            result.add_step("Analyzing forensics challenge")

            # Analyze challenge
            analysis = self.analyze(challenge)
            result.analysis = analysis

            # Process each file
            for file_path in challenge.files:
                content = self._read_file(file_path, binary=True)
                if not content:
                    continue

                result.add_step(f"Processing file: {file_path}")

                # Try to find flags directly in file
                text_content = content.decode('utf-8', errors='ignore')
                flags = self.find_flags(text_content, challenge.flag_format)
                if flags:
                    result.success = True
                    result.flag = flags[0]
                    result.confidence = 0.9
                    result.add_step("Found flag in file content!")
                    result.duration = time.time() - start_time
                    return result

                # Try steganography if indicated
                if "steganography" in analysis["forensics_type"]:
                    stego_result = self._try_steganography(file_path, tools, result)
                    if stego_result:
                        flags = self.find_flags(stego_result, challenge.flag_format)
                        if flags:
                            result.success = True
                            result.flag = flags[0]
                            result.confidence = 0.85
                            result.add_step("Found flag via steganography!")
                            result.duration = time.time() - start_time
                            return result

                # Try file carving
                carved = self._try_file_carving(file_path, tools, result)
                if carved:
                    for carved_content in carved:
                        flags = self.find_flags(carved_content, challenge.flag_format)
                        if flags:
                            result.success = True
                            result.flag = flags[0]
                            result.confidence = 0.8
                            result.add_step("Found flag in carved file!")
                            result.duration = time.time() - start_time
                            return result

                # Extract and check metadata
                metadata = self._extract_metadata(file_path)
                if metadata:
                    metadata_str = str(metadata)
                    flags = self.find_flags(metadata_str, challenge.flag_format)
                    if flags:
                        result.success = True
                        result.flag = flags[0]
                        result.confidence = 0.9
                        result.add_step("Found flag in metadata!")
                        result.duration = time.time() - start_time
                        return result

            # No flag found but analysis completed
            if analysis["file_types"] or analysis["embedded_files"]:
                result.success = True
                result.confidence = 0.4
                result.data = {
                    "file_types": analysis["file_types"],
                    "embedded_files": analysis["embedded_files"][:10],
                    "metadata": {k: v for k, v in list(analysis["metadata"].items())[:5]},
                    "recommendations": analysis["recommendations"],
                }
                result.add_step("Analysis complete - manual investigation required")
            else:
                result.success = False
                result.error = "Could not analyze forensics challenge"

        except Exception as e:
            result.success = False
            result.error = str(e)

        result.duration = time.time() - start_time
        return result

    def can_handle(self, challenge: "Challenge") -> float:
        """Check if this looks like a forensics challenge"""
        score = 0.0
        content = challenge.description.lower()

        # Keyword matching
        forensics_keywords = [
            'forensic', 'stego', 'hidden', 'pcap', 'memory',
            'dump', 'image', 'carved', 'recover', 'deleted',
            'exif', 'metadata', 'binwalk', 'volatility',
        ]

        for keyword in forensics_keywords:
            if keyword in content:
                score += 0.12

        # Check for forensics-related file types (all lowercase for .lower() comparison)
        forensic_extensions = [
            '.pcap', '.pcapng', '.raw', '.mem', '.vmem',
            '.e01', '.dd', '.img', '.hive',
        ]
        for file_path in challenge.files:
            if any(file_path.lower().endswith(ext) for ext in forensic_extensions):
                score += 0.3
                break

        # Check for image files (potential steganography)
        image_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.bmp']
        for file_path in challenge.files:
            if any(file_path.lower().endswith(ext) for ext in image_extensions):
                score += 0.15
                break

        return min(score, 1.0)

    def _analyze_file_type(self, file_path: str) -> Optional[dict]:
        """Analyze file type from magic bytes"""
        content = self._read_file(file_path, binary=True)
        if not content:
            return None

        info = {
            "path": file_path,
            "size": len(content),
            "type": "unknown",
        }

        for type_name, (header, footer) in self.FILE_SIGNATURES.items():
            if content.startswith(header):
                info["type"] = type_name
                break

        return info

    def _detect_embedded_files(self, file_path: str) -> list[dict]:
        """Detect embedded files using magic signatures"""
        content = self._read_file(file_path, binary=True)
        if not content:
            return []

        embedded = []
        for type_name, (header, footer) in self.FILE_SIGNATURES.items():
            offset = 0
            while True:
                pos = content.find(header, offset)
                if pos == -1:
                    break

                # Skip if at the very beginning (the file itself)
                if pos > 0:
                    embedded.append({
                        "type": type_name,
                        "offset": pos,
                    })

                offset = pos + 1
                if len(embedded) > 50:  # Limit
                    break

        return embedded

    def _extract_metadata(self, file_path: str) -> Optional[dict]:
        """Extract metadata from file"""
        content = self._read_file(file_path, binary=True)
        if not content:
            return None

        metadata = {}

        # PNG metadata
        if content.startswith(b'\x89PNG'):
            # Extract tEXt chunks
            pos = 8
            content_len = len(content)
            while pos + 12 <= content_len:
                # Bounds check before unpacking
                if pos + 4 > content_len:
                    break
                length = struct.unpack('>I', content[pos:pos+4])[0]

                # Sanity check: chunk length shouldn't exceed remaining content
                if length > content_len - pos - 12 or length > 10_000_000:
                    break

                chunk_type = content[pos+4:pos+8].decode('ascii', errors='ignore')

                if chunk_type in ['tEXt', 'iTXt', 'zTXt']:
                    chunk_data = content[pos+8:pos+8+length]
                    try:
                        text = chunk_data.decode('utf-8', errors='ignore')
                        metadata[f'png_{chunk_type}'] = text[:200]
                    except Exception:
                        pass

                # Check for IEND chunk (end of PNG)
                if chunk_type == 'IEND':
                    break

                pos += 12 + length

        # JPEG EXIF (simplified)
        if content.startswith(b'\xff\xd8\xff'):
            # Look for EXIF marker
            exif_pos = content.find(b'Exif\x00\x00')
            if exif_pos != -1:
                metadata['has_exif'] = True
                # Extract some ASCII strings around EXIF
                exif_data = content[exif_pos:exif_pos+500]
                strings = re.findall(rb'[\x20-\x7e]{6,}', exif_data)
                metadata['exif_strings'] = [s.decode('ascii') for s in strings[:10]]

        # PDF metadata
        if content.startswith(b'%PDF'):
            # Look for /Author, /Title, etc.
            patterns = [
                (rb'/Author\s*\(([^)]+)\)', 'author'),
                (rb'/Title\s*\(([^)]+)\)', 'title'),
                (rb'/Subject\s*\(([^)]+)\)', 'subject'),
                (rb'/Creator\s*\(([^)]+)\)', 'creator'),
            ]
            for pattern, key in patterns:
                match = re.search(pattern, content)
                if match:
                    metadata[f'pdf_{key}'] = match.group(1).decode('utf-8', errors='ignore')

        return metadata if metadata else None

    def _try_steganography(self, file_path: str, tools, result: EngineResult) -> Optional[str]:
        """Try steganography extraction"""
        result.add_step("Attempting steganography extraction")

        content = self._read_file(file_path, binary=True)
        if not content:
            return None

        try:
            # Try LSB extraction for PNG/BMP
            if content.startswith(b'\x89PNG') or content.startswith(b'BM'):
                stego_result = tools.lsb_extract(file_path)
                result.add_step(f"LSB extraction: {stego_result[:100]}...")
                return stego_result
        except Exception as ex:
            result.add_step(f"Steganography extraction failed: {ex}")

        # Try strings extraction as fallback
        try:
            strings_result = tools.strings_extract(file_path)
            return strings_result
        except Exception:
            pass

        return None

    def _try_file_carving(self, file_path: str, tools, result: EngineResult) -> Optional[list]:
        """Try to carve embedded files"""
        result.add_step("Attempting file carving")

        content = self._read_file(file_path, binary=True)
        if not content:
            return None

        carved_files = []

        # Manual carving for common types
        for type_name, (header, footer) in self.FILE_SIGNATURES.items():
            offset = 0
            while True:
                start = content.find(header, offset)
                if start == -1:
                    break

                if footer:
                    end = content.find(footer, start)
                    if end != -1:
                        end += len(footer)
                        carved = content[start:end]
                        carved_files.append(carved.decode('utf-8', errors='ignore'))
                else:
                    # No footer, take reasonable chunk
                    carved = content[start:start+10000]
                    carved_files.append(carved.decode('utf-8', errors='ignore'))

                offset = start + 1
                if len(carved_files) > 20:
                    break

        if carved_files:
            result.add_step(f"Carved {len(carved_files)} potential files")

        return carved_files if carved_files else None
