"""
Binwalk Adapter
Interface for binwalk firmware analysis tool
"""

import os
import re
import tempfile
from typing import Any, Optional

from .base import ToolAdapter, AdapterResult
from ..utils.security import InputValidator, SecurityError


class BinwalkAdapter(ToolAdapter):
    """
    Adapter for binwalk firmware analysis tool.

    Provides:
    - Signature scanning
    - File extraction
    - Entropy analysis
    - Firmware analysis
    """

    @property
    def name(self) -> str:
        return "binwalk"

    @property
    def tool_name(self) -> str:
        return "binwalk"

    @property
    def description(self) -> str:
        return "Firmware analysis and extraction tool"

    @property
    def min_version(self) -> Optional[str]:
        return "2.0.0"

    def _get_version(self) -> Optional[str]:
        result = self._run_command([self.tool_name, "--help"], timeout=10)
        if result.success:
            match = re.search(r'Binwalk v(\d+\.\d+\.\d+)', result.output)
            if match:
                return match.group(1)
        return None

    def scan(self, file_path: str) -> AdapterResult:
        """
        Scan file for embedded signatures.

        Args:
            file_path: Path to file

        Returns:
            AdapterResult with scan results
        """
        result = AdapterResult()

        # Validate file path
        try:
            file_path = InputValidator.validate_file_path(file_path, must_exist=True)
        except SecurityError as e:
            result.error = str(e)
            return result

        args = [self.tool_name, file_path]

        result = self._run_command(args, timeout=120)

        if result.success:
            # Parse signatures
            signatures = []
            for line in result.output.split('\n'):
                # Skip header and empty lines
                if not line.strip() or line.startswith('DECIMAL'):
                    continue

                match = re.match(r'(\d+)\s+0x([0-9A-Fa-f]+)\s+(.+)', line)
                if match:
                    signatures.append({
                        "offset_dec": int(match.group(1)),
                        "offset_hex": match.group(2),
                        "description": match.group(3).strip(),
                    })

            result.data = {
                "signatures": signatures,
                "count": len(signatures),
            }

        return result

    def extract(
        self,
        file_path: str,
        output_dir: Optional[str] = None
    ) -> AdapterResult:
        """
        Extract embedded files.

        Args:
            file_path: Path to file
            output_dir: Output directory (auto-generated if None)

        Returns:
            AdapterResult with extraction results
        """
        result = AdapterResult()

        # Validate file path
        try:
            file_path = InputValidator.validate_file_path(file_path, must_exist=True)
            if output_dir:
                output_dir = InputValidator.validate_file_path(output_dir)
        except SecurityError as e:
            result.error = str(e)
            return result

        if output_dir is None:
            output_dir = tempfile.mkdtemp(prefix="binwalk_")

        args = [
            self.tool_name,
            "-e",  # Extract
            "-C", output_dir,  # Output directory
            file_path
        ]

        result = self._run_command(args, timeout=300)

        if result.success:
            # List extracted files
            extracted = []
            extract_dir = os.path.join(output_dir, f"_{os.path.basename(file_path)}.extracted")

            if os.path.exists(extract_dir):
                for root, dirs, files in os.walk(extract_dir):
                    for f in files:
                        full_path = os.path.join(root, f)
                        rel_path = os.path.relpath(full_path, extract_dir)
                        extracted.append({
                            "path": rel_path,
                            "size": os.path.getsize(full_path),
                        })

            result.data = {
                "output_dir": extract_dir,
                "extracted_files": extracted[:100],  # Limit
                "count": len(extracted),
            }

        return result

    def entropy(self, file_path: str) -> AdapterResult:
        """
        Analyze file entropy.

        High entropy regions may indicate encryption or compression.

        Args:
            file_path: Path to file

        Returns:
            AdapterResult with entropy analysis
        """
        result = AdapterResult()

        # Validate file path
        try:
            file_path = InputValidator.validate_file_path(file_path, must_exist=True)
        except SecurityError as e:
            result.error = str(e)
            return result

        args = [self.tool_name, "-E", file_path]

        result = self._run_command(args, timeout=60)

        if result.success:
            # Try to extract entropy values
            entropy_regions = []
            high_entropy = False

            for line in result.output.split('\n'):
                # Look for entropy data
                match = re.search(r'(\d+)\s+0x[0-9A-Fa-f]+\s+Entropy:\s*([\d.]+)', line)
                if match:
                    entropy_val = float(match.group(2))
                    entropy_regions.append({
                        "offset": int(match.group(1)),
                        "entropy": entropy_val,
                    })
                    if entropy_val > 0.9:  # High entropy threshold
                        high_entropy = True

            result.data = {
                "high_entropy_detected": high_entropy,
                "regions": entropy_regions,
                "note": "High entropy (>0.9) may indicate encryption or compression",
            }

        return result

    def hexdump(
        self,
        file_path: str,
        offset: int = 0,
        length: int = 256
    ) -> AdapterResult:
        """
        Get hex dump of file region.

        Args:
            file_path: Path to file
            offset: Start offset
            length: Number of bytes

        Returns:
            AdapterResult with hex dump
        """
        result = AdapterResult()

        # Validate file path - CRITICAL: prevents arbitrary file read
        try:
            file_path = InputValidator.validate_file_path(file_path, must_exist=True)
        except SecurityError as e:
            result.error = str(e)
            return result

        # Validate offset and length
        if offset < 0:
            result.error = "Offset must be non-negative"
            return result
        if length <= 0 or length > 65536:  # Cap at 64KB
            result.error = "Length must be between 1 and 65536"
            return result

        try:
            with open(file_path, 'rb') as f:
                f.seek(offset)
                data = f.read(length)

            # Format hex dump
            lines = []
            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                hex_part = ' '.join(f'{b:02x}' for b in chunk)
                ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                lines.append(f'{offset+i:08x}  {hex_part:<48}  {ascii_part}')

            result.success = True
            result.data = {
                "offset": offset,
                "length": len(data),
                "hex": data.hex(),
            }
            result.output = '\n'.join(lines)

        except Exception as e:
            result.error = str(e)

        return result

    def signature_scan(
        self,
        file_path: str,
        signature_type: Optional[str] = None
    ) -> AdapterResult:
        """
        Scan for specific signature types.

        Args:
            file_path: Path to file
            signature_type: Filter by type (filesystem, archive, compressed, etc.)

        Returns:
            AdapterResult with matching signatures
        """
        result = AdapterResult()

        # Validate file path
        try:
            file_path = InputValidator.validate_file_path(file_path, must_exist=True)
        except SecurityError as e:
            result.error = str(e)
            return result

        args = [self.tool_name, file_path]

        result = self._run_command(args, timeout=120)

        if result.success and signature_type:
            # Filter results
            filtered = []
            for line in result.output.split('\n'):
                if signature_type.lower() in line.lower():
                    match = re.match(r'(\d+)\s+0x([0-9A-Fa-f]+)\s+(.+)', line)
                    if match:
                        filtered.append({
                            "offset": int(match.group(1)),
                            "description": match.group(3),
                        })

            result.data = {
                "filter": signature_type,
                "matches": filtered,
            }

        return result

    def matryoshka(self, file_path: str, depth: int = 8) -> AdapterResult:
        """
        Recursive extraction (matryoshka mode).

        Args:
            file_path: Path to file
            depth: Maximum recursion depth

        Returns:
            AdapterResult with extraction results
        """
        result = AdapterResult()

        # Validate file path
        try:
            file_path = InputValidator.validate_file_path(file_path, must_exist=True)
        except SecurityError as e:
            result.error = str(e)
            return result

        # Validate depth
        if depth < 1 or depth > 16:
            result.error = "Depth must be between 1 and 16"
            return result

        output_dir = tempfile.mkdtemp(prefix="binwalk_matryoshka_")

        args = [
            self.tool_name,
            "-e",
            "-M",  # Matryoshka mode
            "-d", str(depth),  # Max depth
            "-C", output_dir,
            file_path
        ]

        result = self._run_command(args, timeout=600)

        if result.success:
            # Count all extracted files
            total_files = 0
            for root, dirs, files in os.walk(output_dir):
                total_files += len(files)

            result.data = {
                "output_dir": output_dir,
                "max_depth": depth,
                "total_extracted": total_files,
            }

        return result
