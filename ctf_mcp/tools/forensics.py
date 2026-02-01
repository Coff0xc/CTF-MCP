"""
Forensics Tools Module for CTF-MCP
File analysis, steganography, and digital forensics tools
"""

import struct
from typing import Optional

from ..utils.helpers import clean_hex

# Try to import optional dependencies
try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


class ForensicsTools:
    """Digital forensics tools for CTF challenges"""

    # File magic bytes signatures
    MAGIC_SIGNATURES = {
        b'\x89PNG\r\n\x1a\n': 'PNG Image',
        b'\xff\xd8\xff': 'JPEG Image',
        b'GIF87a': 'GIF Image (87a)',
        b'GIF89a': 'GIF Image (89a)',
        b'BM': 'BMP Image',
        b'PK\x03\x04': 'ZIP Archive',
        b'PK\x05\x06': 'ZIP Archive (empty)',
        b'Rar!\x1a\x07': 'RAR Archive',
        b'\x1f\x8b\x08': 'GZIP Archive',
        b'BZh': 'BZIP2 Archive',
        b'\xfd7zXZ\x00': 'XZ Archive',
        b'\x7fELF': 'ELF Executable',
        b'MZ': 'DOS/PE Executable',
        b'%PDF': 'PDF Document',
        b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': 'MS Office (OLE)',
        b'PK\x03\x04\x14\x00\x06\x00': 'MS Office (OOXML)',
        b'SQLite format 3': 'SQLite Database',
        b'RIFF': 'RIFF (WAV/AVI)',
        b'ftyp': 'MP4/MOV Video',
        b'OggS': 'OGG Audio',
        b'ID3': 'MP3 Audio (ID3)',
        b'\xff\xfb': 'MP3 Audio',
        b'\x00\x00\x01\x00': 'ICO Image',
        b'fLaC': 'FLAC Audio',
        b'\x1a\x45\xdf\xa3': 'MKV/WebM Video',
    }

    def get_tools(self) -> dict[str, str]:
        """Return available tools and their descriptions"""
        return {
            "file_magic": "Identify file type by magic bytes",
            "exif_extract": "Extract EXIF metadata from image",
            "steghide_detect": "Detect potential steganography in image",
            "lsb_extract": "Extract LSB hidden data from image",
            "strings_file": "Extract strings from file",
            "binwalk_scan": "Scan for embedded files and data",
            "hex_dump": "Generate hex dump of file",
        }

    # === File Type Detection ===

    def file_magic(self, data: str) -> str:
        """Identify file type by magic bytes"""
        try:
            # Handle hex string input
            header_bytes = bytes.fromhex(clean_hex(data)[:64])
        except ValueError:
            return "Invalid hex data"

        result = ["File Type Detection:", "-" * 50]
        result.append(f"Header (hex): {header_bytes[:16].hex()}")
        result.append(f"Header (ascii): {header_bytes[:16].decode('ascii', errors='replace')}")
        result.append("")

        # Check against signatures
        detected = []
        for sig, file_type in self.MAGIC_SIGNATURES.items():
            if header_bytes.startswith(sig):
                detected.append(file_type)

        # Check for ftyp (MP4) which appears at offset 4
        if len(header_bytes) > 8 and header_bytes[4:8] == b'ftyp':
            detected.append("MP4/MOV Video")

        if detected:
            result.append("Detected file type(s):")
            for ft in detected:
                result.append(f"  - {ft}")
        else:
            result.append("Unknown file type")

        # Additional analysis
        result.append("")
        result.append("Additional info:")
        if header_bytes[:4] == b'\x89PNG':
            # PNG chunk info
            if len(header_bytes) >= 16:
                width = struct.unpack('>I', header_bytes[16:20])[0] if len(header_bytes) >= 20 else 0
                height = struct.unpack('>I', header_bytes[20:24])[0] if len(header_bytes) >= 24 else 0
                result.append(f"  PNG dimensions: {width}x{height}")

        return '\n'.join(result)

    # === EXIF Metadata ===

    def exif_extract(self, file_path: str) -> str:
        """Extract EXIF metadata from image"""
        if not PIL_AVAILABLE:
            return "PIL not available. Install with: pip install Pillow"

        try:
            img = Image.open(file_path)
            result = ["EXIF Metadata:", "-" * 50]

            # Basic image info
            result.append(f"Format: {img.format}")
            result.append(f"Size: {img.size[0]}x{img.size[1]}")
            result.append(f"Mode: {img.mode}")

            # EXIF data
            exif = img._getexif()
            if exif:
                from PIL.ExifTags import TAGS

                result.append("")
                result.append("EXIF Tags:")
                for tag_id, value in exif.items():
                    tag = TAGS.get(tag_id, tag_id)
                    # Truncate long values
                    str_val = str(value)
                    if len(str_val) > 100:
                        str_val = str_val[:100] + "..."
                    result.append(f"  {tag}: {str_val}")

                # Look for GPS data
                if 34853 in exif:  # GPSInfo tag
                    result.append("")
                    result.append("[!] GPS data found - may contain location info!")
            else:
                result.append("")
                result.append("No EXIF data found")

            # Check for comments/metadata in other places
            if hasattr(img, 'info'):
                if img.info:
                    result.append("")
                    result.append("Image info:")
                    for key, value in img.info.items():
                        result.append(f"  {key}: {str(value)[:100]}")

            return '\n'.join(result)

        except FileNotFoundError:
            return f"File not found: {file_path}"
        except Exception as e:
            return f"Error extracting EXIF: {e}"

    # === Steganography Detection ===

    def steghide_detect(self, file_path: str) -> str:
        """Detect potential steganography in image"""
        result = ["Steganography Analysis:", "-" * 50]

        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            result.append(f"File size: {len(data)} bytes")

            # Check file type
            detected_type = None
            for sig, file_type in self.MAGIC_SIGNATURES.items():
                if data.startswith(sig):
                    detected_type = file_type
                    break

            result.append(f"File type: {detected_type or 'Unknown'}")

            # Look for appended data (data after end-of-file marker)
            if data.startswith(b'\x89PNG'):
                # PNG ends with IEND chunk
                iend_idx = data.find(b'IEND')
                if iend_idx != -1:
                    iend_end = iend_idx + 8 + 4  # chunk type + CRC
                    if len(data) > iend_end:
                        result.append(f"[!] Data after PNG IEND: {len(data) - iend_end} bytes")
                        result.append(f"    Hidden data preview: {data[iend_end:iend_end+50]}")

            elif data.startswith(b'\xff\xd8\xff'):
                # JPEG ends with FFD9
                eoi_idx = data.rfind(b'\xff\xd9')
                if eoi_idx != -1 and len(data) > eoi_idx + 2:
                    result.append(f"[!] Data after JPEG EOI: {len(data) - eoi_idx - 2} bytes")
                    result.append(f"    Hidden data preview: {data[eoi_idx+2:eoi_idx+52]}")

            # Check for embedded files
            embedded = []
            for sig, file_type in self.MAGIC_SIGNATURES.items():
                idx = data.find(sig, 100)  # Start after header
                while idx != -1:
                    embedded.append((idx, file_type))
                    idx = data.find(sig, idx + 1)

            if embedded:
                result.append("")
                result.append("[!] Potential embedded files:")
                for offset, ftype in embedded[:10]:
                    result.append(f"    {ftype} at offset {offset} (0x{offset:x})")

            # Look for strings that might indicate steganography
            steg_indicators = [b'steghide', b'openstego', b'outguess', b'jphide', b'invisible']
            found_indicators = []
            for indicator in steg_indicators:
                if indicator in data.lower():
                    found_indicators.append(indicator.decode())

            if found_indicators:
                result.append("")
                result.append("[!] Steganography tool signatures found:")
                for ind in found_indicators:
                    result.append(f"    {ind}")

            result.append("")
            result.append("Suggested tools:")
            result.append("  - steghide info/extract")
            result.append("  - stegsolve")
            result.append("  - zsteg (for PNG)")
            result.append("  - binwalk")

            return '\n'.join(result)

        except FileNotFoundError:
            return f"File not found: {file_path}"
        except Exception as e:
            return f"Error: {e}"

    # === LSB Extraction ===

    def lsb_extract(self, file_path: str, bits: int = 1) -> str:
        """Extract LSB hidden data from image"""
        if not PIL_AVAILABLE:
            return "PIL not available. Install with: pip install Pillow"

        try:
            img = Image.open(file_path)
            pixels = list(img.getdata())

            result = ["LSB Extraction:", "-" * 50]
            result.append(f"Image: {img.size[0]}x{img.size[1]}, mode: {img.mode}")
            result.append(f"Extracting {bits} LSB(s) from each channel")

            extracted_bits = []
            mask = (1 << bits) - 1

            for pixel in pixels:
                if isinstance(pixel, int):  # Grayscale
                    extracted_bits.append(pixel & mask)
                else:  # RGB/RGBA
                    for channel in pixel[:3]:  # Skip alpha
                        extracted_bits.append(channel & mask)

            # Convert bits to bytes
            extracted_bytes = []
            for i in range(0, len(extracted_bits) - 7, 8):
                byte = 0
                for j in range(8):
                    byte = (byte << bits) | extracted_bits[i + j]
                extracted_bytes.append(byte & 0xFF)

            extracted_data = bytes(extracted_bytes)

            # Look for readable content
            result.append("")
            result.append("Extracted data preview (first 200 bytes):")

            # Try as ASCII
            ascii_preview = ''.join(chr(b) if 32 <= b < 127 else '.' for b in extracted_data[:200])
            result.append(f"ASCII: {ascii_preview}")

            # Hex
            result.append(f"Hex: {extracted_data[:50].hex()}")

            # Look for flag patterns
            import re
            flags = re.findall(rb'flag\{[^}]+\}', extracted_data, re.IGNORECASE)
            flags.extend(re.findall(rb'CTF\{[^}]+\}', extracted_data, re.IGNORECASE))

            if flags:
                result.append("")
                result.append("[!] Potential flags found:")
                for flag in flags:
                    result.append(f"    {flag.decode()}")

            return '\n'.join(result)

        except FileNotFoundError:
            return f"File not found: {file_path}"
        except Exception as e:
            return f"Error: {e}"

    # === String Extraction ===

    def strings_file(self, file_path: str, min_length: int = 4, encoding: str = "ascii") -> str:
        """Extract strings from a file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            import string

            if encoding == "ascii":
                printable = set(string.printable.encode()) - set(b'\t\n\r\x0b\x0c')
                strings = []
                current = []

                for byte in data:
                    if byte in printable:
                        current.append(chr(byte))
                    else:
                        if len(current) >= min_length:
                            strings.append(''.join(current))
                        current = []

                if len(current) >= min_length:
                    strings.append(''.join(current))

            elif encoding == "utf-16":
                # UTF-16 strings (Windows)
                strings = []
                i = 0
                while i < len(data) - 1:
                    current = []
                    while i < len(data) - 1:
                        char = struct.unpack('<H', data[i:i+2])[0]
                        if 32 <= char < 127:
                            current.append(chr(char))
                            i += 2
                        else:
                            break
                    if len(current) >= min_length:
                        strings.append(''.join(current))
                    i += 2

            result = [f"Strings ({encoding}, min={min_length}):", "-" * 50]
            result.append(f"Found {len(strings)} strings\n")

            # Show strings, highlight potential flags
            for s in strings[:100]:
                if 'flag' in s.lower() or 'ctf' in s.lower() or 'password' in s.lower():
                    result.append(f"[!] {s}")
                else:
                    result.append(s)

            if len(strings) > 100:
                result.append(f"\n... and {len(strings) - 100} more")

            return '\n'.join(result)

        except FileNotFoundError:
            return f"File not found: {file_path}"
        except Exception as e:
            return f"Error: {e}"

    # === Binwalk-like Scan ===

    def binwalk_scan(self, file_path: str) -> str:
        """Scan file for embedded files and data"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            result = ["File Scan Results:", "-" * 50]
            result.append(f"File size: {len(data)} bytes\n")

            findings = []

            # Scan for file signatures
            for sig, file_type in self.MAGIC_SIGNATURES.items():
                idx = 0
                while True:
                    idx = data.find(sig, idx)
                    if idx == -1:
                        break
                    findings.append((idx, file_type, sig))
                    idx += 1

            # Sort by offset
            findings.sort(key=lambda x: x[0])

            if findings:
                result.append("Embedded files/data found:")
                result.append(f"{'Offset':<12} {'Type':<25} {'Signature'}")
                result.append("-" * 50)

                for offset, file_type, sig in findings:
                    sig_hex = sig[:8].hex()
                    result.append(f"0x{offset:<10x} {file_type:<25} {sig_hex}")
            else:
                result.append("No embedded files detected")

            # Look for interesting strings
            interesting = [
                (b'flag{', 'Potential flag'),
                (b'CTF{', 'Potential flag'),
                (b'password', 'Password reference'),
                (b'secret', 'Secret reference'),
                (b'key', 'Key reference'),
                (b'-----BEGIN', 'PEM data'),
                (b'ssh-rsa', 'SSH key'),
            ]

            string_finds = []
            for pattern, desc in interesting:
                idx = data.lower().find(pattern.lower())
                if idx != -1:
                    string_finds.append((idx, desc, data[idx:idx+50]))

            if string_finds:
                result.append("")
                result.append("Interesting strings:")
                for offset, desc, preview in string_finds:
                    result.append(f"  0x{offset:x}: {desc}")
                    result.append(f"    Preview: {preview}")

            result.append("")
            result.append("To extract:")
            result.append("  dd if=file bs=1 skip=OFFSET of=extracted")
            result.append("  binwalk -e file")

            return '\n'.join(result)

        except FileNotFoundError:
            return f"File not found: {file_path}"
        except Exception as e:
            return f"Error: {e}"

    # === Hex Analysis ===

    def hex_dump(self, file_path: str, offset: int = 0, length: int = 256) -> str:
        """Generate hex dump of file"""
        try:
            with open(file_path, 'rb') as f:
                f.seek(offset)
                data = f.read(length)

            result = [f"Hex Dump (offset=0x{offset:x}, length={length}):", "-" * 50]

            for i in range(0, len(data), 16):
                chunk = data[i:i+16]
                hex_part = ' '.join(f'{b:02x}' for b in chunk)
                ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                result.append(f"{offset+i:08x}  {hex_part:<48}  {ascii_part}")

            return '\n'.join(result)

        except FileNotFoundError:
            return f"File not found: {file_path}"
        except Exception as e:
            return f"Error: {e}"
