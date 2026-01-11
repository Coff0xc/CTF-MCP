"""
Tests for forensics tools module
"""

import pytest


class TestFileMagic:
    """Test file type identification by magic bytes"""

    def test_file_magic_png(self, forensics_tools):
        """Test PNG file identification"""
        # PNG magic bytes
        data = "89504e470d0a1a0a"
        result = forensics_tools.file_magic(data=data)
        assert "png" in result.lower() or "image" in result.lower()

    def test_file_magic_jpeg(self, forensics_tools):
        """Test JPEG file identification"""
        # JPEG magic bytes
        data = "ffd8ffe000104a46"
        result = forensics_tools.file_magic(data=data)
        assert "jpeg" in result.lower() or "jpg" in result.lower()

    def test_file_magic_pdf(self, forensics_tools):
        """Test PDF file identification"""
        # PDF magic bytes
        data = "255044462d312e34"
        result = forensics_tools.file_magic(data=data)
        assert "pdf" in result.lower()

    def test_file_magic_zip(self, forensics_tools):
        """Test ZIP file identification"""
        # ZIP magic bytes
        data = "504b0304"
        result = forensics_tools.file_magic(data=data)
        assert "zip" in result.lower() or "archive" in result.lower()


class TestEXIFExtraction:
    """Test EXIF metadata extraction"""

    def test_exif_extract_basic(self, forensics_tools, tmp_path):
        """Test basic EXIF extraction"""
        # Create a minimal image file for testing
        img_file = tmp_path / "test.jpg"
        # JPEG header
        img_data = bytes.fromhex("ffd8ffe000104a464946")
        img_file.write_bytes(img_data)

        result = forensics_tools.exif_extract(file_path=str(img_file))
        assert "exif" in result.lower() or "metadata" in result.lower()


class TestSteganography:
    """Test steganography detection and extraction"""

    def test_steghide_detect(self, forensics_tools, tmp_path):
        """Test steghide detection"""
        img_file = tmp_path / "test.png"
        # PNG header
        img_data = bytes.fromhex("89504e470d0a1a0a")
        img_file.write_bytes(img_data)

        result = forensics_tools.steghide_detect(file_path=str(img_file))
        assert "steg" in result.lower() or "hidden" in result.lower()

    def test_lsb_extract(self, forensics_tools, tmp_path):
        """Test LSB extraction"""
        img_file = tmp_path / "test.png"
        img_data = bytes.fromhex("89504e470d0a1a0a")
        img_file.write_bytes(img_data)

        result = forensics_tools.lsb_extract(file_path=str(img_file), bits=1)
        assert "lsb" in result.lower() or "extract" in result.lower()


class TestStringsExtraction:
    """Test string extraction from files"""

    def test_strings_file_ascii(self, forensics_tools, tmp_path):
        """Test ASCII string extraction"""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"Hello\x00World\x00\xff\xfe")

        result = forensics_tools.strings_file(
            file_path=str(test_file),
            min_length=4,
            encoding="ascii"
        )
        assert "Hello" in result or "World" in result

    def test_strings_file_utf8(self, forensics_tools, tmp_path):
        """Test UTF-8 string extraction"""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes("测试".encode('utf-8') + b"\x00")

        result = forensics_tools.strings_file(
            file_path=str(test_file),
            min_length=2,
            encoding="utf-8"
        )
        assert "string" in result.lower()


class TestBinwalk:
    """Test binwalk-like file scanning"""

    def test_binwalk_scan(self, forensics_tools, tmp_path):
        """Test binwalk scanning for embedded files"""
        test_file = tmp_path / "test.bin"
        # Create file with embedded ZIP signature
        data = b"\x00" * 100 + b"PK\x03\x04" + b"\x00" * 100
        test_file.write_bytes(data)

        result = forensics_tools.binwalk_scan(file_path=str(test_file))
        assert "embedded" in result.lower() or "scan" in result.lower()


class TestHexDump:
    """Test hex dump functionality"""

    def test_hex_dump_basic(self, forensics_tools, tmp_path):
        """Test basic hex dump"""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"Hello World!")

        result = forensics_tools.hex_dump(file_path=str(test_file), offset=0, length=12)
        assert "hex" in result.lower() or "48" in result  # 'H' = 0x48
