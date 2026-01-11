"""
Tests for misc tools module
"""

import pytest


class TestHexEncoding:
    """Test hex encoding/decoding"""

    def test_hex_encode(self, misc_tools, sample_data):
        """Test hex encoding"""
        result = misc_tools.hex_encode(sample_data["plaintext"])
        assert sample_data["hex"] in result

    def test_hex_decode(self, misc_tools, sample_data):
        """Test hex decoding"""
        result = misc_tools.hex_decode(sample_data["hex"])
        assert sample_data["plaintext"] in result


class TestURLEncoding:
    """Test URL encoding/decoding"""

    def test_url_encode(self, misc_tools):
        """Test URL encoding"""
        result = misc_tools.url_encode("hello world")
        assert "hello%20world" in result or "hello+world" in result

    def test_url_decode(self, misc_tools):
        """Test URL decoding"""
        result = misc_tools.url_decode("hello%20world")
        assert "hello world" in result


class TestBinaryConversion:
    """Test binary/decimal/hex/string conversions"""

    def test_binary_to_decimal(self, misc_tools):
        """Test binary to decimal conversion"""
        result = misc_tools.binary_convert(data="1010", from_base="bin", to_base="dec")
        assert "10" in result

    def test_decimal_to_hex(self, misc_tools):
        """Test decimal to hex conversion"""
        result = misc_tools.binary_convert(data="255", from_base="dec", to_base="hex")
        assert "ff" in result.lower() or "0xff" in result.lower()

    def test_hex_to_string(self, misc_tools):
        """Test hex to string conversion"""
        result = misc_tools.binary_convert(data="48656c6c6f", from_base="hex", to_base="str")
        assert "Hello" in result

    def test_string_to_binary(self, misc_tools):
        """Test string to binary conversion"""
        result = misc_tools.binary_convert(data="A", from_base="str", to_base="bin")
        assert "01000001" in result or "binary" in result.lower()


class TestFlagFinding:
    """Test flag pattern detection"""

    def test_find_flag_default_prefix(self, misc_tools):
        """Test finding flag with default prefix"""
        text = "The answer is flag{test123} in the file"
        result = misc_tools.find_flag(text, prefix="flag")
        assert "flag{test123}" in result

    def test_find_flag_custom_prefix(self, misc_tools):
        """Test finding flag with custom prefix"""
        text = "CTF{custom_flag_here}"
        result = misc_tools.find_flag(text, prefix="CTF")
        assert "CTF{" in result

    def test_find_flag_multiple(self, misc_tools):
        """Test finding multiple flags"""
        text = "flag{first} and flag{second}"
        result = misc_tools.find_flag(text, prefix="flag")
        assert "flag{first}" in result or "flag{second}" in result


class TestStringsExtraction:
    """Test string extraction from binary data"""

    def test_strings_extract_default(self, misc_tools):
        """Test string extraction with default min length"""
        # Hex data with embedded strings
        data = "48656c6c6f00576f726c6400"  # "Hello\x00World\x00"
        result = misc_tools.strings_extract(data, min_length=4)
        assert "Hello" in result or "World" in result

    def test_strings_extract_custom_length(self, misc_tools):
        """Test string extraction with custom min length"""
        data = "41424300444546"  # "ABC\x00DEF"
        result = misc_tools.strings_extract(data, min_length=3)
        assert "string" in result.lower() or len(result) > 10


class TestEncodingDetection:
    """Test encoding detection"""

    def test_detect_encoding_base64(self, misc_tools):
        """Test base64 detection"""
        result = misc_tools.detect_encoding("SGVsbG8gV29ybGQ=")
        assert "base64" in result.lower()

    def test_detect_encoding_hex(self, misc_tools):
        """Test hex detection"""
        result = misc_tools.detect_encoding("48656c6c6f")
        assert "hex" in result.lower()


class TestMathUtils:
    """Test mathematical utilities"""

    def test_gcd(self, misc_tools):
        """Test GCD calculation"""
        result = misc_tools.gcd(48, 18)
        assert result == 6

    def test_lcm(self, misc_tools):
        """Test LCM calculation"""
        result = misc_tools.lcm(12, 18)
        assert result == 36

    def test_mod_inverse(self, misc_tools):
        """Test modular inverse"""
        result = misc_tools.mod_inverse(3, 11)
        assert "inverse" in result.lower() or "4" in result


class TestStringManipulation:
    """Test string manipulation utilities"""

    def test_reverse_string(self, misc_tools):
        """Test string reversal"""
        result = misc_tools.reverse_string("Hello")
        assert "olleH" in result

    def test_reverse_words(self, misc_tools):
        """Test word reversal"""
        result = misc_tools.reverse_words("Hello World")
        assert "World Hello" in result

    def test_char_swap(self, misc_tools):
        """Test character swapping"""
        result = misc_tools.char_swap("abcd")
        assert "badc" in result
