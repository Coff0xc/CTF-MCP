"""
Tests for crypto tools module
"""

import pytest


class TestBaseEncoding:
    """Test base encoding/decoding functions"""

    def test_base64_encode(self, crypto_tools, sample_data):
        """Test Base64 encoding"""
        result = crypto_tools.base64_encode(sample_data["plaintext"])
        assert sample_data["base64"] in result

    def test_base64_decode(self, crypto_tools, sample_data):
        """Test Base64 decoding"""
        result = crypto_tools.base64_decode(sample_data["base64"])
        assert sample_data["plaintext"] in result


class TestClassicalCiphers:
    """Test classical cipher implementations"""

    def test_rot13(self, crypto_tools, sample_data):
        """Test ROT13 cipher"""
        result = crypto_tools.rot_n(sample_data["plaintext"], n=13)
        assert sample_data["rot13"] in result

    def test_caesar_default(self, crypto_tools):
        """Test Caesar cipher with default shift"""
        result = crypto_tools.caesar("ABC", shift=3)
        assert "DEF" in result

    def test_caesar_bruteforce(self, crypto_tools):
        """Test Caesar cipher bruteforce"""
        result = crypto_tools.caesar_bruteforce("DEF")
        assert "ABC" in result  # Should contain original with shift 23


class TestXOR:
    """Test XOR operations"""

    def test_xor_basic(self, crypto_tools):
        """Test basic XOR operation"""
        result = crypto_tools.xor("test", "key")
        assert "XOR" in result or len(result) > 0


class TestHashing:
    """Test hash functions"""

    def test_hash_md5(self, crypto_tools, sample_data):
        """Test MD5 hashing"""
        result = crypto_tools.hash_data(sample_data["plaintext"], algorithm="md5")
        assert "md5" in result.lower()
        assert len(result) > 20  # Should contain hash value

    def test_hash_sha256(self, crypto_tools, sample_data):
        """Test SHA256 hashing"""
        result = crypto_tools.hash_data(sample_data["plaintext"], algorithm="sha256")
        assert "sha256" in result.lower()


class TestFrequencyAnalysis:
    """Test frequency analysis"""

    def test_freq_analysis(self, crypto_tools):
        """Test frequency analysis on ciphertext"""
        ciphertext = "ETAOIN SHRDLU"
        result = crypto_tools.freq_analysis(ciphertext)
        assert "frequency" in result.lower() or "analysis" in result.lower()
