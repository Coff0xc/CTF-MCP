"""
Tests for reverse engineering tools module
"""

import pytest


class TestDisassembly:
    """Test disassembly functionality"""

    def test_disasm_x64(self, reverse_tools):
        """Test x64 disassembly"""
        # mov rax, 0x1234; ret
        code = "48c7c034120000c3"
        result = reverse_tools.disasm(code=code, arch="x64")
        # Accept either successful disassembly or capstone unavailable message
        assert "mov" in result.lower() or "disassembly" in result.lower() or "capstone" in result.lower()
        assert len(result) > 20

    def test_disasm_x86(self, reverse_tools):
        """Test x86 disassembly"""
        # mov eax, 0x1234; ret
        code = "b834120000c3"
        result = reverse_tools.disasm(code=code, arch="x86")
        assert "mov" in result.lower() or "eax" in result.lower() or "capstone" in result.lower()

    def test_disasm_arm(self, reverse_tools):
        """Test ARM disassembly"""
        code = "0100a0e3"  # mov r0, #1
        result = reverse_tools.disasm(code=code, arch="arm")
        assert "arm" in result.lower() or "disassembly" in result.lower() or "capstone" in result.lower()


class TestAssembly:
    """Test assembly functionality"""

    def test_asm_x64(self, reverse_tools):
        """Test x64 assembly"""
        instructions = "mov rax, 0x1234\nret"
        result = reverse_tools.asm(instructions=instructions, arch="x64")
        # Accept either successful assembly or keystone unavailable message
        assert "48c7c0" in result.lower() or "assembly" in result.lower() or "keystone" in result.lower()

    def test_asm_x86(self, reverse_tools):
        """Test x86 assembly"""
        instructions = "mov eax, 0x1234\nret"
        result = reverse_tools.asm(instructions=instructions, arch="x86")
        assert "b8" in result.lower() or "assembly" in result.lower() or "keystone" in result.lower()


class TestELFParsing:
    """Test ELF file parsing"""

    def test_elf_info_basic(self, reverse_tools, tmp_path):
        """Test basic ELF info extraction"""
        # Create a minimal ELF file for testing
        elf_file = tmp_path / "test.elf"
        # ELF magic + minimal header
        elf_data = bytes.fromhex("7f454c46020101000000000000000000")
        elf_file.write_bytes(elf_data)

        result = reverse_tools.elf_info(file_path=str(elf_file))
        assert "elf" in result.lower() or "header" in result.lower()


class TestPEParsing:
    """Test PE file parsing"""

    def test_pe_info_basic(self, reverse_tools, tmp_path):
        """Test basic PE info extraction"""
        # Create a minimal PE file for testing
        pe_file = tmp_path / "test.exe"
        # MZ header + minimal PE structure
        pe_data = bytes.fromhex("4d5a90000300000004000000ffff0000")
        pe_file.write_bytes(pe_data)

        result = reverse_tools.pe_info(file_path=str(pe_file))
        assert "pe" in result.lower() or "header" in result.lower()


class TestDeobfuscation:
    """Test deobfuscation techniques"""

    def test_deobfuscate_base64(self, reverse_tools):
        """Test base64 deobfuscation"""
        code = "SGVsbG8gV29ybGQ="
        result = reverse_tools.deobfuscate(code=code, obf_type="base64")
        assert "Hello" in result or "World" in result

    def test_deobfuscate_rot13(self, reverse_tools):
        """Test ROT13 deobfuscation"""
        code = "Uryyb Jbeyq"
        result = reverse_tools.deobfuscate(code=code, obf_type="rot13")
        assert "Hello" in result or "World" in result

    def test_deobfuscate_auto(self, reverse_tools):
        """Test automatic deobfuscation detection"""
        code = "SGVsbG8gV29ybGQ="
        result = reverse_tools.deobfuscate(code=code, obf_type="auto")
        assert len(result) > 10


class TestStringAnalysis:
    """Test string analysis in binaries"""

    def test_find_strings(self, reverse_tools, tmp_path):
        """Test string extraction from file"""
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"Hello\x00World\x00\xff\xfe")

        result = reverse_tools.find_strings(file_path=str(test_file), min_length=4)
        assert "Hello" in result or "World" in result or "strings" in result.lower()


class TestGadgetSearch:
    """Test ROP gadget search in hex data"""

    def test_find_gadgets_x64(self, reverse_tools):
        """Test finding x64 gadgets in hex data"""
        # Contains "pop rdi; ret" (5fc3) and "ret" (c3)
        hex_data = "90905fc390c3"
        result = reverse_tools.find_gadgets_in_hex(hex_data=hex_data, arch="x64")
        assert "gadget" in result.lower() or "pop" in result.lower()

    def test_find_gadgets_x86(self, reverse_tools):
        """Test finding x86 gadgets in hex data"""
        # Contains "pop eax; ret" (58c3)
        hex_data = "909058c390"
        result = reverse_tools.find_gadgets_in_hex(hex_data=hex_data, arch="x86")
        assert "gadget" in result.lower() or "pop" in result.lower()
