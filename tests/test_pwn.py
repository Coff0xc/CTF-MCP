"""
Tests for pwn tools module
"""

import pytest


class TestShellcode:
    """Test shellcode generation"""

    def test_shellcode_x64_linux_execve(self, pwn_tools):
        """Test x64 Linux execve shellcode"""
        result = pwn_tools.shellcode_gen(arch="x64", os="linux", sc_type="execve")
        assert "shellcode" in result.lower() or "x64" in result.lower()
        assert len(result) > 20

    def test_shellcode_x86_linux(self, pwn_tools):
        """Test x86 Linux shellcode"""
        result = pwn_tools.shellcode_gen(arch="x86", os="linux", sc_type="execve")
        assert "x86" in result.lower() or "shellcode" in result.lower()

    def test_shellcode_read_flag(self, pwn_tools):
        """Test read flag shellcode"""
        result = pwn_tools.shellcode_gen(arch="x64", os="linux", sc_type="read_flag")
        assert "flag" in result.lower() or "shellcode" in result.lower()


class TestCyclicPattern:
    """Test cyclic pattern generation and offset finding"""

    def test_pattern_create_default(self, pwn_tools):
        """Test cyclic pattern creation with default length"""
        result = pwn_tools.pattern_create(length=100)
        assert len(result) > 50
        assert "pattern" in result.lower() or "cyclic" in result.lower()

    def test_pattern_create_custom_length(self, pwn_tools):
        """Test cyclic pattern with custom length"""
        result = pwn_tools.pattern_create(length=200)
        assert len(result) > 100

    def test_pattern_offset(self, pwn_tools):
        """Test finding offset in cyclic pattern"""
        result = pwn_tools.pattern_offset(value="0x61616161")
        assert "offset" in result.lower() or "found" in result.lower()


class TestROPGadgets:
    """Test ROP gadget patterns"""

    def test_rop_gadgets_x64_all(self, pwn_tools):
        """Test all x64 ROP gadgets"""
        result = pwn_tools.rop_gadgets(arch="x64", gadget_type="all")
        assert "pop" in result.lower() or "ret" in result.lower()
        assert "gadget" in result.lower()

    def test_rop_gadgets_pop_rdi(self, pwn_tools):
        """Test pop rdi gadget"""
        result = pwn_tools.rop_gadgets(arch="x64", gadget_type="pop_rdi")
        assert "rdi" in result.lower()

    def test_rop_gadgets_syscall(self, pwn_tools):
        """Test syscall gadget"""
        result = pwn_tools.rop_gadgets(arch="x64", gadget_type="syscall")
        assert "syscall" in result.lower()

    def test_rop_gadgets_x86(self, pwn_tools):
        """Test x86 ROP gadgets"""
        result = pwn_tools.rop_gadgets(arch="x86", gadget_type="all")
        assert "gadget" in result.lower()


class TestFormatString:
    """Test format string exploit generation"""

    def test_format_string_x64(self, pwn_tools):
        """Test x64 format string exploit"""
        result = pwn_tools.format_string(
            target_addr="0x601020",
            value="0xdeadbeef",
            offset=6,
            arch="x64"
        )
        assert "format" in result.lower() or "%" in result
        assert "0x601020" in result or "601020" in result

    def test_format_string_x86(self, pwn_tools):
        """Test x86 format string exploit"""
        result = pwn_tools.format_string(
            target_addr="0x08048000",
            value="0x41414141",
            offset=4,
            arch="x86"
        )
        assert "format" in result.lower() or "%" in result


class TestLibcOffset:
    """Test libc base calculation"""

    def test_libc_offset_puts(self, pwn_tools):
        """Test libc offset calculation with puts"""
        result = pwn_tools.libc_offset(
            leaked_addr="0x7ffff7a62aa0",
            symbol="puts",
            libc_version="2.31"
        )
        assert "libc" in result.lower() or "base" in result.lower()
        assert "0x" in result

    def test_libc_offset_printf(self, pwn_tools):
        """Test libc offset calculation with printf"""
        result = pwn_tools.libc_offset(
            leaked_addr="0x7ffff7a64e80",
            symbol="printf",
            libc_version="2.31"
        )
        assert "libc" in result.lower() or "offset" in result.lower()


class TestHeapExploitation:
    """Test heap exploitation techniques"""

    def test_heap_tcache(self, pwn_tools):
        """Test tcache techniques"""
        result = pwn_tools.heap_tcache(libc_version="2.31")
        assert "tcache" in result.lower()

    def test_heap_fastbin(self, pwn_tools):
        """Test fastbin techniques"""
        result = pwn_tools.heap_fastbin(arch="x64")
        assert "fastbin" in result.lower()

    def test_heap_unsorted_bin(self, pwn_tools):
        """Test unsorted bin attack"""
        result = pwn_tools.heap_unsorted_bin()
        assert "unsorted" in result.lower() or "bin" in result.lower()


class TestStackTechniques:
    """Test stack exploitation techniques"""

    def test_stack_pivot(self, pwn_tools):
        """Test stack pivot technique"""
        result = pwn_tools.stack_pivot()
        assert "stack" in result.lower() or "pivot" in result.lower()

    def test_stack_layout(self, pwn_tools):
        """Test stack layout visualization"""
        result = pwn_tools.stack_layout(arch="x64")
        assert "stack" in result.lower()


class TestPacking:
    """Test packing and unpacking utilities"""

    def test_pack_64bit(self, pwn_tools):
        """Test 64-bit packing"""
        result = pwn_tools.pack(value=0x4141414141414141, bits=64)
        assert "pack" in result.lower() or "0x" in result

    def test_unpack_64bit(self, pwn_tools):
        """Test 64-bit unpacking"""
        result = pwn_tools.unpack(data="4141414141414141", bits=64)
        assert "unpack" in result.lower() or "0x" in result


class TestOneGadget:
    """Test one_gadget functionality"""

    def test_one_gadget_search(self, pwn_tools):
        """Test one_gadget search"""
        result = pwn_tools.one_gadget(libc_version="2.31")
        assert "gadget" in result.lower() or "one" in result.lower()
