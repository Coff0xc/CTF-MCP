"""
Reverse Engineering Tools Module for CTF-MCP
Disassembly, file analysis, and deobfuscation tools
"""

import struct
from typing import Optional

# Try to import capstone for disassembly
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_ARCH_ARM, CS_MODE_ARM
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False


class ReverseTools:
    """Reverse engineering tools for CTF challenges"""

    def get_tools(self) -> dict:
        """Return available tools and their descriptions"""
        return {
            "disasm": "Disassemble machine code",
            "asm": "Assemble instructions",
            "elf_info": "Parse ELF header",
            "pe_info": "Parse PE header",
            "deobfuscate": "Deobfuscate code",
        }

    # === Disassembly ===

    def disasm(self, code: str, arch: str = "x64") -> str:
        """Disassemble hex-encoded machine code"""
        if not CAPSTONE_AVAILABLE:
            return "Capstone not available. Install with: pip install capstone"

        try:
            code_bytes = bytes.fromhex(code.replace(" ", "").replace("\\x", ""))
        except:
            return "Invalid hex code"

        arch_map = {
            "x86": (CS_ARCH_X86, CS_MODE_32),
            "x64": (CS_ARCH_X86, CS_MODE_64),
            "arm": (CS_ARCH_ARM, CS_MODE_ARM),
        }

        if arch not in arch_map:
            return f"Unknown architecture. Available: {list(arch_map.keys())}"

        cs_arch, cs_mode = arch_map[arch]
        md = Cs(cs_arch, cs_mode)

        result = [f"Disassembly ({arch}):", "-" * 50]
        for insn in md.disasm(code_bytes, 0x0):
            result.append(f"0x{insn.address:08x}:  {insn.mnemonic:8s} {insn.op_str}")

        if len(result) == 2:
            result.append("(no valid instructions found)")

        return '\n'.join(result)

    def asm(self, instructions: str, arch: str = "x64") -> str:
        """Assemble instructions to machine code (using keystone if available)"""
        try:
            from keystone import Ks, KS_ARCH_X86, KS_MODE_32, KS_MODE_64

            arch_map = {
                "x86": (KS_ARCH_X86, KS_MODE_32),
                "x64": (KS_ARCH_X86, KS_MODE_64),
            }

            if arch not in arch_map:
                return f"Unknown architecture. Available: {list(arch_map.keys())}"

            ks_arch, ks_mode = arch_map[arch]
            ks = Ks(ks_arch, ks_mode)

            encoding, count = ks.asm(instructions)

            result = [f"Assembly ({arch}):", "-" * 50]
            result.append(f"Instructions: {instructions}")
            result.append(f"Count: {count}")
            result.append(f"Bytes: {bytes(encoding).hex()}")
            result.append(f"C string: {''.join(f'\\\\x{b:02x}' for b in encoding)}")

            return '\n'.join(result)

        except ImportError:
            # Provide common instruction encodings
            common_encodings = {
                "x64": {
                    "nop": "90",
                    "ret": "c3",
                    "syscall": "0f05",
                    "int3": "cc",
                    "leave": "c9",
                    "pop rdi": "5f",
                    "pop rsi": "5e",
                    "pop rdx": "5a",
                    "pop rax": "58",
                    "xor rax, rax": "4831c0",
                    "xor rdi, rdi": "4831ff",
                    "xor rsi, rsi": "4831f6",
                    "xor rdx, rdx": "4831d2",
                },
                "x86": {
                    "nop": "90",
                    "ret": "c3",
                    "int 0x80": "cd80",
                    "int3": "cc",
                    "leave": "c9",
                    "pop eax": "58",
                    "pop ebx": "5b",
                    "pop ecx": "59",
                    "pop edx": "5a",
                    "xor eax, eax": "31c0",
                    "xor ebx, ebx": "31db",
                },
            }

            result = ["Keystone not available. Common encodings:", "-" * 50]
            if arch in common_encodings:
                for insn, encoding in common_encodings[arch].items():
                    result.append(f"  {insn:20s} -> {encoding}")

                # Check if requested instruction is known
                for insn, encoding in common_encodings[arch].items():
                    if instructions.lower().strip() == insn:
                        result.append("")
                        result.append(f"Your instruction: {encoding}")
                        result.append(f"C string: {''.join(f'\\\\x{encoding[i:i+2]}' for i in range(0, len(encoding), 2))}")

            return '\n'.join(result)

    # === ELF Parsing ===

    def elf_info(self, file_path: str) -> str:
        """Parse ELF file header information"""
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                if magic != b'\x7fELF':
                    return "Not a valid ELF file"

                result = ["ELF File Information:", "-" * 50]

                # ELF class (32/64 bit)
                ei_class = ord(f.read(1))
                bits = "32-bit" if ei_class == 1 else "64-bit"
                result.append(f"Class: {bits}")

                # Endianness
                ei_data = ord(f.read(1))
                endian = "Little-endian" if ei_data == 1 else "Big-endian"
                result.append(f"Endianness: {endian}")

                # Version
                f.read(1)

                # OS/ABI
                ei_osabi = ord(f.read(1))
                osabi_map = {0: "UNIX System V", 3: "Linux", 6: "Solaris"}
                result.append(f"OS/ABI: {osabi_map.get(ei_osabi, f'Unknown ({ei_osabi})')}")

                # Skip padding
                f.read(8)

                # Type
                e_type = struct.unpack('<H', f.read(2))[0]
                type_map = {1: "Relocatable", 2: "Executable", 3: "Shared object", 4: "Core"}
                result.append(f"Type: {type_map.get(e_type, f'Unknown ({e_type})')}")

                # Machine
                e_machine = struct.unpack('<H', f.read(2))[0]
                machine_map = {3: "x86", 62: "x86-64", 40: "ARM", 183: "AArch64"}
                result.append(f"Machine: {machine_map.get(e_machine, f'Unknown ({e_machine})')}")

                # Version
                f.read(4)

                # Entry point
                if ei_class == 2:  # 64-bit
                    e_entry = struct.unpack('<Q', f.read(8))[0]
                else:  # 32-bit
                    e_entry = struct.unpack('<I', f.read(4))[0]
                result.append(f"Entry point: {hex(e_entry)}")

                # Security features (basic checks)
                result.append("")
                result.append("Security Analysis:")
                result.append("  Run 'checksec' for detailed security info")

                return '\n'.join(result)

        except FileNotFoundError:
            return f"File not found: {file_path}"
        except Exception as e:
            return f"Error parsing ELF: {e}"

    def pe_info(self, file_path: str) -> str:
        """Parse PE file header information"""
        try:
            with open(file_path, 'rb') as f:
                # Check DOS header
                dos_magic = f.read(2)
                if dos_magic != b'MZ':
                    return "Not a valid PE file"

                result = ["PE File Information:", "-" * 50]

                # Get PE header offset
                f.seek(0x3c)
                pe_offset = struct.unpack('<I', f.read(4))[0]

                # Check PE signature
                f.seek(pe_offset)
                pe_sig = f.read(4)
                if pe_sig != b'PE\x00\x00':
                    return "Invalid PE signature"

                # Machine type
                machine = struct.unpack('<H', f.read(2))[0]
                machine_map = {0x14c: "i386", 0x8664: "AMD64", 0x1c0: "ARM"}
                result.append(f"Machine: {machine_map.get(machine, hex(machine))}")

                # Number of sections
                num_sections = struct.unpack('<H', f.read(2))[0]
                result.append(f"Sections: {num_sections}")

                # Timestamp
                timestamp = struct.unpack('<I', f.read(4))[0]
                result.append(f"Timestamp: {timestamp}")

                # Skip to characteristics
                f.read(8)
                opt_header_size = struct.unpack('<H', f.read(2))[0]
                characteristics = struct.unpack('<H', f.read(2))[0]

                result.append(f"Characteristics: {hex(characteristics)}")
                if characteristics & 0x0002:
                    result.append("  - Executable")
                if characteristics & 0x2000:
                    result.append("  - DLL")
                if characteristics & 0x0020:
                    result.append("  - Large address aware")

                # Optional header magic
                opt_magic = struct.unpack('<H', f.read(2))[0]
                if opt_magic == 0x10b:
                    result.append("Format: PE32")
                elif opt_magic == 0x20b:
                    result.append("Format: PE32+ (64-bit)")

                return '\n'.join(result)

        except FileNotFoundError:
            return f"File not found: {file_path}"
        except Exception as e:
            return f"Error parsing PE: {e}"

    # === Deobfuscation ===

    def deobfuscate(self, code: str, obf_type: str = "auto") -> str:
        """Attempt to deobfuscate simple obfuscation"""
        result = ["Deobfuscation Attempt:", "-" * 50]

        if obf_type == "auto" or obf_type == "base64":
            import base64
            try:
                decoded = base64.b64decode(code).decode('utf-8', errors='replace')
                result.append(f"Base64 decoded: {decoded[:200]}")
            except:
                pass

        if obf_type == "auto" or obf_type == "rot13":
            rot13 = ''.join(
                chr((ord(c) - ord('a') + 13) % 26 + ord('a')) if c.islower()
                else chr((ord(c) - ord('A') + 13) % 26 + ord('A')) if c.isupper()
                else c
                for c in code
            )
            if rot13 != code:
                result.append(f"ROT13: {rot13[:200]}")

        if obf_type == "auto" or obf_type == "xor":
            # Try single-byte XOR
            try:
                code_bytes = bytes.fromhex(code.replace(" ", ""))
                for key in [0xFF, 0x41, 0x55, 0xAA]:
                    decoded = bytes(b ^ key for b in code_bytes)
                    try:
                        decoded_str = decoded.decode('ascii')
                        if decoded_str.isprintable():
                            result.append(f"XOR 0x{key:02x}: {decoded_str[:100]}")
                    except:
                        pass
            except:
                pass

        if obf_type == "auto" or obf_type == "hex":
            try:
                decoded = bytes.fromhex(code.replace(" ", "")).decode('utf-8', errors='replace')
                result.append(f"Hex decoded: {decoded[:200]}")
            except:
                pass

        if len(result) == 2:
            result.append("No deobfuscation successful")

        return '\n'.join(result)

    # === String Analysis ===

    def find_strings(self, file_path: str, min_length: int = 4) -> str:
        """Extract printable strings from binary file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            import string
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

            result = [f"Strings (min length {min_length}):", "-" * 50]
            result.append(f"Found {len(strings)} strings\n")

            # Show first 50 strings
            for s in strings[:50]:
                result.append(s)

            if len(strings) > 50:
                result.append(f"\n... and {len(strings) - 50} more")

            return '\n'.join(result)

        except FileNotFoundError:
            return f"File not found: {file_path}"
        except Exception as e:
            return f"Error: {e}"

    # === Pattern Matching ===

    def find_gadgets_in_hex(self, hex_data: str, arch: str = "x64") -> str:
        """Find common ROP gadgets in hex data"""
        patterns = {
            "x64": {
                "pop rdi; ret": "5fc3",
                "pop rsi; ret": "5ec3",
                "pop rdx; ret": "5ac3",
                "pop rax; ret": "58c3",
                "ret": "c3",
                "syscall": "0f05",
                "syscall; ret": "0f05c3",
                "leave; ret": "c9c3",
            },
            "x86": {
                "pop eax; ret": "58c3",
                "pop ebx; ret": "5bc3",
                "pop ecx; ret": "59c3",
                "pop edx; ret": "5ac3",
                "ret": "c3",
                "int 0x80": "cd80",
                "leave; ret": "c9c3",
            },
        }

        if arch not in patterns:
            return f"Unknown architecture. Available: {list(patterns.keys())}"

        hex_data = hex_data.lower().replace(" ", "").replace("\\x", "")
        result = [f"Gadget Search ({arch}):", "-" * 50]

        for name, pattern in patterns[arch].items():
            idx = 0
            while True:
                idx = hex_data.find(pattern, idx)
                if idx == -1:
                    break
                offset = idx // 2
                result.append(f"  {name} found at offset {offset} (0x{offset:x})")
                idx += 1

        if len(result) == 2:
            result.append("  No gadgets found")

        return '\n'.join(result)
