"""
Reverse Engineering Tools Module for CTF-MCP
Disassembly, file analysis, and deobfuscation tools
"""

import base64
import string
import struct

from ..utils.security import dangerous_operation, RiskLevel
from ..utils.helpers import hex_to_bytes as _hex_to_bytes, clean_hex

# Try to import capstone for disassembly
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_ARCH_ARM, CS_MODE_ARM
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False


class ReverseTools:
    """Reverse engineering tools for CTF challenges"""

    def get_tools(self) -> dict[str, str]:
        """Return available tools and their descriptions"""
        return {
            "disasm": "Disassemble machine code",
            "asm": "Assemble instructions",
            "elf_info": "Parse ELF header",
            "pe_info": "Parse PE header",
            "deobfuscate": "Deobfuscate code",
            "find_strings": "Extract printable strings from binary file",
            "find_gadgets_in_hex": "Find common ROP gadgets in hex data",
            "checksec": "Check ELF binary security features (NX, PIE, RELRO, Canary)",
            "elf_sections": "List ELF section headers with attributes",
            "elf_symbols": "Extract symbol table entries from ELF",
        }

    # === Disassembly ===

    def disasm(self, code: str, arch: str = "x64") -> str:
        """Disassemble hex-encoded machine code"""
        if not CAPSTONE_AVAILABLE:
            return "Capstone not available. Install with: pip install capstone"

        try:
            code_bytes = _hex_to_bytes(code)
        except ValueError:
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

    @dangerous_operation(
        risk_level=RiskLevel.MEDIUM,
        description="Generates executable machine code that could be used for exploitation"
    )
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
            try:
                decoded = base64.b64decode(code).decode('utf-8', errors='replace')
                result.append(f"Base64 decoded: {decoded[:200]}")
            except (ValueError, UnicodeDecodeError):
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
                code_bytes = _hex_to_bytes(code)
                for key in [0xFF, 0x41, 0x55, 0xAA]:
                    decoded = bytes(b ^ key for b in code_bytes)
                    try:
                        decoded_str = decoded.decode('ascii')
                        if decoded_str.isprintable():
                            result.append(f"XOR 0x{key:02x}: {decoded_str[:100]}")
                    except UnicodeDecodeError:
                        pass
            except ValueError:
                pass

        if obf_type == "auto" or obf_type == "hex":
            try:
                decoded = _hex_to_bytes(code).decode('utf-8', errors='replace')
                result.append(f"Hex decoded: {decoded[:200]}")
            except ValueError:
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

        cleaned = clean_hex(hex_data).lower()
        result = [f"Gadget Search ({arch}):", "-" * 50]

        for name, pattern in patterns[arch].items():
            idx = 0
            while True:
                idx = cleaned.find(pattern, idx)
                if idx == -1:
                    break
                offset = idx // 2
                result.append(f"  {name} found at offset {offset} (0x{offset:x})")
                idx += 1

        if len(result) == 2:
            result.append("  No gadgets found")

        return '\n'.join(result)

    # === Security Feature Detection ===

    def checksec(self, file_path: str) -> str:
        """Check ELF binary security features (NX, PIE, RELRO, Canary)"""
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                if magic != b'\x7fELF':
                    return "Not an ELF file"
                data = magic + f.read()

            result = ["Security Features (checksec):", "-" * 50]

            ei_class = data[4]
            is64 = ei_class == 2
            fmt = '<' if data[5] == 1 else '>'

            if is64:
                e_type = struct.unpack(fmt + 'H', data[16:18])[0]
                e_phoff = struct.unpack(fmt + 'Q', data[32:40])[0]
                e_phentsize = struct.unpack(fmt + 'H', data[54:56])[0]
                e_phnum = struct.unpack(fmt + 'H', data[56:58])[0]
            else:
                e_type = struct.unpack(fmt + 'H', data[16:18])[0]
                e_phoff = struct.unpack(fmt + 'I', data[28:32])[0]
                e_phentsize = struct.unpack(fmt + 'H', data[42:44])[0]
                e_phnum = struct.unpack(fmt + 'H', data[44:46])[0]

            # PIE
            result.append(f"  PIE:    {'Enabled' if e_type == 3 else 'Disabled'}")

            # Scan program headers
            PT_GNU_STACK = 0x6474e551
            PT_GNU_RELRO = 0x6474e552
            PT_DYNAMIC = 2
            has_relro = False
            nx_enabled = False
            dyn_offset = dyn_size = 0

            for i in range(e_phnum):
                off = e_phoff + i * e_phentsize
                p_type = struct.unpack(fmt + 'I', data[off:off+4])[0]
                if is64:
                    p_flags = struct.unpack(fmt + 'I', data[off+4:off+8])[0]
                else:
                    p_flags = struct.unpack(fmt + 'I', data[off+24:off+28])[0]

                if p_type == PT_GNU_STACK:
                    nx_enabled = not (p_flags & 0x1)
                elif p_type == PT_GNU_RELRO:
                    has_relro = True
                elif p_type == PT_DYNAMIC:
                    if is64:
                        dyn_offset = struct.unpack(fmt + 'Q', data[off+8:off+16])[0]
                        dyn_size = struct.unpack(fmt + 'Q', data[off+32:off+40])[0]
                    else:
                        dyn_offset = struct.unpack(fmt + 'I', data[off+4:off+8])[0]
                        dyn_size = struct.unpack(fmt + 'I', data[off+16:off+20])[0]

            result.append(f"  NX:     {'Enabled' if nx_enabled else 'Disabled'}")

            # RELRO + BIND_NOW check
            if has_relro and dyn_size:
                has_bind_now = False
                entry_size = 16 if is64 else 8
                doff = dyn_offset
                while doff + entry_size <= dyn_offset + dyn_size:
                    if is64:
                        d_tag = struct.unpack(fmt + 'q', data[doff:doff+8])[0]
                        d_val = struct.unpack(fmt + 'Q', data[doff+8:doff+16])[0]
                    else:
                        d_tag = struct.unpack(fmt + 'i', data[doff:doff+4])[0]
                        d_val = struct.unpack(fmt + 'I', data[doff+4:doff+8])[0]
                    if d_tag == 24 or (d_tag == 30 and d_val & 0x8):  # BIND_NOW / DF_BIND_NOW
                        has_bind_now = True
                    elif d_tag == 0:
                        break
                    doff += entry_size
                result.append(f"  RELRO:  {'Full RELRO' if has_bind_now else 'Partial RELRO'}")
            elif has_relro:
                result.append("  RELRO:  Partial RELRO")
            else:
                result.append("  RELRO:  No RELRO")

            result.append(f"  Canary: {'Found' if b'__stack_chk_fail' in data else 'Not found'}")
            result.append(f"  FORTIFY:{'Found' if b'_chk@' in data else 'Not found'}")

            return '\n'.join(result)

        except FileNotFoundError:
            return f"File not found: {file_path}"
        except Exception as e:
            return f"Error: {e}"

    # === ELF Section Listing ===

    def elf_sections(self, file_path: str) -> str:
        """List ELF section headers with attributes"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            if data[:4] != b'\x7fELF':
                return "Not an ELF file"

            is64 = data[4] == 2
            fmt = '<' if data[5] == 1 else '>'

            if is64:
                e_shoff = struct.unpack(fmt + 'Q', data[40:48])[0]
                e_shentsize = struct.unpack(fmt + 'H', data[58:60])[0]
                e_shnum = struct.unpack(fmt + 'H', data[60:62])[0]
                e_shstrndx = struct.unpack(fmt + 'H', data[62:64])[0]
            else:
                e_shoff = struct.unpack(fmt + 'I', data[32:36])[0]
                e_shentsize = struct.unpack(fmt + 'H', data[46:48])[0]
                e_shnum = struct.unpack(fmt + 'H', data[48:50])[0]
                e_shstrndx = struct.unpack(fmt + 'H', data[50:52])[0]

            if e_shnum == 0:
                return "No section headers"

            strtab_off = e_shoff + e_shstrndx * e_shentsize
            if is64:
                str_offset = struct.unpack(fmt + 'Q', data[strtab_off+24:strtab_off+32])[0]
                str_size = struct.unpack(fmt + 'Q', data[strtab_off+32:strtab_off+40])[0]
            else:
                str_offset = struct.unpack(fmt + 'I', data[strtab_off+16:strtab_off+20])[0]
                str_size = struct.unpack(fmt + 'I', data[strtab_off+20:strtab_off+24])[0]
            strtab = data[str_offset:str_offset + str_size]

            sh_types = {
                0: 'NULL', 1: 'PROGBITS', 2: 'SYMTAB', 3: 'STRTAB',
                4: 'RELA', 5: 'HASH', 6: 'DYNAMIC', 7: 'NOTE',
                8: 'NOBITS', 9: 'REL', 11: 'DYNSYM',
            }

            result = ["ELF Sections:", "-" * 60]
            result.append(f"{'#':<4} {'Name':<20} {'Type':<12} {'Size':<10} {'Flags'}")
            result.append("-" * 60)

            for i in range(e_shnum):
                off = e_shoff + i * e_shentsize
                if is64:
                    sh_name = struct.unpack(fmt + 'I', data[off:off+4])[0]
                    sh_type = struct.unpack(fmt + 'I', data[off+4:off+8])[0]
                    sh_flags = struct.unpack(fmt + 'Q', data[off+8:off+16])[0]
                    sh_size = struct.unpack(fmt + 'Q', data[off+32:off+40])[0]
                else:
                    sh_name = struct.unpack(fmt + 'I', data[off:off+4])[0]
                    sh_type = struct.unpack(fmt + 'I', data[off+4:off+8])[0]
                    sh_flags = struct.unpack(fmt + 'I', data[off+8:off+12])[0]
                    sh_size = struct.unpack(fmt + 'I', data[off+20:off+24])[0]

                name_end = strtab.find(b'\x00', sh_name)
                name = strtab[sh_name:name_end].decode('ascii', errors='replace') if name_end > sh_name else ''
                type_name = sh_types.get(sh_type, f'0x{sh_type:x}')
                flags_str = ''
                if sh_flags & 0x1: flags_str += 'W'
                if sh_flags & 0x2: flags_str += 'A'
                if sh_flags & 0x4: flags_str += 'X'

                result.append(f"{i:<4} {name:<20} {type_name:<12} {sh_size:<10} {flags_str}")

            return '\n'.join(result)

        except FileNotFoundError:
            return f"File not found: {file_path}"
        except Exception as e:
            return f"Error: {e}"

    # === ELF Symbol Extraction ===

    def elf_symbols(self, file_path: str, section: str = ".symtab") -> str:
        """Extract symbol table entries from ELF binary"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            if data[:4] != b'\x7fELF':
                return "Not an ELF file"

            is64 = data[4] == 2
            fmt = '<' if data[5] == 1 else '>'

            if is64:
                e_shoff = struct.unpack(fmt + 'Q', data[40:48])[0]
                e_shentsize = struct.unpack(fmt + 'H', data[58:60])[0]
                e_shnum = struct.unpack(fmt + 'H', data[60:62])[0]
                e_shstrndx = struct.unpack(fmt + 'H', data[62:64])[0]
            else:
                e_shoff = struct.unpack(fmt + 'I', data[32:36])[0]
                e_shentsize = struct.unpack(fmt + 'H', data[46:48])[0]
                e_shnum = struct.unpack(fmt + 'H', data[48:50])[0]
                e_shstrndx = struct.unpack(fmt + 'H', data[50:52])[0]

            strtab_hdr = e_shoff + e_shstrndx * e_shentsize
            if is64:
                shstr_off = struct.unpack(fmt + 'Q', data[strtab_hdr+24:strtab_hdr+32])[0]
                shstr_sz = struct.unpack(fmt + 'Q', data[strtab_hdr+32:strtab_hdr+40])[0]
            else:
                shstr_off = struct.unpack(fmt + 'I', data[strtab_hdr+16:strtab_hdr+20])[0]
                shstr_sz = struct.unpack(fmt + 'I', data[strtab_hdr+20:strtab_hdr+24])[0]
            shstrtab = data[shstr_off:shstr_off + shstr_sz]

            # Find target section
            sym_off = sym_size = sym_entsize = sym_link = 0
            for i in range(e_shnum):
                off = e_shoff + i * e_shentsize
                sh_name_idx = struct.unpack(fmt + 'I', data[off:off+4])[0]
                name_end = shstrtab.find(b'\x00', sh_name_idx)
                name = shstrtab[sh_name_idx:name_end].decode('ascii', errors='replace') if name_end > sh_name_idx else ''
                if name == section:
                    if is64:
                        sym_off = struct.unpack(fmt + 'Q', data[off+24:off+32])[0]
                        sym_size = struct.unpack(fmt + 'Q', data[off+32:off+40])[0]
                        sym_entsize = struct.unpack(fmt + 'Q', data[off+56:off+64])[0]
                        sym_link = struct.unpack(fmt + 'I', data[off+40:off+44])[0]
                    else:
                        sym_off = struct.unpack(fmt + 'I', data[off+16:off+20])[0]
                        sym_size = struct.unpack(fmt + 'I', data[off+20:off+24])[0]
                        sym_entsize = struct.unpack(fmt + 'I', data[off+36:off+40])[0]
                        sym_link = struct.unpack(fmt + 'I', data[off+28:off+32])[0]
                    break

            if sym_size == 0:
                return f"Section '{section}' not found (try .dynsym)"

            link_hdr = e_shoff + sym_link * e_shentsize
            if is64:
                str_off = struct.unpack(fmt + 'Q', data[link_hdr+24:link_hdr+32])[0]
                str_sz = struct.unpack(fmt + 'Q', data[link_hdr+32:link_hdr+40])[0]
            else:
                str_off = struct.unpack(fmt + 'I', data[link_hdr+16:link_hdr+20])[0]
                str_sz = struct.unpack(fmt + 'I', data[link_hdr+20:link_hdr+24])[0]
            sym_strtab = data[str_off:str_off + str_sz]

            bind_names = {0: 'LOCAL', 1: 'GLOBAL', 2: 'WEAK'}
            type_names = {0: 'NOTYPE', 1: 'OBJECT', 2: 'FUNC', 3: 'SECTION', 4: 'FILE'}

            result = [f"ELF Symbols ({section}):", "-" * 60]
            num_syms = sym_size // sym_entsize if sym_entsize else 0
            func_count = 0

            for i in range(num_syms):
                soff = sym_off + i * sym_entsize
                if is64:
                    st_name = struct.unpack(fmt + 'I', data[soff:soff+4])[0]
                    st_info = data[soff + 4]
                    st_value = struct.unpack(fmt + 'Q', data[soff+8:soff+16])[0]
                    st_size = struct.unpack(fmt + 'Q', data[soff+16:soff+24])[0]
                else:
                    st_name = struct.unpack(fmt + 'I', data[soff:soff+4])[0]
                    st_info = data[soff + 12]
                    st_value = struct.unpack(fmt + 'I', data[soff+4:soff+8])[0]
                    st_size = struct.unpack(fmt + 'I', data[soff+8:soff+12])[0]

                st_bind = st_info >> 4
                st_type = st_info & 0xf
                name_end = sym_strtab.find(b'\x00', st_name)
                name = sym_strtab[st_name:name_end].decode('ascii', errors='replace') if name_end > st_name else ''
                if not name:
                    continue
                if st_type == 2:
                    func_count += 1

                result.append(
                    f"  0x{st_value:016x}  {bind_names.get(st_bind, '?'):<7} "
                    f"{type_names.get(st_type, '?'):<8} size={st_size:<6} {name}"
                )

            result.append(f"\nTotal named symbols: {num_syms}, functions: {func_count}")
            return '\n'.join(result)

        except FileNotFoundError:
            return f"File not found: {file_path}"
        except Exception as e:
            return f"Error: {e}"
