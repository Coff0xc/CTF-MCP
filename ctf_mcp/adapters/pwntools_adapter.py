"""
Pwntools Adapter
Interface for pwntools library (binary exploitation)
"""

import re
import sys
from typing import Any, Optional

from .base import PythonLibraryAdapter, AdapterResult

# Platform check
IS_LINUX = sys.platform.startswith('linux')


class PwntoolsAdapter(PythonLibraryAdapter):
    """
    Adapter for pwntools library.

    Provides:
    - Remote TCP/UDP connections
    - SSH connections
    - ELF binary analysis
    - ROP chain construction
    - Shellcode generation
    - Exploit script execution
    """

    def __init__(self):
        super().__init__()
        self._pwn = None
        self._context = None

    @property
    def name(self) -> str:
        return "pwntools"

    @property
    def tool_name(self) -> str:
        return "pwn"

    @property
    def description(self) -> str:
        return "CTF framework for exploit development"

    @property
    def min_version(self) -> Optional[str]:
        return "4.0.0"

    def _get_version(self) -> Optional[str]:
        try:
            import pwn
            return pwn.__version__
        except Exception:
            return None

    def _get_pwn(self):
        """Lazy load pwntools"""
        if self._pwn is None:
            try:
                import pwn
                self._pwn = pwn
                self._context = pwn.context
            except ImportError:
                pass
        return self._pwn

    def set_context(
        self,
        arch: str = "amd64",
        os: str = "linux",
        log_level: str = "warning"
    ) -> bool:
        """
        Set pwntools context.

        Args:
            arch: Architecture (i386, amd64, arm, mips, etc.)
            os: Operating system (linux, windows, freebsd)
            log_level: Logging level (debug, info, warning, error)

        Returns:
            True if successful
        """
        pwn = self._get_pwn()
        if not pwn:
            return False

        # Use attribute assignment, not function call
        pwn.context.arch = arch
        pwn.context.os = os
        pwn.context.log_level = log_level
        return True

    def analyze_elf(self, binary_path: str) -> AdapterResult:
        """
        Analyze an ELF binary.

        Args:
            binary_path: Path to ELF binary

        Returns:
            AdapterResult with binary info
        """
        result = AdapterResult()
        pwn = self._get_pwn()

        if not pwn:
            result.error = "pwntools not available"
            return result

        try:
            elf = pwn.ELF(binary_path, checksec=False)

            result.success = True
            result.data = {
                "arch": elf.arch,
                "bits": elf.bits,
                "endian": elf.endian,
                "entry": hex(elf.entry),
                "checksec": {
                    "canary": elf.canary,
                    "nx": elf.nx,
                    "pie": elf.pie,
                    "relro": elf.relro,
                },
                "got": {k: hex(v) for k, v in list(elf.got.items())[:20]},
                "plt": {k: hex(v) for k, v in list(elf.plt.items())[:20]},
                "symbols": {k: hex(v) for k, v in list(elf.symbols.items())[:20]},
            }
            result.output = f"ELF {elf.arch} {elf.bits}-bit, entry: {hex(elf.entry)}"

        except Exception as e:
            result.error = str(e)

        return result

    def checksec(self, binary_path: str) -> AdapterResult:
        """
        Run checksec on binary.

        Args:
            binary_path: Path to binary

        Returns:
            AdapterResult with security features
        """
        result = AdapterResult()
        pwn = self._get_pwn()

        if not pwn:
            result.error = "pwntools not available"
            return result

        try:
            elf = pwn.ELF(binary_path, checksec=False)

            features = {
                "RELRO": elf.relro if elf.relro else "No RELRO",
                "Stack Canary": "Enabled" if elf.canary else "Disabled",
                "NX": "Enabled" if elf.nx else "Disabled",
                "PIE": "Enabled" if elf.pie else "Disabled",
            }

            result.success = True
            result.data = features
            result.output = "\n".join(f"{k}: {v}" for k, v in features.items())

        except Exception as e:
            result.error = str(e)

        return result

    def find_gadgets(
        self,
        binary_path: str,
        gadget_type: str = "all"
    ) -> AdapterResult:
        """
        Find ROP gadgets in binary.

        Args:
            binary_path: Path to binary
            gadget_type: Type of gadgets (all, pop, ret, syscall)

        Returns:
            AdapterResult with gadget list
        """
        result = AdapterResult()
        pwn = self._get_pwn()

        if not pwn:
            result.error = "pwntools not available"
            return result

        try:
            elf = pwn.ELF(binary_path, checksec=False)
            rop = pwn.ROP(elf)

            gadgets = []

            # Get specific gadget types
            if gadget_type in ["all", "ret"]:
                try:
                    ret = rop.find_gadget(['ret'])
                    if ret:
                        gadgets.append(f"ret: {hex(ret[0])}")
                except Exception:
                    pass

            if gadget_type in ["all", "pop"]:
                for reg in ['rdi', 'rsi', 'rdx', 'rcx', 'rax', 'rbx']:
                    try:
                        gadget = rop.find_gadget([f'pop {reg}', 'ret'])
                        if gadget:
                            gadgets.append(f"pop {reg}; ret: {hex(gadget[0])}")
                    except Exception:
                        pass

            if gadget_type in ["all", "syscall"]:
                try:
                    syscall = rop.find_gadget(['syscall', 'ret'])
                    if syscall:
                        gadgets.append(f"syscall; ret: {hex(syscall[0])}")
                    syscall = rop.find_gadget(['syscall'])
                    if syscall:
                        gadgets.append(f"syscall: {hex(syscall[0])}")
                except Exception:
                    pass

            result.success = True
            result.data = {"gadgets": gadgets}
            result.output = "\n".join(gadgets) if gadgets else "No gadgets found"

        except Exception as e:
            result.error = str(e)

        return result

    def generate_rop_chain(
        self,
        binary_path: str,
        chain_type: str = "execve"
    ) -> AdapterResult:
        """
        Generate a ROP chain.

        Args:
            binary_path: Path to binary
            chain_type: Type of chain (execve, mprotect, system)

        Returns:
            AdapterResult with ROP chain
        """
        result = AdapterResult()
        pwn = self._get_pwn()

        if not pwn:
            result.error = "pwntools not available"
            return result

        try:
            elf = pwn.ELF(binary_path, checksec=False)
            rop = pwn.ROP(elf)

            if chain_type == "execve":
                # Try to build execve("/bin/sh", NULL, NULL) chain
                try:
                    binsh = next(elf.search(b'/bin/sh\x00'), None)
                    if binsh:
                        rop.execve(binsh, 0, 0)
                except Exception:
                    # Fallback: try system("/bin/sh")
                    try:
                        binsh = next(elf.search(b'/bin/sh\x00'), None)
                        if binsh:
                            rop.call('system', [binsh])
                    except Exception:
                        pass

            elif chain_type == "system":
                try:
                    bin_sh = next(elf.search(b'/bin/sh\x00'), None)
                    if bin_sh:
                        rop.call('system', [bin_sh])
                except Exception:
                    pass

            elif chain_type == "mprotect":
                # Make stack executable
                try:
                    rop.call('mprotect', [elf.bss(), 0x1000, 7])  # RWX
                except Exception:
                    pass

            chain_bytes = rop.chain()
            chain_hex = chain_bytes.hex()

            result.success = True
            result.data = {
                "chain_type": chain_type,
                "chain_hex": chain_hex,
                "chain_length": len(chain_bytes),
                "dump": rop.dump(),
            }
            result.output = f"ROP chain ({len(chain_bytes)} bytes):\n{rop.dump()}"

        except Exception as e:
            result.error = str(e)

        return result

    def generate_shellcode(
        self,
        arch: str = "amd64",
        shellcode_type: str = "sh"
    ) -> AdapterResult:
        """
        Generate shellcode.

        Args:
            arch: Target architecture
            shellcode_type: Type (sh, reverse_shell, bindshell, read_flag)

        Returns:
            AdapterResult with shellcode
        """
        result = AdapterResult()
        pwn = self._get_pwn()

        if not pwn:
            result.error = "pwntools not available"
            return result

        try:
            # Use attribute assignment, not function call
            pwn.context.arch = arch
            pwn.context.os = 'linux'

            if shellcode_type == "sh":
                shellcode = pwn.shellcraft.sh()
            elif shellcode_type == "cat_flag":
                shellcode = pwn.shellcraft.cat('/flag')
            elif shellcode_type == "read_flag":
                shellcode = pwn.shellcraft.cat('/flag.txt')
            else:
                shellcode = pwn.shellcraft.sh()

            assembled = pwn.asm(shellcode)

            result.success = True
            result.data = {
                "arch": arch,
                "type": shellcode_type,
                "assembly": shellcode,
                "bytes": assembled.hex(),
                "length": len(assembled),
            }
            result.output = f"Shellcode ({len(assembled)} bytes):\n{assembled.hex()}"

        except Exception as e:
            result.error = str(e)

        return result

    def create_remote(
        self,
        host: str,
        port: int,
        timeout: float = 10.0
    ) -> AdapterResult:
        """
        Create a remote connection.

        Args:
            host: Target host
            port: Target port
            timeout: Connection timeout

        Returns:
            AdapterResult with connection info
        """
        result = AdapterResult()
        pwn = self._get_pwn()

        if not pwn:
            result.error = "pwntools not available"
            return result

        try:
            conn = pwn.remote(host, port, timeout=timeout)
            # Read initial banner if any
            try:
                banner = conn.recvrepeat(timeout=1)
                result.output = banner.decode('utf-8', errors='ignore')
            except Exception:
                result.output = "Connected successfully"

            result.success = True
            result.data = {
                "host": host,
                "port": port,
                "connected": True,
            }

            # Close connection after test
            conn.close()

        except Exception as e:
            result.error = str(e)

        return result

    def cyclic_pattern(self, length: int = 200) -> AdapterResult:
        """
        Generate cyclic pattern for finding offsets.

        Args:
            length: Pattern length

        Returns:
            AdapterResult with pattern
        """
        result = AdapterResult()
        pwn = self._get_pwn()

        if not pwn:
            result.error = "pwntools not available"
            return result

        try:
            pattern = pwn.cyclic(length)

            result.success = True
            result.data = {
                "pattern": pattern.decode() if isinstance(pattern, bytes) else pattern,
                "length": length,
            }
            result.output = pattern.decode() if isinstance(pattern, bytes) else pattern

        except Exception as e:
            result.error = str(e)

        return result

    def cyclic_find(self, value: str) -> AdapterResult:
        """
        Find offset in cyclic pattern.

        Args:
            value: Value to find (hex string like "0x61616161")

        Returns:
            AdapterResult with offset
        """
        result = AdapterResult()
        pwn = self._get_pwn()

        if not pwn:
            result.error = "pwntools not available"
            return result

        try:
            # Parse hex value
            if value.startswith('0x'):
                int_val = int(value, 16)
            else:
                int_val = int(value)

            offset = pwn.cyclic_find(int_val)

            result.success = True
            result.data = {"offset": offset, "value": value}
            result.output = f"Offset: {offset}"

        except Exception as e:
            result.error = str(e)

        return result

    def pack(self, value: int, bits: int = 64) -> AdapterResult:
        """
        Pack integer to bytes.

        Args:
            value: Integer value
            bits: Bit width (32 or 64)

        Returns:
            AdapterResult with packed bytes
        """
        result = AdapterResult()
        pwn = self._get_pwn()

        if not pwn:
            result.error = "pwntools not available"
            return result

        try:
            if bits == 32:
                packed = pwn.p32(value)
            else:
                packed = pwn.p64(value)

            result.success = True
            result.data = {
                "value": value,
                "hex": hex(value),
                "packed": packed.hex(),
            }
            result.output = packed.hex()

        except Exception as e:
            result.error = str(e)

        return result
