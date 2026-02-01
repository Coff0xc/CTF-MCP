"""
Hashcat Adapter
Interface for hashcat password cracking tool
"""

import os
import re
import tempfile
from typing import Any, Optional

from .base import ToolAdapter, AdapterResult
from ..utils.security import InputValidator, SecurityError


class HashcatAdapter(ToolAdapter):
    """
    Adapter for hashcat password cracking tool.

    Provides:
    - Hash identification
    - Dictionary attacks
    - Brute force attacks
    - Rule-based attacks
    - Mask attacks
    """

    # Common hash mode mappings
    HASH_MODES = {
        "md5": 0,
        "sha1": 100,
        "sha256": 1400,
        "sha512": 1700,
        "md5crypt": 500,
        "sha512crypt": 1800,
        "bcrypt": 3200,
        "ntlm": 1000,
        "mysql": 300,
        "mysql5": 300,
        "mssql": 1731,
        "sha1_raw": 100,
        "md5_raw": 0,
    }

    @property
    def name(self) -> str:
        return "hashcat"

    @property
    def tool_name(self) -> str:
        return "hashcat"

    @property
    def description(self) -> str:
        return "Advanced password recovery tool"

    @property
    def min_version(self) -> Optional[str]:
        return "6.0.0"

    def _get_version(self) -> Optional[str]:
        result = self._run_command([self.tool_name, "--version"], timeout=10)
        if result.success:
            match = re.search(r'v(\d+\.\d+\.\d+)', result.output)
            if match:
                return match.group(1)
        return None

    def identify_hash(self, hash_value: str) -> AdapterResult:
        """
        Identify hash type.

        Args:
            hash_value: Hash string to identify

        Returns:
            AdapterResult with hash type info
        """
        result = AdapterResult()

        # Validate hash input
        try:
            hash_value = InputValidator.validate_hash_value(hash_value)
        except SecurityError as e:
            result.error = str(e)
            return result

        # Simple identification based on length and format
        hash_len = len(hash_value)
        hash_types = []

        if re.match(r'^[a-f0-9]{32}$', hash_value, re.I):
            hash_types.extend(["MD5", "NTLM", "MD4"])
        elif re.match(r'^[a-f0-9]{40}$', hash_value, re.I):
            hash_types.extend(["SHA1", "MySQL5"])
        elif re.match(r'^[a-f0-9]{64}$', hash_value, re.I):
            hash_types.extend(["SHA256", "SHA3-256"])
        elif re.match(r'^[a-f0-9]{128}$', hash_value, re.I):
            hash_types.extend(["SHA512", "SHA3-512", "Whirlpool"])
        elif hash_value.startswith('$1$'):
            hash_types.append("MD5crypt")
        elif hash_value.startswith('$5$'):
            hash_types.append("SHA256crypt")
        elif hash_value.startswith('$6$'):
            hash_types.append("SHA512crypt")
        elif hash_value.startswith('$2'):
            hash_types.append("bcrypt")
        elif hash_value.startswith('$apr1$'):
            hash_types.append("Apache MD5")

        result.success = True
        result.data = {
            "hash": hash_value[:50] + "..." if len(hash_value) > 50 else hash_value,
            "length": hash_len,
            "possible_types": hash_types,
        }
        result.output = f"Possible types: {', '.join(hash_types)}" if hash_types else "Unknown hash type"

        return result

    def crack_dictionary(
        self,
        hash_value: str,
        hash_type: str,
        wordlist: str,
        rules: Optional[str] = None,
        timeout: int = 600
    ) -> AdapterResult:
        """
        Crack hash using dictionary attack.

        Args:
            hash_value: Hash to crack
            hash_type: Hash type (md5, sha1, etc.)
            wordlist: Path to wordlist file
            rules: Optional rules file
            timeout: Attack timeout

        Returns:
            AdapterResult with cracked password
        """
        result = AdapterResult()

        # Validate inputs
        try:
            hash_value = InputValidator.validate_hash_value(hash_value)
            wordlist = InputValidator.validate_file_path(wordlist, must_exist=True)
            if rules:
                rules = InputValidator.validate_file_path(rules, must_exist=True)
        except SecurityError as e:
            result.error = str(e)
            return result

        # Get hash mode
        mode = self.HASH_MODES.get(hash_type.lower())
        if mode is None:
            result.error = f"Unknown hash type: {hash_type}"
            return result

        # Create temp file for hash
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(hash_value)
            hash_file = f.name

        try:
            args = [
                self.tool_name,
                "-m", str(mode),
                "-a", "0",  # Dictionary attack
                hash_file,
                wordlist,
                "--potfile-disable",
                "-O",  # Optimized kernels
            ]

            if rules:
                args.extend(["-r", rules])

            cmd_result = self._run_command(args, timeout=timeout)

            # Check for cracked password
            if cmd_result.success or "Cracked" in cmd_result.output:
                # Try to find cracked password in output
                match = re.search(rf'{re.escape(hash_value)}:(.+)', cmd_result.output)
                if match:
                    result.success = True
                    result.data = {
                        "cracked": True,
                        "password": match.group(1).strip(),
                        "hash": hash_value,
                    }
                    result.output = f"Cracked: {match.group(1).strip()}"
                else:
                    result.success = False
                    result.data = {"cracked": False}
                    result.output = "Hash not cracked"
            else:
                result.success = False
                result.error = cmd_result.error or "Cracking failed"

        finally:
            os.unlink(hash_file)

        return result

    def crack_bruteforce(
        self,
        hash_value: str,
        hash_type: str,
        mask: str = "?a?a?a?a?a?a",
        timeout: int = 600
    ) -> AdapterResult:
        """
        Crack hash using brute force with mask.

        Mask characters:
        - ?l = lowercase (a-z)
        - ?u = uppercase (A-Z)
        - ?d = digits (0-9)
        - ?s = special chars
        - ?a = all printable

        Args:
            hash_value: Hash to crack
            hash_type: Hash type
            mask: Attack mask
            timeout: Attack timeout

        Returns:
            AdapterResult with cracked password
        """
        result = AdapterResult()

        # Validate inputs
        try:
            hash_value = InputValidator.validate_hash_value(hash_value)
            # Validate mask - only allow hashcat mask characters
            if not re.match(r'^[\?ludsahb0-9a-fA-F]+$', mask):
                raise SecurityError(f"Invalid mask format: {mask}")
        except SecurityError as e:
            result.error = str(e)
            return result

        mode = self.HASH_MODES.get(hash_type.lower())
        if mode is None:
            result.error = f"Unknown hash type: {hash_type}"
            return result

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(hash_value)
            hash_file = f.name

        try:
            args = [
                self.tool_name,
                "-m", str(mode),
                "-a", "3",  # Brute force
                hash_file,
                mask,
                "--potfile-disable",
                "-O",
            ]

            cmd_result = self._run_command(args, timeout=timeout)

            match = re.search(rf'{re.escape(hash_value)}:(.+)', cmd_result.output)
            if match:
                result.success = True
                result.data = {
                    "cracked": True,
                    "password": match.group(1).strip(),
                    "mask": mask,
                }
                result.output = f"Cracked: {match.group(1).strip()}"
            else:
                result.success = False
                result.data = {"cracked": False}
                result.output = "Hash not cracked"

        finally:
            os.unlink(hash_file)

        return result

    def benchmark(self, hash_type: Optional[str] = None) -> AdapterResult:
        """
        Run hashcat benchmark.

        Args:
            hash_type: Specific hash type to benchmark

        Returns:
            AdapterResult with benchmark results
        """
        args = [self.tool_name, "-b"]

        if hash_type and hash_type.lower() in self.HASH_MODES:
            args.extend(["-m", str(self.HASH_MODES[hash_type.lower()])])

        result = self._run_command(args, timeout=120)

        if result.success:
            # Parse benchmark speeds
            speeds = {}
            for line in result.output.split('\n'):
                match = re.search(r'Hashmode:\s*(\d+).*?Speed.*?:\s*([\d.]+\s*\w+/s)', line)
                if match:
                    speeds[match.group(1)] = match.group(2)

            result.data = {"speeds": speeds}

        return result

    def show_potfile(self) -> AdapterResult:
        """
        Show cracked hashes from potfile.

        Returns:
            AdapterResult with cracked hashes
        """
        # Expand ~ to actual home directory
        potfile_path = os.path.expanduser("~/.hashcat/hashcat.potfile")
        args = [self.tool_name, "--show", "--potfile-path", potfile_path]

        return self._run_command(args, timeout=30)
