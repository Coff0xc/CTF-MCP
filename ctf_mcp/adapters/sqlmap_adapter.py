"""
SQLMap Adapter
Interface for sqlmap SQL injection tool
"""

import json
import os
import re
import tempfile
from typing import Any, Optional

from .base import ToolAdapter, AdapterResult
from ..utils.security import InputValidator, SecurityError


class SqlmapAdapter(ToolAdapter):
    """
    Adapter for sqlmap SQL injection tool.

    Provides:
    - SQL injection detection
    - Database enumeration
    - Data extraction
    - WAF bypass techniques
    """

    @property
    def name(self) -> str:
        return "sqlmap"

    @property
    def tool_name(self) -> str:
        return "sqlmap"

    @property
    def description(self) -> str:
        return "Automatic SQL injection and database takeover tool"

    @property
    def min_version(self) -> Optional[str]:
        return "1.5"

    def _get_version(self) -> Optional[str]:
        result = self._run_command([self.tool_name, "--version"], timeout=10)
        if result.success:
            # Parse version from output
            match = re.search(r'(\d+\.\d+(?:\.\d+)?)', result.output)
            if match:
                return match.group(1)
        return None

    def scan(
        self,
        url: str,
        data: Optional[str] = None,
        cookie: Optional[str] = None,
        level: int = 1,
        risk: int = 1,
        timeout: int = 300
    ) -> AdapterResult:
        """
        Scan URL for SQL injection vulnerabilities.

        Args:
            url: Target URL
            data: POST data
            cookie: Cookie string
            level: Test level (1-5)
            risk: Risk level (1-3)
            timeout: Scan timeout

        Returns:
            AdapterResult with scan results
        """
        result = AdapterResult()

        # Validate inputs
        try:
            url = InputValidator.validate_url(url)
            # Validate level and risk are within bounds
            if not 1 <= level <= 5:
                raise SecurityError(f"Invalid level: {level} (must be 1-5)")
            if not 1 <= risk <= 3:
                raise SecurityError(f"Invalid risk: {risk} (must be 1-3)")
        except SecurityError as e:
            result.error = str(e)
            return result

        args = [
            self.tool_name,
            "-u", url,
            "--batch",  # Non-interactive
            "--level", str(level),
            "--risk", str(risk),
            "--output-dir", tempfile.gettempdir(),
        ]

        if data:
            args.extend(["--data", data])

        if cookie:
            args.extend(["--cookie", cookie])

        result = self._run_command(args, timeout=timeout)

        # Parse results
        if result.success or "sqlmap identified" in result.output.lower():
            vulnerabilities = []

            # Check for injection points
            if "injectable" in result.output.lower():
                vuln_match = re.findall(
                    r"Parameter: (\w+).*?Type: ([^\n]+)",
                    result.output,
                    re.DOTALL
                )
                for param, vuln_type in vuln_match:
                    vulnerabilities.append({
                        "parameter": param,
                        "type": vuln_type.strip(),
                    })

            result.success = True
            result.data = {
                "vulnerable": bool(vulnerabilities),
                "vulnerabilities": vulnerabilities,
            }

        return result

    def enumerate_dbs(
        self,
        url: str,
        data: Optional[str] = None,
        cookie: Optional[str] = None,
        timeout: int = 300
    ) -> AdapterResult:
        """
        Enumerate databases.

        Args:
            url: Target URL
            data: POST data
            cookie: Cookie string
            timeout: Operation timeout

        Returns:
            AdapterResult with database list
        """
        result = AdapterResult()

        # Validate inputs
        try:
            url = InputValidator.validate_url(url)
        except SecurityError as e:
            result.error = str(e)
            return result

        args = [
            self.tool_name,
            "-u", url,
            "--batch",
            "--dbs",
        ]

        if data:
            args.extend(["--data", data])

        if cookie:
            args.extend(["--cookie", cookie])

        result = self._run_command(args, timeout=timeout)

        # Parse databases
        if result.success:
            databases = []
            in_db_list = False

            for line in result.output.split('\n'):
                if "available databases" in line.lower():
                    in_db_list = True
                    continue
                if in_db_list:
                    line = line.strip()
                    if line.startswith('[*]'):
                        db_name = line.replace('[*]', '').strip()
                        if db_name:
                            databases.append(db_name)
                    elif not line:
                        break

            result.data = {"databases": databases}

        return result

    def enumerate_tables(
        self,
        url: str,
        database: str,
        data: Optional[str] = None,
        cookie: Optional[str] = None,
        timeout: int = 300
    ) -> AdapterResult:
        """
        Enumerate tables in database.

        Args:
            url: Target URL
            database: Database name
            data: POST data
            cookie: Cookie string
            timeout: Operation timeout

        Returns:
            AdapterResult with table list
        """
        result = AdapterResult()

        # Validate inputs
        try:
            url = InputValidator.validate_url(url)
            database = InputValidator.validate_identifier(database)
        except SecurityError as e:
            result.error = str(e)
            return result

        args = [
            self.tool_name,
            "-u", url,
            "--batch",
            "-D", database,
            "--tables",
        ]

        if data:
            args.extend(["--data", data])

        if cookie:
            args.extend(["--cookie", cookie])

        result = self._run_command(args, timeout=timeout)

        # Parse tables
        if result.success:
            tables = []
            in_table_list = False

            for line in result.output.split('\n'):
                if "tables" in line.lower() and database in line:
                    in_table_list = True
                    continue
                if in_table_list:
                    line = line.strip()
                    if line.startswith('|'):
                        table_name = line.strip('| ').strip()
                        if table_name and table_name not in ['-' * len(table_name)]:
                            tables.append(table_name)
                    elif line.startswith('+'):
                        continue
                    elif not line:
                        break

            result.data = {"database": database, "tables": tables}

        return result

    def dump_table(
        self,
        url: str,
        database: str,
        table: str,
        data: Optional[str] = None,
        cookie: Optional[str] = None,
        timeout: int = 600
    ) -> AdapterResult:
        """
        Dump table contents.

        Args:
            url: Target URL
            database: Database name
            table: Table name
            data: POST data
            cookie: Cookie string
            timeout: Operation timeout

        Returns:
            AdapterResult with table data
        """
        result = AdapterResult()

        # Validate inputs
        try:
            url = InputValidator.validate_url(url)
            database = InputValidator.validate_identifier(database)
            table = InputValidator.validate_identifier(table)
        except SecurityError as e:
            result.error = str(e)
            return result

        args = [
            self.tool_name,
            "-u", url,
            "--batch",
            "-D", database,
            "-T", table,
            "--dump",
        ]

        if data:
            args.extend(["--data", data])

        if cookie:
            args.extend(["--cookie", cookie])

        result = self._run_command(args, timeout=timeout)

        if result.success:
            result.data = {
                "database": database,
                "table": table,
                "dumped": True,
            }

        return result

    def get_shell(
        self,
        url: str,
        shell_type: str = "sql",
        data: Optional[str] = None,
        cookie: Optional[str] = None
    ) -> AdapterResult:
        """
        Get interactive shell.

        Note: This returns shell command, actual interaction requires manual execution.

        Args:
            url: Target URL
            shell_type: Shell type (sql, os)
            data: POST data
            cookie: Cookie string

        Returns:
            AdapterResult with shell command
        """
        result = AdapterResult()

        # Validate inputs
        try:
            url = InputValidator.validate_url(url)
            if shell_type not in ("sql", "os"):
                raise SecurityError(f"Invalid shell type: {shell_type}")
        except SecurityError as e:
            result.error = str(e)
            return result

        args = [
            self.tool_name,
            "-u", url,
        ]

        if data:
            args.extend(["--data", data])

        if cookie:
            args.extend(["--cookie", cookie])

        if shell_type == "os":
            args.append("--os-shell")
        else:
            args.append("--sql-shell")

        result.success = True
        result.data = {
            "command": " ".join(args),
            "type": shell_type,
            "note": "Run this command manually for interactive shell",
        }
        result.output = f"Shell command: {' '.join(args)}"

        return result

    def test_waf(
        self,
        url: str,
        timeout: int = 60
    ) -> AdapterResult:
        """
        Test for WAF/IPS presence.

        Args:
            url: Target URL
            timeout: Test timeout

        Returns:
            AdapterResult with WAF detection info
        """
        result = AdapterResult()

        # Validate inputs
        try:
            url = InputValidator.validate_url(url)
        except SecurityError as e:
            result.error = str(e)
            return result

        args = [
            self.tool_name,
            "-u", url,
            "--batch",
            "--identify-waf",
        ]

        result = self._run_command(args, timeout=timeout)

        if result.success:
            waf_detected = None

            if "waf/ips" in result.output.lower():
                waf_match = re.search(r"identified as '([^']+)'", result.output)
                if waf_match:
                    waf_detected = waf_match.group(1)

            result.data = {
                "waf_detected": waf_detected is not None,
                "waf_name": waf_detected,
            }

        return result
