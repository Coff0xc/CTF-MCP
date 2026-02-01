"""
Nmap Adapter
Interface for nmap network scanning tool
"""

import re
import tempfile
from typing import Any, Optional

from .base import ToolAdapter, AdapterResult
from ..utils.security import InputValidator, SecurityError, safe_xml_parse


class NmapAdapter(ToolAdapter):
    """
    Adapter for nmap network scanner.

    Provides:
    - Port scanning
    - Service detection
    - OS fingerprinting
    - Vulnerability scanning (NSE scripts)
    """

    @property
    def name(self) -> str:
        return "nmap"

    @property
    def tool_name(self) -> str:
        return "nmap"

    @property
    def description(self) -> str:
        return "Network exploration and security auditing tool"

    @property
    def min_version(self) -> Optional[str]:
        return "7.0"

    def _get_version(self) -> Optional[str]:
        result = self._run_command([self.tool_name, "--version"], timeout=10)
        if result.success:
            match = re.search(r'Nmap version (\d+\.\d+)', result.output)
            if match:
                return match.group(1)
        return None

    def scan_ports(
        self,
        target: str,
        ports: str = "1-1000",
        scan_type: str = "syn",
        timeout: int = 300
    ) -> AdapterResult:
        """
        Scan ports on target.

        Args:
            target: Target IP or hostname
            ports: Port specification (e.g., "1-1000", "80,443,8080")
            scan_type: Scan type (syn, connect, udp, ack)
            timeout: Scan timeout

        Returns:
            AdapterResult with open ports
        """
        result = AdapterResult()

        # Validate inputs
        try:
            target = InputValidator.validate_hostname(target)
            ports = InputValidator.validate_port_spec(ports)
        except SecurityError as e:
            result.error = str(e)
            return result

        scan_flags = {
            "syn": "-sS",
            "connect": "-sT",
            "udp": "-sU",
            "ack": "-sA",
            "fin": "-sF",
        }

        flag = scan_flags.get(scan_type, "-sT")

        args = [
            self.tool_name,
            flag,
            "-p", ports,
            "-T4",  # Aggressive timing
            "--open",  # Only show open ports
            target,
        ]

        result = self._run_command(args, timeout=timeout)

        if result.success:
            # Parse open ports
            open_ports = []

            for line in result.output.split('\n'):
                match = re.match(r'(\d+)/(\w+)\s+open\s+(\S+)', line)
                if match:
                    open_ports.append({
                        "port": int(match.group(1)),
                        "protocol": match.group(2),
                        "service": match.group(3),
                    })

            result.data = {
                "target": target,
                "scan_type": scan_type,
                "open_ports": open_ports,
                "count": len(open_ports),
            }

        return result

    def service_scan(
        self,
        target: str,
        ports: Optional[str] = None,
        timeout: int = 300
    ) -> AdapterResult:
        """
        Detect services and versions on target.

        Args:
            target: Target IP or hostname
            ports: Port specification (None for common ports)
            timeout: Scan timeout

        Returns:
            AdapterResult with service info
        """
        result = AdapterResult()

        # Validate inputs
        try:
            target = InputValidator.validate_hostname(target)
            if ports:
                ports = InputValidator.validate_port_spec(ports)
        except SecurityError as e:
            result.error = str(e)
            return result

        args = [
            self.tool_name,
            "-sV",  # Version detection
            "-sC",  # Default scripts
            "-T4",
            target,
        ]

        if ports:
            args.extend(["-p", ports])

        result = self._run_command(args, timeout=timeout)

        if result.success:
            services = []

            for line in result.output.split('\n'):
                match = re.match(r'(\d+)/(\w+)\s+open\s+(\S+)\s*(.*)', line)
                if match:
                    services.append({
                        "port": int(match.group(1)),
                        "protocol": match.group(2),
                        "service": match.group(3),
                        "version": match.group(4).strip() if match.group(4) else None,
                    })

            result.data = {
                "target": target,
                "services": services,
            }

        return result

    def os_detect(self, target: str, timeout: int = 300) -> AdapterResult:
        """
        Detect operating system.

        Args:
            target: Target IP or hostname
            timeout: Scan timeout

        Returns:
            AdapterResult with OS info
        """
        result = AdapterResult()

        # Validate inputs
        try:
            target = InputValidator.validate_hostname(target)
        except SecurityError as e:
            result.error = str(e)
            return result

        args = [
            self.tool_name,
            "-O",  # OS detection
            "-T4",
            target,
        ]

        result = self._run_command(args, timeout=timeout)

        if result.success:
            os_matches = []

            for line in result.output.split('\n'):
                if "OS:" in line or "Running:" in line:
                    os_matches.append(line.strip())

            result.data = {
                "target": target,
                "os_matches": os_matches,
            }

        return result

    def vuln_scan(
        self,
        target: str,
        ports: Optional[str] = None,
        timeout: int = 600
    ) -> AdapterResult:
        """
        Scan for vulnerabilities using NSE scripts.

        Args:
            target: Target IP or hostname
            ports: Port specification
            timeout: Scan timeout

        Returns:
            AdapterResult with vulnerabilities
        """
        result = AdapterResult()

        # Validate inputs
        try:
            target = InputValidator.validate_hostname(target)
            if ports:
                ports = InputValidator.validate_port_spec(ports)
        except SecurityError as e:
            result.error = str(e)
            return result

        args = [
            self.tool_name,
            "--script", "vuln",
            "-T4",
            target,
        ]

        if ports:
            args.extend(["-p", ports])

        result = self._run_command(args, timeout=timeout)

        if result.success:
            vulnerabilities = []

            # Parse NSE output for vulnerabilities
            current_vuln = None
            for line in result.output.split('\n'):
                if "VULNERABLE" in line:
                    if current_vuln:
                        vulnerabilities.append(current_vuln)
                    current_vuln = {"title": line.strip()}
                elif current_vuln and line.strip().startswith("|"):
                    info = line.strip().lstrip("|").strip()
                    if info:
                        current_vuln.setdefault("details", []).append(info)

            if current_vuln:
                vulnerabilities.append(current_vuln)

            result.data = {
                "target": target,
                "vulnerabilities": vulnerabilities,
                "count": len(vulnerabilities),
            }

        return result

    def quick_scan(self, target: str, timeout: int = 120) -> AdapterResult:
        """
        Quick scan of most common ports.

        Args:
            target: Target IP or hostname
            timeout: Scan timeout

        Returns:
            AdapterResult with scan results
        """
        result = AdapterResult()

        # Validate inputs
        try:
            target = InputValidator.validate_hostname(target)
        except SecurityError as e:
            result.error = str(e)
            return result

        args = [
            self.tool_name,
            "-F",  # Fast scan (top 100 ports)
            "-T4",
            target,
        ]

        result = self._run_command(args, timeout=timeout)

        if result.success:
            open_ports = []

            for line in result.output.split('\n'):
                match = re.match(r'(\d+)/(\w+)\s+open\s+(\S+)', line)
                if match:
                    open_ports.append({
                        "port": int(match.group(1)),
                        "protocol": match.group(2),
                        "service": match.group(3),
                    })

            result.data = {
                "target": target,
                "open_ports": open_ports,
                "count": len(open_ports),
            }

        return result

    def script_scan(
        self,
        target: str,
        scripts: str,
        ports: Optional[str] = None,
        script_args: Optional[str] = None,
        timeout: int = 300
    ) -> AdapterResult:
        """
        Run specific NSE scripts.

        Args:
            target: Target IP or hostname
            scripts: Script names (comma-separated or category)
            ports: Port specification
            script_args: Script arguments
            timeout: Scan timeout

        Returns:
            AdapterResult with script output
        """
        result = AdapterResult()

        # Validate inputs
        try:
            target = InputValidator.validate_hostname(target)
            scripts = InputValidator.validate_nse_script(scripts)
            if ports:
                ports = InputValidator.validate_port_spec(ports)
            # script_args validation - only allow safe characters
            if script_args:
                if not re.match(r'^[\w\-.,=:/@]+$', script_args):
                    raise SecurityError(f"Invalid script arguments: {script_args}")
        except SecurityError as e:
            result.error = str(e)
            return result

        args = [
            self.tool_name,
            "--script", scripts,
            "-T4",
            target,
        ]

        if ports:
            args.extend(["-p", ports])

        if script_args:
            args.extend(["--script-args", script_args])

        result = self._run_command(args, timeout=timeout)

        if result.success:
            result.data = {
                "target": target,
                "scripts": scripts,
            }

        return result

    def scan_to_xml(
        self,
        target: str,
        ports: Optional[str] = None,
        timeout: int = 300
    ) -> AdapterResult:
        """
        Scan and return XML output for parsing.

        Args:
            target: Target IP or hostname
            ports: Port specification
            timeout: Scan timeout

        Returns:
            AdapterResult with parsed XML data
        """
        result = AdapterResult()

        # Validate inputs
        try:
            target = InputValidator.validate_hostname(target)
            if ports:
                ports = InputValidator.validate_port_spec(ports)
        except SecurityError as e:
            result.error = str(e)
            return result

        output_file = tempfile.NamedTemporaryFile(suffix='.xml', delete=False)
        output_file.close()

        args = [
            self.tool_name,
            "-sV",
            "-T4",
            "-oX", output_file.name,
            target,
        ]

        if ports:
            args.extend(["-p", ports])

        result = self._run_command(args, timeout=timeout)

        if result.success:
            try:
                # Use safe_xml_parse to prevent XXE attacks
                tree = safe_xml_parse(output_file.name)
                root = tree.getroot()

                # Parse XML
                hosts = []
                for host in root.findall('host'):
                    host_data = {
                        "addresses": [],
                        "ports": [],
                        "os": None,
                    }

                    for addr in host.findall('address'):
                        host_data["addresses"].append({
                            "addr": addr.get('addr'),
                            "type": addr.get('addrtype'),
                        })

                    for port in host.findall('.//port'):
                        port_data = {
                            "port": int(port.get('portid')),
                            "protocol": port.get('protocol'),
                        }
                        state = port.find('state')
                        if state is not None:
                            port_data["state"] = state.get('state')

                        service = port.find('service')
                        if service is not None:
                            port_data["service"] = service.get('name')
                            port_data["product"] = service.get('product')
                            port_data["version"] = service.get('version')

                        host_data["ports"].append(port_data)

                    hosts.append(host_data)

                result.data = {
                    "hosts": hosts,
                    "xml_file": output_file.name,
                }

            except Exception as e:
                result.error = f"XML parse error: {e}"

        return result
