"""
Web Solving Engine
Specialized engine for web security challenges
"""

import re
import time
import urllib.parse
from typing import Any, Optional, TYPE_CHECKING

from .base import SolvingEngine, EngineResult, EngineCapability

if TYPE_CHECKING:
    from ..core.orchestrator import Challenge

# Optional HTTP client
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


class WebEngine(SolvingEngine):
    """
    Web security challenge solving engine.

    Handles:
    - SQL Injection
    - XSS (Cross-Site Scripting)
    - SSTI (Server-Side Template Injection)
    - LFI/RFI (Local/Remote File Inclusion)
    - JWT attacks
    - Command Injection
    - SSRF
    - Authentication bypass
    """

    # Vulnerability indicators
    SQLI_INDICATORS = [
        'sql', 'query', 'select', 'insert', 'update', 'delete',
        'database', 'mysql', 'postgres', 'sqlite', 'login', 'auth',
    ]

    XSS_INDICATORS = [
        'xss', 'script', 'alert', 'reflect', 'input', 'search',
        'comment', 'message', 'post',
    ]

    SSTI_INDICATORS = [
        'template', 'jinja', 'twig', 'render', 'flask', 'django',
        '{{', '{%', '${',
    ]

    LFI_INDICATORS = [
        'file', 'include', 'path', 'page', 'load', 'read',
        'download', 'view', 'open',
    ]

    JWT_INDICATORS = [
        'jwt', 'token', 'bearer', 'authorization', 'auth',
    ]

    @property
    def name(self) -> str:
        return "web"

    @property
    def capabilities(self) -> list[EngineCapability]:
        caps = [
            EngineCapability.ANALYZE,
            EngineCapability.EXPLOIT,
        ]
        if HTTPX_AVAILABLE or REQUESTS_AVAILABLE:
            caps.append(EngineCapability.REMOTE)
        return caps

    def analyze(self, challenge: "Challenge") -> dict[str, Any]:
        """Analyze a web challenge"""
        analysis = {
            "vuln_types": [],
            "detected_tech": [],
            "endpoints": [],
            "recommendations": [],
        }

        content = challenge.description.lower()

        # Check for SQL injection indicators
        if any(ind in content for ind in self.SQLI_INDICATORS):
            analysis["vuln_types"].append("SQL Injection")
            analysis["recommendations"].append("Try UNION-based or blind SQLi")

        # Check for XSS indicators
        if any(ind in content for ind in self.XSS_INDICATORS):
            analysis["vuln_types"].append("XSS")
            analysis["recommendations"].append("Try reflected/stored XSS payloads")

        # Check for SSTI indicators
        if any(ind in content for ind in self.SSTI_INDICATORS):
            analysis["vuln_types"].append("SSTI")
            analysis["recommendations"].append("Identify template engine and try RCE")

        # Check for LFI indicators
        if any(ind in content for ind in self.LFI_INDICATORS):
            analysis["vuln_types"].append("LFI/Path Traversal")
            analysis["recommendations"].append("Try path traversal to read /etc/passwd or flag")

        # Check for JWT
        if any(ind in content for ind in self.JWT_INDICATORS):
            analysis["vuln_types"].append("JWT Attack")
            analysis["recommendations"].append("Try none algorithm or weak secret attacks")

        # Extract URLs
        urls = re.findall(r'https?://[^\s<>"]+', challenge.description)
        analysis["endpoints"] = urls

        # Check remote endpoint
        if challenge.remote:
            analysis["endpoints"].append(challenge.remote)
            if 'http' in challenge.remote.lower():
                analysis["detected_tech"].append("HTTP Service")

        return analysis

    def solve(self, challenge: "Challenge", **kwargs) -> EngineResult:
        """Attempt to solve a web challenge"""
        start_time = time.time()
        result = EngineResult()

        try:
            tools = self._get_tools()["web"]
            content = challenge.description

            result.add_step("Analyzing web challenge")

            # Analyze vulnerability type
            analysis = self.analyze(challenge)
            result.analysis = analysis

            # Extract any JWT tokens from description
            jwt_token = self._extract_jwt(content)
            if jwt_token:
                jwt_result = self._try_jwt_attack(jwt_token, tools, result)
                if jwt_result:
                    flags = self.find_flags(jwt_result, challenge.flag_format)
                    if flags:
                        result.success = True
                        result.flag = flags[0]
                        result.confidence = 0.9
                        result.duration = time.time() - start_time
                        return result

            # Generate payloads based on detected vuln type
            if "SQL Injection" in analysis["vuln_types"]:
                payloads = self._get_sqli_payloads(tools, result)
                result.data = {"sqli_payloads": payloads[:10]}

            if "SSTI" in analysis["vuln_types"]:
                payloads = self._get_ssti_payloads(tools, result)
                result.data = result.data or {}
                result.data["ssti_payloads"] = payloads[:10]

            if "LFI/Path Traversal" in analysis["vuln_types"]:
                payloads = self._get_lfi_payloads(tools, result)
                result.data = result.data or {}
                result.data["lfi_payloads"] = payloads[:10]

            # If we have a remote endpoint, try to interact
            if challenge.remote and (HTTPX_AVAILABLE or REQUESTS_AVAILABLE):
                remote_result = self._try_remote_exploit(
                    challenge.remote, analysis, tools, result
                )
                if remote_result:
                    flags = self.find_flags(remote_result, challenge.flag_format)
                    if flags:
                        result.success = True
                        result.flag = flags[0]
                        result.confidence = 0.85
                        result.duration = time.time() - start_time
                        return result

            # Check if payloads were generated (partial success)
            if result.data:
                result.success = True
                result.confidence = 0.5
                result.add_step("Generated exploit payloads - manual testing required")
            else:
                result.success = False
                result.error = "Could not generate exploits"

        except Exception as e:
            result.success = False
            result.error = str(e)

        result.duration = time.time() - start_time
        return result

    def can_handle(self, challenge: "Challenge") -> float:
        """Check if this looks like a web challenge"""
        score = 0.0
        content = challenge.description.lower()

        # Keyword matching
        web_keywords = [
            'web', 'http', 'url', 'sql', 'xss', 'csrf', 'cookie',
            'session', 'login', 'admin', 'api', 'rest', 'graphql',
            'php', 'javascript', 'html', 'form', 'input',
        ]

        for keyword in web_keywords:
            if keyword in content:
                score += 0.08

        # Check for HTTP URLs
        if re.search(r'https?://', content):
            score += 0.2

        # Check remote endpoint
        if challenge.remote:
            if 'http' in challenge.remote.lower():
                score += 0.3
            elif ':' in challenge.remote:
                score += 0.1

        return min(score, 1.0)

    def _extract_jwt(self, content: str) -> Optional[str]:
        """Extract JWT token from content"""
        # JWT format: xxxxx.yyyyy.zzzzz
        jwt_pattern = r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
        match = re.search(jwt_pattern, content)
        return match.group(0) if match else None

    def _try_jwt_attack(self, token: str, tools, result: EngineResult) -> Optional[str]:
        """Try JWT attacks"""
        result.add_step(f"Found JWT token: {token[:50]}...")

        try:
            # Decode JWT
            decode_result = tools.jwt_decode(token)
            result.add_step(f"JWT decoded: {decode_result[:100]}...")

            # Try none algorithm attack
            forge_result = tools.jwt_forge(token, attack="none")
            result.add_step(f"JWT forged (none alg): {forge_result[:100]}...")

            return forge_result

        except Exception as ex:
            result.add_step(f"JWT attack failed: {ex}")
            return None

    def _get_sqli_payloads(self, tools, result: EngineResult) -> list[str]:
        """Get SQL injection payloads"""
        result.add_step("Generating SQLi payloads")

        payloads = []
        try:
            for technique in ['union', 'error', 'blind', 'time']:
                payload_result = tools.sql_payloads(dbms="mysql", technique=technique)
                # Extract payloads from result
                lines = payload_result.split('\n')
                for line in lines:
                    if "'" in line or '"' in line or '--' in line:
                        payloads.append(line.strip())
        except Exception as ex:
            result.add_step(f"SQLi payload generation failed: {ex}")

        return payloads[:20]

    def _get_ssti_payloads(self, tools, result: EngineResult) -> list[str]:
        """Get SSTI payloads"""
        result.add_step("Generating SSTI payloads")

        payloads = []
        try:
            for engine in ['jinja2', 'twig', 'freemarker']:
                payload_result = tools.ssti_payloads(engine=engine)
                lines = payload_result.split('\n')
                for line in lines:
                    if '{{' in line or '{%' in line or '${' in line:
                        payloads.append(line.strip())
        except Exception as ex:
            result.add_step(f"SSTI payload generation failed: {ex}")

        return payloads[:20]

    def _get_lfi_payloads(self, tools, result: EngineResult) -> list[str]:
        """Get LFI payloads"""
        result.add_step("Generating LFI payloads")

        payloads = []
        try:
            payload_result = tools.lfi_payloads(os="linux", wrapper=True)
            lines = payload_result.split('\n')
            for line in lines:
                if '../' in line or 'php://' in line or 'file://' in line:
                    payloads.append(line.strip())
        except Exception as ex:
            result.add_step(f"LFI payload generation failed: {ex}")

        return payloads[:20]

    def _try_remote_exploit(
        self,
        remote: str,
        analysis: dict,
        tools,
        result: EngineResult
    ) -> Optional[str]:
        """Try to exploit remote endpoint"""
        result.add_step(f"Attempting remote exploitation: {remote}")

        # Ensure URL format
        if not remote.startswith('http'):
            remote = f"http://{remote}"

        try:
            # Simple GET request first
            response_text = self._http_get(remote)
            if response_text:
                # Check for flags in response
                flags = self.find_flags(response_text)
                if flags:
                    result.add_step(f"Found flag in initial response!")
                    return response_text

                result.add_step(f"Got response ({len(response_text)} bytes)")

            # Try common endpoints
            common_paths = [
                '/flag', '/flag.txt', '/admin', '/robots.txt',
                '/.git/config', '/.env', '/api/flag',
            ]

            for path in common_paths:
                try:
                    url = urllib.parse.urljoin(remote, path)
                    resp = self._http_get(url)
                    if resp:
                        flags = self.find_flags(resp)
                        if flags:
                            result.add_step(f"Found flag at {path}")
                            return resp
                except Exception:
                    pass

        except Exception as ex:
            result.add_step(f"Remote exploitation failed: {ex}")

        return None

    def _http_get(self, url: str, timeout: float = 10.0) -> Optional[str]:
        """Make HTTP GET request"""
        try:
            if HTTPX_AVAILABLE:
                with httpx.Client(timeout=timeout, verify=False) as client:
                    response = client.get(url, follow_redirects=True)
                    return response.text
            elif REQUESTS_AVAILABLE:
                response = requests.get(url, timeout=timeout, verify=False)
                return response.text
        except Exception:
            pass
        return None

    def _http_post(
        self,
        url: str,
        data: dict = None,
        json: dict = None,
        timeout: float = 10.0
    ) -> Optional[str]:
        """Make HTTP POST request"""
        try:
            if HTTPX_AVAILABLE:
                with httpx.Client(timeout=timeout, verify=False) as client:
                    response = client.post(
                        url, data=data, json=json, follow_redirects=True
                    )
                    return response.text
            elif REQUESTS_AVAILABLE:
                response = requests.post(
                    url, data=data, json=json, timeout=timeout, verify=False
                )
                return response.text
        except Exception:
            pass
        return None
