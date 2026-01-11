"""
Tests for web security tools module
"""

import pytest


class TestSQLInjection:
    """Test SQL injection payload generation"""

    def test_sql_payloads_mysql_union(self, web_tools):
        """Test MySQL UNION-based SQL injection payloads"""
        result = web_tools.sql_payloads(dbms="mysql", technique="union")
        assert "UNION SELECT" in result
        assert "mysql" in result.lower()

    def test_sql_payloads_error_based(self, web_tools):
        """Test error-based SQL injection payloads"""
        result = web_tools.sql_payloads(dbms="mysql", technique="error")
        assert "EXTRACTVALUE" in result or "UPDATEXML" in result

    def test_sql_payloads_time_based(self, web_tools):
        """Test time-based blind SQL injection"""
        result = web_tools.sql_payloads(dbms="mysql", technique="time")
        assert "SLEEP" in result


class TestXSS:
    """Test XSS payload generation"""

    def test_xss_html_context(self, web_tools):
        """Test XSS payloads for HTML context"""
        result = web_tools.xss_payloads(context="html", bypass=False)
        assert "<script>" in result.lower()
        assert "alert" in result.lower()

    def test_xss_attribute_context(self, web_tools):
        """Test XSS payloads for attribute context"""
        result = web_tools.xss_payloads(context="attribute")
        assert "onmouseover" in result.lower() or "onclick" in result.lower()

    def test_xss_bypass_techniques(self, web_tools):
        """Test XSS WAF bypass techniques"""
        result = web_tools.xss_payloads(context="html", bypass=True)
        assert "bypass" in result.lower() or len(result) > 500


class TestLFI:
    """Test Local File Inclusion payloads"""

    def test_lfi_linux(self, web_tools):
        """Test LFI payloads for Linux"""
        result = web_tools.lfi_payloads(os="linux", wrapper=True)
        assert "/etc/passwd" in result
        assert "php://" in result.lower()

    def test_lfi_windows(self, web_tools):
        """Test LFI payloads for Windows"""
        result = web_tools.lfi_payloads(os="windows", wrapper=False)
        assert "win.ini" in result.lower() or "Windows" in result


class TestSSTI:
    """Test Server-Side Template Injection"""

    def test_ssti_detection(self, web_tools):
        """Test SSTI detection payloads"""
        result = web_tools.ssti_payloads(engine="auto")
        assert "{{7*7}}" in result or "${7*7}" in result

    def test_ssti_jinja2(self, web_tools):
        """Test Jinja2 SSTI payloads"""
        result = web_tools.ssti_payloads(engine="jinja2")
        assert "{{" in result
        assert "config" in result.lower() or "__" in result


class TestJWT:
    """Test JWT token operations"""

    def test_jwt_decode(self, web_tools):
        """Test JWT token decoding"""
        # Standard JWT token (header.payload.signature)
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = web_tools.jwt_decode(token)
        assert "Header" in result or "Payload" in result
        assert "alg" in result.lower()

    def test_jwt_forge_none(self, web_tools):
        """Test JWT none algorithm attack"""
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result = web_tools.jwt_forge(token, attack="none")
        assert "none" in result.lower()


class TestDeserialization:
    """Test deserialization payloads"""

    def test_php_serialize(self, web_tools):
        """Test PHP serialization"""
        result = web_tools.php_serialize({"test": "value"})
        assert "PHP" in result
        assert "serialize" in result.lower()

    def test_pickle_payload(self, web_tools):
        """Test Python pickle RCE payload"""
        result = web_tools.pickle_payload()
        assert "pickle" in result.lower()
        assert "import" in result


class TestCommandInjection:
    """Test command injection payloads"""

    def test_cmd_injection_linux(self, web_tools):
        """Test Linux command injection"""
        result = web_tools.cmd_injection(os_type="linux", context="basic")
        assert "; id" in result or "| id" in result

    def test_cmd_injection_bypass(self, web_tools):
        """Test command injection bypass techniques"""
        result = web_tools.cmd_injection(os_type="linux", context="bypass")
        assert "$IFS" in result or "{" in result


class TestSSRF:
    """Test SSRF payloads"""

    def test_ssrf_basic(self, web_tools):
        """Test basic SSRF payloads"""
        result = web_tools.ssrf_payloads(bypass=False)
        assert "127.0.0.1" in result or "localhost" in result

    def test_ssrf_bypass(self, web_tools):
        """Test SSRF bypass techniques"""
        result = web_tools.ssrf_payloads(bypass=True)
        assert "bypass" in result.lower() or "0x" in result


class TestXXE:
    """Test XXE injection payloads"""

    def test_xxe_file_read(self, web_tools):
        """Test XXE file read payloads"""
        result = web_tools.xxe_payloads(target="file")
        assert "<!ENTITY" in result
        assert "/etc/passwd" in result or "file://" in result
