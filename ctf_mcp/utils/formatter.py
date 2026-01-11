"""
Result formatting utilities for CTF-MCP
Provides beautiful output formatting inspired by CTFCrackTools
"""

from typing import List, Dict, Any, Optional
from enum import Enum


class OutputFormat(Enum):
    """Output format types"""
    TEXT = "text"
    JSON = "json"
    MARKDOWN = "markdown"
    TABLE = "table"


class ResultFormatter:
    """
    Unified result formatter for all CTF-MCP tools

    Features inspired by:
    - CTFCrackTools: Beautiful visual output
    - hexstrike-ai: Structured result presentation
    """

    @staticmethod
    def format_success(message: str, details: Optional[str] = None) -> str:
        """Format success message"""
        lines = [
            "✅ SUCCESS",
            "=" * 60,
            message
        ]

        if details:
            lines.append("")
            lines.append(details)

        return '\n'.join(lines)

    @staticmethod
    def format_error(message: str, details: Optional[str] = None) -> str:
        """Format error message"""
        lines = [
            "❌ ERROR",
            "=" * 60,
            message
        ]

        if details:
            lines.append("")
            lines.append("Details:")
            lines.append(details)

        return '\n'.join(lines)

    @staticmethod
    def format_warning(message: str) -> str:
        """Format warning message"""
        return f"⚠️  WARNING: {message}"

    @staticmethod
    def format_info(message: str) -> str:
        """Format info message"""
        return f"ℹ️  INFO: {message}"

    @staticmethod
    def format_table(
        data: List[Dict[str, Any]],
        title: Optional[str] = None,
        headers: Optional[List[str]] = None
    ) -> str:
        """
        Format data as ASCII table

        Args:
            data: List of dictionaries
            title: Optional table title
            headers: Optional custom headers

        Returns:
            Formatted table string
        """
        if not data:
            return "No data to display"

        # Get headers
        if headers is None:
            headers = list(data[0].keys())

        # Calculate column widths
        col_widths = {}
        for header in headers:
            col_widths[header] = len(header)
            for row in data:
                value = str(row.get(header, ""))
                col_widths[header] = max(col_widths[header], len(value))

        # Build table
        lines = []

        # Title
        if title:
            total_width = sum(col_widths.values()) + len(headers) * 3 + 1
            lines.append("=" * total_width)
            lines.append(f" {title}")
            lines.append("=" * total_width)

        # Header row
        header_row = "| "
        for header in headers:
            header_row += f"{header:<{col_widths[header]}} | "
        lines.append(header_row)

        # Separator
        separator = "|-"
        for header in headers:
            separator += "-" * col_widths[header] + "-|-"
        lines.append(separator)

        # Data rows
        for row in data:
            data_row = "| "
            for header in headers:
                value = str(row.get(header, ""))
                data_row += f"{value:<{col_widths[header]}} | "
            lines.append(data_row)

        return '\n'.join(lines)

    @staticmethod
    def format_list(
        items: List[str],
        title: Optional[str] = None,
        numbered: bool = True
    ) -> str:
        """Format list of items"""
        lines = []

        if title:
            lines.append(title)
            lines.append("-" * len(title))

        for i, item in enumerate(items, 1):
            if numbered:
                lines.append(f"{i}. {item}")
            else:
                lines.append(f"• {item}")

        return '\n'.join(lines)

    @staticmethod
    def format_key_value(
        data: Dict[str, Any],
        title: Optional[str] = None
    ) -> str:
        """Format key-value pairs"""
        lines = []

        if title:
            lines.append(title)
            lines.append("=" * len(title))

        max_key_len = max(len(str(k)) for k in data.keys()) if data else 0

        for key, value in data.items():
            lines.append(f"{str(key):<{max_key_len}} : {value}")

        return '\n'.join(lines)

    @staticmethod
    def format_section(title: str, content: str) -> str:
        """Format a section with title"""
        lines = [
            "",
            f"{'=' * 60}",
            f" {title}",
            f"{'=' * 60}",
            content,
            ""
        ]
        return '\n'.join(lines)

    @staticmethod
    def format_code_block(code: str, language: str = "") -> str:
        """Format code block"""
        return f"```{language}\n{code}\n```"

    @staticmethod
    def format_progress(current: int, total: int, message: str = "") -> str:
        """Format progress indicator"""
        percentage = (current / total * 100) if total > 0 else 0
        bar_length = 40
        filled = int(bar_length * current / total) if total > 0 else 0
        bar = "█" * filled + "░" * (bar_length - filled)

        return f"[{bar}] {percentage:.1f}% ({current}/{total}) {message}"

    @staticmethod
    def format_banner(text: str, char: str = "=") -> str:
        """Format banner text"""
        width = max(60, len(text) + 4)
        lines = [
            char * width,
            f"{text:^{width}}",
            char * width
        ]
        return '\n'.join(lines)

    @staticmethod
    def format_box(text: str, padding: int = 2) -> str:
        """Format text in a box"""
        lines = text.split('\n')
        max_len = max(len(line) for line in lines)
        width = max_len + padding * 2

        result = []
        result.append("┌" + "─" * width + "┐")

        for line in lines:
            padded = line.ljust(max_len)
            result.append("│" + " " * padding + padded + " " * padding + "│")

        result.append("└" + "─" * width + "┘")

        return '\n'.join(result)

    @staticmethod
    def format_tree(data: Dict[str, Any], indent: int = 0) -> str:
        """Format hierarchical data as tree"""
        lines = []
        prefix = "  " * indent

        for key, value in data.items():
            if isinstance(value, dict):
                lines.append(f"{prefix}├─ {key}")
                lines.append(ResultFormatter.format_tree(value, indent + 1))
            elif isinstance(value, list):
                lines.append(f"{prefix}├─ {key} ({len(value)} items)")
                for item in value:
                    if isinstance(item, dict):
                        lines.append(ResultFormatter.format_tree(item, indent + 1))
                    else:
                        lines.append(f"{prefix}  └─ {item}")
            else:
                lines.append(f"{prefix}├─ {key}: {value}")

        return '\n'.join(lines)

    @staticmethod
    def format_diff(old: str, new: str, context_lines: int = 3) -> str:
        """Format diff between two strings"""
        import difflib

        old_lines = old.splitlines()
        new_lines = new.splitlines()

        diff = difflib.unified_diff(
            old_lines,
            new_lines,
            lineterm='',
            n=context_lines
        )

        return '\n'.join(diff)

    @staticmethod
    def truncate(text: str, max_length: int = 100, suffix: str = "...") -> str:
        """Truncate text to maximum length"""
        if len(text) <= max_length:
            return text
        return text[:max_length - len(suffix)] + suffix

    @staticmethod
    def highlight(text: str, keyword: str, color: str = "yellow") -> str:
        """Highlight keyword in text (for terminal output)"""
        # Simple highlighting without ANSI codes for now
        # Can be enhanced with colorama or rich library
        return text.replace(keyword, f"**{keyword}**")
