"""
Knowledge Retriever

RAG retriever that connects to the CTF-MCP KnowledgeBase for relevant solving patterns.
"""

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("ctf-mcp.llm.rag.retriever")


@dataclass
class RetrievedPattern:
    """A pattern retrieved from the knowledge base"""
    name: str
    category: str
    description: str
    techniques: list[str]
    tools: list[str]
    score: float = 1.0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "techniques": self.techniques,
            "tools": self.tools,
            "relevance_score": self.score,
        }


class KnowledgeRetriever:
    """
    RAG retriever connecting to CTF-MCP KnowledgeBase.

    Features:
    - Keyword-based pattern matching
    - Category filtering
    - Relevance scoring
    - Integration with solving patterns
    """

    def __init__(self, knowledge_base: Optional["KnowledgeBase"] = None):
        """
        Initialize the retriever.

        Args:
            knowledge_base: KnowledgeBase instance (creates new if not provided)
        """
        self._kb = knowledge_base

    def _get_kb(self):
        """Get or create KnowledgeBase (lazy initialization)"""
        if self._kb is None:
            try:
                from ctf_mcp.core.knowledge import KnowledgeBase
                self._kb = KnowledgeBase()
                self._kb.load_builtin_patterns()
            except ImportError:
                logger.warning("KnowledgeBase not available")
                self._kb = None
        return self._kb

    def retrieve(
        self,
        query: str,
        category: Optional[str] = None,
        top_k: int = 5,
    ) -> list[RetrievedPattern]:
        """
        Retrieve relevant patterns for a query.

        Args:
            query: Search query (challenge description, keywords)
            category: Optional category filter (crypto, web, pwn, etc.)
            top_k: Maximum number of patterns to return

        Returns:
            List of RetrievedPattern sorted by relevance
        """
        kb = self._get_kb()
        if kb is None:
            return []

        # Get patterns from knowledge base
        if hasattr(kb, "search_patterns"):
            results = kb.search_patterns(query, category=category, limit=top_k)
        elif hasattr(kb, "get_patterns"):
            # Fallback to simple pattern retrieval
            all_patterns = kb.get_patterns(category=category)
            results = self._score_patterns(query, all_patterns, top_k)
        else:
            return []

        # Convert to RetrievedPattern objects
        patterns = []
        for result in results:
            if isinstance(result, dict):
                patterns.append(RetrievedPattern(
                    name=result.get("name", "Unknown"),
                    category=result.get("category", "misc"),
                    description=result.get("description", ""),
                    techniques=result.get("techniques", []),
                    tools=result.get("tools", []),
                    score=result.get("score", 1.0),
                ))
            elif hasattr(result, "to_dict"):
                d = result.to_dict()
                patterns.append(RetrievedPattern(
                    name=d.get("name", "Unknown"),
                    category=d.get("category", "misc"),
                    description=d.get("description", ""),
                    techniques=d.get("techniques", []),
                    tools=d.get("tools", []),
                    score=d.get("score", 1.0),
                ))

        return patterns[:top_k]

    def _score_patterns(
        self,
        query: str,
        patterns: list,
        top_k: int,
    ) -> list[dict]:
        """
        Score patterns by relevance to query.

        Simple keyword-based scoring.
        """
        query_lower = query.lower()
        query_words = set(query_lower.split())

        scored = []
        for pattern in patterns:
            if isinstance(pattern, dict):
                text = f"{pattern.get('name', '')} {pattern.get('description', '')}".lower()
            else:
                text = str(pattern).lower()

            # Count matching words
            pattern_words = set(text.split())
            matches = len(query_words & pattern_words)

            if matches > 0:
                score = matches / len(query_words)
                if isinstance(pattern, dict):
                    pattern["score"] = score
                    scored.append(pattern)
                else:
                    scored.append({"pattern": pattern, "score": score})

        # Sort by score
        scored.sort(key=lambda x: x.get("score", 0), reverse=True)
        return scored[:top_k]

    def get_category_patterns(self, category: str) -> list[RetrievedPattern]:
        """Get all patterns for a specific category"""
        return self.retrieve("", category=category, top_k=100)

    def get_technique_tools(self, technique: str) -> list[str]:
        """Get recommended tools for a technique"""
        patterns = self.retrieve(technique, top_k=3)
        tools = []
        for p in patterns:
            tools.extend(p.tools)
        return list(set(tools))

    def format_for_agent(self, patterns: list[RetrievedPattern]) -> str:
        """Format patterns for agent prompt"""
        if not patterns:
            return "No relevant patterns found."

        lines = ["Relevant solving patterns:"]
        for p in patterns:
            lines.append(f"\n## {p.name} ({p.category})")
            lines.append(f"Description: {p.description}")
            if p.techniques:
                lines.append(f"Techniques: {', '.join(p.techniques[:5])}")
            if p.tools:
                lines.append(f"Tools: {', '.join(p.tools[:5])}")

        return "\n".join(lines)
