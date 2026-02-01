"""
Enhanced Orchestrator

LLM-augmented CTF challenge orchestrator.
Combines traditional solving engines with ReAct agent for improved success rate.
"""

import logging
from dataclasses import dataclass
from typing import Any, Optional

from ..config import LLMConfig, get_llm_config
from ..agent.react import ReActAgent, AgentResult
from ..agent.tools import create_ctf_agent_tools
from ..rag.retriever import KnowledgeRetriever

logger = logging.getLogger("ctf-mcp.llm.integration.orchestrator")


@dataclass
class EnhancedSolveResult:
    """Result from enhanced orchestrator"""
    success: bool
    flag: Optional[str] = None
    method: str = "unknown"  # "traditional", "llm_agent", "hybrid"
    confidence: float = 0.0
    traditional_result: Optional[Any] = None
    agent_result: Optional[AgentResult] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "flag": self.flag,
            "method": self.method,
            "confidence": self.confidence,
            "error": self.error,
            "traditional_result": str(self.traditional_result) if self.traditional_result else None,
            "agent_result": self.agent_result.to_dict() if self.agent_result else None,
        }


class EnhancedOrchestrator:
    """
    LLM-enhanced CTF Challenge Orchestrator.

    Strategy:
    1. First attempt traditional solving (faster, deterministic)
    2. If traditional fails, use ReAct agent with RAG
    3. Combine insights from both approaches

    Features:
    - Automatic fallback from traditional to LLM
    - RAG-based pattern retrieval
    - Tool binding for agent
    - Configurable LLM provider
    """

    def __init__(
        self,
        llm_config: Optional[LLMConfig] = None,
        traditional_orchestrator: Optional["CTFOrchestrator"] = None,
        use_traditional: bool = True,
        use_agent: bool = True,
    ):
        """
        Initialize the enhanced orchestrator.

        Args:
            llm_config: LLM configuration (uses global if not provided)
            traditional_orchestrator: CTFOrchestrator instance (creates new if not provided)
            use_traditional: Try traditional solving first
            use_agent: Fall back to LLM agent if traditional fails
        """
        self.llm_config = llm_config or get_llm_config()
        self.use_traditional = use_traditional
        self.use_agent = use_agent

        self._traditional = traditional_orchestrator
        self._agent: Optional[ReActAgent] = None
        self._retriever: Optional[KnowledgeRetriever] = None
        self._tools = None

    def _get_traditional(self):
        """Get or create traditional orchestrator"""
        if self._traditional is None:
            try:
                from ctf_mcp.core.orchestrator import CTFOrchestrator
                self._traditional = CTFOrchestrator()
            except ImportError:
                logger.warning("Traditional orchestrator not available")
                self._traditional = None
        return self._traditional

    def _get_agent(self) -> ReActAgent:
        """Get or create ReAct agent"""
        if self._agent is None:
            if self._tools is None:
                self._tools = create_ctf_agent_tools()

            self._agent = ReActAgent(
                config=self.llm_config,
                tools=self._tools.get_tools_dict(),
                verbose=self.llm_config.verbose,
            )
        return self._agent

    def _get_retriever(self) -> KnowledgeRetriever:
        """Get or create knowledge retriever"""
        if self._retriever is None:
            self._retriever = KnowledgeRetriever()
        return self._retriever

    async def solve(
        self,
        challenge: "Challenge",
        force_agent: bool = False,
    ) -> EnhancedSolveResult:
        """
        Solve a CTF challenge using enhanced approach.

        Args:
            challenge: Challenge to solve
            force_agent: Skip traditional, go directly to agent

        Returns:
            EnhancedSolveResult with flag and method
        """
        # Step 1: Try traditional solving (if enabled)
        if self.use_traditional and not force_agent:
            traditional = self._get_traditional()
            if traditional:
                try:
                    logger.info("Attempting traditional solving...")
                    result = await traditional.solve(challenge)

                    if result and result.flag:
                        return EnhancedSolveResult(
                            success=True,
                            flag=result.flag,
                            method="traditional",
                            confidence=0.9,
                            traditional_result=result,
                        )
                except Exception as e:
                    logger.warning("Traditional solving failed: %s", e)

        # Step 2: Use ReAct agent (if enabled)
        if self.use_agent:
            try:
                logger.info("Attempting LLM agent solving...")

                # Get relevant patterns from RAG
                retriever = self._get_retriever()
                patterns = retriever.retrieve(
                    challenge.description,
                    category=getattr(challenge, "category", None),
                    top_k=5,
                )

                # Build context for agent
                context = {
                    "description": challenge.description,
                    "category": getattr(challenge, "category", "unknown"),
                    "files": getattr(challenge, "files", []),
                    "remote": getattr(challenge, "remote", None),
                    "patterns": [p.to_dict() for p in patterns],
                }

                # Run agent
                agent = self._get_agent()
                agent_result = await agent.run(context)

                if agent_result.success and agent_result.flag:
                    return EnhancedSolveResult(
                        success=True,
                        flag=agent_result.flag,
                        method="llm_agent",
                        confidence=0.7,
                        agent_result=agent_result,
                    )
                else:
                    return EnhancedSolveResult(
                        success=False,
                        method="llm_agent",
                        agent_result=agent_result,
                        error=agent_result.error or "Agent did not find flag",
                    )

            except Exception as e:
                logger.error("Agent solving failed: %s", e)
                return EnhancedSolveResult(
                    success=False,
                    method="llm_agent",
                    error=str(e),
                )

        return EnhancedSolveResult(
            success=False,
            error="No solving method available",
        )

    async def analyze(
        self,
        challenge: "Challenge",
    ) -> dict:
        """
        Analyze a challenge without solving.

        Returns:
            Dictionary with classification, patterns, and recommendations
        """
        result = {
            "category": "unknown",
            "subcategory": None,
            "difficulty": "unknown",
            "patterns": [],
            "recommended_tools": [],
            "approach": [],
        }

        # Get classification from traditional orchestrator
        traditional = self._get_traditional()
        if traditional and hasattr(traditional, "classify"):
            try:
                classification = await traditional.classify(challenge)
                result["category"] = classification.category
                result["subcategory"] = classification.subcategory
                result["difficulty"] = classification.difficulty
            except Exception as e:
                logger.warning("Classification failed: %s", e)

        # Get patterns from RAG
        retriever = self._get_retriever()
        patterns = retriever.retrieve(
            challenge.description,
            category=result.get("category"),
            top_k=5,
        )

        result["patterns"] = [p.to_dict() for p in patterns]

        # Collect recommended tools
        tools = set()
        for p in patterns:
            tools.update(p.tools[:3])
        result["recommended_tools"] = list(tools)[:10]

        return result

    def reset(self) -> None:
        """Reset the orchestrator state"""
        if self._agent:
            self._agent.reset()


# Convenience function
async def solve_with_llm(
    description: str,
    category: Optional[str] = None,
    files: Optional[list[str]] = None,
    remote: Optional[dict] = None,
) -> EnhancedSolveResult:
    """
    Convenience function to solve a challenge with LLM agent.

    Args:
        description: Challenge description
        category: Optional category hint
        files: Optional list of file paths
        remote: Optional remote connection info

    Returns:
        EnhancedSolveResult
    """
    # Create a simple challenge object
    class SimpleChallenge:
        def __init__(self):
            self.description = description
            self.category = category or "unknown"
            self.files = files or []
            self.remote = remote

    orchestrator = EnhancedOrchestrator(use_traditional=False, use_agent=True)
    return await orchestrator.solve(SimpleChallenge())
