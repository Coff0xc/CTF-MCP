"""
CTF-MCP Core Module
Orchestration engine for automated CTF challenge solving
"""

from .classifier import ChallengeClassifier, ChallengeType, ClassificationResult
from .planner import SolvingPlanner, SolvingStrategy, StrategyStep, StepType
from .executor import StrategyExecutor, ExecutionResult, ExecutionStatus
from .session import SolveSession, SessionState
from .orchestrator import CTFOrchestrator, Challenge, SolveResult, SolveStatus
from .knowledge import KnowledgeBase, SolvePattern, SolutionCache, get_knowledge_base

__all__ = [
    # Orchestrator
    "CTFOrchestrator",
    "Challenge",
    "SolveResult",
    "SolveStatus",
    # Classifier
    "ChallengeClassifier",
    "ChallengeType",
    "ClassificationResult",
    # Planner
    "SolvingPlanner",
    "SolvingStrategy",
    "StrategyStep",
    "StepType",
    # Executor
    "StrategyExecutor",
    "ExecutionResult",
    "ExecutionStatus",
    # Session
    "SolveSession",
    "SessionState",
    # Knowledge
    "KnowledgeBase",
    "SolvePattern",
    "SolutionCache",
    "get_knowledge_base",
]
