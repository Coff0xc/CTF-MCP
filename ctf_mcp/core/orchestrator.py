"""
CTF Challenge Orchestrator
Main entry point for automated CTF challenge solving

Orchestrates the full pipeline: Classification -> Planning -> Execution -> Validation
"""

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Union

from .classifier import ChallengeClassifier, ChallengeType, ClassificationResult
from .planner import SolvingPlanner, SolvingStrategy
from .executor import StrategyExecutor, ExecutionResult
from .session import SolveSession, SessionState

logger = logging.getLogger("ctf-mcp.orchestrator")


class SolveStatus(Enum):
    """Status of a solve attempt"""
    PENDING = "pending"
    CLASSIFYING = "classifying"
    PLANNING = "planning"
    EXECUTING = "executing"
    VALIDATING = "validating"
    SOLVED = "solved"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


@dataclass
class Challenge:
    """
    Represents a CTF challenge to solve.

    Attributes:
        name: Challenge name/identifier
        description: Challenge description text
        files: List of file paths associated with the challenge
        remote: Remote connection info (host:port or URL)
        flag_format: Expected flag format regex (e.g., "flag{.*}")
        category_hint: Optional category hint from CTF platform
        metadata: Additional metadata
    """
    name: str
    description: str = ""
    files: list[str] = field(default_factory=list)
    remote: Optional[str] = None
    flag_format: str = r"flag\{[^}]+\}"
    category_hint: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_file(cls, file_path: str, **kwargs) -> "Challenge":
        """Create a challenge from a single file"""
        path = Path(file_path)
        return cls(
            name=path.stem,
            files=[str(path.absolute())],
            **kwargs
        )

    @classmethod
    def from_directory(cls, dir_path: str, **kwargs) -> "Challenge":
        """Create a challenge from a directory of files"""
        path = Path(dir_path)
        files = [str(f.absolute()) for f in path.iterdir() if f.is_file()]
        return cls(
            name=path.name,
            files=files,
            **kwargs
        )


@dataclass
class SolveResult:
    """
    Result of a solve attempt.

    Attributes:
        status: Final status of the solve attempt
        flag: Extracted flag (if found)
        classification: Challenge classification result
        strategies_tried: List of strategies attempted
        execution_results: Results from each strategy execution
        total_time: Total time taken in seconds
        error: Error message if failed
        session_id: ID of the solve session
    """
    status: SolveStatus
    flag: Optional[str] = None
    classification: Optional[ClassificationResult] = None
    strategies_tried: list[SolvingStrategy] = field(default_factory=list)
    execution_results: list[ExecutionResult] = field(default_factory=list)
    total_time: float = 0.0
    error: Optional[str] = None
    session_id: Optional[str] = None

    @property
    def is_solved(self) -> bool:
        return self.status == SolveStatus.SOLVED and self.flag is not None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "status": self.status.value,
            "flag": self.flag,
            "classification": self.classification.to_dict() if self.classification else None,
            "strategies_tried": len(self.strategies_tried),
            "total_time": self.total_time,
            "error": self.error,
            "session_id": self.session_id,
        }


class CTFOrchestrator:
    """
    Main orchestrator for automated CTF challenge solving.

    Coordinates:
    - Challenge classification (identify type)
    - Strategy planning (select solving approach)
    - Strategy execution (run tools)
    - Result validation (verify flag)

    Usage:
        orchestrator = CTFOrchestrator()
        result = await orchestrator.solve(challenge)
        if result.is_solved:
            print(f"Flag: {result.flag}")
    """

    def __init__(
        self,
        timeout: float = 1800.0,  # 30 minutes default
        max_strategies: int = 5,
        auto_validate: bool = True,
    ):
        """
        Initialize the orchestrator.

        Args:
            timeout: Maximum time for solving in seconds
            max_strategies: Maximum number of strategies to try
            auto_validate: Automatically validate found flags
        """
        self.timeout = timeout
        self.max_strategies = max_strategies
        self.auto_validate = auto_validate

        # Components
        self.classifier = ChallengeClassifier()
        self.planner = SolvingPlanner()
        self.executor = StrategyExecutor()

        # State
        self._current_session: Optional[SolveSession] = None

    async def solve(self, challenge: Challenge) -> SolveResult:
        """
        Attempt to solve a CTF challenge automatically.

        Args:
            challenge: The challenge to solve

        Returns:
            SolveResult with status and flag if found
        """
        start_time = time.time()
        session = SolveSession(challenge)
        self._current_session = session

        logger.info("Starting solve attempt for: %s", challenge.name)

        try:
            # Phase 1: Classification
            session.update_state(SessionState.CLASSIFYING)
            classification = await self._classify(challenge)
            session.set_classification(classification)

            if not classification.types:
                return SolveResult(
                    status=SolveStatus.FAILED,
                    error="Could not classify challenge type",
                    classification=classification,
                    total_time=time.time() - start_time,
                    session_id=session.session_id,
                )

            logger.info("Classified as: %s", [t.value for t in classification.types])

            # Phase 2: Planning
            session.update_state(SessionState.PLANNING)
            strategies = await self._plan(challenge, classification)
            session.set_strategies(strategies)

            if not strategies:
                return SolveResult(
                    status=SolveStatus.FAILED,
                    error="No viable solving strategies found",
                    classification=classification,
                    total_time=time.time() - start_time,
                    session_id=session.session_id,
                )

            logger.info("Generated %d strategies", len(strategies))

            # Phase 3: Execution
            session.update_state(SessionState.EXECUTING)
            strategies_tried = []
            execution_results = []
            flag = None

            for i, strategy in enumerate(strategies[:self.max_strategies]):
                # Check timeout
                elapsed = time.time() - start_time
                if elapsed >= self.timeout:
                    logger.warning("Solve attempt timed out")
                    return SolveResult(
                        status=SolveStatus.TIMEOUT,
                        classification=classification,
                        strategies_tried=strategies_tried,
                        execution_results=execution_results,
                        total_time=elapsed,
                        session_id=session.session_id,
                    )

                logger.info("Trying strategy %d/%d: %s", i+1, len(strategies), strategy.name)
                strategies_tried.append(strategy)

                # Execute strategy with remaining time
                remaining_time = self.timeout - elapsed
                result = await self._execute(
                    challenge, strategy, timeout=remaining_time
                )
                execution_results.append(result)
                session.add_execution_result(result)

                # Check for flag
                if result.flag:
                    flag = result.flag
                    logger.info("Found potential flag: %s", flag)

                    # Validate if enabled
                    if self.auto_validate:
                        session.update_state(SessionState.VALIDATING)
                        if self._validate_flag(flag, challenge.flag_format):
                            logger.info("Flag validated successfully!")
                            return SolveResult(
                                status=SolveStatus.SOLVED,
                                flag=flag,
                                classification=classification,
                                strategies_tried=strategies_tried,
                                execution_results=execution_results,
                                total_time=time.time() - start_time,
                                session_id=session.session_id,
                            )
                        else:
                            logger.warning("Flag validation failed, continuing...")
                            flag = None
                    else:
                        # Accept without validation
                        return SolveResult(
                            status=SolveStatus.SOLVED,
                            flag=flag,
                            classification=classification,
                            strategies_tried=strategies_tried,
                            execution_results=execution_results,
                            total_time=time.time() - start_time,
                            session_id=session.session_id,
                        )

            # All strategies exhausted
            return SolveResult(
                status=SolveStatus.FAILED,
                error="All strategies exhausted without finding flag",
                classification=classification,
                strategies_tried=strategies_tried,
                execution_results=execution_results,
                total_time=time.time() - start_time,
                session_id=session.session_id,
            )

        except asyncio.CancelledError:
            logger.info("Solve attempt cancelled")
            return SolveResult(
                status=SolveStatus.CANCELLED,
                total_time=time.time() - start_time,
                session_id=session.session_id,
            )
        except Exception as e:
            logger.error("Solve attempt failed with error: %s", e)
            return SolveResult(
                status=SolveStatus.FAILED,
                error=str(e),
                total_time=time.time() - start_time,
                session_id=session.session_id,
            )
        finally:
            # Only update to COMPLETED if not already in a terminal state (e.g., CANCELLED)
            if session.state not in (SessionState.COMPLETED, SessionState.CANCELLED):
                session.update_state(SessionState.COMPLETED)
            self._current_session = None

    async def _classify(self, challenge: Challenge) -> ClassificationResult:
        """Classify the challenge type"""
        return await asyncio.to_thread(
            self.classifier.classify,
            description=challenge.description,
            files=challenge.files,
            remote=challenge.remote,
            hint=challenge.category_hint,
        )

    async def _plan(
        self,
        challenge: Challenge,
        classification: ClassificationResult
    ) -> list[SolvingStrategy]:
        """Generate solving strategies"""
        return await asyncio.to_thread(
            self.planner.plan,
            challenge_types=classification.types,
            files=challenge.files,
            remote=challenge.remote,
            analysis=classification.analysis,
        )

    async def _execute(
        self,
        challenge: Challenge,
        strategy: SolvingStrategy,
        timeout: float
    ) -> ExecutionResult:
        """Execute a solving strategy"""
        return await self.executor.execute(
            strategy=strategy,
            challenge=challenge,
            timeout=timeout,
        )

    def _validate_flag(self, flag: str, pattern: str) -> bool:
        """Validate flag against expected pattern"""
        try:
            # Use fullmatch to reject trailing garbage (e.g., "flag{valid}extra")
            return bool(re.fullmatch(pattern, flag))
        except re.error:
            # If pattern is invalid, accept any non-empty flag
            return bool(flag)

    def get_current_session(self) -> Optional[SolveSession]:
        """Get the current solve session"""
        return self._current_session

    async def cancel(self):
        """Cancel the current solve attempt"""
        if self._current_session:
            self._current_session.cancel()


# Convenience function for simple usage
async def solve_challenge(
    challenge: Union[Challenge, str],
    **kwargs
) -> SolveResult:
    """
    Convenience function to solve a challenge.

    Args:
        challenge: Challenge object or file path
        **kwargs: Additional arguments for CTFOrchestrator

    Returns:
        SolveResult
    """
    if isinstance(challenge, str):
        challenge = Challenge.from_file(challenge)

    orchestrator = CTFOrchestrator(**kwargs)
    return await orchestrator.solve(challenge)
