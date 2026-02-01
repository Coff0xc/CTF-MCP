"""
CTF Solve Session Manager
Tracks state, history, and intermediate results for a solve attempt
"""

import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .orchestrator import Challenge
    from .classifier import ClassificationResult
    from .planner import SolvingStrategy
    from .executor import ExecutionResult

logger = logging.getLogger("ctf-mcp.session")


class SessionState(Enum):
    """States of a solve session"""
    CREATED = "created"
    CLASSIFYING = "classifying"
    PLANNING = "planning"
    EXECUTING = "executing"
    VALIDATING = "validating"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    ERROR = "error"


@dataclass
class SessionEvent:
    """A recorded event in the session"""
    timestamp: float
    event_type: str
    message: str
    data: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "type": self.event_type,
            "message": self.message,
            "data": self.data,
        }


class SolveSession:
    """
    Manages the state and history of a single solve attempt.

    Tracks:
    - Current state
    - Classification results
    - Strategies generated
    - Execution results
    - Event log
    """

    def __init__(self, challenge: "Challenge"):
        """
        Initialize a solve session.

        Args:
            challenge: The challenge being solved
        """
        self.session_id: str = str(uuid.uuid4())[:8]
        self.challenge = challenge
        self.state: SessionState = SessionState.CREATED
        self.created_at: float = time.time()
        self.updated_at: float = self.created_at

        # Results
        self.classification: Optional["ClassificationResult"] = None
        self.strategies: list["SolvingStrategy"] = []
        self.execution_results: list["ExecutionResult"] = []
        self.flag: Optional[str] = None

        # Event log
        self.events: list[SessionEvent] = []
        self._add_event("session_created", f"Session created for: {challenge.name}")

        # Cancellation flag
        self._cancelled = False

        logger.info("Session %s created for: %s", self.session_id, challenge.name)

    def update_state(self, new_state: SessionState):
        """Update session state"""
        old_state = self.state
        self.state = new_state
        self.updated_at = time.time()
        self._add_event(
            "state_change",
            f"State: {old_state.value} -> {new_state.value}"
        )
        logger.debug("Session %s: %s -> %s", self.session_id, old_state.value, new_state.value)

    def set_classification(self, classification: "ClassificationResult"):
        """Set classification result"""
        self.classification = classification
        self._add_event(
            "classification",
            f"Classified as: {[t.value for t in classification.types]}",
            data=classification.to_dict()
        )

    def set_strategies(self, strategies: list["SolvingStrategy"]):
        """Set generated strategies"""
        self.strategies = strategies
        self._add_event(
            "strategies_generated",
            f"Generated {len(strategies)} strategies",
            data={"strategies": [s.name for s in strategies]}
        )

    def add_execution_result(self, result: "ExecutionResult"):
        """Add an execution result"""
        self.execution_results.append(result)
        self._add_event(
            "execution_complete",
            f"Strategy '{result.strategy_name}': {result.status.value}",
            data=result.to_dict()
        )

        if result.flag:
            self.flag = result.flag
            self._add_event("flag_found", f"Flag found: {result.flag}")

    def cancel(self):
        """Cancel the session"""
        self._cancelled = True
        self.update_state(SessionState.CANCELLED)
        self._add_event("cancelled", "Session cancelled by user")

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled

    @property
    def duration(self) -> float:
        """Total session duration"""
        return time.time() - self.created_at

    def _add_event(self, event_type: str, message: str, data: dict[str, Any] = None):
        """Add an event to the log"""
        self.events.append(SessionEvent(
            timestamp=time.time(),
            event_type=event_type,
            message=message,
            data=data,
        ))

    def get_summary(self) -> dict[str, Any]:
        """Get session summary"""
        return {
            "session_id": self.session_id,
            "challenge": self.challenge.name,
            "state": self.state.value,
            "duration": self.duration,
            "classification": (
                [t.value for t in self.classification.types]
                if self.classification else None
            ),
            "strategies_tried": len(self.execution_results),
            "strategies_available": len(self.strategies),
            "flag": self.flag,
            "events": len(self.events),
        }

    def get_event_log(self) -> list[dict[str, Any]]:
        """Get full event log"""
        return [e.to_dict() for e in self.events]

    def __repr__(self) -> str:
        return (
            f"SolveSession(id={self.session_id}, "
            f"challenge={self.challenge.name}, "
            f"state={self.state.value})"
        )
