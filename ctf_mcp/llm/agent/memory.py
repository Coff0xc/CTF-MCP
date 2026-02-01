"""
Agent Memory

Manages conversation history and context for the ReAct agent.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from ..providers.base import Message

logger = logging.getLogger("ctf-mcp.llm.agent.memory")


@dataclass
class ConversationTurn:
    """A single turn in the conversation"""
    role: str
    content: str
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: dict = field(default_factory=dict)


class ConversationHistory:
    """
    Manages conversation history with optional summarization.

    Features:
    - Stores full conversation history
    - Can summarize old messages to save context
    - Provides window of recent messages
    """

    def __init__(self, max_turns: int = 50, summarize_after: int = 30):
        """
        Initialize conversation history.

        Args:
            max_turns: Maximum turns to keep in memory
            summarize_after: Summarize after this many turns
        """
        self.max_turns = max_turns
        self.summarize_after = summarize_after
        self._turns: list[ConversationTurn] = []
        self._summary: Optional[str] = None

    def add(self, role: str, content: str, **metadata) -> None:
        """Add a new turn to the history"""
        self._turns.append(ConversationTurn(
            role=role,
            content=content,
            metadata=metadata,
        ))

        # Trim if exceeds max
        if len(self._turns) > self.max_turns:
            self._turns = self._turns[-self.max_turns:]

    def add_message(self, message: Message) -> None:
        """Add a Message object to the history"""
        self.add(message.role, message.content)

    def get_messages(self, last_n: Optional[int] = None) -> list[Message]:
        """
        Get messages for API call.

        Args:
            last_n: Only return last N messages (None for all)

        Returns:
            List of Message objects
        """
        turns = self._turns[-last_n:] if last_n else self._turns
        messages = []

        # Add summary if available
        if self._summary and last_n and len(self._turns) > last_n:
            messages.append(Message.system(
                f"Previous conversation summary:\n{self._summary}"
            ))

        for turn in turns:
            messages.append(Message(role=turn.role, content=turn.content))

        return messages

    def clear(self) -> None:
        """Clear all history"""
        self._turns = []
        self._summary = None

    def to_dict(self) -> dict:
        """Export history as dictionary"""
        return {
            "turns": [
                {
                    "role": t.role,
                    "content": t.content,
                    "timestamp": t.timestamp.isoformat(),
                    "metadata": t.metadata,
                }
                for t in self._turns
            ],
            "summary": self._summary,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ConversationHistory":
        """Import history from dictionary"""
        history = cls()
        for turn in data.get("turns", []):
            history.add(
                role=turn["role"],
                content=turn["content"],
                **turn.get("metadata", {}),
            )
        history._summary = data.get("summary")
        return history

    def __len__(self) -> int:
        return len(self._turns)


@dataclass
class ChallengeContext:
    """Context about the current CTF challenge"""
    description: str = ""
    category: str = ""
    files: list[str] = field(default_factory=list)
    remote: Optional[dict] = None
    hints: list[str] = field(default_factory=list)
    solved_patterns: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "description": self.description,
            "category": self.category,
            "files": self.files,
            "remote": self.remote,
            "hints": self.hints,
            "solved_patterns": self.solved_patterns,
            "notes": self.notes,
        }


class AgentMemory:
    """
    Complete memory system for the CTF solving agent.

    Components:
    - Conversation history
    - Challenge context
    - Working memory (temporary storage)
    - Long-term patterns (successful strategies)
    """

    def __init__(self):
        self.conversation = ConversationHistory()
        self.challenge = ChallengeContext()
        self._working: dict[str, Any] = {}
        self._patterns: list[dict] = []

    def set_challenge(
        self,
        description: str,
        category: str = "",
        files: Optional[list[str]] = None,
        remote: Optional[dict] = None,
    ) -> None:
        """Set the current challenge context"""
        self.challenge = ChallengeContext(
            description=description,
            category=category,
            files=files or [],
            remote=remote,
        )
        # Clear conversation for new challenge
        self.conversation.clear()
        self._working.clear()

    def add_hint(self, hint: str) -> None:
        """Add a hint for the current challenge"""
        self.challenge.hints.append(hint)

    def add_note(self, note: str) -> None:
        """Add a note/observation"""
        self.challenge.notes.append(note)

    def store(self, key: str, value: Any) -> None:
        """Store a value in working memory"""
        self._working[key] = value

    def recall(self, key: str, default: Any = None) -> Any:
        """Recall a value from working memory"""
        return self._working.get(key, default)

    def add_pattern(self, pattern: dict) -> None:
        """Add a successful solving pattern for future reference"""
        self._patterns.append(pattern)

    def get_context_for_agent(self) -> dict:
        """Get context dictionary for agent prompt"""
        return {
            "challenge": self.challenge.to_dict(),
            "working_memory": self._working,
            "relevant_patterns": self._patterns[-5:],  # Last 5 patterns
        }

    def reset(self) -> None:
        """Reset all memory"""
        self.conversation.clear()
        self.challenge = ChallengeContext()
        self._working.clear()

    def to_dict(self) -> dict:
        """Export full memory state"""
        return {
            "conversation": self.conversation.to_dict(),
            "challenge": self.challenge.to_dict(),
            "working": self._working,
            "patterns": self._patterns,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "AgentMemory":
        """Import memory from dictionary"""
        memory = cls()
        memory.conversation = ConversationHistory.from_dict(data.get("conversation", {}))
        cd = data.get("challenge", {})
        memory.challenge = ChallengeContext(
            description=cd.get("description", ""),
            category=cd.get("category", ""),
            files=cd.get("files", []),
            remote=cd.get("remote"),
            hints=cd.get("hints", []),
            solved_patterns=cd.get("solved_patterns", []),
            notes=cd.get("notes", []),
        )
        memory._working = data.get("working", {})
        memory._patterns = data.get("patterns", [])
        return memory
