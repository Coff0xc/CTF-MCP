"""
Base LLM Provider

Abstract base class for all LLM provider implementations.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, AsyncIterator, Optional

logger = logging.getLogger("ctf-mcp.llm.provider")


class MessageRole(Enum):
    """Message roles in conversation"""
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


@dataclass
class Message:
    """
    A message in the conversation.

    Attributes:
        role: Message role (system, user, assistant, tool)
        content: Message content (text)
        name: Optional name for tool messages
        tool_calls: Optional list of tool calls (for assistant messages)
        tool_call_id: Optional ID for tool response messages
    """
    role: str
    content: str
    name: Optional[str] = None
    tool_calls: Optional[list[dict]] = None
    tool_call_id: Optional[str] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for API calls"""
        d = {"role": self.role, "content": self.content}
        if self.name:
            d["name"] = self.name
        if self.tool_calls:
            d["tool_calls"] = self.tool_calls
        if self.tool_call_id:
            d["tool_call_id"] = self.tool_call_id
        return d

    @classmethod
    def system(cls, content: str) -> "Message":
        """Create a system message"""
        return cls(role="system", content=content)

    @classmethod
    def user(cls, content: str) -> "Message":
        """Create a user message"""
        return cls(role="user", content=content)

    @classmethod
    def assistant(cls, content: str, tool_calls: Optional[list[dict]] = None) -> "Message":
        """Create an assistant message"""
        return cls(role="assistant", content=content, tool_calls=tool_calls)

    @classmethod
    def tool(cls, content: str, tool_call_id: str, name: str) -> "Message":
        """Create a tool response message"""
        return cls(role="tool", content=content, tool_call_id=tool_call_id, name=name)


@dataclass
class ToolCall:
    """
    A tool call from the LLM.

    Attributes:
        id: Unique identifier for this call
        name: Tool name to call
        arguments: Arguments as JSON string
    """
    id: str
    name: str
    arguments: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": "function",
            "function": {
                "name": self.name,
                "arguments": self.arguments,
            }
        }


@dataclass
class LLMResponse:
    """
    Response from an LLM completion.

    Attributes:
        content: Text content of the response
        tool_calls: List of tool calls (if any)
        finish_reason: Why the response ended (stop, tool_calls, length, etc.)
        usage: Token usage statistics
        raw: Raw response from the provider
    """
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    finish_reason: str = "stop"
    usage: dict[str, int] = field(default_factory=dict)
    raw: Any = None

    @property
    def has_tool_calls(self) -> bool:
        """Check if response contains tool calls"""
        return len(self.tool_calls) > 0


class LLMProviderBase(ABC):
    """
    Abstract base class for LLM providers.

    Implementations should handle:
    - Authentication
    - Message formatting
    - Tool/function calling
    - Error handling and retries
    - Streaming responses
    """

    def __init__(self, config: "LLMConfig"):
        """
        Initialize the provider.

        Args:
            config: LLM configuration
        """
        from ..config import LLMConfig
        self.config = config
        self.logger = logging.getLogger(f"ctf-mcp.llm.{self.name}")

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name"""
        pass

    @abstractmethod
    async def complete(
        self,
        messages: list[Message],
        tools: Optional[list[dict]] = None,
        **kwargs
    ) -> LLMResponse:
        """
        Generate a completion from the LLM.

        Args:
            messages: Conversation history
            tools: Optional list of tools (in OpenAI function format)
            **kwargs: Additional provider-specific arguments

        Returns:
            LLMResponse with content and/or tool calls
        """
        pass

    @abstractmethod
    async def stream(
        self,
        messages: list[Message],
        **kwargs
    ) -> AsyncIterator[str]:
        """
        Stream a completion from the LLM.

        Args:
            messages: Conversation history
            **kwargs: Additional arguments

        Yields:
            Text chunks as they arrive
        """
        pass

    async def check_health(self) -> bool:
        """
        Check if the provider is healthy and reachable.

        Returns:
            True if healthy, False otherwise
        """
        try:
            response = await self.complete([Message.user("ping")])
            return bool(response.content)
        except Exception as e:
            self.logger.warning("Health check failed: %s", e)
            return False

    def _format_tools(self, tools: list[dict]) -> list[dict]:
        """
        Format tools for this provider's API.

        Default implementation returns tools as-is (OpenAI format).
        Override for provider-specific formatting.
        """
        return tools

    def _parse_response(self, raw_response: Any) -> LLMResponse:
        """
        Parse raw API response into LLMResponse.

        Must be implemented by subclasses.
        """
        raise NotImplementedError
