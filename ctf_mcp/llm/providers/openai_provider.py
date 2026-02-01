"""
OpenAI LLM Provider

Supports OpenAI API (GPT-4, GPT-4o, etc.) and Azure OpenAI.
"""

import json
import logging
from typing import Any, AsyncIterator, Optional

from .base import LLMProviderBase, LLMResponse, Message, ToolCall

logger = logging.getLogger("ctf-mcp.llm.openai")


class OpenAIProvider(LLMProviderBase):
    """
    OpenAI API provider.

    Supports:
    - OpenAI API (gpt-4o, gpt-4-turbo, gpt-3.5-turbo)
    - Azure OpenAI Service
    - Function/tool calling
    - Streaming responses
    """

    def __init__(self, config: "LLMConfig"):
        super().__init__(config)
        self._client = None

    @property
    def name(self) -> str:
        return "openai"

    def _get_client(self):
        """Get or create OpenAI client (lazy initialization)"""
        if self._client is None:
            try:
                from openai import AsyncOpenAI
            except ImportError:
                raise ImportError(
                    "OpenAI package not installed. "
                    "Install with: pip install openai"
                )

            if self.config.provider == "azure":
                from openai import AsyncAzureOpenAI
                self._client = AsyncAzureOpenAI(
                    api_key=self.config.api_key,
                    azure_endpoint=self.config.base_url,
                    api_version="2024-02-15-preview",
                )
            else:
                self._client = AsyncOpenAI(
                    api_key=self.config.api_key,
                    base_url=self.config.base_url,
                    timeout=self.config.timeout,
                    max_retries=self.config.max_retries,
                )

        return self._client

    async def complete(
        self,
        messages: list[Message],
        tools: Optional[list[dict]] = None,
        **kwargs
    ) -> LLMResponse:
        """
        Generate a completion using OpenAI API.

        Args:
            messages: Conversation history
            tools: Optional list of tools in OpenAI format
            **kwargs: Additional arguments (passed to API)

        Returns:
            LLMResponse with content and/or tool calls
        """
        client = self._get_client()

        # Prepare messages
        api_messages = [m.to_dict() for m in messages]

        # Build request kwargs
        request_kwargs = {
            "model": self.config.model,
            "messages": api_messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }

        # Add tools if provided
        if tools:
            request_kwargs["tools"] = self._format_tools(tools)
            request_kwargs["tool_choice"] = "auto"

        # Merge additional kwargs
        request_kwargs.update(kwargs)

        try:
            response = await client.chat.completions.create(**request_kwargs)
            return self._parse_response(response)

        except Exception as e:
            self.logger.error("OpenAI API error: %s", e)
            raise

    async def stream(
        self,
        messages: list[Message],
        **kwargs
    ) -> AsyncIterator[str]:
        """
        Stream a completion from OpenAI.

        Yields text chunks as they arrive.
        """
        client = self._get_client()

        api_messages = [m.to_dict() for m in messages]

        request_kwargs = {
            "model": self.config.model,
            "messages": api_messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "stream": True,
        }
        request_kwargs.update(kwargs)

        try:
            async for chunk in await client.chat.completions.create(**request_kwargs):
                if chunk.choices and chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content

        except Exception as e:
            self.logger.error("OpenAI streaming error: %s", e)
            raise

    def _format_tools(self, tools: list[dict]) -> list[dict]:
        """Format tools for OpenAI API"""
        formatted = []
        for tool in tools:
            if "type" not in tool:
                # Wrap in function type if not already
                formatted.append({
                    "type": "function",
                    "function": tool,
                })
            else:
                formatted.append(tool)
        return formatted

    def _parse_response(self, response) -> LLMResponse:
        """Parse OpenAI API response"""
        choice = response.choices[0]
        message = choice.message

        # Extract content
        content = message.content or ""

        # Extract tool calls
        tool_calls = []
        if message.tool_calls:
            for tc in message.tool_calls:
                tool_calls.append(ToolCall(
                    id=tc.id,
                    name=tc.function.name,
                    arguments=tc.function.arguments,
                ))

        # Extract usage
        usage = {}
        if response.usage:
            usage = {
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens,
            }

        return LLMResponse(
            content=content,
            tool_calls=tool_calls,
            finish_reason=choice.finish_reason or "stop",
            usage=usage,
            raw=response,
        )
