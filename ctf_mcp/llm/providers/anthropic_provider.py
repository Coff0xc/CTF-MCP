"""
Anthropic LLM Provider

Supports Claude models via Anthropic API.
"""

import json
import logging
from typing import Any, AsyncIterator, Optional

from .base import LLMProviderBase, LLMResponse, Message, ToolCall

logger = logging.getLogger("ctf-mcp.llm.anthropic")


class AnthropicProvider(LLMProviderBase):
    """
    Anthropic API provider.

    Supports:
    - Claude 3.5 Sonnet, Claude 3 Opus, Claude 3 Haiku
    - Tool use (function calling)
    - Streaming responses
    """

    def __init__(self, config: "LLMConfig"):
        super().__init__(config)
        self._client = None

    @property
    def name(self) -> str:
        return "anthropic"

    def _get_client(self):
        """Get or create Anthropic client (lazy initialization)"""
        if self._client is None:
            try:
                from anthropic import AsyncAnthropic
            except ImportError:
                raise ImportError(
                    "Anthropic package not installed. "
                    "Install with: pip install anthropic"
                )

            self._client = AsyncAnthropic(
                api_key=self.config.api_key,
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
        Generate a completion using Anthropic API.

        Args:
            messages: Conversation history
            tools: Optional list of tools
            **kwargs: Additional arguments

        Returns:
            LLMResponse with content and/or tool calls
        """
        client = self._get_client()

        # Separate system message from conversation
        system_content = ""
        api_messages = []

        for msg in messages:
            if msg.role == "system":
                system_content += msg.content + "\n"
            else:
                api_messages.append(self._format_message(msg))

        # Build request
        request_kwargs = {
            "model": self.config.model,
            "messages": api_messages,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
        }

        if system_content:
            request_kwargs["system"] = system_content.strip()

        # Add tools if provided
        if tools:
            request_kwargs["tools"] = self._format_tools(tools)

        request_kwargs.update(kwargs)

        try:
            response = await client.messages.create(**request_kwargs)
            return self._parse_response(response)

        except Exception as e:
            self.logger.error("Anthropic API error: %s", e)
            raise

    async def stream(
        self,
        messages: list[Message],
        **kwargs
    ) -> AsyncIterator[str]:
        """
        Stream a completion from Anthropic.

        Yields text chunks as they arrive.
        """
        client = self._get_client()

        # Separate system message
        system_content = ""
        api_messages = []

        for msg in messages:
            if msg.role == "system":
                system_content += msg.content + "\n"
            else:
                api_messages.append(self._format_message(msg))

        request_kwargs = {
            "model": self.config.model,
            "messages": api_messages,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
        }

        if system_content:
            request_kwargs["system"] = system_content.strip()

        request_kwargs.update(kwargs)

        try:
            async with client.messages.stream(**request_kwargs) as stream:
                async for text in stream.text_stream:
                    yield text

        except Exception as e:
            self.logger.error("Anthropic streaming error: %s", e)
            raise

    def _format_message(self, msg: Message) -> dict:
        """Format message for Anthropic API"""
        if msg.role == "tool":
            # Tool result message
            return {
                "role": "user",
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": msg.tool_call_id,
                    "content": msg.content,
                }]
            }
        elif msg.role == "assistant" and msg.tool_calls:
            # Assistant message with tool use
            content = []
            if msg.content:
                content.append({"type": "text", "text": msg.content})
            for tc in msg.tool_calls:
                content.append({
                    "type": "tool_use",
                    "id": tc.get("id"),
                    "name": tc.get("function", {}).get("name"),
                    "input": json.loads(tc.get("function", {}).get("arguments", "{}")),
                })
            return {"role": "assistant", "content": content}
        else:
            return {"role": msg.role, "content": msg.content}

    def _format_tools(self, tools: list[dict]) -> list[dict]:
        """Format tools for Anthropic API"""
        formatted = []
        for tool in tools:
            # Handle OpenAI format
            if "type" in tool and tool["type"] == "function":
                func = tool["function"]
                formatted.append({
                    "name": func["name"],
                    "description": func.get("description", ""),
                    "input_schema": func.get("parameters", {"type": "object", "properties": {}}),
                })
            elif "function" in tool:
                func = tool["function"]
                formatted.append({
                    "name": func["name"],
                    "description": func.get("description", ""),
                    "input_schema": func.get("parameters", {"type": "object", "properties": {}}),
                })
            else:
                # Assume already in Anthropic format
                formatted.append(tool)
        return formatted

    def _parse_response(self, response) -> LLMResponse:
        """Parse Anthropic API response"""
        content_parts = []
        tool_calls = []

        for block in response.content:
            if block.type == "text":
                content_parts.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append(ToolCall(
                    id=block.id,
                    name=block.name,
                    arguments=json.dumps(block.input),
                ))

        content = "\n".join(content_parts)

        # Extract usage
        usage = {}
        if hasattr(response, "usage"):
            usage = {
                "prompt_tokens": response.usage.input_tokens,
                "completion_tokens": response.usage.output_tokens,
                "total_tokens": response.usage.input_tokens + response.usage.output_tokens,
            }

        return LLMResponse(
            content=content,
            tool_calls=tool_calls,
            finish_reason=response.stop_reason or "end_turn",
            usage=usage,
            raw=response,
        )
