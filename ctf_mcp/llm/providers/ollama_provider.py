"""
Ollama LLM Provider

Supports local Ollama models for offline/private CTF solving.
"""

import json
import logging
from typing import Any, AsyncIterator, Optional

from .base import LLMProviderBase, LLMResponse, Message, ToolCall

logger = logging.getLogger("ctf-mcp.llm.ollama")


class OllamaProvider(LLMProviderBase):
    """
    Ollama provider for local LLM inference.

    Supports:
    - Any Ollama model (llama3, codellama, mistral, etc.)
    - Tool calling (with supported models)
    - Streaming responses
    - Fully offline operation
    """

    def __init__(self, config: "LLMConfig"):
        super().__init__(config)
        self._client = None
        # Default to localhost if no base_url
        if not self.config.base_url:
            self.config.base_url = "http://localhost:11434"

    @property
    def name(self) -> str:
        return "ollama"

    def _get_client(self):
        """Get or create HTTP client for Ollama API"""
        if self._client is None:
            try:
                import httpx
            except ImportError:
                raise ImportError(
                    "httpx package not installed. "
                    "Install with: pip install httpx"
                )

            self._client = httpx.AsyncClient(
                base_url=self.config.base_url,
                timeout=self.config.timeout,
            )

        return self._client

    async def complete(
        self,
        messages: list[Message],
        tools: Optional[list[dict]] = None,
        **kwargs
    ) -> LLMResponse:
        """
        Generate a completion using Ollama API.

        Args:
            messages: Conversation history
            tools: Optional list of tools (limited support)
            **kwargs: Additional arguments

        Returns:
            LLMResponse with content
        """
        client = self._get_client()

        # Format messages for Ollama
        api_messages = [m.to_dict() for m in messages]

        # Build request
        request_data = {
            "model": self.config.model,
            "messages": api_messages,
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens,
            }
        }

        # Add tools if provided (Ollama 0.1.44+ supports tools)
        if tools:
            request_data["tools"] = self._format_tools(tools)

        try:
            response = await client.post(
                "/api/chat",
                json=request_data,
            )
            response.raise_for_status()
            data = response.json()
            return self._parse_response(data)

        except Exception as e:
            self.logger.error("Ollama API error: %s", e)
            raise

    async def stream(
        self,
        messages: list[Message],
        **kwargs
    ) -> AsyncIterator[str]:
        """
        Stream a completion from Ollama.

        Yields text chunks as they arrive.
        """
        client = self._get_client()

        api_messages = [m.to_dict() for m in messages]

        request_data = {
            "model": self.config.model,
            "messages": api_messages,
            "stream": True,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens,
            }
        }

        try:
            async with client.stream(
                "POST",
                "/api/chat",
                json=request_data,
            ) as response:
                async for line in response.aiter_lines():
                    if line:
                        try:
                            data = json.loads(line)
                            if "message" in data and "content" in data["message"]:
                                yield data["message"]["content"]
                        except json.JSONDecodeError:
                            continue

        except Exception as e:
            self.logger.error("Ollama streaming error: %s", e)
            raise

    def _format_tools(self, tools: list[dict]) -> list[dict]:
        """Format tools for Ollama API (same as OpenAI format)"""
        formatted = []
        for tool in tools:
            if "type" not in tool:
                formatted.append({
                    "type": "function",
                    "function": tool,
                })
            else:
                formatted.append(tool)
        return formatted

    def _parse_response(self, data: dict) -> LLMResponse:
        """Parse Ollama API response"""
        message = data.get("message", {})
        content = message.get("content", "")

        # Extract tool calls if present
        tool_calls = []
        if "tool_calls" in message:
            for tc in message["tool_calls"]:
                tool_calls.append(ToolCall(
                    id=tc.get("id", f"call_{len(tool_calls)}"),
                    name=tc.get("function", {}).get("name", ""),
                    arguments=json.dumps(tc.get("function", {}).get("arguments", {})),
                ))

        # Extract token counts
        usage = {}
        if "prompt_eval_count" in data:
            usage["prompt_tokens"] = data["prompt_eval_count"]
        if "eval_count" in data:
            usage["completion_tokens"] = data["eval_count"]
        if usage:
            usage["total_tokens"] = usage.get("prompt_tokens", 0) + usage.get("completion_tokens", 0)

        return LLMResponse(
            content=content,
            tool_calls=tool_calls,
            finish_reason="stop" if data.get("done", False) else "length",
            usage=usage,
            raw=data,
        )

    async def check_health(self) -> bool:
        """Check if Ollama is running and model is available"""
        try:
            client = self._get_client()
            response = await client.get("/api/tags")
            response.raise_for_status()
            data = response.json()

            # Check if our model is available
            models = [m["name"] for m in data.get("models", [])]
            if self.config.model not in models:
                # Check with version suffix
                model_base = self.config.model.split(":")[0]
                available = any(m.startswith(model_base) for m in models)
                if not available:
                    self.logger.warning(
                        "Model '%s' not found. Available: %s",
                        self.config.model, models[:5]
                    )
                    return False

            return True

        except Exception as e:
            self.logger.warning("Ollama health check failed: %s", e)
            return False

    async def list_models(self) -> list[str]:
        """List available Ollama models"""
        try:
            client = self._get_client()
            response = await client.get("/api/tags")
            response.raise_for_status()
            data = response.json()
            return [m["name"] for m in data.get("models", [])]
        except Exception:
            return []
