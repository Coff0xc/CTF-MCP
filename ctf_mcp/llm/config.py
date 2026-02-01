"""
LLM Configuration Management

Supports multiple LLM providers with environment-based configuration.
"""

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class LLMProvider(Enum):
    """Supported LLM providers"""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"
    AZURE = "azure"


@dataclass
class LLMConfig:
    """
    LLM configuration for CTF solving agent.

    Attributes:
        provider: LLM provider (openai, anthropic, ollama, azure)
        model: Model name/ID
        api_key: API key (loaded from environment if not provided)
        base_url: Custom API base URL (for Ollama or Azure)
        temperature: Sampling temperature (lower = more deterministic)
        max_tokens: Maximum tokens in response
        timeout: Request timeout in seconds
        max_retries: Maximum retry attempts on failure
    """
    provider: str = "openai"
    model: str = "gpt-4o"
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    temperature: float = 0.1
    max_tokens: int = 4096
    timeout: float = 60.0
    max_retries: int = 3
    # Agent-specific settings
    max_iterations: int = 20
    verbose: bool = False

    def __post_init__(self):
        """Validate and load configuration"""
        # Auto-load API key from environment
        if self.api_key is None:
            self.api_key = self._get_api_key_from_env()

        # Validate provider
        try:
            LLMProvider(self.provider)
        except ValueError:
            valid = [p.value for p in LLMProvider]
            raise ValueError(f"Invalid provider '{self.provider}'. Valid: {valid}")

    def _get_api_key_from_env(self) -> Optional[str]:
        """Get API key from environment variables"""
        env_vars = {
            "openai": ["OPENAI_API_KEY", "CTF_OPENAI_KEY"],
            "anthropic": ["ANTHROPIC_API_KEY", "CTF_ANTHROPIC_KEY"],
            "azure": ["AZURE_OPENAI_API_KEY", "CTF_AZURE_KEY"],
            "ollama": [],  # Ollama typically doesn't need API key
        }

        for var in env_vars.get(self.provider, []):
            key = os.getenv(var)
            if key:
                return key
        return None

    @classmethod
    def from_env(cls) -> "LLMConfig":
        """
        Create configuration from environment variables.

        Environment variables:
            CTF_LLM_PROVIDER: openai|anthropic|ollama|azure (default: openai)
            CTF_LLM_MODEL: Model name (default: gpt-4o)
            CTF_LLM_BASE_URL: Custom API base URL
            CTF_LLM_TEMPERATURE: Sampling temperature (default: 0.1)
            CTF_LLM_MAX_TOKENS: Max response tokens (default: 4096)
            CTF_LLM_TIMEOUT: Request timeout seconds (default: 60)
            CTF_LLM_MAX_ITERATIONS: Max agent iterations (default: 20)
            CTF_LLM_VERBOSE: Enable verbose output (default: false)
        """
        return cls(
            provider=os.getenv("CTF_LLM_PROVIDER", "openai"),
            model=os.getenv("CTF_LLM_MODEL", "gpt-4o"),
            base_url=os.getenv("CTF_LLM_BASE_URL"),
            temperature=float(os.getenv("CTF_LLM_TEMPERATURE", "0.1")),
            max_tokens=int(os.getenv("CTF_LLM_MAX_TOKENS", "4096")),
            timeout=float(os.getenv("CTF_LLM_TIMEOUT", "60")),
            max_retries=int(os.getenv("CTF_LLM_MAX_RETRIES", "3")),
            max_iterations=int(os.getenv("CTF_LLM_MAX_ITERATIONS", "20")),
            verbose=os.getenv("CTF_LLM_VERBOSE", "").lower() in ("true", "1", "yes"),
        )

    def validate(self) -> list[str]:
        """
        Validate configuration.

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        # Check API key for providers that need it
        if self.provider in ("openai", "anthropic", "azure"):
            if not self.api_key:
                errors.append(f"API key required for provider '{self.provider}'")

        # Check base URL for Ollama
        if self.provider == "ollama" and not self.base_url:
            # Default to localhost
            self.base_url = "http://localhost:11434"

        # Validate numeric ranges
        if not 0.0 <= self.temperature <= 2.0:
            errors.append(f"Temperature must be 0.0-2.0, got {self.temperature}")

        if self.max_tokens < 1:
            errors.append(f"max_tokens must be positive, got {self.max_tokens}")

        if self.timeout < 1:
            errors.append(f"timeout must be positive, got {self.timeout}")

        if self.max_iterations < 1:
            errors.append(f"max_iterations must be positive, got {self.max_iterations}")

        return errors

    def is_valid(self) -> bool:
        """Check if configuration is valid"""
        return len(self.validate()) == 0

    def to_dict(self) -> dict:
        """Convert to dictionary (excluding sensitive data)"""
        return {
            "provider": self.provider,
            "model": self.model,
            "base_url": self.base_url,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "timeout": self.timeout,
            "max_retries": self.max_retries,
            "max_iterations": self.max_iterations,
            "has_api_key": self.api_key is not None,
        }


# Global configuration
_config: Optional[LLMConfig] = None


def get_llm_config() -> LLMConfig:
    """Get global LLM configuration (creates from env if not set)"""
    global _config
    if _config is None:
        _config = LLMConfig.from_env()
    return _config


def set_llm_config(config: LLMConfig) -> None:
    """Set global LLM configuration"""
    global _config
    _config = config
