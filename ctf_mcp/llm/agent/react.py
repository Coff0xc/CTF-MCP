"""
ReAct Agent

Implementation of ReAct (Reasoning + Acting) agent for CTF solving.
"""

import json
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from ..config import LLMConfig, get_llm_config
from ..providers.base import LLMProviderBase, LLMResponse, Message

logger = logging.getLogger("ctf-mcp.llm.agent.react")


class AgentState(Enum):
    """Agent execution state"""
    IDLE = "idle"
    THINKING = "thinking"
    ACTING = "acting"
    OBSERVING = "observing"
    FINISHED = "finished"
    ERROR = "error"


@dataclass
class AgentStep:
    """A single step in the agent's execution"""
    iteration: int
    thought: str = ""
    action: Optional[str] = None
    action_input: Optional[dict] = None
    observation: Optional[str] = None
    error: Optional[str] = None
    duration: float = 0.0

    def to_dict(self) -> dict:
        return {
            "iteration": self.iteration,
            "thought": self.thought,
            "action": self.action,
            "action_input": self.action_input,
            "observation": self.observation[:500] if self.observation else None,
            "error": self.error,
            "duration": self.duration,
        }


@dataclass
class AgentResult:
    """Result of agent execution"""
    success: bool
    answer: Optional[str] = None
    flag: Optional[str] = None
    steps: list[AgentStep] = field(default_factory=list)
    total_iterations: int = 0
    total_duration: float = 0.0
    error: Optional[str] = None
    state: AgentState = AgentState.FINISHED

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "answer": self.answer,
            "flag": self.flag,
            "total_iterations": self.total_iterations,
            "total_duration": self.total_duration,
            "error": self.error,
            "state": self.state.value,
            "steps": [s.to_dict() for s in self.steps],
        }


class ReActAgent:
    """
    ReAct (Reasoning + Acting) Agent for CTF solving.

    The agent follows a think-act-observe loop:
    1. Thought: Reason about what to do next
    2. Action: Call a tool
    3. Observation: Process tool result
    4. Repeat until task is complete or max iterations reached

    Format:
        Thought: <reasoning about what to do>
        Action: <tool_name>
        Action Input: <JSON arguments>

        OR:

        Final Answer: <the answer/flag>
    """

    SYSTEM_PROMPT = '''You are an expert CTF (Capture The Flag) challenge solver.
Your goal is to analyze challenges and find the flag.

You have access to various CTF tools for cryptography, web exploitation, binary analysis, and more.
Use the ReAct framework: Think step by step, take actions, observe results, and iterate.

For each step, you MUST respond in EXACTLY this format:

Thought: <your reasoning about what to do next>
Action: <tool_name>
Action Input: <JSON object with tool arguments>

OR when you have found the flag or completed the task:

Final Answer: <the flag or conclusion>

IMPORTANT RULES:
1. Always start with a Thought explaining your reasoning
2. Only call ONE tool per step
3. Wait for the observation before your next thought
4. Look for flags in format: flag{...}, FLAG{...}, CTF{...}
5. If stuck, try alternative approaches
6. Be systematic and thorough

Available tools:
{tools_description}

Challenge context:
{challenge_context}
'''

    # Regex patterns for parsing agent output
    THOUGHT_PATTERN = re.compile(r"Thought:\s*(.+?)(?=Action:|Final Answer:|$)", re.DOTALL | re.IGNORECASE)
    ACTION_PATTERN = re.compile(r"Action:\s*(\w+)", re.IGNORECASE)
    ACTION_INPUT_PATTERN = re.compile(r"Action Input:\s*({.+?}|\{[\s\S]*?\})", re.IGNORECASE)
    FINAL_ANSWER_PATTERN = re.compile(r"Final Answer:\s*(.+?)$", re.DOTALL | re.IGNORECASE)
    FLAG_PATTERN = re.compile(r"(flag\{[^}]+\}|FLAG\{[^}]+\}|CTF\{[^}]+\})", re.IGNORECASE)

    def __init__(
        self,
        config: Optional[LLMConfig] = None,
        tools: Optional[dict[str, Callable]] = None,
        verbose: bool = False,
    ):
        """
        Initialize the ReAct agent.

        Args:
            config: LLM configuration (uses global config if not provided)
            tools: Dictionary of tool name -> callable
            verbose: Enable verbose logging
        """
        self.config = config or get_llm_config()
        self.tools = tools or {}
        self.verbose = verbose or self.config.verbose

        self._provider: Optional[LLMProviderBase] = None
        self._conversation: list[Message] = []

    def _get_provider(self) -> LLMProviderBase:
        """Get LLM provider (lazy initialization)"""
        if self._provider is None:
            from ..providers import OpenAIProvider, AnthropicProvider, OllamaProvider

            provider_map = {
                "openai": OpenAIProvider,
                "azure": OpenAIProvider,
                "anthropic": AnthropicProvider,
                "ollama": OllamaProvider,
            }

            provider_class = provider_map.get(self.config.provider)
            if not provider_class:
                raise ValueError(f"Unknown provider: {self.config.provider}")

            self._provider = provider_class(self.config)

        return self._provider

    def register_tool(self, name: str, func: Callable, description: str = "") -> None:
        """Register a tool for the agent to use"""
        self.tools[name] = func
        if description:
            self.tools[f"_desc_{name}"] = description

    def _get_tools_description(self) -> str:
        """Generate tools description for the system prompt"""
        lines = []
        for name, func in self.tools.items():
            if name.startswith("_"):
                continue
            desc = self.tools.get(f"_desc_{name}", func.__doc__ or "No description")
            # Truncate long descriptions
            desc = desc.split("\n")[0][:100]
            lines.append(f"- {name}: {desc}")
        return "\n".join(lines) if lines else "No tools available"

    async def run(
        self,
        challenge_context: dict,
        max_iterations: Optional[int] = None,
    ) -> AgentResult:
        """
        Run the agent on a CTF challenge.

        Args:
            challenge_context: Dictionary with challenge information
                - description: Challenge description
                - files: List of file paths
                - remote: Remote connection info
                - patterns: Relevant solving patterns (from RAG)
            max_iterations: Maximum iterations (uses config if not provided)

        Returns:
            AgentResult with steps and final answer
        """
        max_iter = max_iterations or self.config.max_iterations
        provider = self._get_provider()

        # Build system prompt
        context_str = json.dumps(challenge_context, indent=2, ensure_ascii=False)
        system_prompt = self.SYSTEM_PROMPT.format(
            tools_description=self._get_tools_description(),
            challenge_context=context_str,
        )

        # Initialize conversation
        self._conversation = [Message.system(system_prompt)]
        self._conversation.append(Message.user("Please solve this CTF challenge and find the flag."))

        steps = []
        start_time = time.time()

        for iteration in range(1, max_iter + 1):
            step = AgentStep(iteration=iteration)
            step_start = time.time()

            try:
                if self.verbose:
                    logger.info("Iteration %d/%d", iteration, max_iter)

                # Get LLM response
                response = await provider.complete(self._conversation)
                output = response.content

                if self.verbose:
                    logger.debug("Agent output: %s", output[:500])

                # Parse response
                thought_match = self.THOUGHT_PATTERN.search(output)
                if thought_match:
                    step.thought = thought_match.group(1).strip()

                # Check for final answer
                final_match = self.FINAL_ANSWER_PATTERN.search(output)
                if final_match:
                    answer = final_match.group(1).strip()

                    # Extract flag from answer
                    flag_match = self.FLAG_PATTERN.search(answer)
                    flag = flag_match.group(1) if flag_match else None

                    step.duration = time.time() - step_start
                    steps.append(step)

                    return AgentResult(
                        success=True,
                        answer=answer,
                        flag=flag,
                        steps=steps,
                        total_iterations=iteration,
                        total_duration=time.time() - start_time,
                        state=AgentState.FINISHED,
                    )

                # Parse action
                action_match = self.ACTION_PATTERN.search(output)
                input_match = self.ACTION_INPUT_PATTERN.search(output)

                if action_match:
                    step.action = action_match.group(1)

                    # Parse action input
                    action_input = {}
                    if input_match:
                        try:
                            action_input = json.loads(input_match.group(1))
                        except json.JSONDecodeError:
                            # Try to fix common JSON issues
                            fixed = input_match.group(1).replace("'", '"')
                            try:
                                action_input = json.loads(fixed)
                            except json.JSONDecodeError:
                                step.error = f"Invalid JSON in Action Input: {input_match.group(1)}"

                    step.action_input = action_input

                    # Execute action
                    if step.action in self.tools:
                        try:
                            result = self.tools[step.action](**action_input)
                            # Handle async tools
                            if hasattr(result, "__await__"):
                                import asyncio
                                result = await result
                            step.observation = str(result)
                        except Exception as e:
                            step.observation = f"Error executing {step.action}: {e}"
                            step.error = str(e)
                    else:
                        step.observation = f"Unknown tool: {step.action}. Available: {list(self.tools.keys())}"

                    # Add assistant message and observation to conversation
                    self._conversation.append(Message.assistant(output))
                    self._conversation.append(Message.user(f"Observation: {step.observation}"))

                else:
                    # No action found, prompt to continue
                    step.error = "No action found in response"
                    self._conversation.append(Message.assistant(output))
                    self._conversation.append(Message.user(
                        "Please continue with the next step. "
                        "Use the format: Thought: ...\nAction: ...\nAction Input: {...}"
                    ))

            except Exception as e:
                logger.error("Agent error at iteration %d: %s", iteration, e)
                step.error = str(e)

            step.duration = time.time() - step_start
            steps.append(step)

            # Check if we should stop (e.g., found flag in observation)
            if step.observation:
                flag_match = self.FLAG_PATTERN.search(step.observation)
                if flag_match:
                    return AgentResult(
                        success=True,
                        answer=f"Found flag: {flag_match.group(1)}",
                        flag=flag_match.group(1),
                        steps=steps,
                        total_iterations=iteration,
                        total_duration=time.time() - start_time,
                        state=AgentState.FINISHED,
                    )

        # Max iterations reached
        return AgentResult(
            success=False,
            error="Maximum iterations reached without finding flag",
            steps=steps,
            total_iterations=max_iter,
            total_duration=time.time() - start_time,
            state=AgentState.ERROR,
        )

    def reset(self) -> None:
        """Reset agent state for a new challenge"""
        self._conversation = []
