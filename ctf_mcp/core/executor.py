"""
CTF Strategy Executor
Executes solving strategies with timeout, retry, and error handling
"""

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, TYPE_CHECKING

from .planner import SolvingStrategy, StrategyStep, StepType

if TYPE_CHECKING:
    from .orchestrator import Challenge

logger = logging.getLogger("ctf-mcp.executor")


class ExecutionStatus(Enum):
    """Status of strategy execution"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL = "partial"  # Some steps succeeded
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


@dataclass
class StepResult:
    """Result of executing a single step"""
    step_index: int
    status: ExecutionStatus
    output: Any = None
    error: Optional[str] = None
    duration: float = 0.0
    flag_candidates: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step_index,
            "status": self.status.value,
            "output": str(self.output)[:500] if self.output else None,
            "error": self.error,
            "duration": self.duration,
            "flag_candidates": self.flag_candidates,
        }


@dataclass
class ExecutionResult:
    """Result of executing a complete strategy"""
    strategy_name: str
    status: ExecutionStatus
    step_results: list[StepResult] = field(default_factory=list)
    flag: Optional[str] = None
    total_duration: float = 0.0
    error: Optional[str] = None

    @property
    def successful_steps(self) -> int:
        return sum(1 for r in self.step_results if r.status == ExecutionStatus.SUCCESS)

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy": self.strategy_name,
            "status": self.status.value,
            "steps_completed": f"{self.successful_steps}/{len(self.step_results)}",
            "flag": self.flag,
            "duration": self.total_duration,
            "error": self.error,
        }


class StrategyExecutor:
    """
    Executes CTF solving strategies.

    Features:
    - Async execution with timeout
    - Step-by-step execution with dependencies
    - Automatic flag extraction
    - Retry on failure
    - Graceful cancellation
    """

    # Common flag patterns
    FLAG_PATTERNS = [
        r'flag\{[^}]+\}',
        r'FLAG\{[^}]+\}',
        r'ctf\{[^}]+\}',
        r'CTF\{[^}]+\}',
        r'picoCTF\{[^}]+\}',
        r'HTB\{[^}]+\}',
        r'FLAG-[A-Za-z0-9-]+',
        r'flag:[A-Za-z0-9+/=]+',
    ]

    def __init__(
        self,
        max_retries: int = 2,
        step_timeout: float = 60.0,
    ):
        """
        Initialize the executor.

        Args:
            max_retries: Maximum retries per step
            step_timeout: Default timeout per step in seconds
        """
        self.max_retries = max_retries
        self.step_timeout = step_timeout
        self._tools_module = None
        self._cancelled = False

    async def execute(
        self,
        strategy: SolvingStrategy,
        challenge: "Challenge",
        timeout: float = 300.0,
    ) -> ExecutionResult:
        """
        Execute a solving strategy.

        Args:
            strategy: Strategy to execute
            challenge: Challenge being solved
            timeout: Maximum execution time

        Returns:
            ExecutionResult with status and any found flag
        """
        start_time = time.time()
        self._cancelled = False
        step_results: list[StepResult] = []
        context: dict[str, Any] = {
            "challenge": challenge,
            "files": challenge.files,
            "remote": challenge.remote,
        }

        logger.info("Executing strategy: %s", strategy.name)

        try:
            for i, step in enumerate(strategy.steps):
                # Check timeout
                elapsed = time.time() - start_time
                if elapsed >= timeout:
                    logger.warning("Strategy timeout after step %s", i)
                    return ExecutionResult(
                        strategy_name=strategy.name,
                        status=ExecutionStatus.TIMEOUT,
                        step_results=step_results,
                        total_duration=elapsed,
                    )

                # Check cancellation
                if self._cancelled:
                    return ExecutionResult(
                        strategy_name=strategy.name,
                        status=ExecutionStatus.CANCELLED,
                        step_results=step_results,
                        total_duration=time.time() - start_time,
                    )

                # Check dependencies
                if not self._check_dependencies(step, step_results):
                    logger.debug("Skipping step %d due to failed dependencies", i)
                    step_results.append(StepResult(
                        step_index=i,
                        status=ExecutionStatus.FAILED,
                        error="Dependency not satisfied",
                    ))
                    continue

                # Execute step with retry
                step_timeout = min(step.timeout, timeout - elapsed)
                result = await self._execute_step_with_retry(
                    step, i, context, step_timeout
                )
                step_results.append(result)

                # Update context with results
                if result.output:
                    context[f"step_{i}_output"] = result.output

                # Check for flags
                if result.flag_candidates:
                    # Return first valid flag
                    flag = result.flag_candidates[0]
                    logger.info("Found flag candidate: %s", flag)
                    return ExecutionResult(
                        strategy_name=strategy.name,
                        status=ExecutionStatus.SUCCESS,
                        step_results=step_results,
                        flag=flag,
                        total_duration=time.time() - start_time,
                    )

                # Handle step failure
                if result.status == ExecutionStatus.FAILED:
                    if step.on_failure is not None:
                        # Jump to failure handler
                        logger.debug("Step %d failed, jumping to step %s", i, step.on_failure)
                        continue
                    # Check if we can continue
                    if not self._can_continue_after_failure(strategy, i):
                        break

            # Determine final status
            successful = sum(1 for r in step_results if r.status == ExecutionStatus.SUCCESS)
            if successful == len(strategy.steps):
                status = ExecutionStatus.SUCCESS
            elif successful > 0:
                status = ExecutionStatus.PARTIAL
            else:
                status = ExecutionStatus.FAILED

            return ExecutionResult(
                strategy_name=strategy.name,
                status=status,
                step_results=step_results,
                total_duration=time.time() - start_time,
            )

        except asyncio.CancelledError:
            logger.info("Strategy execution cancelled")
            return ExecutionResult(
                strategy_name=strategy.name,
                status=ExecutionStatus.CANCELLED,
                step_results=step_results,
                total_duration=time.time() - start_time,
            )
        except Exception as e:
            logger.error("Strategy execution error: %s", e)
            return ExecutionResult(
                strategy_name=strategy.name,
                status=ExecutionStatus.FAILED,
                step_results=step_results,
                error=str(e),
                total_duration=time.time() - start_time,
            )

    async def _execute_step_with_retry(
        self,
        step: StrategyStep,
        index: int,
        context: dict[str, Any],
        timeout: float,
    ) -> StepResult:
        """Execute a step with retry on failure"""
        last_error = None

        for attempt in range(self.max_retries + 1):
            try:
                result = await asyncio.wait_for(
                    self._execute_step(step, index, context),
                    timeout=timeout,
                )
                if result.status == ExecutionStatus.SUCCESS:
                    return result
                last_error = result.error

            except asyncio.TimeoutError:
                last_error = "Step timeout"
                logger.warning("Step %s timeout (attempt %s)", index, attempt + 1)

            except Exception as e:
                last_error = str(e)
                logger.warning("Step %s error (attempt %s): %s", index, attempt + 1, e)

            # Brief delay before retry
            if attempt < self.max_retries:
                await asyncio.sleep(0.5)

        return StepResult(
            step_index=index,
            status=ExecutionStatus.FAILED,
            error=last_error,
        )

    async def _execute_step(
        self,
        step: StrategyStep,
        index: int,
        context: dict[str, Any],
    ) -> StepResult:
        """Execute a single step"""
        start_time = time.time()
        logger.debug("Executing step %d: %s", index, step.description)

        try:
            if step.step_type == StepType.TOOL:
                output = await self._execute_tool(step, context)
            elif step.step_type == StepType.ANALYZE:
                output = await self._analyze(step, context)
            elif step.step_type == StepType.EXTRACT:
                output = await self._extract_flag(context)
            elif step.step_type == StepType.VALIDATE:
                output = await self._validate(step, context)
            elif step.step_type == StepType.REMOTE:
                output = await self._remote_interaction(step, context)
            elif step.step_type == StepType.MANUAL:
                output = "Manual step - requires user intervention"
            else:
                output = None

            # Search for flags in output
            flag_candidates = self._find_flags(str(output) if output else "")

            duration = time.time() - start_time
            return StepResult(
                step_index=index,
                status=ExecutionStatus.SUCCESS,
                output=output,
                duration=duration,
                flag_candidates=flag_candidates,
            )

        except Exception as e:
            return StepResult(
                step_index=index,
                status=ExecutionStatus.FAILED,
                error=str(e),
                duration=time.time() - start_time,
            )

    async def _execute_tool(
        self,
        step: StrategyStep,
        context: dict[str, Any],
    ) -> Any:
        """Execute a CTF-MCP tool"""
        if not step.tool_name:
            raise ValueError("Tool name not specified")

        # Resolve parameters
        params = self._resolve_params(step.params, context)

        # Get tools module
        tools = self._get_tools_module()

        # Parse tool name (format: module_toolname)
        parts = step.tool_name.split("_", 1)
        if len(parts) != 2:
            raise ValueError(f"Invalid tool name format: {step.tool_name}")

        module_name, method_name = parts

        # Get module
        module_map = {
            "crypto": tools.crypto_tools,
            "web": tools.web_tools,
            "pwn": tools.pwn_tools,
            "reverse": tools.reverse_tools,
            "forensics": tools.forensics_tools,
            "misc": tools.misc_tools,
        }

        module = module_map.get(module_name)
        if not module:
            raise ValueError(f"Unknown module: {module_name}")

        # Get method
        if not hasattr(module, method_name):
            raise ValueError(f"Tool not found: {step.tool_name}")

        method = getattr(module, method_name)

        # Execute
        logger.debug("Calling %s with params: %s", step.tool_name, params)
        result = await asyncio.to_thread(method, **params)

        return result

    async def _analyze(
        self,
        step: StrategyStep,
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Analyze challenge data"""
        analysis = {}

        # Extract data from files
        challenge = context.get("challenge")
        if challenge and challenge.files:
            for file_path in challenge.files:
                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                    # Look for common patterns
                    analysis["file_content_preview"] = content[:1000]

                    # RSA parameters
                    n_match = re.search(r'n\s*[=:]\s*(\d+)', content)
                    if n_match:
                        analysis["n"] = n_match.group(1)
                    e_match = re.search(r'e\s*[=:]\s*(\d+)', content)
                    if e_match:
                        analysis["e"] = e_match.group(1)
                    c_match = re.search(r'c\s*[=:]\s*(\d+)', content)
                    if c_match:
                        analysis["c"] = c_match.group(1)

                except (IOError, UnicodeDecodeError):
                    pass

        # Update context with analysis
        context.update(analysis)
        return analysis

    async def _extract_flag(self, context: dict[str, Any]) -> list[str]:
        """Extract flags from accumulated context"""
        flags = []

        # Search all context values for flags
        for key, value in context.items():
            if isinstance(value, str):
                flags.extend(self._find_flags(value))
            elif isinstance(value, dict):
                for v in value.values():
                    if isinstance(v, str):
                        flags.extend(self._find_flags(v))

        return list(set(flags))

    async def _validate(
        self,
        step: StrategyStep,
        context: dict[str, Any],
    ) -> bool:
        """Validate a result"""
        # Basic validation - check if flag exists
        return bool(context.get("flag"))

    async def _remote_interaction(
        self,
        step: StrategyStep,
        context: dict[str, Any],
    ) -> str:
        """Handle remote interaction (placeholder)"""
        # This would be implemented with pwntools remote/ssh
        # For now, return placeholder
        remote = context.get("remote")
        if not remote:
            return "No remote endpoint specified"

        return f"Remote interaction with {remote} - requires implementation"

    def _resolve_params(
        self,
        params: dict[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        """Resolve parameter placeholders from context"""
        resolved = {}

        for key, value in params.items():
            if isinstance(value, str) and value.startswith("{") and value.endswith("}"):
                var_name = value[1:-1]
                if var_name in context:
                    resolved[key] = context[var_name]
                else:
                    # Keep original if not found
                    resolved[key] = value
            else:
                resolved[key] = value

        return resolved

    def _find_flags(self, text: str) -> list[str]:
        """Find flag patterns in text"""
        flags = []
        for pattern in self.FLAG_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            flags.extend(matches)
        return list(set(flags))

    def _check_dependencies(
        self,
        step: StrategyStep,
        results: list[StepResult],
    ) -> bool:
        """Check if step dependencies are satisfied"""
        for dep_index in step.depends_on:
            if dep_index >= len(results):
                return False
            if results[dep_index].status != ExecutionStatus.SUCCESS:
                return False
        return True

    def _can_continue_after_failure(
        self,
        strategy: SolvingStrategy,
        failed_index: int,
    ) -> bool:
        """Check if execution can continue after a step failure"""
        # Check if any remaining steps don't depend on failed step
        for i, step in enumerate(strategy.steps[failed_index + 1:], failed_index + 1):
            if failed_index not in step.depends_on:
                return True
        return False

    def _get_tools_module(self):
        """Get or import tools module"""
        if self._tools_module is None:
            from ctf_mcp import server
            self._tools_module = server
        return self._tools_module

    def cancel(self):
        """Cancel current execution"""
        self._cancelled = True
