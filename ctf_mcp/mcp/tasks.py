"""
MCP Long-Running Tasks Management
Task creation, tracking, cancellation, and status reporting
"""

import asyncio
import inspect
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Callable, Optional, Coroutine
from concurrent.futures import ThreadPoolExecutor
import threading

logger = logging.getLogger("ctf-mcp.mcp.tasks")


class TaskState(Enum):
    """Task execution state"""
    PENDING = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()
    CANCELLED = auto()
    TIMEOUT = auto()


class TaskPriority(Enum):
    """Task priority levels"""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class TaskProgress:
    """Task progress information"""
    current: int = 0
    total: int = 100
    message: str = ""
    percentage: float = 0.0

    def update(self, current: int, total: Optional[int] = None, message: str = ""):
        self.current = current
        if total is not None:
            self.total = total
        self.message = message
        self.percentage = (self.current / self.total * 100) if self.total > 0 else 0


@dataclass
class Task:
    """Long-running task representation"""
    id: str
    name: str
    state: TaskState = TaskState.PENDING
    priority: TaskPriority = TaskPriority.NORMAL
    progress: TaskProgress = field(default_factory=TaskProgress)
    result: Any = None
    error: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    timeout: float = 300.0
    metadata: dict[str, Any] = field(default_factory=dict)
    _cancel_event: threading.Event = field(default_factory=threading.Event)

    @property
    def duration(self) -> float:
        """Get task duration in seconds"""
        if self.started_at is None:
            return 0.0
        end_time = self.completed_at or datetime.now()
        return (end_time - self.started_at).total_seconds()

    @property
    def is_running(self) -> bool:
        return self.state == TaskState.RUNNING

    @property
    def is_complete(self) -> bool:
        return self.state in (TaskState.COMPLETED, TaskState.FAILED,
                              TaskState.CANCELLED, TaskState.TIMEOUT)

    def cancel(self) -> bool:
        """Request task cancellation"""
        if self.is_complete:
            return False
        self._cancel_event.set()
        return True

    def is_cancelled(self) -> bool:
        """Check if cancellation was requested"""
        return self._cancel_event.is_set()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "state": self.state.name,
            "priority": self.priority.name,
            "progress": {
                "current": self.progress.current,
                "total": self.progress.total,
                "percentage": self.progress.percentage,
                "message": self.progress.message,
            },
            "result": str(self.result)[:500] if self.result else None,
            "error": self.error,
            "duration": self.duration,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class TaskManager:
    """
    Manager for long-running tasks.

    Features:
    - Async and sync task execution
    - Progress tracking
    - Timeout control
    - Cancellation support
    - Result caching
    """

    def __init__(
        self,
        max_workers: int = 4,
        default_timeout: float = 300.0,
    ):
        """
        Initialize task manager.

        Args:
            max_workers: Maximum concurrent tasks
            default_timeout: Default task timeout in seconds
        """
        self.max_workers = max_workers
        self.default_timeout = default_timeout

        self._tasks: dict[str, Task] = {}
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._lock = threading.Lock()

    def create_task(
        self,
        name: str,
        timeout: Optional[float] = None,
        priority: TaskPriority = TaskPriority.NORMAL,
        metadata: Optional[dict] = None,
    ) -> Task:
        """
        Create a new task.

        Args:
            name: Task name
            timeout: Task timeout
            priority: Task priority
            metadata: Additional metadata

        Returns:
            Created Task
        """
        task_id = str(uuid.uuid4())[:8]

        task = Task(
            id=task_id,
            name=name,
            priority=priority,
            timeout=timeout or self.default_timeout,
            metadata=metadata or {},
        )

        with self._lock:
            self._tasks[task_id] = task

        logger.info("Created task: %s (%s)", task_id, name)
        return task

    def submit(
        self,
        func: Callable,
        *args,
        name: str = "task",
        timeout: Optional[float] = None,
        priority: TaskPriority = TaskPriority.NORMAL,
        **kwargs,
    ) -> Task:
        """
        Submit a function for execution.

        Args:
            func: Function to execute
            *args: Function arguments
            name: Task name
            timeout: Timeout
            priority: Priority
            **kwargs: Function keyword arguments

        Returns:
            Task object
        """
        task = self.create_task(name, timeout, priority)

        def run_task():
            task.state = TaskState.RUNNING
            task.started_at = datetime.now()

            try:
                # Check if function accepts 'task' parameter before passing it
                sig = inspect.signature(func)
                if 'task' in sig.parameters:
                    result = func(*args, task=task, **kwargs)
                else:
                    result = func(*args, **kwargs)
                task.result = result
                task.state = TaskState.COMPLETED

            except Exception as e:
                task.error = str(e)
                task.state = TaskState.FAILED
                logger.error("Task %s failed: %s", task.id, e)

            finally:
                task.completed_at = datetime.now()

        self._executor.submit(run_task)
        return task

    async def submit_async(
        self,
        coro: Coroutine,
        name: str = "async_task",
        timeout: Optional[float] = None,
        priority: TaskPriority = TaskPriority.NORMAL,
    ) -> Task:
        """
        Submit an async coroutine for execution.

        Args:
            coro: Coroutine to execute
            name: Task name
            timeout: Timeout
            priority: Priority

        Returns:
            Task object
        """
        task = self.create_task(name, timeout, priority)
        task.state = TaskState.RUNNING
        task.started_at = datetime.now()

        try:
            result = await asyncio.wait_for(
                coro,
                timeout=task.timeout
            )
            task.result = result
            task.state = TaskState.COMPLETED

        except asyncio.TimeoutError:
            task.state = TaskState.TIMEOUT
            task.error = f"Task timed out after {task.timeout}s"

        except asyncio.CancelledError:
            task.state = TaskState.CANCELLED
            task.error = "Task was cancelled"

        except Exception as e:
            task.state = TaskState.FAILED
            task.error = str(e)

        finally:
            task.completed_at = datetime.now()

        return task

    def get_task(self, task_id: str) -> Optional[Task]:
        """Get task by ID"""
        return self._tasks.get(task_id)

    def list_tasks(
        self,
        state: Optional[TaskState] = None,
        limit: int = 100,
    ) -> list[Task]:
        """
        List tasks.

        Args:
            state: Filter by state
            limit: Maximum results

        Returns:
            List of tasks
        """
        tasks = list(self._tasks.values())

        if state:
            tasks = [t for t in tasks if t.state == state]

        # Sort by created time (newest first)
        tasks.sort(key=lambda t: t.created_at, reverse=True)

        return tasks[:limit]

    def cancel_task(self, task_id: str) -> bool:
        """
        Cancel a task.

        Args:
            task_id: Task ID

        Returns:
            True if cancellation was requested
        """
        task = self.get_task(task_id)
        if task:
            if task.cancel():
                task.state = TaskState.CANCELLED
                task.completed_at = datetime.now()
                logger.info("Cancelled task: %s", task_id)
                return True
        return False

    def cleanup(self, max_age: float = 3600.0) -> int:
        """
        Remove old completed tasks.

        Args:
            max_age: Maximum age in seconds

        Returns:
            Number of tasks removed
        """
        now = datetime.now()
        to_remove = []

        with self._lock:
            for task_id, task in self._tasks.items():
                if task.is_complete and task.completed_at:
                    age = (now - task.completed_at).total_seconds()
                    if age > max_age:
                        to_remove.append(task_id)

            for task_id in to_remove:
                del self._tasks[task_id]

        return len(to_remove)

    def get_stats(self) -> dict:
        """Get task manager statistics"""
        states = {}
        for task in self._tasks.values():
            state_name = task.state.name
            states[state_name] = states.get(state_name, 0) + 1

        return {
            "total": len(self._tasks),
            "by_state": states,
            "max_workers": self.max_workers,
        }

    def shutdown(self, wait: bool = True) -> None:
        """Shutdown the task manager"""
        self._executor.shutdown(wait=wait)


# Convenience wrapper for task functions
class TaskContext:
    """
    Context object passed to task functions.

    Provides methods for progress reporting and cancellation checking.
    """

    def __init__(self, task: Task):
        self._task = task

    def update_progress(
        self,
        current: int,
        total: Optional[int] = None,
        message: str = "",
    ) -> None:
        """Update task progress"""
        self._task.progress.update(current, total, message)

    def is_cancelled(self) -> bool:
        """Check if task was cancelled"""
        return self._task.is_cancelled()

    def check_cancelled(self) -> None:
        """Raise exception if cancelled"""
        if self.is_cancelled():
            raise asyncio.CancelledError("Task was cancelled")

    def set_metadata(self, key: str, value: Any) -> None:
        """Set task metadata"""
        self._task.metadata[key] = value


# Global task manager
_manager: Optional[TaskManager] = None


def get_task_manager() -> TaskManager:
    """Get global task manager"""
    global _manager
    if _manager is None:
        _manager = TaskManager()
    return _manager


def create_task(name: str, **kwargs) -> Task:
    """Create a task using global manager"""
    return get_task_manager().create_task(name, **kwargs)


def submit_task(func: Callable, *args, **kwargs) -> Task:
    """Submit a task using global manager"""
    return get_task_manager().submit(func, *args, **kwargs)
