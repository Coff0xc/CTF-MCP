"""
MCP Streaming Output
Real-time progress notifications and log streaming
"""

import asyncio
import json
import logging
import queue
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, AsyncIterator, Callable, Optional
from collections import deque
import threading

logger = logging.getLogger("ctf-mcp.mcp.streaming")


class StreamEventType(Enum):
    """Types of stream events"""
    PROGRESS = auto()      # Progress update
    LOG = auto()           # Log message
    STEP = auto()          # Solving step
    RESULT = auto()        # Partial result
    FLAG = auto()          # Flag found
    ERROR = auto()         # Error occurred
    COMPLETE = auto()      # Task complete
    HEARTBEAT = auto()     # Keep-alive


class LogLevel(Enum):
    """Log levels for streaming"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class StreamEvent:
    """A streaming event"""
    type: StreamEventType
    timestamp: datetime = field(default_factory=datetime.now)
    data: dict[str, Any] = field(default_factory=dict)
    message: str = ""
    task_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "type": self.type.name,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
            "message": self.message,
            "task_id": self.task_id,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class StreamBuffer:
    """
    Circular buffer for stream events.

    Thread-safe buffer with maximum size.
    Uses thread-safe queue for cross-thread communication.
    """

    def __init__(self, max_size: int = 1000):
        self.max_size = max_size
        self._buffer: deque[StreamEvent] = deque(maxlen=max_size)
        self._lock = threading.Lock()
        # Use thread-safe queue.Queue for cross-thread communication
        self._subscribers: list[queue.Queue] = []
        self._subscriber_lock = threading.Lock()

    def push(self, event: StreamEvent) -> None:
        """Add event to buffer (thread-safe)"""
        with self._lock:
            self._buffer.append(event)

        # Notify subscribers using thread-safe queue
        with self._subscriber_lock:
            for q in self._subscribers:
                try:
                    q.put_nowait(event)
                except queue.Full:
                    pass

    def get_recent(self, count: int = 100) -> list[StreamEvent]:
        """Get recent events"""
        with self._lock:
            return list(self._buffer)[-count:]

    def get_since(self, timestamp: datetime) -> list[StreamEvent]:
        """Get events since timestamp"""
        with self._lock:
            return [e for e in self._buffer if e.timestamp > timestamp]

    def subscribe(self) -> queue.Queue:
        """Subscribe to new events (returns thread-safe queue)"""
        q: queue.Queue = queue.Queue(maxsize=100)
        with self._subscriber_lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        """Unsubscribe from events"""
        with self._subscriber_lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def clear(self) -> None:
        """Clear buffer"""
        with self._lock:
            self._buffer.clear()


class StreamEmitter:
    """
    Emitter for streaming events.

    Use this to send progress updates, logs, and results.
    """

    def __init__(
        self,
        buffer: StreamBuffer,
        task_id: Optional[str] = None,
    ):
        self._buffer = buffer
        self._task_id = task_id

    def emit(
        self,
        event_type: StreamEventType,
        message: str = "",
        data: Optional[dict] = None,
    ) -> StreamEvent:
        """Emit an event"""
        event = StreamEvent(
            type=event_type,
            message=message,
            data=data or {},
            task_id=self._task_id,
        )
        self._buffer.push(event)
        return event

    def progress(
        self,
        current: int,
        total: int,
        message: str = "",
    ) -> StreamEvent:
        """Emit progress update"""
        percentage = (current / total * 100) if total > 0 else 0
        return self.emit(
            StreamEventType.PROGRESS,
            message=message,
            data={
                "current": current,
                "total": total,
                "percentage": round(percentage, 2),
            },
        )

    def log(
        self,
        message: str,
        level: LogLevel = LogLevel.INFO,
        details: Optional[dict] = None,
    ) -> StreamEvent:
        """Emit log message"""
        return self.emit(
            StreamEventType.LOG,
            message=message,
            data={
                "level": level.value,
                "details": details,
            },
        )

    def step(self, step_name: str, details: Optional[dict] = None) -> StreamEvent:
        """Emit solving step"""
        return self.emit(
            StreamEventType.STEP,
            message=step_name,
            data={"details": details},
        )

    def result(self, result_data: Any, partial: bool = True) -> StreamEvent:
        """Emit result"""
        return self.emit(
            StreamEventType.RESULT,
            data={
                "result": str(result_data)[:1000],
                "partial": partial,
            },
        )

    def flag(self, flag: str) -> StreamEvent:
        """Emit flag found"""
        return self.emit(
            StreamEventType.FLAG,
            message=f"Flag found: {flag}",
            data={"flag": flag},
        )

    def error(self, error: str, details: Optional[dict] = None) -> StreamEvent:
        """Emit error"""
        return self.emit(
            StreamEventType.ERROR,
            message=error,
            data={"details": details},
        )

    def complete(self, success: bool, summary: str = "") -> StreamEvent:
        """Emit completion"""
        return self.emit(
            StreamEventType.COMPLETE,
            message=summary,
            data={"success": success},
        )


class StreamManager:
    """
    Central manager for all streaming operations.

    Features:
    - Multiple named streams
    - Event routing
    - Async iteration
    - Heartbeat support
    """

    def __init__(self):
        self._streams: dict[str, StreamBuffer] = {}
        self._global_buffer = StreamBuffer()
        self._heartbeat_task: Optional[asyncio.Task] = None

    def get_stream(self, name: str) -> StreamBuffer:
        """Get or create a named stream"""
        if name not in self._streams:
            self._streams[name] = StreamBuffer()
        return self._streams[name]

    def get_emitter(
        self,
        stream_name: str = "default",
        task_id: Optional[str] = None,
    ) -> StreamEmitter:
        """Get an emitter for a stream"""
        buffer = self.get_stream(stream_name)
        return StreamEmitter(buffer, task_id)

    def emit_global(
        self,
        event_type: StreamEventType,
        message: str = "",
        data: Optional[dict] = None,
    ) -> StreamEvent:
        """Emit to global stream"""
        event = StreamEvent(
            type=event_type,
            message=message,
            data=data or {},
        )
        self._global_buffer.push(event)
        return event

    async def iter_stream(
        self,
        stream_name: str,
        timeout: Optional[float] = None,
    ) -> AsyncIterator[StreamEvent]:
        """
        Async iterator for stream events.

        Args:
            stream_name: Stream name
            timeout: Iteration timeout

        Yields:
            StreamEvent objects
        """
        buffer = self.get_stream(stream_name)
        q = buffer.subscribe()

        try:
            start_time = time.time()
            while True:
                if timeout and (time.time() - start_time) > timeout:
                    break

                try:
                    # Poll the thread-safe queue with a short timeout
                    # Run in executor to avoid blocking the event loop
                    loop = asyncio.get_event_loop()
                    try:
                        event = await asyncio.wait_for(
                            loop.run_in_executor(None, lambda: q.get(timeout=0.1)),
                            timeout=1.0
                        )
                    except queue.Empty:
                        continue

                    yield event

                    # Stop on completion
                    if event.type == StreamEventType.COMPLETE:
                        break

                except asyncio.TimeoutError:
                    continue

        finally:
            buffer.unsubscribe(q)

    async def iter_global(
        self,
        timeout: Optional[float] = None,
    ) -> AsyncIterator[StreamEvent]:
        """Async iterator for global events"""
        q = self._global_buffer.subscribe()

        try:
            start_time = time.time()
            while True:
                if timeout and (time.time() - start_time) > timeout:
                    break

                try:
                    # Poll the thread-safe queue with a short timeout
                    loop = asyncio.get_event_loop()
                    try:
                        event = await asyncio.wait_for(
                            loop.run_in_executor(None, lambda: q.get(timeout=0.1)),
                            timeout=1.0
                        )
                    except queue.Empty:
                        continue

                    yield event
                except asyncio.TimeoutError:
                    continue

        finally:
            self._global_buffer.unsubscribe(q)

    def get_recent_events(
        self,
        stream_name: str = "default",
        count: int = 100,
    ) -> list[StreamEvent]:
        """Get recent events from stream"""
        buffer = self.get_stream(stream_name)
        return buffer.get_recent(count)

    async def start_heartbeat(self, interval: float = 30.0) -> None:
        """Start heartbeat emitter"""
        async def heartbeat_loop():
            while True:
                await asyncio.sleep(interval)
                self.emit_global(
                    StreamEventType.HEARTBEAT,
                    message="heartbeat",
                    data={"timestamp": time.time()},
                )

        self._heartbeat_task = asyncio.create_task(heartbeat_loop())

    def stop_heartbeat(self) -> None:
        """Stop heartbeat emitter"""
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            self._heartbeat_task = None

    def list_streams(self) -> list[str]:
        """List all stream names"""
        return list(self._streams.keys())

    def clear_stream(self, stream_name: str) -> None:
        """Clear a stream buffer"""
        if stream_name in self._streams:
            self._streams[stream_name].clear()

    def delete_stream(self, stream_name: str) -> bool:
        """Delete a stream"""
        if stream_name in self._streams:
            del self._streams[stream_name]
            return True
        return False


# Global stream manager
_manager: Optional[StreamManager] = None


def get_stream_manager() -> StreamManager:
    """Get global stream manager"""
    global _manager
    if _manager is None:
        _manager = StreamManager()
    return _manager


def emit(
    event_type: StreamEventType,
    message: str = "",
    data: Optional[dict] = None,
    stream: str = "default",
) -> StreamEvent:
    """Convenience function to emit event"""
    manager = get_stream_manager()
    emitter = manager.get_emitter(stream)
    return emitter.emit(event_type, message, data)


def progress(current: int, total: int, message: str = "", stream: str = "default") -> StreamEvent:
    """Convenience function to emit progress"""
    return emit(
        StreamEventType.PROGRESS,
        message=message,
        data={"current": current, "total": total},
        stream=stream,
    )


def log(message: str, level: str = "info", stream: str = "default") -> StreamEvent:
    """Convenience function to emit log"""
    return emit(
        StreamEventType.LOG,
        message=message,
        data={"level": level},
        stream=stream,
    )
