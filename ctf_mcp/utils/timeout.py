"""
Timeout utilities for CTF-MCP
Provides timeout mechanisms for long-running operations
"""

import signal
import functools
from typing import Callable, Any, Optional


class TimeoutError(Exception):
    """Custom timeout exception"""
    pass


def timeout(seconds: int = 30, error_message: Optional[str] = None):
    """
    Decorator to add timeout to functions

    Args:
        seconds: Timeout in seconds
        error_message: Custom error message

    Example:
        @timeout(seconds=10)
        def long_running_operation():
            # Implementation
            pass

    Note:
        This uses SIGALRM which is not available on Windows.
        On Windows, this decorator will not enforce timeouts.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # Check if signal.SIGALRM is available (Unix-like systems)
            if not hasattr(signal, 'SIGALRM'):
                # Windows or other platforms without SIGALRM
                # Just execute the function without timeout
                return func(*args, **kwargs)

            def timeout_handler(signum, frame):
                msg = error_message or f"Function {func.__name__} timed out after {seconds}s"
                raise TimeoutError(msg)

            # Set signal handler
            old_handler = signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(seconds)

            try:
                result = func(*args, **kwargs)
            finally:
                # Disable alarm and restore old handler
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)

            return result

        return wrapper
    return decorator


class TimeoutContext:
    """
    Context manager for timeout operations

    Example:
        with TimeoutContext(seconds=10):
            # Long running operation
            pass
    """

    def __init__(self, seconds: int = 30, error_message: Optional[str] = None):
        self.seconds = seconds
        self.error_message = error_message or f"Operation timed out after {seconds}s"
        self.old_handler = None

    def __enter__(self):
        if not hasattr(signal, 'SIGALRM'):
            return self

        def timeout_handler(signum, frame):
            raise TimeoutError(self.error_message)

        self.old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(self.seconds)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if hasattr(signal, 'SIGALRM'):
            signal.alarm(0)
            if self.old_handler:
                signal.signal(signal.SIGALRM, self.old_handler)
        return False
