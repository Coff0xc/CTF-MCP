"""
Remote Connection Module
TCP/UDP client for CTF challenge interaction
"""

import socket
import ssl
import time
import re
from dataclasses import dataclass, field
from typing import Optional, Union
from contextlib import contextmanager
import logging

logger = logging.getLogger("ctf-mcp.network.remote")


@dataclass
class ConnectionResult:
    """Result from a connection operation"""
    success: bool = False
    data: bytes = b""
    error: Optional[str] = None
    duration: float = 0.0

    @property
    def text(self) -> str:
        """Get data as text"""
        return self.data.decode('utf-8', errors='replace')

    def find_flag(self, pattern: str = r'flag\{[^}]+\}') -> Optional[str]:
        """Search for flag pattern in data"""
        match = re.search(pattern, self.text, re.IGNORECASE)
        return match.group(0) if match else None


class RemoteConnection:
    """
    TCP/UDP client for CTF challenges.

    Features:
    - TCP and UDP support
    - SSL/TLS support
    - Timeout management
    - Receive until pattern
    - Interactive mode support
    """

    def __init__(
        self,
        host: str,
        port: int,
        protocol: str = "tcp",
        timeout: float = 10.0,
        ssl_enabled: bool = False,
    ):
        """
        Initialize remote connection.

        Args:
            host: Target host
            port: Target port
            protocol: Protocol (tcp or udp)
            timeout: Connection timeout
            ssl_enabled: Enable SSL/TLS
        """
        self.host = host
        self.port = port
        self.protocol = protocol.lower()
        self.timeout = timeout
        self.ssl_enabled = ssl_enabled

        self._socket: Optional[socket.socket] = None
        self._connected = False
        self._buffer = b""

    @property
    def connected(self) -> bool:
        """Check if connected"""
        return self._connected and self._socket is not None

    def connect(self) -> ConnectionResult:
        """
        Establish connection.

        Returns:
            ConnectionResult with connection status
        """
        result = ConnectionResult()
        start_time = time.time()

        try:
            if self.protocol == "tcp":
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            else:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            self._socket.settimeout(self.timeout)

            if self.protocol == "tcp":
                self._socket.connect((self.host, self.port))

                if self.ssl_enabled:
                    try:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        self._socket = context.wrap_socket(
                            self._socket,
                            server_hostname=self.host
                        )
                    except Exception:
                        # Close socket if SSL wrap fails to prevent leak
                        if self._socket:
                            self._socket.close()
                            self._socket = None
                        raise

            self._connected = True
            result.success = True

        except socket.timeout:
            result.error = "Connection timed out"
        except ConnectionRefusedError:
            result.error = "Connection refused"
        except Exception as e:
            result.error = str(e)

        result.duration = time.time() - start_time
        return result

    def close(self) -> None:
        """Close connection"""
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
        self._socket = None
        self._connected = False
        self._buffer = b""

    def send(self, data: Union[bytes, str]) -> ConnectionResult:
        """
        Send data.

        Args:
            data: Data to send (bytes or str)

        Returns:
            ConnectionResult
        """
        result = ConnectionResult()

        if not self.connected:
            result.error = "Not connected"
            return result

        if isinstance(data, str):
            data = data.encode()

        try:
            if self.protocol == "tcp":
                self._socket.sendall(data)
            else:
                self._socket.sendto(data, (self.host, self.port))

            result.success = True
            result.data = data

        except Exception as e:
            result.error = str(e)

        return result

    def sendline(self, data: Union[bytes, str]) -> ConnectionResult:
        """
        Send data with newline.

        Args:
            data: Data to send

        Returns:
            ConnectionResult
        """
        if isinstance(data, str):
            data = data.encode()
        return self.send(data + b"\n")

    def recv(self, size: int = 4096, timeout: Optional[float] = None) -> ConnectionResult:
        """
        Receive data.

        Args:
            size: Maximum bytes to receive
            timeout: Receive timeout (None for default)

        Returns:
            ConnectionResult with received data
        """
        result = ConnectionResult()
        start_time = time.time()

        if not self.connected:
            result.error = "Not connected"
            return result

        try:
            if timeout is not None:
                self._socket.settimeout(timeout)

            if self.protocol == "tcp":
                data = self._socket.recv(size)
            else:
                data, _ = self._socket.recvfrom(size)

            result.success = True
            result.data = data
            self._buffer += data

        except socket.timeout:
            result.error = "Receive timed out"
        except Exception as e:
            result.error = str(e)
        finally:
            if self._socket:
                self._socket.settimeout(self.timeout)

        result.duration = time.time() - start_time
        return result

    def recvline(self, timeout: Optional[float] = None) -> ConnectionResult:
        """
        Receive until newline.

        Args:
            timeout: Receive timeout

        Returns:
            ConnectionResult with received line
        """
        result = ConnectionResult()
        start_time = time.time()

        if not self.connected:
            result.error = "Not connected"
            return result

        try:
            if timeout is not None:
                self._socket.settimeout(timeout)

            data = b""
            while b"\n" not in data:
                chunk = self._socket.recv(1)
                if not chunk:
                    break
                data += chunk

            result.success = True
            result.data = data
            self._buffer += data

        except socket.timeout:
            result.error = "Receive timed out"
        except Exception as e:
            result.error = str(e)
        finally:
            if self._socket:
                self._socket.settimeout(self.timeout)

        result.duration = time.time() - start_time
        return result

    def recvuntil(
        self,
        delim: Union[bytes, str],
        timeout: Optional[float] = None
    ) -> ConnectionResult:
        """
        Receive until delimiter.

        Args:
            delim: Delimiter to wait for
            timeout: Receive timeout

        Returns:
            ConnectionResult with received data
        """
        result = ConnectionResult()
        start_time = time.time()

        if not self.connected:
            result.error = "Not connected"
            return result

        if isinstance(delim, str):
            delim = delim.encode()

        try:
            if timeout is not None:
                self._socket.settimeout(timeout)

            data = b""
            while delim not in data:
                chunk = self._socket.recv(1)
                if not chunk:
                    break
                data += chunk

            result.success = True
            result.data = data
            self._buffer += data

        except socket.timeout:
            result.error = "Receive timed out"
            result.data = data  # Return partial data
        except Exception as e:
            result.error = str(e)
        finally:
            if self._socket:
                self._socket.settimeout(self.timeout)

        result.duration = time.time() - start_time
        return result

    def recvall(self, timeout: float = 2.0) -> ConnectionResult:
        """
        Receive all available data.

        Args:
            timeout: Time to wait for more data

        Returns:
            ConnectionResult with all received data
        """
        result = ConnectionResult()
        start_time = time.time()

        if not self.connected:
            result.error = "Not connected"
            return result

        try:
            self._socket.settimeout(timeout)
            data = b""

            while True:
                try:
                    chunk = self._socket.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                except socket.timeout:
                    break

            result.success = True
            result.data = data
            self._buffer += data

        except Exception as e:
            result.error = str(e)
        finally:
            if self._socket:
                self._socket.settimeout(self.timeout)

        result.duration = time.time() - start_time
        return result

    def sendafter(
        self,
        delim: Union[bytes, str],
        data: Union[bytes, str],
        timeout: Optional[float] = None
    ) -> ConnectionResult:
        """
        Wait for delimiter, then send data.

        Args:
            delim: Delimiter to wait for
            data: Data to send after delimiter
            timeout: Receive timeout

        Returns:
            ConnectionResult
        """
        recv_result = self.recvuntil(delim, timeout)
        if not recv_result.success:
            return recv_result

        return self.send(data)

    def sendlineafter(
        self,
        delim: Union[bytes, str],
        data: Union[bytes, str],
        timeout: Optional[float] = None
    ) -> ConnectionResult:
        """
        Wait for delimiter, then send data with newline.

        Args:
            delim: Delimiter to wait for
            data: Data to send
            timeout: Receive timeout

        Returns:
            ConnectionResult
        """
        recv_result = self.recvuntil(delim, timeout)
        if not recv_result.success:
            return recv_result

        return self.sendline(data)

    def interactive(self) -> None:
        """
        Enter interactive mode.

        Note: This is blocking and requires manual termination.
        """
        import sys
        import threading

        if not self.connected:
            print("Not connected")
            return

        print(f"[*] Switching to interactive mode (Ctrl+C to exit)")

        def recv_thread():
            while self.connected:
                try:
                    data = self._socket.recv(4096)
                    if data:
                        sys.stdout.write(data.decode('utf-8', errors='replace'))
                        sys.stdout.flush()
                except Exception:
                    break

        thread = threading.Thread(target=recv_thread, daemon=True)
        thread.start()

        try:
            while self.connected:
                line = input()
                self.sendline(line)
        except (KeyboardInterrupt, EOFError):
            print("\n[*] Exiting interactive mode")

    def __enter__(self):
        """Context manager entry"""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


@contextmanager
def remote(
    host: str,
    port: int,
    protocol: str = "tcp",
    timeout: float = 10.0,
    ssl_enabled: bool = False
):
    """
    Context manager for remote connection.

    Usage:
        with remote("host", 1234) as r:
            r.sendline("hello")
            print(r.recvline().text)
    """
    conn = RemoteConnection(host, port, protocol, timeout, ssl_enabled)
    result = conn.connect()

    if not result.success:
        raise ConnectionError(result.error)

    try:
        yield conn
    finally:
        conn.close()


def nc(host: str, port: int, timeout: float = 10.0) -> RemoteConnection:
    """
    Quick netcat-like connection.

    Args:
        host: Target host
        port: Target port
        timeout: Connection timeout

    Returns:
        Connected RemoteConnection
    """
    conn = RemoteConnection(host, port, timeout=timeout)
    result = conn.connect()

    if not result.success:
        raise ConnectionError(result.error)

    return conn


class RemotePool:
    """
    Pool of remote connections for parallel operations.
    """

    def __init__(self, max_connections: int = 10):
        self.max_connections = max_connections
        self._connections: list[RemoteConnection] = []

    def add(
        self,
        host: str,
        port: int,
        protocol: str = "tcp",
        timeout: float = 10.0
    ) -> RemoteConnection:
        """Add a new connection to pool"""
        if len(self._connections) >= self.max_connections:
            raise RuntimeError("Connection pool full")

        conn = RemoteConnection(host, port, protocol, timeout)
        self._connections.append(conn)
        return conn

    def connect_all(self) -> list[ConnectionResult]:
        """Connect all connections in pool"""
        return [conn.connect() for conn in self._connections]

    def close_all(self) -> None:
        """Close all connections"""
        for conn in self._connections:
            conn.close()
        self._connections.clear()

    def __len__(self) -> int:
        return len(self._connections)

    def __iter__(self):
        return iter(self._connections)
