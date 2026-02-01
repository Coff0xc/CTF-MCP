"""
HTTP Client Module
Async HTTP client for web-based CTF challenges
"""

import asyncio
import time
import re
from dataclasses import dataclass, field
from typing import Any, Optional, Union
from urllib.parse import urljoin, urlparse
import logging

logger = logging.getLogger("ctf-mcp.network.http")

# Try to import httpx for async support
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

# Fallback to requests
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


@dataclass
class HTTPResponse:
    """HTTP response wrapper"""
    success: bool = False
    status_code: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    text: str = ""
    content: bytes = b""
    url: str = ""
    elapsed: float = 0.0
    error: Optional[str] = None

    def json(self) -> Any:
        """Parse response as JSON"""
        import json
        return json.loads(self.text)

    def find_flag(self, pattern: str = r'flag\{[^}]+\}') -> Optional[str]:
        """Search for flag pattern"""
        match = re.search(pattern, self.text, re.IGNORECASE)
        return match.group(0) if match else None

    def find_all(self, pattern: str) -> list[str]:
        """Find all matches of pattern"""
        return re.findall(pattern, self.text)


class HTTPClient:
    """
    HTTP client for CTF web challenges.

    Features:
    - Session management
    - Cookie handling
    - Proxy support
    - Auto redirect following
    - Request retry
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout: float = 30.0,
        verify_ssl: bool = False,
        proxy: Optional[str] = None,
        headers: Optional[dict] = None,
    ):
        """
        Initialize HTTP client.

        Args:
            base_url: Base URL for requests
            timeout: Request timeout
            verify_ssl: Verify SSL certificates
            proxy: Proxy URL (e.g., "http://127.0.0.1:8080")
            headers: Default headers
        """
        self.base_url = base_url
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self.default_headers = headers or {}

        self._session = None
        self._cookies: dict[str, str] = {}

    def _build_url(self, path: str) -> str:
        """Build full URL from path"""
        if path.startswith('http'):
            return path
        if self.base_url:
            return urljoin(self.base_url, path)
        return path

    def _create_session(self):
        """Create HTTP session"""
        if HTTPX_AVAILABLE:
            return httpx.Client(
                timeout=self.timeout,
                verify=self.verify_ssl,
                follow_redirects=True,
                proxies={"all://": self.proxy} if self.proxy else None,
            )
        elif REQUESTS_AVAILABLE:
            session = requests.Session()
            session.verify = self.verify_ssl
            if self.proxy:
                session.proxies = {"http": self.proxy, "https": self.proxy}
            return session
        else:
            raise RuntimeError("No HTTP library available (install httpx or requests)")

    def _to_response(self, resp, elapsed: float) -> HTTPResponse:
        """Convert library response to HTTPResponse"""
        result = HTTPResponse(
            success=True,
            status_code=resp.status_code,
            text=resp.text,
            content=resp.content,
            elapsed=elapsed,
        )

        # Headers
        if hasattr(resp, 'headers'):
            result.headers = dict(resp.headers)

        # Cookies
        if hasattr(resp, 'cookies'):
            result.cookies = dict(resp.cookies)

        # URL
        if hasattr(resp, 'url'):
            result.url = str(resp.url)

        return result

    def get(
        self,
        url: str,
        params: Optional[dict] = None,
        headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
    ) -> HTTPResponse:
        """
        Send GET request.

        Args:
            url: Request URL
            params: Query parameters
            headers: Request headers
            cookies: Request cookies

        Returns:
            HTTPResponse
        """
        return self._request("GET", url, params=params, headers=headers, cookies=cookies)

    def post(
        self,
        url: str,
        data: Optional[dict] = None,
        json: Optional[dict] = None,
        headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
    ) -> HTTPResponse:
        """
        Send POST request.

        Args:
            url: Request URL
            data: Form data
            json: JSON data
            headers: Request headers
            cookies: Request cookies

        Returns:
            HTTPResponse
        """
        return self._request("POST", url, data=data, json=json, headers=headers, cookies=cookies)

    def put(
        self,
        url: str,
        data: Optional[dict] = None,
        json: Optional[dict] = None,
        headers: Optional[dict] = None,
    ) -> HTTPResponse:
        """Send PUT request"""
        return self._request("PUT", url, data=data, json=json, headers=headers)

    def delete(self, url: str, headers: Optional[dict] = None) -> HTTPResponse:
        """Send DELETE request"""
        return self._request("DELETE", url, headers=headers)

    def _request(
        self,
        method: str,
        url: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        json: Optional[dict] = None,
        headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
    ) -> HTTPResponse:
        """Internal request method"""
        result = HTTPResponse()
        full_url = self._build_url(url)

        # Merge headers
        req_headers = {**self.default_headers}
        if headers:
            req_headers.update(headers)

        # Merge cookies
        req_cookies = {**self._cookies}
        if cookies:
            req_cookies.update(cookies)

        start_time = time.time()

        try:
            if self._session is None:
                self._session = self._create_session()

            if HTTPX_AVAILABLE and isinstance(self._session, httpx.Client):
                resp = self._session.request(
                    method,
                    full_url,
                    params=params,
                    data=data,
                    json=json,
                    headers=req_headers,
                    cookies=req_cookies,
                )
            else:
                resp = self._session.request(
                    method,
                    full_url,
                    params=params,
                    data=data,
                    json=json,
                    headers=req_headers,
                    cookies=req_cookies,
                    timeout=self.timeout,
                )

            elapsed = time.time() - start_time
            result = self._to_response(resp, elapsed)

            # Update session cookies
            self._cookies.update(result.cookies)

        except Exception as e:
            result.error = str(e)
            result.elapsed = time.time() - start_time

        return result

    def set_cookie(self, name: str, value: str) -> None:
        """Set a cookie"""
        self._cookies[name] = value

    def get_cookie(self, name: str) -> Optional[str]:
        """Get a cookie value"""
        return self._cookies.get(name)

    def clear_cookies(self) -> None:
        """Clear all cookies"""
        self._cookies.clear()

    def close(self) -> None:
        """Close the session"""
        if self._session:
            self._session.close()
            self._session = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class AsyncHTTPClient:
    """
    Async HTTP client for parallel requests.
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout: float = 30.0,
        verify_ssl: bool = False,
        proxy: Optional[str] = None,
    ):
        self.base_url = base_url
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        self._client: Optional[httpx.AsyncClient] = None

    def _build_url(self, path: str) -> str:
        if path.startswith('http'):
            return path
        if self.base_url:
            return urljoin(self.base_url, path)
        return path

    async def _get_client(self) -> "httpx.AsyncClient":
        if not HTTPX_AVAILABLE:
            raise RuntimeError("httpx required for async HTTP")

        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                verify=self.verify_ssl,
                follow_redirects=True,
                proxies={"all://": self.proxy} if self.proxy else None,
            )
        return self._client

    async def get(self, url: str, **kwargs) -> HTTPResponse:
        """Async GET request"""
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> HTTPResponse:
        """Async POST request"""
        return await self._request("POST", url, **kwargs)

    async def _request(self, method: str, url: str, **kwargs) -> HTTPResponse:
        """Internal async request"""
        result = HTTPResponse()
        full_url = self._build_url(url)
        start_time = time.time()

        try:
            client = await self._get_client()
            resp = await client.request(method, full_url, **kwargs)

            result.success = True
            result.status_code = resp.status_code
            result.headers = dict(resp.headers)
            result.text = resp.text
            result.content = resp.content
            result.url = str(resp.url)

        except Exception as e:
            result.error = str(e)

        result.elapsed = time.time() - start_time
        return result

    async def parallel_get(self, urls: list[str]) -> list[HTTPResponse]:
        """Execute parallel GET requests"""
        tasks = [self.get(url) for url in urls]
        return await asyncio.gather(*tasks)

    async def close(self) -> None:
        """Close async client"""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


# Convenience functions

def get(url: str, **kwargs) -> HTTPResponse:
    """Quick GET request"""
    with HTTPClient() as client:
        return client.get(url, **kwargs)


def post(url: str, **kwargs) -> HTTPResponse:
    """Quick POST request"""
    with HTTPClient() as client:
        return client.post(url, **kwargs)


def session(base_url: Optional[str] = None, **kwargs) -> HTTPClient:
    """Create HTTP session"""
    return HTTPClient(base_url=base_url, **kwargs)
