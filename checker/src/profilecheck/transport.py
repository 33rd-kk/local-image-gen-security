"""The only way the checker talks to the network.

Every request goes through `Transport.request`, which refuses any method but
GET, HEAD and OPTIONS and any host that is neither one the owner named nor
one of this computer's own addresses. It follows no redirects and reads at
most MAX_BODY bytes of an answer.
"""

from __future__ import annotations

import http.client
import ssl
from dataclasses import dataclass, field
from urllib.parse import urlsplit

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
MAX_BODY = 256 * 1024
USER_AGENT = "profilecheck (read-only security check)"


class RefusedRequest(Exception):
    """A request the checker's own rules do not allow."""


@dataclass
class Answer:
    status: int
    headers: dict[str, str]
    body: bytes

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())


@dataclass
class Transport:
    """Requests only to `allowed_hosts` (lowercase host names or addresses)."""

    allowed_hosts: set[str] = field(default_factory=set)
    timeout: float = 4.0
    sent: list[tuple[str, str]] = field(default_factory=list)  # (method, url), for tests and --verbose

    def allow(self, host: str) -> None:
        self.allowed_hosts.add(host.lower().strip("[]"))

    def request(self, method: str, url: str, headers: dict[str, str] | None = None, timeout: float | None = None) -> Answer | None:
        """The answer, or None when nothing answered (refused, timed out, not HTTP)."""
        method = method.upper()
        if method not in SAFE_METHODS:
            raise RefusedRequest(f"{method} is not a read-only method")
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        if parts.scheme not in ("http", "https") or not host:
            raise RefusedRequest(f"not an http(s) URL: {url}")
        if host not in self.allowed_hosts:
            raise RefusedRequest(f"{host} was not named and is not this computer")
        port = parts.port or (443 if parts.scheme == "https" else 80)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        wanted = {"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close", **(headers or {})}
        limit = self.timeout if timeout is None else timeout
        if parts.scheme == "https":
            connection: http.client.HTTPConnection = http.client.HTTPSConnection(host, port, timeout=limit, context=ssl.create_default_context())
        else:
            connection = http.client.HTTPConnection(host, port, timeout=limit)
        self.sent.append((method, url))
        try:
            # A Host header given by the caller (the DNS-rebinding check) replaces the real one.
            connection.putrequest(method, path, skip_host="Host" in wanted, skip_accept_encoding=True)
            for name, value in wanted.items():
                connection.putheader(name, value)
            connection.endheaders()
            response = connection.getresponse()
            body = b"" if method == "HEAD" else response.read(MAX_BODY)
            return Answer(response.status, {name.lower(): value for name, value in response.getheaders()}, body)
        except (OSError, http.client.HTTPException):  # timeouts and TLS errors are OSErrors
            return None
        finally:
            connection.close()
