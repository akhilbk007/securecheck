"""Minimal HTTP client that connects only to pre-validated IP addresses.

Built on the standard library so the connection path is fully under our
control: the TCP socket goes to the IP that netguard approved, while SNI and
the Host header still carry the hostname.
"""
from __future__ import annotations

import http.client
import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import urljoin

from .netguard import Target, TargetError, parse_target, resolve_public

TIMEOUT = 8.0
MAX_BODY = 512 * 1024
MAX_REDIRECTS = 5
USER_AGENT = "SecureCheck/1.0 (passive security header check)"


class FetchError(Exception):
    pass


@dataclass
class Response:
    url: str
    status: int
    headers: list[tuple[str, str]]
    body: bytes = b""
    ip: str = ""
    cert_verified: bool = True
    redirects: list[str] = field(default_factory=list)

    def header(self, name: str) -> str | None:
        """Last value wins for single-valued headers, joined for lists."""
        values = self.header_all(name)
        return ", ".join(values) if values else None

    def header_all(self, name: str) -> list[str]:
        name = name.lower()
        return [v for k, v in self.headers if k.lower() == name]


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, ip, context, timeout):
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned_ip = ip
        self._ctx = context

    def connect(self):
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        self.sock = self._ctx.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port, ip, timeout):
        super().__init__(host, port, timeout=timeout)
        self._pinned_ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)


def _context(verify: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch_once(target: Target, extra_headers: dict[str, str] | None = None,
               ip: str | None = None) -> Response:
    """One GET request, no redirect following."""
    ip = ip or resolve_public(target.host, target.port)
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,*/*;q=0.8",
        "Accept-Encoding": "identity",
        "Connection": "close",
    }
    if extra_headers:
        headers.update(extra_headers)

    verified = True
    try:
        return _request(target, ip, headers, verify=True)
    except ssl.SSLCertVerificationError:
        verified = False
    except (OSError, http.client.HTTPException) as exc:
        raise FetchError(_describe(exc)) from None

    # The certificate is not trusted. The TLS check reports that as a
    # finding; here we still read the headers so the rest of the report is
    # useful. Nothing sensitive is sent on this connection.
    try:
        resp = _request(target, ip, headers, verify=False)
    except (OSError, http.client.HTTPException) as exc:
        raise FetchError(_describe(exc)) from None
    resp.cert_verified = verified
    return resp


def _request(target: Target, ip: str, headers: dict[str, str], verify: bool) -> Response:
    if target.scheme == "https":
        conn = _PinnedHTTPSConnection(target.host, target.port, ip, _context(verify), TIMEOUT)
    else:
        conn = _PinnedHTTPConnection(target.host, target.port, ip, TIMEOUT)
    try:
        conn.request("GET", target.path, headers=headers)
        raw = conn.getresponse()
        body = raw.read(MAX_BODY)
        return Response(
            url=target.url,
            status=raw.status,
            headers=[(k, v) for k, v in raw.getheaders()],
            body=body,
            ip=ip,
        )
    finally:
        conn.close()


def fetch(url: str, extra_headers: dict[str, str] | None = None) -> Response:
    """GET with redirects. Every hop is validated by netguard."""
    seen: list[str] = []
    target = parse_target(url)
    for _ in range(MAX_REDIRECTS + 1):
        resp = fetch_once(target, extra_headers)
        if resp.status in (301, 302, 303, 307, 308):
            location = resp.header_all("Location")
            if location:
                seen.append(target.url)
                next_url = urljoin(target.url, location[0])
                try:
                    target = parse_target(next_url)
                except TargetError as exc:
                    raise FetchError(f"The site redirects somewhere this scanner will not follow: {exc}") from None
                continue
        resp.redirects = seen
        return resp
    raise FetchError("The site redirected too many times.")


def _describe(exc: Exception) -> str:
    if isinstance(exc, socket.timeout) or isinstance(exc, TimeoutError):
        return "The site took too long to respond."
    if isinstance(exc, ConnectionRefusedError):
        return "The site refused the connection."
    if isinstance(exc, ssl.SSLError):
        return "A secure connection could not be established."
    return "The site could not be reached."
