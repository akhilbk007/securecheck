"""Target validation and SSRF protection.

A scanner that fetches user-supplied URLs is a textbook Server-Side Request
Forgery (SSRF) risk: without guards, anyone could point it at
http://169.254.169.254/ (cloud metadata), http://localhost:6379/ or an
internal admin panel and use this service as a proxy into a private network.

Defences implemented here:

1. Only http/https, only ports 80/443, no credentials in the URL.
2. Hostnames only (no raw IP literals).
3. The hostname is resolved ONCE and every resolved address must be public.
4. The caller connects to the validated IP directly ("DNS pinning"), so a
   second DNS lookup cannot return a different, internal address
   (DNS-rebinding defence). See fetch.py.
5. Every redirect hop is re-validated through the same path.
"""
from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443}
MAX_URL_LENGTH = 2048


class TargetError(ValueError):
    """The requested target is invalid or not allowed."""


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str  # ASCII (IDNA-encoded) hostname, lower case
    port: int
    path: str  # path + query, always starts with "/"

    @property
    def url(self) -> str:
        default = 443 if self.scheme == "https" else 80
        netloc = self.host if self.port == default else f"{self.host}:{self.port}"
        return f"{self.scheme}://{netloc}{self.path}"


def _private_allowed() -> bool:
    # Test-only escape hatch. Never set this in production.
    return os.environ.get("SECURECHECK_ALLOW_PRIVATE") == "1"


def parse_target(raw: str) -> Target:
    """Turn user input into a validated Target or raise TargetError."""
    if not isinstance(raw, str):
        raise TargetError("Enter a website address.")
    raw = raw.strip()
    if not raw:
        raise TargetError("Enter a website address.")
    if len(raw) > MAX_URL_LENGTH:
        raise TargetError("That address is too long.")
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in raw):
        raise TargetError("The address contains spaces or control characters.")
    if "://" not in raw:
        raw = "https://" + raw

    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        raise TargetError("That does not look like a valid address.") from None

    scheme = (parts.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        raise TargetError("Only http:// and https:// addresses can be scanned.")
    if parts.username is not None or parts.password is not None:
        raise TargetError("Addresses containing a username or password are not allowed.")

    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise TargetError("That does not look like a valid address.")

    if _is_ip_literal(host):
        if not _private_allowed():
            raise TargetError("Enter a domain name, not an IP address.")
    else:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise TargetError("That domain name is not valid.") from None
        if "." not in host and not _private_allowed():
            raise TargetError("Enter a full domain name, such as example.com.")
        if len(host) > 253 or not all(_valid_label(l) for l in host.split(".")):
            raise TargetError("That domain name is not valid.")

    if port is None:
        port = 443 if scheme == "https" else 80
    if port not in ALLOWED_PORTS and not _private_allowed():
        raise TargetError("Only the standard web ports (80 and 443) can be scanned.")

    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return Target(scheme=scheme, host=host, port=port, path=path)


def _valid_label(label: str) -> bool:
    if not 1 <= len(label) <= 63:
        return False
    if label[0] == "-" or label[-1] == "-":
        return False
    return all(c.isalnum() or c in "-_" for c in label)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        pass
    # Legacy forms such as "2130706433", "0x7f.1" or "127.1" that some
    # resolvers silently accept as IPv4.
    try:
        socket.inet_aton(host)
        return True
    except OSError:
        return False


def is_public_ip(value: str) -> bool:
    """True only for globally routable unicast addresses."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:  # ::ffff:10.0.0.1
            ip = ip.ipv4_mapped
        elif ip.sixtofour is not None:  # 2002::/16 wraps an IPv4 address
            ip = ip.sixtofour
        elif ip.teredo is not None:
            ip = ip.teredo[1]
    if ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local:
        return False
    return ip.is_global


def resolve_public(host: str, port: int) -> str:
    """Resolve host and return one IP to connect to.

    Raises TargetError if the name does not resolve or if ANY of its
    addresses is non-public (an attacker controlling DNS could otherwise mix
    one public and one internal record and hope we pick the internal one).
    """
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        raise TargetError(f"Could not find {host}. Check the spelling.") from None

    addresses = []
    for family, _type, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if ip not in addresses:
            addresses.append(ip)
    if not addresses:
        raise TargetError(f"Could not find {host}. Check the spelling.")

    if not _private_allowed():
        for ip in addresses:
            if not is_public_ip(ip):
                raise TargetError(
                    "That address points to a private or internal network, "
                    "which this scanner will not connect to."
                )

    ipv4 = [a for a in addresses if ":" not in a]
    return (ipv4 or addresses)[0]
