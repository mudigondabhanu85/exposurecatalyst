"""SSRF guard for every outbound URL (built-in sources and admin-configurable URLs alike)."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable
from urllib.parse import urlsplit

METADATA_HOSTS = frozenset({
    "169.254.169.254",  # AWS/Azure/GCP/OpenStack IMDS
    "fd00:ec2::254",  # AWS IMDS IPv6
    "169.254.170.2",  # ECS task metadata
    "100.100.100.200",  # Alibaba
    "metadata.google.internal",
    "metadata",
})
_CGNAT = ipaddress.ip_network("100.64.0.0/10")


class UnsafeURLError(ValueError):
    pass


def _ip_is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or (isinstance(ip, ipaddress.IPv4Address) and ip in _CGNAT)
    )


def host_matches(host: str, allowlist: Iterable[str]) -> bool:
    for entry in allowlist:
        entry = entry.lower().rstrip(".")
        if entry.startswith("*."):
            if host.endswith(entry[1:]) and host != entry[2:]:
                return True
        elif host == entry:
            return True
    return False


def validate_outbound_url(
    url: str,
    *,
    allowlist: Iterable[str] | None,
    allow_private: bool = False,
    resolve_dns: bool = True,
    allowed_schemes: tuple[str, ...] = ("https",),
) -> str:
    """Return ``url`` if safe to fetch, else raise :class:`UnsafeURLError`."""
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise UnsafeURLError("malformed URL") from exc
    if parts.scheme.lower() not in allowed_schemes:
        raise UnsafeURLError(f"scheme '{parts.scheme}' not allowed")
    if parts.username or parts.password:
        raise UnsafeURLError("credentials in URL are not allowed")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise UnsafeURLError("missing host")

    if host in METADATA_HOSTS and not allow_private:
        raise UnsafeURLError("cloud metadata endpoints are blocked")
    if allowlist is not None and not host_matches(host, allowlist):
        raise UnsafeURLError(f"host '{host}' is not in the egress allowlist")

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if _ip_is_blocked(literal) and not allow_private:
            raise UnsafeURLError("private/internal addresses are blocked")
        return url

    if resolve_dns and not allow_private:
        try:
            infos = socket.getaddrinfo(host, parts.port or 443, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise UnsafeURLError(f"cannot resolve host '{host}'") from exc
        for info in infos:
            addr = ipaddress.ip_address(info[4][0].split("%")[0])
            if _ip_is_blocked(addr) or str(addr) in METADATA_HOSTS:
                raise UnsafeURLError(f"host '{host}' resolves to a blocked address")
    return url
