"""Validation for security-sensitive outbound HTTP destinations.

User- or tenant-controlled URLs must not be fetched until every resolved
address has been shown to be globally routable. Rejecting a mixed DNS answer
is intentional: accepting the first public address would still leave a client
free to connect to a private address from the same answer set.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import SplitResult, urlsplit

import httpcore
import httpx
from httpcore._backends.anyio import AnyIOBackend


class OutboundURLPolicyError(ValueError):
    """The destination is not permitted by the outbound request policy."""


@dataclass(frozen=True)
class ResolvedOutboundURL:
    """An HTTPS destination and the exact public addresses it may connect to."""

    url: str
    hostname: str
    addresses: tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]


def _parse_public_https_url(url: str) -> SplitResult:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise OutboundURLPolicyError("invalid_url") from exc

    if parsed.scheme.lower() != "https":
        raise OutboundURLPolicyError("https_required")
    if not parsed.hostname:
        raise OutboundURLPolicyError("hostname_required")
    if parsed.username is not None or parsed.password is not None:
        raise OutboundURLPolicyError("userinfo_forbidden")
    if parsed.fragment:
        raise OutboundURLPolicyError("fragment_forbidden")
    if "%" in parsed.hostname:
        # Zone-scoped IPv6 literals are never valid public OIDC destinations.
        raise OutboundURLPolicyError("zone_id_forbidden")
    if port == 0:
        raise OutboundURLPolicyError("invalid_port")
    return parsed


def _resolve(hostname: str, port: int) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            answers = socket.getaddrinfo(
                hostname,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
        except OSError as exc:
            raise OutboundURLPolicyError("dns_resolution_failed") from exc
        addresses = {ipaddress.ip_address(answer[4][0]) for answer in answers}
    else:
        addresses = {literal}

    if not addresses:
        raise OutboundURLPolicyError("dns_no_addresses")
    return addresses


async def resolve_public_https_url(
    url: str, *, dns_timeout_seconds: float = 5.0
) -> ResolvedOutboundURL:
    """Resolve *url* once and return only public addresses.

    Callers making a request must use :func:`pinned_async_transport`; validating
    and then allowing the HTTP client to resolve the hostname again would leave
    a DNS-rebinding time-of-check/time-of-use window.
    """

    parsed = _parse_public_https_url(url)
    hostname = parsed.hostname
    if hostname is None:  # Defensive: _parse_public_https_url already refuses this.
        raise OutboundURLPolicyError("hostname_required")
    port = parsed.port or 443
    try:
        addresses = await asyncio.wait_for(
            asyncio.to_thread(_resolve, hostname, port),
            timeout=dns_timeout_seconds,
        )
    except TimeoutError as exc:
        raise OutboundURLPolicyError("dns_resolution_timeout") from exc

    if any(not address.is_global for address in addresses):
        raise OutboundURLPolicyError("non_public_destination")
    return ResolvedOutboundURL(
        url=url,
        hostname=hostname,
        addresses=tuple(sorted(addresses, key=lambda address: (address.version, address.packed))),
    )


async def validate_public_https_url(url: str, *, dns_timeout_seconds: float = 5.0) -> str:
    """Return *url* only when it resolves exclusively to public HTTPS endpoints."""

    await resolve_public_https_url(url, dns_timeout_seconds=dns_timeout_seconds)
    return url


class _PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Connect an HTTP origin only to addresses from its validated DNS answer."""

    def __init__(self, destination: ResolvedOutboundURL) -> None:
        self._destination = destination
        self._delegate = AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        if host.rstrip(".").lower() != self._destination.hostname.rstrip(".").lower():
            raise httpcore.ConnectError("outbound transport refused an unvalidated hostname")

        last_error: httpcore.ConnectError | None = None
        for address in self._destination.addresses:
            try:
                return await self._delegate.connect_tcp(
                    str(address),
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except httpcore.ConnectError as exc:
                last_error = exc
        if last_error is not None:
            raise last_error
        raise httpcore.ConnectError("outbound transport has no validated addresses")

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        raise httpcore.ConnectError("outbound transport does not permit Unix sockets")

    async def sleep(self, seconds: float) -> None:
        await self._delegate.sleep(seconds)


async def pinned_async_transport(url: str) -> httpx.AsyncHTTPTransport:
    """Build an HTTPS transport pinned to the URL's validated DNS answer."""

    destination = await resolve_public_https_url(url)
    transport = httpx.AsyncHTTPTransport(verify=True, trust_env=False, retries=0)
    transport._pool = httpcore.AsyncConnectionPool(
        ssl_context=httpx.create_ssl_context(verify=True, trust_env=False),
        network_backend=_PinnedNetworkBackend(destination),
        retries=0,
    )
    return transport
