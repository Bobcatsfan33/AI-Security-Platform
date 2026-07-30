from __future__ import annotations

import socket

import pytest
from fastapi import HTTPException

from app.api.v1 import idp_admin
from app.security import outbound_url
from app.security.outbound_url import (
    OutboundURLPolicyError,
    validate_public_https_url,
)


def _answer(address: str) -> tuple[int, int, int, str, tuple[str, int]]:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 443))


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("http://idp.example.com", "https_required"),
        ("https://user:secret@idp.example.com", "userinfo_forbidden"),
        ("https://127.0.0.1", "non_public_destination"),
        ("https://169.254.169.254/latest/meta-data", "non_public_destination"),
        ("https://10.10.0.8", "non_public_destination"),
        ("https://[::1]", "non_public_destination"),
    ],
)
async def test_rejects_unsafe_literal_destination(url: str, reason: str) -> None:
    with pytest.raises(OutboundURLPolicyError, match=reason):
        await validate_public_https_url(url)


async def test_rejects_hostname_resolving_to_private_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [_answer("10.0.0.7")],
    )

    with pytest.raises(OutboundURLPolicyError, match="non_public_destination"):
        await validate_public_https_url("https://idp.example.com")


async def test_rejects_mixed_public_and_private_dns_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            _answer("93.184.216.34"),
            _answer("192.168.1.20"),
        ],
    )

    with pytest.raises(OutboundURLPolicyError, match="non_public_destination"):
        await validate_public_https_url("https://idp.example.com")


async def test_accepts_hostname_with_only_global_addresses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            _answer("93.184.216.34"),
            _answer("2606:2800:220:1:248:1893:25c8:1946"),
        ],
    )

    url = "https://idp.example.com/.well-known/openid-configuration"
    assert await validate_public_https_url(url) == url


async def test_pinned_backend_connects_to_validated_address_not_second_dns_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [_answer("93.184.216.34")],
    )
    destination = await outbound_url.resolve_public_https_url("https://idp.example.com")
    backend = outbound_url._PinnedNetworkBackend(destination)
    connected: list[str] = []
    stream = object()

    class Delegate:
        async def connect_tcp(self, host: str, *_args: object, **_kwargs: object) -> object:
            connected.append(host)
            return stream

        async def sleep(self, _seconds: float) -> None:
            return None

    backend._delegate = Delegate()  # type: ignore[assignment]

    assert await backend.connect_tcp("idp.example.com", 443) is stream
    assert connected == ["93.184.216.34"]


async def test_pinned_backend_refuses_a_different_hostname_before_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [_answer("93.184.216.34")],
    )
    destination = await outbound_url.resolve_public_https_url("https://idp.example.com")
    backend = outbound_url._PinnedNetworkBackend(destination)

    with pytest.raises(Exception, match="unvalidated hostname"):
        await backend.connect_tcp("metadata.internal", 443)


async def test_oidc_discovery_validates_every_fetched_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checked: list[str] = []

    async def validate(url: str) -> str:
        checked.append(url)
        return url

    class Response:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, str]:
            return {
                "issuer": "https://idp.example.com",
                "authorization_endpoint": "https://login.example.com/authorize",
                "token_endpoint": "https://login.example.com/token",
                "jwks_uri": "https://keys.example.com/jwks",
            }

    class Client:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def __aenter__(self) -> Client:
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def get(self, _url: str) -> Response:
            return Response()

    async def transport(url: str) -> object:
        await validate(url)
        return object()

    monkeypatch.setattr(idp_admin, "pinned_async_transport", transport)
    monkeypatch.setattr(idp_admin, "validate_public_https_url", validate)
    monkeypatch.setattr(idp_admin.httpx, "AsyncClient", Client)

    await idp_admin._validate_oidc_discovery("https://idp.example.com")

    assert checked == [
        "https://idp.example.com/.well-known/openid-configuration",
        "https://login.example.com/authorize",
        "https://login.example.com/token",
        "https://keys.example.com/jwks",
    ]


async def test_oidc_discovery_blocks_before_opening_http_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def block(_url: str) -> str:
        raise OutboundURLPolicyError("non_public_destination")

    class Client:
        def __init__(self, **_kwargs: object) -> None:
            raise AssertionError("HTTP client must not open for a blocked destination")

    monkeypatch.setattr(idp_admin, "pinned_async_transport", block)
    monkeypatch.setattr(idp_admin.httpx, "AsyncClient", Client)

    with pytest.raises(HTTPException) as exc:
        await idp_admin._validate_oidc_discovery("https://idp.example.com")
    assert exc.value.status_code == 400
    assert exc.value.detail == "oidc_discovery_destination_blocked: non_public_destination"
