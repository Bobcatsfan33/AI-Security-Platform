"""Tests for the API key plaintext format and verifier (no DB required for
the obvious-rejection cases).
"""

from __future__ import annotations

import pytest

from app.auth.api_key_service import KEY_PREFIX_LEN, _generate_plaintext


@pytest.mark.unit
class TestApiKeyFormat:
    def test_generated_key_has_prefix_and_secret(self) -> None:
        prefix, plaintext = _generate_plaintext()
        assert len(prefix) == KEY_PREFIX_LEN
        assert plaintext.startswith(prefix + ".")
        secret_half = plaintext.split(".", 1)[1]
        assert len(secret_half) > 20  # urlsafe-base64 of 32 bytes is ~43 chars

    def test_generated_keys_are_unique(self) -> None:
        keys = {_generate_plaintext()[1] for _ in range(100)}
        assert len(keys) == 100

    def test_prefix_length_constant(self) -> None:
        # Guard against accidental drift — the DB column is sized to this length.
        assert KEY_PREFIX_LEN == 8
