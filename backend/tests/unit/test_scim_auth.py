"""SCIM bearer-token mint + verify."""

from __future__ import annotations

import pytest
from passlib.hash import bcrypt

from app.scim.auth import _verify_token, generate_scim_token


@pytest.mark.unit
class TestGenerateScimToken:
    def test_returns_plaintext_and_hash(self) -> None:
        plaintext, hashed = generate_scim_token()
        assert plaintext.startswith("scim_")
        assert len(plaintext) > 20
        assert hashed != plaintext  # never store plaintext
        assert bcrypt.verify(plaintext, hashed)

    def test_each_token_is_unique(self) -> None:
        tokens = {generate_scim_token()[0] for _ in range(20)}
        assert len(tokens) == 20

    def test_hashes_differ_even_for_same_plaintext(self) -> None:
        # bcrypt salts each hash uniquely
        h1 = bcrypt.hash("static-token")
        h2 = bcrypt.hash("static-token")
        assert h1 != h2
        # but both verify against the same plaintext
        assert bcrypt.verify("static-token", h1)
        assert bcrypt.verify("static-token", h2)


@pytest.mark.unit
class TestVerifyToken:
    def test_correct_token_verifies(self) -> None:
        plaintext, hashed = generate_scim_token()
        assert _verify_token(plaintext, hashed) is True

    def test_wrong_token_rejected(self) -> None:
        _, hashed = generate_scim_token()
        assert _verify_token("scim_definitely-wrong-token", hashed) is False

    def test_malformed_hash_returns_false(self) -> None:
        assert _verify_token("any-token", "not-a-bcrypt-hash") is False

    def test_empty_inputs_safe(self) -> None:
        assert _verify_token("", "") is False
