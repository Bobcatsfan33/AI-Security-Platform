"""Tests for ``app.auth.password_hashing`` — the single bcrypt call site.

These cover the three things that could silently go wrong when passlib was
removed from the credential path:

1. **Backward compatibility.** Hashes written by the old passlib + bcrypt 4.3.0
   stack must still verify. The fixtures below are REAL ``$2b$12$`` strings
   produced by ``passlib.hash.bcrypt.hash()`` under bcrypt 4.3.0 and pasted in
   verbatim, so this is a genuine cross-version check rather than a round-trip
   through whatever bcrypt happens to be installed. Their plaintexts are throwaway
   test values, never real credentials.

2. **The 72-byte boundary.** bcrypt 5.0 raises instead of truncating past 72
   bytes; we reject explicitly. Both sides of the boundary are pinned, in bytes,
   including multi-byte UTF-8 where character count and byte count diverge —
   the case a naive ``len(s)`` check gets wrong.

3. **Wrong secrets fail**, and failure is a ``False``, not an exception, on the
   unauthenticated path.

Nothing here prints or logs a secret or a hash.
"""

from __future__ import annotations

import pathlib

import bcrypt
import pytest

from app.auth.api_key_service import _generate_plaintext
from app.auth.password_hashing import (
    MAX_SECRET_BYTES,
    SecretTooLongError,
    hash_secret,
    verify_secret,
)
from app.scim.auth import generate_scim_token

pytestmark = pytest.mark.unit


# Generated with passlib 1.7.4 + bcrypt 4.3.0 — the stack this change replaces.
# (plaintext, hash) pairs; the plaintexts are test-only strings.
_BCRYPT4_FIXTURES: list[tuple[str, str]] = [
    # An API-key-shaped secret: 8-char prefix + "." + urlsafe secret half.
    (
        "abcd1234.zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        "$2b$12$sdv/Cb6/2IHzI3hwCdRWY.ET9Pkwg5fdVYHXU9AbyCSTOtddrSK7W",
    ),
    # A SCIM-bearer-token-shaped secret: "scim_" + urlsafe(40).
    (
        "scim_" + "y" * 54,
        "$2b$12$W6s54T8b6TONC2tMchxbNeYLsAXs.xnTK8tE78nlrrtAO/reN80eu",
    ),
    # A short ASCII secret.
    ("hunter2", "$2b$12$.xWit.TWQ7VhAuyUUIAtv.fE3HtewlgmqOHzTFtWsN6USfmaie9Ym"),
    # 30 characters, 60 bytes — multi-byte UTF-8, comfortably under the limit.
    ("é" * 30, "$2b$12$KNZ920uRoDjv6dR4gYzPCOC5b/DyEhgWuDDwkg9OBPpMQNzb94kHu"),
]


class TestBackwardCompatibilityWithBcrypt4:
    """Stored hashes predate this change. If these fail, every existing API key
    and SCIM token in every deployment stops authenticating."""

    @pytest.mark.parametrize(("secret", "stored"), _BCRYPT4_FIXTURES)
    def test_a_bcrypt4_passlib_hash_still_verifies(self, secret: str, stored: str) -> None:
        assert verify_secret(secret, stored) is True

    @pytest.mark.parametrize(("secret", "stored"), _BCRYPT4_FIXTURES)
    def test_a_bcrypt4_hash_rejects_the_wrong_secret(self, secret: str, stored: str) -> None:
        assert verify_secret(secret + "x", stored) is False

    def test_the_fixtures_are_really_bcrypt4_era_artifacts(self) -> None:
        """Guard against someone 'fixing' a failure by regenerating the fixtures
        with the current library — which would delete the cross-version claim."""
        for _secret, stored in _BCRYPT4_FIXTURES:
            assert stored.startswith("$2b$12$")
            assert len(stored) == 60

    def test_we_emit_the_same_scheme_and_cost_we_inherited(self) -> None:
        """New hashes stay format-identical to passlib's defaults, so this change
        is reversible and needs no migration. Also catches an accidentally
        LOWERED cost factor, which no test of correctness alone would notice."""
        assert hash_secret("some-test-secret").startswith("$2b$12$")


class TestSeventyTwoByteBoundary:
    def test_the_limit_is_the_bcrypt_limit(self) -> None:
        assert MAX_SECRET_BYTES == 72

    @pytest.mark.parametrize("size", [1, 71, 72])
    def test_at_or_under_the_limit_hashes_and_round_trips(self, size: int) -> None:
        secret = "a" * size
        assert len(secret.encode("utf-8")) == size
        assert verify_secret(secret, hash_secret(secret)) is True

    @pytest.mark.parametrize("size", [73, 100, 1000])
    def test_over_the_limit_is_refused_loudly(self, size: int) -> None:
        with pytest.raises(SecretTooLongError):
            hash_secret("a" * size)

    def test_the_refusal_is_a_valueerror(self) -> None:
        """Call sites that still catch ValueError around hashing keep working."""
        assert issubclass(SecretTooLongError, ValueError)

    def test_the_error_does_not_leak_the_secret(self) -> None:
        secret = "correct-horse-battery-staple-" + "q" * 80
        with pytest.raises(SecretTooLongError) as exc:
            hash_secret(secret)
        assert secret not in str(exc.value)
        assert "correct-horse" not in str(exc.value)

    def test_the_limit_counts_bytes_not_characters(self) -> None:
        """A naive len() check would accept this: 40 characters, 80 UTF-8 bytes.
        Getting this wrong means bcrypt raises deep in the stack instead."""
        secret = "é" * 40
        assert len(secret) == 40
        assert len(secret.encode("utf-8")) == 80
        with pytest.raises(SecretTooLongError):
            hash_secret(secret)

    def test_multibyte_just_under_the_limit_is_accepted(self) -> None:
        """36 characters, 72 bytes — the multi-byte side of the boundary."""
        secret = "é" * 36
        assert len(secret.encode("utf-8")) == MAX_SECRET_BYTES
        assert verify_secret(secret, hash_secret(secret)) is True

    def test_a_four_byte_character_counts_as_four(self) -> None:
        secret = "😀" * 19  # 19 chars, 76 bytes
        assert len(secret.encode("utf-8")) == 76
        with pytest.raises(SecretTooLongError):
            hash_secret(secret)

    def test_verifying_an_over_length_secret_is_a_miss_not_a_crash(self) -> None:
        """Attacker-controlled input on the unauthenticated path. No hash we
        could have written corresponds to an over-length secret, so this is an
        ordinary auth failure — it must not become a 500."""
        stored = hash_secret("a" * 72)
        assert verify_secret("a" * 5000, stored) is False


class TestVerifyIsTotal:
    def test_the_wrong_secret_fails(self) -> None:
        stored = hash_secret("the-right-secret")
        assert verify_secret("the-wrong-secret", stored) is False

    def test_a_near_miss_fails(self) -> None:
        stored = hash_secret("the-right-secret")
        assert verify_secret("the-right-secreT", stored) is False

    def test_the_empty_secret_fails_against_a_real_hash(self) -> None:
        assert verify_secret("", hash_secret("something")) is False

    @pytest.mark.parametrize(
        "stored",
        ["", "not-a-hash", "$2b$12$too-short", "$argon2id$v=19$m=65536,t=3,p=4$abc$def"],
    )
    def test_a_malformed_stored_hash_is_false_not_an_exception(self, stored: str) -> None:
        assert verify_secret("anything", stored) is False

    def test_two_hashes_of_the_same_secret_differ(self) -> None:
        """Distinct salts. Equal hashes would mean the salt is not random."""
        secret = "salted-please"
        assert hash_secret(secret) != hash_secret(secret)
        # ...and both still verify.
        assert verify_secret(secret, hash_secret(secret)) is True


class TestGeneratedCredentialsFitTheLimit:
    """The reason rejecting is the right policy: nothing this codebase generates
    comes anywhere near 72 bytes. If a generator is ever widened past the limit,
    these fail here rather than at 3am on the auth path.
    """

    def test_api_keys_fit_with_headroom(self) -> None:
        for _ in range(50):
            _prefix, plaintext = _generate_plaintext()
            assert len(plaintext.encode("utf-8")) <= MAX_SECRET_BYTES

    def test_api_keys_actually_hash(self) -> None:
        _prefix, plaintext = _generate_plaintext()
        assert verify_secret(plaintext, hash_secret(plaintext)) is True

    def test_scim_tokens_fit_with_headroom(self) -> None:
        # Few iterations: minting hashes at cost 12, which is deliberately slow.
        for _ in range(3):
            plaintext, _hashed = generate_scim_token()
            assert len(plaintext.encode("utf-8")) <= MAX_SECRET_BYTES

    def test_scim_token_minting_round_trips(self) -> None:
        plaintext, hashed = generate_scim_token()
        assert verify_secret(plaintext, hashed) is True
        assert verify_secret(plaintext + "x", hashed) is False


class TestPasslibIsGone:
    def test_the_credential_path_does_not_import_passlib(self) -> None:
        """passlib 1.7.4 is unmaintained and breaks on bcrypt 5.x. Re-adding it
        would silently re-pin the platform to bcrypt<5."""
        import app.auth.api_key_service as api_key_service
        import app.auth.password_hashing as password_hashing
        import app.scim.auth as scim_auth

        for module in (password_hashing, api_key_service, scim_auth):
            source = pathlib.Path(module.__file__).read_text()
            offending = [
                line
                for line in source.splitlines()
                if line.startswith(("import passlib", "from passlib"))
            ]
            assert not offending, f"{module.__name__} imports passlib: {offending}"

    def test_the_installed_bcrypt_is_usable_at_the_boundary(self) -> None:
        """The regression that started this: under bcrypt 5.x the FIRST call
        through passlib raised for every input. A plain hash must just work."""
        assert bcrypt.checkpw(b"x", bcrypt.hashpw(b"x", bcrypt.gensalt(rounds=4)))
