"""Field-level encryption tests — round-trip, versioning, tamper detection,
inline-encrypted secret resolution.
"""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from app.security import field_crypto, secrets as secrets_mod
from app.security.field_crypto import (
    FieldCrypto,
    FieldCryptoError,
    _KeyEntry,
    generate_key,
    reset_engine_for_tests,
)


def _engine_with(*versions: int, active: int | None = None) -> FieldCrypto:
    keys = {
        v: _KeyEntry(version=v, fernet=Fernet(Fernet.generate_key()))
        for v in versions
    }
    return FieldCrypto(keys=keys, active_version=active or max(versions))


@pytest.fixture(autouse=True)
def _reset_engine() -> None:
    reset_engine_for_tests()


@pytest.mark.unit
class TestRoundTrip:
    def test_encrypt_decrypt_round_trip(self) -> None:
        engine = _engine_with(1)
        ciphertext = engine.encrypt("super-secret-oidc-client-secret")
        assert ciphertext.startswith("v1:")
        assert engine.decrypt(ciphertext) == "super-secret-oidc-client-secret"

    def test_bytes_input_round_trips_as_str(self) -> None:
        engine = _engine_with(1)
        ciphertext = engine.encrypt(b"raw-bytes-secret")
        assert engine.decrypt(ciphertext) == "raw-bytes-secret"

    def test_empty_input_returns_empty(self) -> None:
        engine = _engine_with(1)
        assert engine.encrypt("") == ""
        assert engine.encrypt(None) == ""
        assert engine.encrypt(b"") == ""

    def test_empty_ciphertext_decrypts_to_empty(self) -> None:
        engine = _engine_with(1)
        assert engine.decrypt("") == ""
        assert engine.decrypt(None) == ""


@pytest.mark.unit
class TestVersioning:
    def test_active_version_used_for_writes(self) -> None:
        engine = _engine_with(1, 2, 3, active=2)
        ciphertext = engine.encrypt("hello")
        assert ciphertext.startswith("v2:")

    def test_old_versions_still_decrypt(self) -> None:
        # Simulate a rotation: v1 was active, now v2 is active.
        v1_engine = _engine_with(1)
        old_ciphertext = v1_engine.encrypt("old-data")

        # New engine has both keys but v2 active for writes
        new_engine = FieldCrypto(
            keys={
                **v1_engine.keys,
                2: _KeyEntry(version=2, fernet=Fernet(Fernet.generate_key())),
            },
            active_version=2,
        )
        # Old ciphertext decrypts via v1 even though active is v2
        assert new_engine.decrypt(old_ciphertext) == "old-data"

    def test_unknown_version_raises(self) -> None:
        engine = _engine_with(1)
        # Forge a ciphertext claiming to be v99
        fake = "v99:abc"
        with pytest.raises(FieldCryptoError, match="v99"):
            engine.decrypt(fake)

    def test_reencrypt_under_active_key(self) -> None:
        v1_engine = _engine_with(1)
        old = v1_engine.encrypt("rotate-me")

        new_engine = FieldCrypto(
            keys={
                **v1_engine.keys,
                2: _KeyEntry(version=2, fernet=Fernet(Fernet.generate_key())),
            },
            active_version=2,
        )
        new_ct = new_engine.reencrypt(old)
        assert new_ct.startswith("v2:")
        assert new_engine.decrypt(new_ct) == "rotate-me"


@pytest.mark.unit
class TestTamperDetection:
    def test_corrupted_ciphertext_raises(self) -> None:
        engine = _engine_with(1)
        ct = engine.encrypt("secret")
        # Flip a character in the body
        corrupted = ct[:5] + ("A" if ct[5] != "A" else "B") + ct[6:]
        with pytest.raises(FieldCryptoError, match="invalid_or_tampered_ciphertext"):
            engine.decrypt(corrupted)

    def test_missing_version_prefix_raises(self) -> None:
        engine = _engine_with(1)
        with pytest.raises(FieldCryptoError, match="missing version prefix"):
            engine.decrypt("not-a-versioned-ciphertext")

    def test_is_encrypted_distinguishes(self) -> None:
        engine = _engine_with(1)
        ct = engine.encrypt("x")
        assert engine.is_encrypted(ct) is True
        assert engine.is_encrypted("plain text") is False
        assert engine.is_encrypted(None) is False
        assert engine.is_encrypted("") is False


@pytest.mark.unit
class TestFromEnv:
    def test_single_key_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        key = Fernet.generate_key().decode()
        monkeypatch.setenv("FIELD_CRYPTO_KEY", key)
        monkeypatch.setenv("FIELD_CRYPTO_KEY_REF", "env:FIELD_CRYPTO_KEY")
        monkeypatch.delenv("FIELD_CRYPTO_KEYRING_REF", raising=False)
        monkeypatch.delenv("FIELD_CRYPTO_ACTIVE_VERSION", raising=False)

        engine = FieldCrypto.from_env()
        assert engine.active_version == 1
        assert engine.keyring_versions() == [1]

    def test_keyring_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        k1 = Fernet.generate_key().decode()
        k2 = Fernet.generate_key().decode()
        monkeypatch.setenv("FIELD_CRYPTO_KEYRING", f"v1:{k1},v2:{k2}")
        monkeypatch.setenv("FIELD_CRYPTO_KEYRING_REF", "env:FIELD_CRYPTO_KEYRING")
        monkeypatch.delenv("FIELD_CRYPTO_KEY_REF", raising=False)
        monkeypatch.delenv("FIELD_CRYPTO_ACTIVE_VERSION", raising=False)

        engine = FieldCrypto.from_env()
        assert engine.keyring_versions() == [1, 2]
        assert engine.active_version == 2

    def test_explicit_active_version(self, monkeypatch: pytest.MonkeyPatch) -> None:
        k1 = Fernet.generate_key().decode()
        k2 = Fernet.generate_key().decode()
        monkeypatch.setenv("FIELD_CRYPTO_KEYRING", f"v1:{k1},v2:{k2}")
        monkeypatch.setenv("FIELD_CRYPTO_KEYRING_REF", "env:FIELD_CRYPTO_KEYRING")
        monkeypatch.setenv("FIELD_CRYPTO_ACTIVE_VERSION", "1")
        monkeypatch.delenv("FIELD_CRYPTO_KEY_REF", raising=False)

        engine = FieldCrypto.from_env()
        assert engine.active_version == 1

    def test_no_key_configured_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("FIELD_CRYPTO_KEY_REF", raising=False)
        monkeypatch.delenv("FIELD_CRYPTO_KEYRING_REF", raising=False)
        with pytest.raises(FieldCryptoError, match="No field-encryption keys"):
            FieldCrypto.from_env()


@pytest.mark.unit
class TestEncryptedInlineResolver:
    def test_resolves_inline_ciphertext(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Wire a deterministic engine so the resolver decrypts predictably
        engine = _engine_with(1)
        monkeypatch.setattr(field_crypto, "_INSTANCE", engine)

        ciphertext = engine.encrypt("oidc-client-secret-value")
        ref = f"enc:{ciphertext}"

        resolved = secrets_mod.EncryptedInlineResolver().resolve(ref)
        assert resolved == "oidc-client-secret-value"

    def test_rejects_non_enc_prefix(self) -> None:
        with pytest.raises(secrets_mod.SecretResolutionError):
            secrets_mod.EncryptedInlineResolver().resolve("env:VAR")

    def test_corrupted_inline_ciphertext_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        engine = _engine_with(1)
        monkeypatch.setattr(field_crypto, "_INSTANCE", engine)
        ct = engine.encrypt("x")
        corrupted = "enc:" + ct[:5] + ("A" if ct[5] != "A" else "B") + ct[6:]
        with pytest.raises(secrets_mod.SecretResolutionError):
            secrets_mod.EncryptedInlineResolver().resolve(corrupted)


@pytest.mark.unit
class TestGenerateKey:
    def test_generates_valid_fernet_key(self) -> None:
        key = generate_key()
        # Should be usable to construct a Fernet immediately
        Fernet(key.encode())
