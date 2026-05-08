"""Application-level field encryption (versioned Fernet).

Encrypts the small set of database columns that carry the most sensitive
operational signal — primarily inline-stored OIDC client secrets and any
future cases where a user pastes a credential directly into the admin UI.

Postgres at-rest encryption (TDE / EBS) covers the disk; this layer covers
leakage *above* the disk: backup files, log slurps, replica scrapes,
debugging ``SELECT *`` statements. The encryption key itself never appears
in the database — it lives in the secrets backend (AWS Secrets Manager /
Vault / env), resolved via :mod:`app.security.secrets`.

Origin: ported from TokenDNA ``modules/security/field_crypto.py``. Adapted
to load the keyring through the platform's secrets resolver instead of
reading raw env vars.

Versioned ciphertexts
---------------------
On-disk format: ``v<int>:<urlsafe-base64-fernet-token>``. The version
prefix lets the keyring carry multiple keys at once — old reads succeed as
long as the prior key remains in the keyring; new writes always use the
active version. Rotation: add a new key at a higher version, set it
active, run a background re-encrypt job over affected columns, eventually
drop the old key.

Configuration
-------------
Two formats supported via env:

1. Single key:
       FIELD_CRYPTO_KEY_REF=env:FIELD_CRYPTO_KEY        (treated as v1)
   Where the resolved value is a urlsafe-base64 32-byte Fernet key.

2. Versioned keyring:
       FIELD_CRYPTO_KEYRING_REF=env:FIELD_CRYPTO_KEYRING
   Where the resolved value is ``v1:<key>,v2:<key>,...``
   FIELD_CRYPTO_ACTIVE_VERSION optionally selects which version is
   active; defaults to the highest.

Generate a fresh key:
    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Optional

from app.security.secrets import SecretResolutionError, get_resolver

logger = logging.getLogger("platform.field_crypto")

_PREFIX_RE = re.compile(r"^v(\d+):(.+)$")


class FieldCryptoError(Exception):
    """Raised when encryption or decryption cannot complete."""


def _import_fernet():
    try:
        from cryptography.fernet import Fernet, InvalidToken
    except ImportError as exc:  # pragma: no cover — listed as a hard dep
        raise FieldCryptoError(
            "cryptography>=42 is required for app.security.field_crypto"
        ) from exc
    return Fernet, InvalidToken


@dataclass
class _KeyEntry:
    version: int
    fernet: object  # Fernet instance


@dataclass
class FieldCrypto:
    """Versioned field encryption engine.

    Construct with :meth:`from_env` for production. Tests inject an
    explicit ``keys`` dict.
    """

    keys: dict[int, _KeyEntry] = field(default_factory=dict)
    active_version: int = 1

    # ─────────────────────────────────────────────── construction

    @classmethod
    def from_env(cls) -> "FieldCrypto":
        Fernet, _ = _import_fernet()
        keys: dict[int, _KeyEntry] = {}

        keyring_ref = os.getenv("FIELD_CRYPTO_KEYRING_REF", "").strip()
        single_ref = os.getenv("FIELD_CRYPTO_KEY_REF", "").strip()

        if keyring_ref:
            try:
                keyring_value = get_resolver().resolve(keyring_ref)
            except SecretResolutionError as exc:
                raise FieldCryptoError(
                    f"could not resolve FIELD_CRYPTO_KEYRING_REF: {exc}"
                ) from exc
            for entry in keyring_value.split(","):
                entry = entry.strip()
                if not entry:
                    continue
                if ":" not in entry:
                    raise FieldCryptoError(
                        f"keyring entry missing version prefix: {entry[:6]}…"
                    )
                tag, key_b64 = entry.split(":", 1)
                if not (tag.startswith("v") and tag[1:].isdigit()):
                    raise FieldCryptoError(
                        f"keyring version tag must be vN; got {tag}"
                    )
                version = int(tag[1:])
                keys[version] = _KeyEntry(
                    version=version, fernet=Fernet(key_b64.encode())
                )
        elif single_ref:
            try:
                key_value = get_resolver().resolve(single_ref)
            except SecretResolutionError as exc:
                raise FieldCryptoError(
                    f"could not resolve FIELD_CRYPTO_KEY_REF: {exc}"
                ) from exc
            keys[1] = _KeyEntry(version=1, fernet=Fernet(key_value.encode()))

        if not keys:
            raise FieldCryptoError(
                "No field-encryption keys configured. Set FIELD_CRYPTO_KEY_REF "
                "(single) or FIELD_CRYPTO_KEYRING_REF (versioned)."
            )

        active_env = os.getenv("FIELD_CRYPTO_ACTIVE_VERSION", "").strip()
        active_version = (
            int(active_env) if active_env.isdigit() else max(keys.keys())
        )
        if active_version not in keys:
            raise FieldCryptoError(
                f"FIELD_CRYPTO_ACTIVE_VERSION={active_version} not in keyring"
            )
        return cls(keys=keys, active_version=active_version)

    # ─────────────────────────────────────────────── operations

    def encrypt(self, plaintext: str | bytes | None) -> str:
        """Encrypt with the active key. Empty/None passes through unchanged
        so nullable columns don't pick up a non-empty ciphertext that looks
        real to a naive reader."""
        if plaintext in (None, "", b""):
            return ""
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode("utf-8")
        else:
            plaintext_bytes = plaintext
        entry = self.keys[self.active_version]
        token = entry.fernet.encrypt(plaintext_bytes).decode("utf-8")  # type: ignore[union-attr]
        return f"v{self.active_version}:{token}"

    def decrypt(self, ciphertext: str | None) -> str:
        if not ciphertext:
            return ""
        match = _PREFIX_RE.match(ciphertext)
        if not match:
            raise FieldCryptoError("ciphertext missing version prefix")
        version = int(match.group(1))
        token = match.group(2)
        entry = self.keys.get(version)
        if entry is None:
            raise FieldCryptoError(
                f"ciphertext key version v{version} not in current keyring"
            )
        _, InvalidToken = _import_fernet()
        try:
            return entry.fernet.decrypt(token.encode("utf-8")).decode("utf-8")  # type: ignore[union-attr]
        except InvalidToken as exc:
            raise FieldCryptoError("invalid_or_tampered_ciphertext") from exc

    def is_encrypted(self, value: Optional[str]) -> bool:
        return bool(value) and bool(_PREFIX_RE.match(value))

    def reencrypt(self, ciphertext: str) -> str:
        """Re-encrypt under the active key. Used by background rotation jobs."""
        return self.encrypt(self.decrypt(ciphertext))

    def keyring_versions(self) -> list[int]:
        return sorted(self.keys.keys())


# ─────────────────────────────────────────────── module-level singleton

_INSTANCE: Optional[FieldCrypto] = None


def get_engine() -> FieldCrypto:
    global _INSTANCE
    if _INSTANCE is None:
        _INSTANCE = FieldCrypto.from_env()
    return _INSTANCE


def reset_engine_for_tests() -> None:
    """Drop the cached singleton — call between tests that mutate env."""
    global _INSTANCE
    _INSTANCE = None


def encrypt(plaintext: str | bytes | None) -> str:
    return get_engine().encrypt(plaintext)


def decrypt(ciphertext: str | None) -> str:
    return get_engine().decrypt(ciphertext)


def generate_key() -> str:
    """Print-friendly: generate a fresh urlsafe-base64 32-byte Fernet key."""
    Fernet, _ = _import_fernet()
    return Fernet.generate_key().decode("utf-8")
