"""API key creation and validation.

Format: 36 chars total — 8-char public prefix + 32-char secret. The prefix
is stored in plaintext for indexed lookup; the full key is bcrypt-hashed and
compared on auth. The plaintext key is shown to the user exactly once at
creation time.

Why bcrypt: API keys are credentials and should never be reversible. The
prefix is the only attacker-observable part; you cannot enumerate keys by
brute-forcing the prefix because matching it gets you nothing without the
secret half.
"""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Sequence

from passlib.hash import bcrypt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.api_key import ApiKey

KEY_PREFIX_LEN = 8
KEY_SECRET_LEN = 32  # bytes; will be ~43 chars urlsafe-base64


@dataclass(frozen=True)
class CreatedApiKey:
    """The result of issuing a new API key — plaintext is returned ONCE only."""

    plaintext: str
    record: ApiKey


def _generate_plaintext() -> tuple[str, str]:
    prefix = secrets.token_urlsafe(6)[:KEY_PREFIX_LEN]
    secret = secrets.token_urlsafe(KEY_SECRET_LEN)
    return prefix, prefix + "." + secret


async def create_api_key(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    name: str,
    scopes: Sequence[str],
    created_by: uuid.UUID | None,
    expires_at: datetime | None = None,
) -> CreatedApiKey:
    prefix, plaintext = _generate_plaintext()
    key_hash = bcrypt.hash(plaintext)

    record = ApiKey(
        org_id=org_id,
        key_hash=key_hash,
        key_prefix=prefix,
        name=name,
        scopes=list(scopes),
        created_by=created_by,
        expires_at=expires_at,
        is_active=True,
    )
    db.add(record)
    await db.flush()
    await db.refresh(record)
    return CreatedApiKey(plaintext=plaintext, record=record)


async def verify_api_key(db: AsyncSession, plaintext: str) -> ApiKey | None:
    """Return the matching ApiKey row or None. Constant-time per candidate."""
    if "." not in plaintext or len(plaintext) < KEY_PREFIX_LEN + 2:
        return None
    prefix = plaintext.split(".", 1)[0]
    if len(prefix) != KEY_PREFIX_LEN:
        return None

    stmt = select(ApiKey).where(
        ApiKey.key_prefix == prefix,
        ApiKey.is_active.is_(True),
    )
    result = await db.execute(stmt)
    candidates = result.scalars().all()

    for candidate in candidates:
        # bcrypt.verify is constant-time per candidate. We loop because two keys
        # could in theory share a prefix (collisions are rare but possible).
        try:
            if bcrypt.verify(plaintext, candidate.key_hash):
                if candidate.expires_at is not None:
                    from datetime import timezone

                    now = datetime.now(timezone.utc)
                    if candidate.expires_at < now:
                        return None
                return candidate
        except ValueError:
            continue
    return None
