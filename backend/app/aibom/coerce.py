"""Strict coercion for operator-shaped JSONB.

The v2.0 pivot moved the asset's agentic config from typed columns into the
``metadata_json`` bag. A column was ``bool``; a bag value is whatever a connector
or a hand-edit wrote — ``"false"``, ``"shell"``, ``true`` where a number was
meant. The AI-BOM math consumed it as if it were still typed, which produced two
failure classes:

* **Fabrication** (a Tier A honesty violation): ``bool("false")`` is ``True``, so
  a string ``"false"`` scores an asset agentic; ``len("shell")`` counts five
  tools; ``list("gdpr")`` is four frameworks. The number, and the reasons that
  justify it, become fiction.
* **500s** (an availability bug in a security product): ``float("abc")`` and
  ``entry.get(...)`` on a non-dict raise, turning malformed operator data into a
  server error.

The rule these helpers enforce: a value scores only if it is STRICTLY the
expected type (``bool`` is ``bool``; ``int`` is ``int`` and not ``bool``; a
number is finite and not ``bool``; a list is a ``list``). Anything else is
UNPARSEABLE — it falls to the honest-empty path, and the caller reports it as
such rather than inventing a value from it. Absence and present-but-malformed
are both "not scored", but the caller distinguishes them in its reason text.
"""

from __future__ import annotations

import math
from typing import Any


def as_list(value: Any) -> list[Any]:
    """The value if it is a list, else ``[]``. Items are NOT coerced — callers
    that need strings sort/stringify locally. A string is NOT a list (``len``
    of it would miscount)."""
    return list(value) if isinstance(value, list) else []


def as_bool(value: Any) -> bool | None:
    """The value if it is strictly ``True``/``False``, else ``None``.

    ``None`` means "not a boolean" — absent OR a truthy/falsy non-bool like the
    string ``"false"``. ``bool(x)`` is exactly the trap this replaces."""
    return value if isinstance(value, bool) else None


def as_positive_int(value: Any) -> int | None:
    """The value if it is a strictly positive ``int`` (and not ``bool``), else
    ``None``. ``True`` is not 1 and ``-3`` is not a budget."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return value
    return None


def as_number(value: Any) -> float | None:
    """The value as ``float`` if it is a finite number (and not ``bool``), else
    ``None``. Replaces ``float(x)``, which raises on a non-numeric string."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and math.isfinite(value):
        return float(value)
    return None


def as_dict_list(value: Any) -> list[dict[str, Any]]:
    """The dict entries of a list, dropping anything that is not a dict. For
    ``change_log``, whose entries are ``{field, old_value, …}`` — a non-dict
    entry (or a non-list log) must not ``AttributeError`` on ``.get``."""
    return [e for e in as_list(value) if isinstance(e, dict)]


def as_str(value: Any) -> str | None:
    """The value lower-cased if it is a string, else ``None`` — so a caller can
    tell "absent" from "present but not a string"."""
    return value.lower() if isinstance(value, str) else None
