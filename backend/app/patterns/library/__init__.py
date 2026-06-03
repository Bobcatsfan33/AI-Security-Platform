"""Built-in pattern library — ATLAS-mapped detection content.

The patterns ship as JSON (``builtin_patterns.json``) — data, not code — so they
can be versioned, signed, and distributed separately from the engine. Each maps
to one or more MITRE ATLAS techniques (the AI-native analog to the platform's
existing OWASP LLM / NIST AI RMF report mappings).

ATLAS mappings are best-effort and meant to be reviewed against the current
ATLAS matrix before a customer-facing release.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.patterns.compiled import CompiledPattern, compile_pattern

_LIBRARY_FILE = Path(__file__).parent / "builtin_patterns.json"


def library_specs() -> list[dict[str, Any]]:
    """Return the raw library pattern specs (data)."""
    return json.loads(_LIBRARY_FILE.read_text())


def load_library() -> list[CompiledPattern]:
    """Compile every built-in pattern. Raises if any spec is invalid — the
    shipped library must always compile."""
    return [compile_pattern(spec) for spec in library_specs()]


def library_by_name() -> dict[str, CompiledPattern]:
    return {p.name: p for p in load_library()}


__all__ = ["library_specs", "load_library", "library_by_name"]
