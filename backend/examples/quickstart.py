"""Run the zero-infrastructure AI Guard quickstart from its documented module."""

from __future__ import annotations

from app.quickstart import PROBES, main

__all__ = ["PROBES", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
