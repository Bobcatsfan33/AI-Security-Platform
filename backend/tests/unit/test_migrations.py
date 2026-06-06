"""Migration integrity + completeness (A5).

Offline guards (no DB needed):
  - the revision chain is linear: one base, one head, no gaps/cycles
  - every migration has a real downgrade (forward+rollback discipline)
  - every model table has a create_table somewhere in the history (drift guard)
  - alembic generates symmetric forward (CREATE) + rollback (DROP) SQL offline
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

_VERSIONS = Path(__file__).resolve().parents[2] / "alembic" / "versions"
_BACKEND = Path(__file__).resolve().parents[2]


def _migration_files() -> list[Path]:
    return sorted(p for p in _VERSIONS.glob("2026*.py") if p.is_file())


def _field(txt: str, name: str) -> str | None:
    m = re.search(rf"^{name}\s*[:=].*?[\"']([^\"']+)[\"']", txt, re.MULTILINE)
    return m.group(1) if m else None


def _down_revision(txt: str) -> str | None:
    if re.search(r"^down_revision\s*[:=]\s*None", txt, re.MULTILINE):
        return None
    return _field(txt, "down_revision")


class TestRevisionChain:
    def test_single_linear_chain(self):
        files = _migration_files()
        assert files, "no migrations found"
        revs, downs = {}, {}
        for f in files:
            txt = f.read_text()
            rev = _field(txt, "revision")
            assert rev, f"{f.name}: no revision id"
            revs[rev] = f.name
            downs[rev] = _down_revision(txt)

        bases = [r for r, d in downs.items() if d is None]
        assert len(bases) == 1, f"expected exactly one base, got {bases}"

        # Every non-base down_revision must point at a known revision.
        for rev, down in downs.items():
            if down is not None:
                assert down in revs, f"{revs[rev]}: dangling down_revision {down}"

        # Exactly one head (a revision nobody points back to).
        pointed_to = {d for d in downs.values() if d}
        heads = [r for r in revs if r not in pointed_to]
        assert len(heads) == 1, f"expected one head, got {heads}"

    def test_every_migration_has_a_downgrade(self):
        for f in _migration_files():
            txt = f.read_text()
            body = txt.split("def downgrade", 1)
            assert len(body) == 2, f"{f.name}: no downgrade()"
            downgrade_src = body[1]
            assert re.search(
                r"op\.(drop|alter|execute|rename)", downgrade_src
            ), f"{f.name}: downgrade has no reversal ops (forward+rollback discipline)"


class TestModelCompleteness:
    def test_every_model_table_has_a_migration(self):
        os.environ.setdefault("JWT_SECRET", "x" * 40)
        os.environ.setdefault("ENVIRONMENT", "test")
        import importlib
        import pkgutil

        import app.db.models as models_pkg
        from app.db.base import Base

        for mod in pkgutil.iter_modules(models_pkg.__path__):
            importlib.import_module(f"app.db.models.{mod.name}")

        migrated = set()
        for f in _migration_files():
            migrated |= set(re.findall(r'create_table\(\s*["\']([a-z_]+)["\']', f.read_text()))

        model_tables = set(Base.metadata.tables.keys())
        missing = model_tables - migrated
        assert not missing, f"model tables with no migration (drift): {sorted(missing)}"


class TestOfflineRoundTrip:
    """DB-free reversibility: alembic emits forward + rollback SQL."""

    def _alembic(self, *args: str) -> str:
        env = {
            **os.environ,
            "JWT_SECRET": "x" * 40,
            "ENVIRONMENT": "test",
            "DATABASE_URL": "postgresql+asyncpg://u:p@localhost/db",
        }
        out = subprocess.run(
            [sys.executable, "-m", "alembic", *args],
            cwd=_BACKEND,
            env=env,
            capture_output=True,
            text=True,
        )
        assert out.returncode == 0, f"alembic {args} failed: {out.stderr[-500:]}"
        return out.stdout

    def test_forward_and_rollback_sql_is_symmetric(self):
        up = self._alembic("upgrade", "--sql", "head")
        down = self._alembic("downgrade", "--sql", "head:base")
        creates = len(re.findall(r"CREATE TABLE", up, re.IGNORECASE))
        drops = len(re.findall(r"DROP TABLE", down, re.IGNORECASE))
        assert creates > 0
        assert creates == drops, f"non-reversible: {creates} CREATE vs {drops} DROP"
