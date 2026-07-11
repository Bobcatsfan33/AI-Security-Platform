"""Tenant isolation enforced at the data layer — two independent walls.

Wall 1 — ORM guard: a SQLAlchemy ``do_orm_execute`` listener injects
    ``WHERE org_id = <current org>`` into every ORM SELECT/UPDATE/DELETE that
    touches a model carrying the :class:`TenantScoped` marker. Repositories no
    longer need to remember the filter; forgetting it is impossible.

Wall 2 — Postgres Row-Level Security: every tenant table carries an RLS policy
    keyed on the ``app.current_org`` GUC, set per-transaction from the
    authenticated identity (see ``auth/dependencies.py``). Raw SQL, future ORM
    bypasses, and bugs in Wall 1 all stop here. The application connects as a
    role WITHOUT BYPASSRLS (see ``deploy/db/roles.sql``); only Alembic uses the
    owner role. Tables are ``FORCE``d so even the owner is bound.

Fail-closed semantics: a query against tenant-scoped data with no org in context
returns zero rows (criteria ``1=0``), never all rows. The only escape hatch is
an explicit, grep-able execution option (``bypass_tenant_guard``) used at exactly
two sanctioned call sites — API-key resolution and SCIM IdP resolution — each of
which emits a ``tenant.guard_bypass`` audit event.
"""

from __future__ import annotations

import uuid
from contextvars import ContextVar

from sqlalchemy import ForeignKey, event, false, or_
from sqlalchemy.orm import Mapped, Session, declared_attr, mapped_column, with_loader_criteria

# The authenticated org for the current request/task. None outside a request,
# which fails tenant-scoped queries closed (zero rows) rather than open.
current_org_id: ContextVar[uuid.UUID | None] = ContextVar("current_org_id", default=None)


class TenantScoped:
    """Marker mixin for tenant-owned models.

        class AIAsset(Base, TenantScoped): ...

    Declares the ``org_id`` foreign key once, so every tenant model carries an
    identical, indexed FK to ``organizations`` and the Wall-1 guard can target
    the whole family via ``with_loader_criteria(TenantScoped, ...)``. A concrete
    model may still restate ``org_id`` (e.g. for a composite constraint); the
    definitions are identical, so the schema is unchanged.
    """

    __abstract__ = True

    # Most tenant models are strictly per-tenant: every row has a non-null
    # ``org_id`` and is visible only to that org. A few carry a shared,
    # cross-tenant library alongside per-tenant rows, encoded as ``org_id IS
    # NULL`` (e.g. TestCase's global attack library — see the nullable
    # ``org_id`` in ``app/db/models/test_case.py`` and the NULL-tolerant RLS
    # policy in migration 0008). Those models set this True so the Wall-1 guard
    # keeps their shared rows visible instead of filtering them out. NULL-org
    # rows hold no tenant data, so exposing them across tenants is intentional,
    # not a leak; the matching RLS policy admits them too.
    __tenant_global_readable__: bool = False

    @declared_attr
    def org_id(cls) -> Mapped[uuid.UUID]:  # noqa: N805 - SQLAlchemy mixin convention
        return mapped_column(
            ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        )


def _tenant_guard(execute_state) -> None:
    if not (execute_state.is_select or execute_state.is_update or execute_state.is_delete):
        return
    if execute_state.execution_options.get("bypass_tenant_guard", False):
        return  # sanctioned bypass — see module docstring

    org = current_org_id.get()

    def _criteria(cls):
        # ``with_loader_criteria`` invokes this once per TenantScoped entity in
        # the statement, so the rule can vary per model. Global-readable models
        # keep their shared ``org_id IS NULL`` rows visible.
        global_readable = getattr(cls, "__tenant_global_readable__", False)
        if org is None:
            # Fail closed: a request with no org sees nothing tenant-owned —
            # except a global-readable model's shared rows, which hold no
            # tenant data (never a tenant's private rows).
            return cls.org_id.is_(None) if global_readable else false()
        if global_readable:
            return or_(cls.org_id == org, cls.org_id.is_(None))
        return cls.org_id == org

    execute_state.statement = execute_state.statement.options(
        with_loader_criteria(TenantScoped, _criteria, include_aliases=True)
    )


def install_tenant_guard() -> None:
    """Arm Wall 1. Call once at startup (app.main lifespan). Idempotent."""
    if not event.contains(Session, "do_orm_execute", _tenant_guard):
        event.listen(Session, "do_orm_execute", _tenant_guard)
