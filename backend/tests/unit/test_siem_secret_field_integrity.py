"""SECRET_CONFIG_FIELDS must describe fields the exporters actually accept.

The N1 finding: ``SECRET_CONFIG_FIELDS["elastic"]`` declared ``basic_auth_password``,
but ``ElasticExporter.__init__`` took a ``basic_auth`` tuple — no such parameter.
A config using the DECLARED field resolved its secret, then TypeError'd at build
and was dropped as ``siem_config_invalid``; meanwhile the field the constructor
ACTUALLY accepted was in no secret map, matched no redaction pattern, and so a
raw password there was stored in the clear and echoed verbatim in
``config_redacted``.

The fix aligned the field with the constructor. This is the ratchet that stops
the next such drift: a secret field that names a non-existent parameter is dead
by construction — it can never carry a secret to the wire, which is the one job
a secret field has.
"""

from __future__ import annotations

import inspect

import pytest

from app.api.v1.siem import _looks_secret
from app.siem import exporters as ex
from app.siem.exporters import SECRET_CONFIG_FIELDS

pytestmark = pytest.mark.unit


def _exporter_classes() -> dict[str, type]:
    """type-string -> exporter class, via each class's ``exporter_type`` attr."""
    out: dict[str, type] = {}
    for obj in vars(ex).values():
        etype = getattr(obj, "exporter_type", None)
        if isinstance(obj, type) and isinstance(etype, str):
            out[etype] = obj
    return out


def test_every_exporter_type_has_a_class() -> None:
    classes = _exporter_classes()
    missing = sorted(set(SECRET_CONFIG_FIELDS) - set(classes))
    assert not missing, f"SECRET_CONFIG_FIELDS names types with no exporter class: {missing}"


@pytest.mark.parametrize("etype", sorted(SECRET_CONFIG_FIELDS))
def test_secret_fields_are_real_constructor_parameters(etype: str) -> None:
    """A declared secret field that the constructor does not accept is a dead
    field — it TypeErrors at build and never reaches the wire."""
    cls = _exporter_classes()[etype]
    params = set(inspect.signature(cls.__init__).parameters) - {"self"}

    dead = sorted(SECRET_CONFIG_FIELDS[etype] - params)
    assert not dead, (
        f"{cls.__name__} declares secret field(s) {dead} that its constructor does "
        f"not accept (accepts: {sorted(params)}). A secret field must name a real "
        "parameter, or it cannot carry the secret to the wire."
    )


@pytest.mark.parametrize("etype", sorted(SECRET_CONFIG_FIELDS))
def test_declared_secret_fields_are_redacted(etype: str) -> None:
    """Every declared secret field must also be caught by the redactor — the map
    and the redaction pattern-set must agree, or a validated field still leaks
    on read."""
    for field in SECRET_CONFIG_FIELDS[etype]:
        assert _looks_secret(field, SECRET_CONFIG_FIELDS[etype]), (
            f"{etype}: secret field {field!r} is not redacted by _looks_secret"
        )
