"""Computed blast radius (Tier A). The reasons are the product, so the tests
assert on the reasons — not just the score.
"""

from __future__ import annotations

import copy

import pytest

from app.aibom.blast_radius import compute_blast_radius

pytestmark = pytest.mark.unit


def _reasons(br) -> dict[str, str]:
    return {f.name: f.detail for f in br.factors}


# ─────────────────────────────────────────── the honest-empty case (Tier A claim)


def test_empty_asset_is_low_radius_with_reasons() -> None:
    """An asset with no agentic metadata is not a middling guess — it is a LOW
    radius whose factors state the absence, because a CISO trusts a number as
    far as its stated basis."""
    br = compute_blast_radius({"id": "a1"})

    assert br.severity == "low"
    assert br.score < 25.0
    r = _reasons(br)
    assert r["tool_reach"] == "no tool grants recorded"
    assert r["external_action_surface"] == "no external actions granted"
    assert r["downstream_fanout"] == "no downstream connections known"
    assert r["autonomy"] == "non-agentic (no autonomous action)"
    assert r["exposure"] == "exposure not recorded"
    assert r["data_sensitivity"] == "data classification not recorded"


def test_nothing_is_invented_from_unknown_keys() -> None:
    """Permissive-when-missing lens: a metadata bag of ONLY unknown keys must
    invent nothing — same result as an empty asset."""
    junk = compute_blast_radius({"id": "a1", "wibble": 5, "unknown_field": ["x"], "foo": "bar"})
    empty = compute_blast_radius({"id": "a1"})

    assert junk.score == empty.score
    assert _reasons(junk) == _reasons(empty)
    assert junk.reach == empty.reach


# ─────────────────────────────────────────── partial and rich


def test_partial_asset_scores_only_what_is_present() -> None:
    """Some reach known, some not. Present factors carry real reasons; absent
    ones say so."""
    br = compute_blast_radius(
        {"id": "a2", "tools": ["shell", "http"], "downstream_consumers": ["billing"]}
    )
    r = _reasons(br)
    assert "2 tool grant(s)" in r["tool_reach"]
    assert "billing" in r["downstream_fanout"]
    assert r["external_action_surface"] == "no external actions granted"
    assert 0.0 < br.score < 100.0


def test_rich_agentic_internet_asset_is_high_or_critical() -> None:
    br = compute_blast_radius(
        {
            "id": "a3",
            "is_agentic": True,
            "human_in_loop_required": False,
            "max_tool_calls_per_session": 999,
            "tools": ["shell", "http", "db"],
            "mcp_servers": ["fs", "web"],
            "allowed_external_actions": ["send_email", "post_webhook", "wire_transfer"],
            "downstream_consumers": ["billing", "crm", "analytics"],
            "exposure": "public",
            "data_classification": "restricted",
        }
    )
    assert br.severity in ("high", "critical")
    assert br.score >= 50.0
    assert br.reach["autonomy"]["is_agentic"] is True


# ─────────────────────────────────────────── containment


def test_containment_lists_present_mitigations() -> None:
    br = compute_blast_radius(
        {
            "id": "a4",
            "is_agentic": True,
            "human_in_loop_required": True,
            "max_tool_calls_per_session": 5,
            "exposure": "internal_only",
        }
    )
    assert "human-in-the-loop required for agentic actions" in br.containment
    assert "tool-call budget capped at 5 per session" in br.containment
    assert "internal-only exposure" in br.containment
    assert "no external actions granted" in br.containment


# ─────────────────────────────────────────── determinism (Tier A liability if not)


def test_same_asset_yields_byte_identical_decomposition() -> None:
    asset = {
        "id": "a5",
        "is_agentic": True,
        "tools": ["b", "a", "c"],
        "downstream_consumers": ["z", "y"],
        "allowed_external_actions": ["m", "n"],
        "exposure": "public",
    }
    a = compute_blast_radius(copy.deepcopy(asset))
    b = compute_blast_radius(copy.deepcopy(asset))
    assert a == b


def test_list_ordering_in_input_does_not_change_output() -> None:
    """Reach lists are sorted before they are read, so a different storage order
    of the same set produces the same reasons and score — a design partner who
    reruns gets the same answer."""
    one = compute_blast_radius(
        {"id": "a6", "tools": ["a", "b", "c"], "downstream_consumers": ["x", "y"]}
    )
    two = compute_blast_radius(
        {"id": "a6", "tools": ["c", "a", "b"], "downstream_consumers": ["y", "x"]}
    )
    assert one == two


def test_reach_lists_are_sorted() -> None:
    br = compute_blast_radius({"id": "a7", "downstream_consumers": ["gamma", "alpha", "beta"]})
    assert br.reach["downstream_consumers"] == ["alpha", "beta", "gamma"]


# ─────────────────────────────────────────── malformed input must not fabricate


def test_string_false_is_not_agentic() -> None:
    """bool("false") is True — the trap. A string must not score the asset
    agentic, and the reason must say the value was unparseable."""
    br = compute_blast_radius({"id": "m1", "is_agentic": "false"})
    assert br.reach["autonomy"]["is_agentic"] is False
    assert _reasons(br)["autonomy"] == (
        "is_agentic present but not a boolean — unscored (treated non-agentic)"
    )
    # containment must NOT claim a human gate on a non-agentic asset
    assert not any("human-in-the-loop" in c for c in br.containment)


def test_string_false_human_in_loop_is_not_claimed_as_containment() -> None:
    """The operator recorded human_in_loop as absent (string 'false'); a
    mitigation must not be claimed present."""
    br = compute_blast_radius(
        {"id": "m2", "is_agentic": True, "human_in_loop_required": "false"}
    )
    assert not any("human-in-the-loop" in c for c in br.containment)
    assert "human_in_loop=unparseable (treated absent)" in _reasons(br)["autonomy"]


def test_bool_budget_is_not_a_budget() -> None:
    """max_tool_calls_per_session=True must not become 'capped at 1'."""
    br = compute_blast_radius(
        {"id": "m3", "is_agentic": True, "max_tool_calls_per_session": True}
    )
    assert br.reach["autonomy"]["max_tool_calls_per_session"] is None
    assert not any("budget capped" in c for c in br.containment)
    assert "max_tool_calls=unparseable" in _reasons(br)["autonomy"]


def test_negative_budget_is_not_a_budget() -> None:
    br = compute_blast_radius(
        {"id": "m4", "is_agentic": True, "max_tool_calls_per_session": -3}
    )
    assert br.reach["autonomy"]["max_tool_calls_per_session"] is None
    assert not any("-3" in c for c in br.containment)


def test_string_where_list_expected_counts_nothing() -> None:
    """tools='shell' must not count 5 tools (len of the string)."""
    br = compute_blast_radius({"id": "m5", "tools": "shell", "downstream_consumers": "billing"})
    assert br.reach["tool_reach"]["tools"] == 0
    assert _reasons(br)["tool_reach"] == "no tool grants recorded"
    assert br.reach["downstream_consumers"] == []


def test_present_but_unmapped_exposure_says_unrecognised_not_absent() -> None:
    """exposure='dmz' IS recorded — the reason must not claim 'not recorded'."""
    br = compute_blast_radius({"id": "m6", "exposure": "dmz"})
    detail = _reasons(br)["exposure"]
    assert "not a recognised level" in detail
    assert "not recorded" not in detail


def test_absent_exposure_says_not_recorded() -> None:
    br = compute_blast_radius({"id": "m7"})
    assert _reasons(br)["exposure"] == "exposure not recorded"
