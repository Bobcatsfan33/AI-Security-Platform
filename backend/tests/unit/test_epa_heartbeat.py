"""The EPA consumer's liveness signal.

These are the cases a liveness probe gets judged on, and every one of them is a
way to be wrong in a direction that matters. Reporting a wedged consumer as
healthy leaves detection silently stopped; reporting a healthy one as dead
restarts the fleet and forces the rebalance that wedges consumers in the first
place. Both failures are asserted here rather than assumed.
"""

from __future__ import annotations

import time

import pytest

from app.epa.heartbeat import (
    heartbeat_age,
    heartbeat_is_fresh,
    main,
    write_heartbeat,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def beat_path(tmp_path):
    return tmp_path / "epa.heartbeat"


class TestFreshness:
    def test_a_just_written_heartbeat_is_fresh(self, beat_path):
        write_heartbeat(beat_path)

        assert heartbeat_is_fresh(beat_path, max_age_seconds=60) is True
        assert heartbeat_age(beat_path) == pytest.approx(0, abs=5)

    def test_an_old_heartbeat_is_stale(self, beat_path):
        beat_path.write_text(f"{time.time() - 600:.3f}\n", encoding="utf-8")

        assert heartbeat_is_fresh(beat_path, max_age_seconds=90) is False
        assert heartbeat_age(beat_path) == pytest.approx(600, abs=5)

    def test_the_boundary_is_inclusive(self, beat_path, monkeypatch):
        """A heartbeat exactly at the limit counts as fresh. Excluding it would
        make the probe fire on the tick it was configured to tolerate.

        The clock is frozen rather than computed from ``time.time()``: real time
        advances between writing the file and reading it, so an "exactly 30s"
        test written the obvious way is 30s + epsilon and fails intermittently.
        A flaky liveness test is worse than none — it gets muted.
        """
        monkeypatch.setattr("app.epa.heartbeat.time.time", lambda: 1_000_030.0)
        beat_path.write_text("1000000.000\n", encoding="utf-8")

        assert heartbeat_age(beat_path) == 30.0
        assert heartbeat_is_fresh(beat_path, max_age_seconds=30) is True
        assert heartbeat_is_fresh(beat_path, max_age_seconds=29.9) is False


class TestUnreadableHeartbeatsFailClosed:
    """ "Cannot tell" must never read as healthy.

    Every state below is one a broken consumer actually leaves behind, and each
    would be reported as alive by a check that treated a read failure as a
    non-event.
    """

    def test_a_missing_file_is_not_fresh(self, beat_path):
        assert heartbeat_age(beat_path) is None
        assert heartbeat_is_fresh(beat_path) is False

    def test_an_empty_file_is_not_fresh(self, beat_path):
        beat_path.write_text("", encoding="utf-8")

        assert heartbeat_age(beat_path) is None
        assert heartbeat_is_fresh(beat_path) is False

    def test_garbage_content_is_not_fresh(self, beat_path):
        beat_path.write_text("not-a-timestamp", encoding="utf-8")

        assert heartbeat_age(beat_path) is None
        assert heartbeat_is_fresh(beat_path) is False

    def test_a_directory_where_the_file_should_be_is_not_fresh(self, tmp_path):
        wrong = tmp_path / "epa.heartbeat"
        wrong.mkdir()

        assert heartbeat_age(wrong) is None
        assert heartbeat_is_fresh(wrong) is False


class TestClockSkew:
    def test_a_future_heartbeat_clamps_to_zero_rather_than_going_negative(self, beat_path):
        """An NTP step backwards must not invent a fault. The loop did run; a
        negative age would otherwise sail past any `age > max` comparison as
        healthy in one direction and be nonsense in the other."""
        beat_path.write_text(f"{time.time() + 3600:.3f}\n", encoding="utf-8")

        assert heartbeat_age(beat_path) == 0.0
        assert heartbeat_is_fresh(beat_path, max_age_seconds=1) is True


class TestWriting:
    def test_writing_creates_the_parent_directory(self, tmp_path):
        nested = tmp_path / "var" / "run" / "aisp" / "epa.heartbeat"

        write_heartbeat(nested)

        assert nested.exists()
        assert heartbeat_is_fresh(nested, max_age_seconds=60)

    def test_writing_leaves_no_temp_files_behind(self, tmp_path):
        """The write is atomic via a temp file + rename. A long-running
        consumer beating every few seconds would otherwise fill its volume."""
        target = tmp_path / "epa.heartbeat"

        for _ in range(20):
            write_heartbeat(target)

        assert sorted(p.name for p in tmp_path.iterdir()) == ["epa.heartbeat"]

    def test_a_rewrite_advances_the_timestamp(self, beat_path):
        beat_path.write_text(f"{time.time() - 300:.3f}\n", encoding="utf-8")
        assert heartbeat_is_fresh(beat_path, max_age_seconds=60) is False

        write_heartbeat(beat_path)

        assert heartbeat_is_fresh(beat_path, max_age_seconds=60) is True


class TestProbeEntryPoint:
    """The exec probe contract: Kubernetes reads the exit code and nothing else."""

    def test_a_fresh_heartbeat_exits_zero(self, beat_path, monkeypatch, capsys):
        monkeypatch.setattr("app.epa.heartbeat.DEFAULT_HEARTBEAT_PATH", beat_path)
        write_heartbeat(beat_path)

        assert main(["90"]) == 0
        assert "old" in capsys.readouterr().out

    def test_a_stale_heartbeat_exits_nonzero(self, beat_path, monkeypatch, capsys):
        monkeypatch.setattr("app.epa.heartbeat.DEFAULT_HEARTBEAT_PATH", beat_path)
        beat_path.write_text(f"{time.time() - 600:.3f}\n", encoding="utf-8")

        assert main(["90"]) == 1
        assert "max 90.0s" in capsys.readouterr().out

    def test_a_missing_heartbeat_exits_nonzero(self, beat_path, monkeypatch, capsys):
        monkeypatch.setattr("app.epa.heartbeat.DEFAULT_HEARTBEAT_PATH", beat_path)

        assert main(["90"]) == 1
        assert "no readable heartbeat" in capsys.readouterr().out

    def test_the_default_max_age_applies_when_no_argument_is_given(self, beat_path, monkeypatch):
        monkeypatch.setattr("app.epa.heartbeat.DEFAULT_HEARTBEAT_PATH", beat_path)
        write_heartbeat(beat_path)

        assert main([]) == 0
