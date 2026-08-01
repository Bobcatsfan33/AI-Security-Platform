"""Liveness signal for the EPA consumer fleet.

The consumer had no probe of any kind. That is a worse gap than it looks: the
process is a long-lived loop over a Kafka stream, and the ways it stops working
mostly leave it *running*. A rebalance that never completes, a broker
connection that half-closes, an await that never returns — the container stays
Up, Kubernetes stays satisfied, and detection stops. Silently, because nothing
downstream distinguishes "no events matched" from "no events arrived".

A TCP or HTTP probe cannot help here; the consumer serves nothing. What is
observable is progress, so that is what gets recorded: the loop touches a file
each time round, and the probe asks how long ago that was.

Deliberately a file and not a metric endpoint. The probe has to work when the
process is too wedged to serve a request, which is the case the probe exists
for — anything that requires the process to respond would go green in exactly
the scenario it is meant to catch.

Freshness is measured against wall-clock ``time.time`` rather than a monotonic
clock: the value has to survive being written by one process and read by
another (the probe runs in a separate exec), and monotonic clocks are only
comparable within a process.
"""

from __future__ import annotations

import contextlib
import os
import pathlib
import tempfile
import time

# Written by the consumer loop, read by the exec probe. Overridable so tests
# and multiple local processes do not fight over one path.
DEFAULT_HEARTBEAT_PATH = pathlib.Path(
    os.environ.get("EPA_HEARTBEAT_PATH", "/tmp/epa-consumer.heartbeat")
)

# How stale is dead. Generous on purpose: a quiet stream is not a fault, so the
# loop touches the heartbeat on its poll cycle rather than only on an event
# (see EpaConsumerService.run). A tighter bound would restart healthy consumers
# during low traffic, which is a self-inflicted outage.
DEFAULT_MAX_AGE_SECONDS = 90.0


def write_heartbeat(path: pathlib.Path | None = None) -> None:
    """Record that the loop is making progress, atomically.

    Atomic because the probe may read at any moment: a torn write would be
    parsed as a corrupt/absent heartbeat and restart a perfectly healthy
    consumer. Write to a temp file in the same directory, then rename.
    """
    target = path or DEFAULT_HEARTBEAT_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(dir=str(target.parent), prefix=".heartbeat-")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(f"{time.time():.3f}\n")
        os.replace(temp_name, target)
    except BaseException:
        # Never leave the temp file behind — the consumer's data directory
        # would fill with them over a long run. suppress() so a cleanup failure
        # cannot mask the original exception.
        with contextlib.suppress(OSError):
            os.unlink(temp_name)
        raise


def heartbeat_age(path: pathlib.Path | None = None) -> float | None:
    """Seconds since the last heartbeat, or None if there is not a usable one.

    None means "cannot tell", which the caller must treat as NOT fresh. An
    absent or unparseable heartbeat is exactly the state a crashed-on-startup
    consumer leaves behind, so reading it as healthy would invert the check.
    """
    target = path or DEFAULT_HEARTBEAT_PATH
    try:
        raw = target.read_text(encoding="utf-8").strip()
    except (FileNotFoundError, NotADirectoryError, PermissionError, IsADirectoryError):
        return None
    try:
        written = float(raw)
    except ValueError:
        return None
    # A heartbeat from the future means the clock moved backwards. Clamp to 0
    # rather than reporting a negative age: the loop did run, and restarting it
    # over an NTP step would be a fault the probe invented.
    return max(0.0, time.time() - written)


def heartbeat_is_fresh(
    path: pathlib.Path | None = None,
    max_age_seconds: float = DEFAULT_MAX_AGE_SECONDS,
) -> bool:
    age = heartbeat_age(path)
    return age is not None and age <= max_age_seconds


def main(argv: list[str] | None = None) -> int:
    """Exec-probe entry point: ``python -m app.epa.heartbeat [max_age]``.

    Exit 0 = fresh, 1 = stale/missing. Kubernetes reads only the exit code, so
    the message goes to stdout for `kubectl describe` to surface.
    """
    import sys

    args = sys.argv[1:] if argv is None else argv
    max_age = float(args[0]) if args else DEFAULT_MAX_AGE_SECONDS
    age = heartbeat_age()
    if age is None:
        print(f"no readable heartbeat at {DEFAULT_HEARTBEAT_PATH}")
        return 1
    if age > max_age:
        print(f"heartbeat is {age:.1f}s old (max {max_age:.1f}s)")
        return 1
    print(f"heartbeat is {age:.1f}s old")
    return 0


if __name__ == "__main__":  # pragma: no cover - process entry point
    raise SystemExit(main())
