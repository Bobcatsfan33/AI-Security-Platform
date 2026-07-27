"""End-to-end load profile for the runtime agent proxy (Phase 2 increment 3).

Drives the REAL proxy on :18400 over a socket at a controlled request rate, so
the reported p50/p95/p99 are the tail an operator sees under load — the
authoritative tail the single-request microbench (docs/BENCHMARKS.md) defers to.

Run it against BOTH targets and subtract:

    # proxy path (pipeline + reverse-proxy forward)
    LOAD_PATH=/proxy/v1/chat/completions locust -f locustfile.py \\
        --host http://127.0.0.1:18400 --headless -u 40 -r 40 --run-time 30s --csv proxy

    # upstream baseline (same locust + socket, no agent) — subtract this
    LOAD_PATH=/v1/chat/completions locust -f locustfile.py \\
        --host http://127.0.0.1:19000 --headless -u 40 -r 40 --run-time 30s --csv upstream

The Go proxy is far faster than a Python generator can saturate, so absolute
numbers are dominated by locust + loopback overhead. That common overhead is
exactly what the subtraction removes: both runs traverse the same
locust+socket path; the difference is the agent's added latency. bench/run.sh
orchestrates the RPS sweep and the subtraction.

FastHttpUser (geventhttpclient) is used, not the default requests client, to
push meaningfully more RPS at the proxy.
"""

from __future__ import annotations

import os

from locust import FastHttpUser, constant_throughput, task

# A benign prompt: it does not match the ruleset, so the proxy runs the full
# pipeline and forwards to the upstream — the allow-path worst case.
_BODY = {
    "model": "gpt-4",
    "messages": [
        {"role": "user", "content": "Summarize the quarterly earnings report in three bullet points."}
    ],
}
_PATH = os.getenv("LOAD_PATH", "/proxy/v1/chat/completions")
# Each simulated user targets this many requests/second; total offered RPS is
# roughly users * PER_USER_RPS (bench/run.sh sets users per RPS level).
_PER_USER_RPS = float(os.getenv("PER_USER_RPS", "25"))


class InferenceUser(FastHttpUser):
    wait_time = constant_throughput(_PER_USER_RPS)

    @task
    def infer(self) -> None:
        # name= keeps every RPS level under one stats row regardless of path.
        self.client.post(_PATH, json=_BODY, name="infer")
