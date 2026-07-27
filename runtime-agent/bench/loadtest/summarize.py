"""Summarize a proxy-vs-upstream load sweep into the added-overhead table.

Reads locust `<tag>_stats.csv` files written by run.sh (proxy_<level> and
upstream_<level> for each RPS level), pulls the Aggregated row's achieved RPS
and p50/p95/p99, and reports BOTH tails side by side plus their difference —
the proxy's ADDED end-to-end overhead. Absolute numbers are locust+socket
bound; the subtraction removes that common cost.

Percentile subtraction (p99_proxy - p99_upstream) is an approximation — the p99
of a difference is not the difference of p99s — so both tails are reported so a
reader can check the subtraction, exactly as the reviewer asked.

Usage: python3 summarize.py <out_dir> <commit> <level1> <level2> ...
Writes <out_dir>/results.json (env-stamped) and prints a Markdown table.
"""

from __future__ import annotations

import csv
import datetime
import json
import os
import platform
import subprocess
import sys


def agg_row(path: str) -> dict | None:
    if not os.path.exists(path):
        return None
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            if row.get("Name") == "Aggregated":
                return row
    return None


def num(row: dict, key: str) -> float:
    try:
        return float(row[key])
    except (KeyError, ValueError, TypeError):
        return float("nan")


def go_version() -> str:
    try:
        out = subprocess.check_output(["go", "version"], text=True).split()
        return out[2]
    except Exception:
        return "unknown"


def main() -> None:
    out_dir, commit, *levels = sys.argv[1:]
    rows = []
    for level in levels:
        p = agg_row(os.path.join(out_dir, f"proxy_{level}_stats.csv"))
        u = agg_row(os.path.join(out_dir, f"upstream_{level}_stats.csv"))
        if p is None or u is None:
            print(f"! missing CSV for level {level}", file=sys.stderr)
            continue
        p_count = int(num(p, "Request Count"))
        p_fail = int(num(p, "Failure Count"))
        rec = {
            "level": level,
            "proxy_rps": round(num(p, "Requests/s")),
            "proxy_fail_pct": round(100 * p_fail / max(p_count, 1), 1),
            "proxy_p50": num(p, "50%"),
            "proxy_p95": num(p, "95%"),
            "proxy_p99": num(p, "99%"),
            "proxy_failures": int(num(p, "Failure Count")),
            "upstream_p50": num(u, "50%"),
            "upstream_p95": num(u, "95%"),
            "upstream_p99": num(u, "99%"),
        }
        for q in ("50", "95", "99"):
            rec[f"added_p{q}"] = rec[f"proxy_p{q}"] - rec[f"upstream_p{q}"]
        rows.append(rec)

    results = {
        "env": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "commit": commit,
            "go_version": go_version(),
            "os": platform.system().lower(),
            "arch": platform.machine(),
            "num_cpu": os.cpu_count(),
            "locust_ms": "percentiles are milliseconds",
        },
        "levels": rows,
    }
    with open(os.path.join(out_dir, "results.json"), "w") as f:
        json.dump(results, f, indent=2)

    # Markdown table for docs/BENCHMARKS.md (added overhead = proxy - upstream).
    print("\n| RPS (achieved) | fail% | proxy p50/p95/p99 (ms) | upstream p50/p95/p99 (ms) | ADDED p50/p95/p99 (ms) |")
    print("|---|---|---|---|---|")
    for r in rows:
        print(
            f"| {r['proxy_rps']} | {r['proxy_fail_pct']} | "
            f"{r['proxy_p50']:.0f} / {r['proxy_p95']:.0f} / {r['proxy_p99']:.0f} "
            f"| {r['upstream_p50']:.0f} / {r['upstream_p95']:.0f} / {r['upstream_p99']:.0f} "
            f"| {r['added_p50']:.0f} / {r['added_p95']:.0f} / {r['added_p99']:.0f} |"
        )


if __name__ == "__main__":
    main()
