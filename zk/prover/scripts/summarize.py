#!/usr/bin/env python3
"""Median table from run.py results.

usage: summarize.py RESULTS.jsonl [RESULTS.jsonl ...]

Groups runs by label, keeps successful ones, and prints the median of each stage time
with the run count and min-max range of the prove time, as a Markdown table.
"""

import json
import statistics
import sys
from collections import defaultdict


def main() -> None:
    runs = defaultdict(list)
    failed = defaultdict(int)
    for path in sys.argv[1:]:
        with open(path) as f:
            for line in f:
                r = json.loads(line)
                if r.get("exit") == 0 and "bench" in r:
                    runs[r["label"]].append(r)
                else:
                    failed[r["label"]] += 1

    def med(rs, key, src="bench"):
        vals = [r[src][key] for r in rs if key in r.get(src, {})] if src else [r[key] for r in rs if key in r]
        return statistics.median(vals) if vals else None

    print("| run | n | steps | execute s | prove s (median) | prove range | verify s | cores used | peak RSS MiB |")
    print("|---|---|---|---|---|---|---|---|---|")
    for label in sorted(runs, key=lambda l: (l.split("/")[3] if l.count("/") >= 3 else "", l)):
        rs = runs[label]
        proves = [r["bench"]["prove_s"] for r in rs if "prove_s" in r["bench"]]
        rng = f"{min(proves):.1f}-{max(proves):.1f}" if proves else ""
        def fmt(v, p=2):
            return "" if v is None else f"{v:.{p}f}"
        print(
            f"| {label} | {len(rs)} | {rs[0]['bench'].get('steps', '')} | {fmt(med(rs, 'execute_s'))} "
            f"| {fmt(med(rs, 'prove_s'), 1)} | {rng} | {fmt(med(rs, 'verify_s'))} "
            f"| {fmt(med(rs, 'cores_used', None))} | {fmt(med(rs, 'child_peak_rss_mib', None), 0)} |"
        )
    for label, n in sorted(failed.items()):
        print(f"\nfailed: {label} x{n}")


if __name__ == "__main__":
    main()
