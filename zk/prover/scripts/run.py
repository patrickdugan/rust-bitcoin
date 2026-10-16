#!/usr/bin/env python3
"""Run one zk-bench configuration and append a JSON line to a results file.

The bench prints its own per-stage timings as one JSON object on stdout. This wrapper
adds what the bench cannot see from inside a WASM sandbox: wall time of the whole
process and the peak RSS of the child (for WASM runs, that is the wasmtime process,
so it includes the engine's own overhead).

usage: run.py RESULTS.jsonl LABEL -- COMMAND [ARGS...]
"""

import json
import os
import resource
import subprocess
import sys
import time


def main() -> int:
    results, label = sys.argv[1], sys.argv[2]
    cmd = sys.argv[sys.argv.index("--") + 1 :]
    start = time.monotonic()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    wall = time.monotonic() - start
    usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    cpu = usage.ru_utime + usage.ru_stime
    record = {"label": label, "exit": proc.returncode, "wall_s": round(wall, 3),
              "cpu_s": round(cpu, 3), "cores_used": round(cpu / wall, 2) if wall else None,
              "child_peak_rss_mib": round(usage.ru_maxrss / 1024, 1),
              "rayon_threads": os.environ.get("RAYON_NUM_THREADS")}
    bench = None
    for line in proc.stdout.splitlines():
        if line.startswith("{"):
            try:
                bench = json.loads(line)
            except json.JSONDecodeError:
                pass
    if bench is not None:
        record["bench"] = bench
    if proc.returncode != 0:
        record["stderr_tail"] = proc.stderr[-1500:]
    with open(results, "a") as f:
        f.write(json.dumps(record) + "\n")
    print(json.dumps(record))
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
