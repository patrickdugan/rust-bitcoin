#!/usr/bin/env bash
# Native benchmark matrix. Paths are the WSL layout used on the dev machine; override
# with env vars. Results go to $RESULTS as JSON lines (see run.py). Every run goes
# through guard.sh, which kills a run that starts paging (see GUARD_SWAP_MIB).
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=${BIN:-/root/build/rb-zk-prover/release/zk-bench}
RAITO=${RAITO:-/mnt/c/Users/patri/OneDrive/Documents/GitHub/raito}
DATA=${DATA:-$(cd "$HERE/../../args/tests/data" && pwd)}
UP=${UP:-/root/build/raito-up/release/client.executable.json}
FORK=${FORK:-/root/build/raito-fork/release/client.executable.json}
OUT=${OUT:-/root/zk-runs}
RESULTS=${RESULTS:-$OUT/native.jsonl}
RUNS=${RUNS:-"up-boot-exec fork-boot-exec fork-direct-exec-2016 fork-direct-exec-170 fork-direct-full-2016 fork-direct-full-170"}
mkdir -p "$OUT"

run() {  # label, executable, height, extra flags...
  local label=$1 exe=$2 h=$3; shift 3
  [ -n "${RAYON_NUM_THREADS:-}" ] && label="$label/t$RAYON_NUM_THREADS"
  GUARD_LOG=$OUT/guard-$(echo "$label" | tr '/' '_').log python3 "$HERE/run.py" "$RESULTS" "$label" -- \
    bash "$HERE/guard.sh" "$BIN" --executable "$exe" \
    --bootloader "$RAITO/bootloaders/simple_bootloader_compiled.json" \
    --fixture "$DATA/full_$((h - 1)).json" --block "$DATA/block_$h.bin" \
    --out "$OUT/$(echo "$label" | tr '/' '_')" "$@"
}

for r in $RUNS; do
  case $r in
    # Raito's bootloader path; upstream Shinigami pin vs the Core-vector fork.
    up-boot-exec)          run native/upstream/boot/170/execute "$UP" 170 --stop-after execute ;;
    fork-boot-exec)        run native/fork/boot/170/execute "$FORK" 170 --stop-after execute ;;
    fork-boot-full-2016)   run native/fork/boot/2016/full "$FORK" 2016 ;;
    # cairo-prove's direct path: no bootloader, program pinned by the verifier.
    fork-direct-exec-2016) run native/fork/direct/2016/execute "$FORK" 2016 --direct --stop-after execute ;;
    fork-direct-exec-170)  run native/fork/direct/170/execute "$FORK" 170 --direct --stop-after execute ;;
    fork-direct-full-2016) run native/fork/direct/2016/full "$FORK" 2016 --direct ;;
    fork-direct-full-170)  run native/fork/direct/170/full "$FORK" 170 --direct ;;
    # This fork's bounded preprocessed trace (Seq and twiddles up to 2^20 rows).
    fork-direct-bounded-2016) run native/fork/direct-k20/2016/full "$FORK" 2016 --direct --max-log-rows 20 ;;
    fork-direct-bounded-170)  run native/fork/direct-k20/170/full "$FORK" 170 --direct --max-log-rows 20 ;;
    # Any block in the test data, by height H: fork-direct-exec-H (execute only),
    # fork-direct-kK-H (bounded proof, components up to 2^K rows), fork-direct-capN-H
    # (cairo-vm stopped after N steps, for blocks too large to execute here).
    fork-direct-exec-*)       h=${r##*-}; run native/fork/direct/$h/execute "$FORK" "$h" --direct --stop-after execute ;;
    fork-direct-k[0-9]*-*)    h=${r##*-}; k=${r#fork-direct-k}; k=${k%-*}
                              run native/fork/direct-k$k/$h/full "$FORK" "$h" --direct --max-log-rows "$k" ;;
    fork-direct-cap[0-9]*-*)  h=${r##*-}; n=${r#fork-direct-cap}; n=${n%-*}
                              run native/fork/direct-cap$n/$h/execute "$FORK" "$h" --direct --stop-after execute --max-steps "$n" ;;
    *) echo "unknown run $r" >&2 ;;
  esac
done
