#!/usr/bin/env bash
# WASM benchmark matrix under wasmtime, same inputs and flags as native.sh.
#   wasm-st  wasm32-wasip1, one thread
#   wasm-mt  wasm32-wasip1-threads, rayon over wasi-threads ($THREADS workers)
# Every run goes through guard.sh; peak RSS is the wasmtime process's.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
WASMTIME=${WASMTIME:-/root/.wasmtime/bin/wasmtime}
# wasm32-wasip1-threads uses the legacy wasi-threads proposal, which wasmtime removed
# after the 36 LTS line; run it on a 36.x build.
WASMTIME_THREADS=${WASMTIME_THREADS:-/root/.wasmtime-wasi-threads/bin/wasmtime}
TGT=${TGT:-/root/build/rb-zk-prover}
RAITO=${RAITO:-/mnt/c/Users/patri/OneDrive/Documents/GitHub/raito}
DATA=${DATA:-$(cd "$HERE/../../args/tests/data" && pwd)}
FORK=${FORK:-/root/build/raito-fork/release/client.executable.json}
OUT=${OUT:-/root/zk-runs}
RESULTS=${RESULTS:-$OUT/wasm.jsonl}
THREADS=${THREADS:-20}
RUNS=${RUNS:-"st-exec-170 mt-exec-170 st-bounded-170 mt-bounded-170"}
mkdir -p "$OUT"

# Preopen the host root at the same path so the bench's absolute paths resolve.
ST="$WASMTIME run --dir /::/ -W max-memory-size=4294967296 $TGT/wasm32-wasip1/release/zk-bench.wasm"
MT="$WASMTIME_THREADS run --dir /::/ -W threads=y -S threads=y -W max-memory-size=4294967296 --env RAYON_NUM_THREADS=$THREADS $TGT/wasm32-wasip1-threads/release/zk-bench.wasm"

run() {  # label, engine command, height, extra flags...
  local label=$1 engine=$2 h=$3; shift 3
  case $label in wasm-mt/*) label="$label/t$THREADS" ;; esac
  GUARD_LOG=$OUT/guard-$(echo "$label" | tr '/' '_').log python3 "$HERE/run.py" "$RESULTS" "$label" -- \
    bash "$HERE/guard.sh" $engine --executable "$FORK" \
    --bootloader "$RAITO/bootloaders/simple_bootloader_compiled.json" \
    --fixture "$DATA/full_$((h - 1)).json" --block "$DATA/block_$h.bin" \
    --out "$OUT/$(echo "$label" | tr '/' '_')" "$@"
}

for r in $RUNS; do
  case $r in
    st-exec-2016)    run wasm-st/fork/direct/2016/execute "$ST" 2016 --direct --stop-after execute ;;
    st-exec-170)     run wasm-st/fork/direct/170/execute "$ST" 170 --direct --stop-after execute ;;
    mt-exec-170)     run wasm-mt/fork/direct/170/execute "$MT" 170 --direct --stop-after execute ;;
    # Stock preprocessed trace: expected to fail on wasm32 (a 2 GiB Merkle layer).
    st-stock-2016)   run wasm-st/fork/direct/2016/full "$ST" 2016 --direct ;;
    # This fork's bounded preprocessed trace.
    st-bounded-2016) run wasm-st/fork/direct-k20/2016/full "$ST" 2016 --direct --max-log-rows 20 ;;
    st-bounded-170)  run wasm-st/fork/direct-k20/170/full "$ST" 170 --direct --max-log-rows 20 ;;
    mt-bounded-2016) run wasm-mt/fork/direct-k20/2016/full "$MT" 2016 --direct --max-log-rows 20 ;;
    mt-bounded-170)  run wasm-mt/fork/direct-k20/170/full "$MT" 170 --direct --max-log-rows 20 ;;
  esac
done
