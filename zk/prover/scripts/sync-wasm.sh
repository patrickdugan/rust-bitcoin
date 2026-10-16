#!/usr/bin/env bash
# The light client in WebAssembly: run `zk-sync verify` under wasmtime over the proofs
# sync-e2e.sh produced, then prove the first segment in WASM and compare it byte for byte
# with the native proof.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ZK=$(cd "$HERE/../.." && pwd)
WASMTIME=${WASMTIME:-/root/.wasmtime/bin/wasmtime}
WASM=${WASM:-/root/build/rb-zk-prover/wasm32-wasip1/release/zk-sync.wasm}
EXE=${EXE:-/root/build/raito-fork/release/chain_segment.executable.json}
H=$ZK/sync/tests/data/headers_0_2100.bin
OUT=${OUT:-/root/zk-sync-e2e}
K=${K:-20}
HAL=f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16
RUN="$WASMTIME run --dir /::/ -W max-memory-size=4294967296 $WASM"

echo "== light client in wasm32-wasip1"
python3 "$HERE/run.py" "${RESULTS:-/root/zk-runs/sync.jsonl}" wasm-st/sync/verify -- \
  $RUN verify --executable "$EXE" --proofs "$OUT" --max-log-rows "$K" --min-work 0xC900C900C9 \
  --headers "$H" --extend-to 2100 --spv-block "$ZK/args/tests/data/block_170.bin" --txid "$HAL"

[ "${VERIFY_ONLY:-0}" = 1 ] && exit 0
echo "== one segment proven in wasm32-wasip1"
first=$(ls "$OUT"/*.args.json | sort | head -1)
seg=$(basename "$first" .args.json)
end=$(echo "$seg" | cut -d_ -f3 | sed 's/^0*//')
W=$OUT.wasm-seg && rm -rf "$W"
python3 "$HERE/run.py" "${RESULTS:-/root/zk-runs/sync.jsonl}" wasm-st/sync/prove-$seg -- \
  $RUN prove --executable "$EXE" --headers "$H" --from 1 --to "$end" --segment "$end" --out "$W" --max-log-rows "$K"
sha256sum "$OUT/$seg.proof.json" "$W/$seg.proof.json"
