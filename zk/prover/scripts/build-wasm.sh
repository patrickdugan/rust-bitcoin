#!/usr/bin/env bash
# Build zk-bench (or BIN=zk-sync) for WASI. Needs wasi-sdk (for secp256k1-sys's C code) at $WASI_SDK.
#   wasm32-wasip1          single thread, simd128
#   wasm32-wasip1-threads  rayon on wasi-threads, simd128
# Both cap linear memory at 4 GiB, the wasm32 ceiling (the threads target already
# links shared, imported memory; only its default 1 GiB maximum is overridden).
set -eu
WASI_SDK=${WASI_SDK:-/opt/wasi-sdk}
cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-/root/build/rb-zk-prover}
COMMON="-C target-feature=+simd128 -C link-arg=--max-memory=4294967296 -C link-arg=-zstack-size=16777216"
for T in ${TARGETS:-wasm32-wasip1 wasm32-wasip1-threads}; do
  U=$(echo "$T" | tr '-' '_')
  export "CC_$U=$WASI_SDK/bin/clang" "AR_$U=$WASI_SDK/bin/llvm-ar"
  export "CFLAGS_$U=--sysroot=$WASI_SDK/share/wasi-sysroot"
  echo "== $T"
  RUSTFLAGS="$COMMON" cargo build --release --target "$T" --bin "${BIN:-zk-bench}"
  ls -la "$CARGO_TARGET_DIR/$T/release/${BIN:-zk-bench}.wasm"
done
