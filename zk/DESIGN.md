# bitcoin-zk: rust-bitcoin as a proving client

Experimental fork branch (`zk-client`). Not intended for upstream: rust-bitcoin's
CONTRIBUTING.md does not accept agent-authored PRs, and this branch is agent-assisted.

## Goal

Make rust-bitcoin types the front door to a STARK-proven Bitcoin client:

    bitcoin::Block + spent TxOuts
        -> Raito client arguments (Cairo serde felts)         [bitcoin-zk::args]
        -> Raito `client` program, script checks via Shinigami [Cairo, built by Scarb]
        -> cairo-vm run under the simple bootloader             [bitcoin-zk::prove]
        -> stwo-cairo proof                                     [bitcoin-zk::prove]
        -> stwo-cairo verification                              [bitcoin-zk::verify]

and measure every stage natively and compiled to WebAssembly, on the same input.

## What already exists upstream (so we do not rebuild it)

- Raito (`starkware-bitcoin/raito`) validates blocks in Cairo, and its `consensus`
  package has a `shinigami` feature that routes script validation to Shinigami
  (`packages/consensus/src/validation/script.cairo`).
- Raito drives proving from Rust (`crates/raito-assumevalid/src/prove.rs`): bootloader,
  `cairo_run_program`, `stwo_cairo_adapter::adapt`, `create_and_serialize_proof`.
- Raito ships a WASM *verifier* (`crates/raito-spv-verify-wasm`).
- Raito already depends on rust-bitcoin 0.32.6, but only for RPC/header plumbing. Its
  block-argument generator is Python (`scripts/data/generate_data.py`).

## What this branch adds

1. `args`: a Rust serializer from rust-bitcoin types to Raito's client arguments,
   replacing the Python generator. Checked differentially against Raito's own fixtures
   (`packages/client/tests/data/full_*.json`).
2. `prove` / `verify`: the bootloader + cairo-vm + stwo pipeline as a library with
   per-stage timing and peak memory, buildable for `x86_64` and `wasm32-wasip1(-threads)`.
3. `zk-bench`: one binary, same input, JSON timings per stage per target.
4. Shinigami swap: build Raito's `client` against `patrickdugan/shinigami@taproot-provable`
   (the branch fixed against Bitcoin Core's script vectors) instead of Raito's pin of
   upstream `1963116`, and record whether the program hash and step count change.

## Benchmark matrix

| target                    | SIMD                     | threads     | address space |
|---------------------------|--------------------------|-------------|---------------|
| x86_64 native             | AVX-512 (target-cpu=native) | rayon, 20 | host          |
| x86_64 portable           | baseline SSE2            | rayon       | host          |
| wasm32-wasip1 (wasmtime)  | simd128                  | 1           | 4 GiB         |
| wasm32-wasip1-threads     | simd128                  | wasi threads | 4 GiB        |
| wasm64 (memory64), stretch | simd128                 | 1           | > 4 GiB       |

Stages timed separately: args serialization, cairo-vm execution (steps), adapt, prove,
verify; plus proof size and peak RSS.

Inputs, smallest first:
- block 170 (`full_169.json`): the first non-coinbase spend, one P2PK ECDSA check.
- block 2016 (`full_2015.json`): difficulty-epoch boundary, no scripts.
- later fixtures (segwit, taproot) once the small cases work.

## Known risk, stated up front

Earlier Stwo runs on this machine peaked at 14 to 15 GB RSS even for tiny programs
(see the vtxo-exit-proof notes). wasm32 has a hard 4 GiB linear memory. If that floor
comes from the preprocessed trace (Pedersen columns are the usual suspect) the
`canonical_without_pedersen` preprocessed variant may fit; if not, wasm32 proving is
infeasible for Cairo programs and the WASM result is "verify and execute in WASM, prove
natively", which is still worth measuring. memory64 is the escape hatch.

The claim this branch can support is a measured one: stage timings and memory for the
same block on each target, with the proof verified. Nothing here makes rust-bitcoin a
validating node by itself; it makes rust-bitcoin the typed entry point to one.
