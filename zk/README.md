# bitcoin-zk: proving Bitcoin blocks from rust-bitcoin, natively and in WebAssembly

Experimental branch `zk-client` of rust-bitcoin. Agent-assisted, not for upstream
(rust-bitcoin's CONTRIBUTING.md does not accept agent-authored PRs). Design notes are in
[DESIGN.md](DESIGN.md).

## What runs end to end

    raw block bytes
      -> rust-bitcoin decode + validate (Block<Checked>)         zk/args
      -> Raito `client` arguments, chain-state transition          zk/args
      -> Raito client program (Cairo), scripts via Shinigami       ../raito @ shinigami-provable
      -> cairo-vm in proof mode, no bootloader                     zk/prover/bench (--direct)
      -> stwo-cairo proof, bounded preprocessed trace              vendored stwo-cairo + patch
      -> stwo-cairo verification + program pinning                 zk/prover/bench

The same `zk-bench` binary builds for x86_64 and for `wasm32-wasip1` /
`wasm32-wasip1-threads`, and on block 170 and block 2016 **the WASM build produces the
same proof, byte for byte, as the native build** (identical SHA-256 of the proof files),
and that proof verifies.

Block 170 is the first transaction spending a real output (Satoshi to Hal Finney, one
P2PK ECDSA check). Block 2016 is the first difficulty-retarget block (coinbase only).

## Results (2026-10-16)

One laptop: AMD Ryzen AI 9 365 (10 cores / 20 threads, AVX-512), 31 GB, running the
benchmarks in WSL2 (15.5 GB plus a 32 GB swap file). Native builds use
`-C target-cpu=native`; WASM builds use `+simd128` and run under wasmtime (49.0.3
single-threaded, 36.0.2 for wasi-threads). Production stwo-cairo parameters throughout:
Blake2s channel, blowup 2, 70 queries, 26 PoW bits (96-bit security). Peak RSS is the
process's (wasmtime's for WASM). Raw runs: `zk-runs/*.jsonl` on the dev machine;
`prover/scripts/summarize.py` makes these tables.

**Bounded preprocessed trace (k = 20), direct mode, prove time in seconds, median of 3:**

| rayon threads | native 2016 | WASM 2016 | WASM / native | native 170 | WASM 170 | WASM / native |
|---|---|---|---|---|---|---|
| 1 | 8.5 | 16.4 | 1.9x | 12.8 | 23.7 | 1.85x |
| 4 | **5.9** | **10.5** | 1.8x | **9.8** | **16.8** | 1.7x |
| 10 | 12.9 | 25.1 | 1.9x | 20.1 | 39.5 | 2.0x |

Verify: 0.1 s native, 0.15 to 0.35 s WASM. Peak RSS: 1.8 to 2.0 GB (block 2016) and
2.6 to 2.7 GB (block 170) on both targets. cairo-vm execution: 2.2 to 2.4 s native,
4.2 to 5.7 s WASM. rust-bitcoin decode plus argument serialization: under 1 ms on both.
Proofs are JSON, 66 to 68 MB, mostly the client bytecode carried in public memory.

Both targets are fastest at 4 threads and get slower with more: at 10 or 20 threads the
prover spends 3 to 5 cores of CPU time for a 2x slower result. The default (one rayon
thread per logical CPU, 20 here) is the worst setting on this machine.

**How the paths compare (block 170 unless noted):**

| path | steps | prove | peak RSS |
|---|---|---|---|
| Raito's bootloader, stock preprocessed (block 2016) | 4,137,748 | 676 s, paging | 14.9 GB + swap |
| direct, stock preprocessed, 20 threads (1 run) | 839,768 | 53.9 s | 9.1 GB |
| direct, stock preprocessed, 4 threads (3 runs) | 839,768 | 80 to 144 s | 9.1 GB |
| direct, bounded k=20, 4 threads (3 runs) | 839,768 | 8.7 to 10.4 s | 2.6 GB |
| WASM, stock preprocessed | | fails: a 2 GiB `Vec` in the preprocessed Merkle tree | |
| WASM threads (4), bounded k=20 (3 runs) | 839,768 | 14.9 to 18.7 s | 2.7 GB |

The stock 9 GB runs were erratic (even their cairo-vm stage took 3 to 16 s) because a
9 GB working set in a 15.5 GB VM on a 31 GB laptop puts the host under memory pressure;
how much of the bounded variant's speedup survives on a machine with ample RAM is not
measured here. Its memory reduction (3.5x on block 170, 4.5x on block 2016) is.

## Where the time and memory went, and what this branch changed

1. **The bootloader was 82 to 95% of the trace.** Raito proves by running its client as
   a task under StarkWare's simple bootloader, which hashes the 250,651-word client
   program inside Cairo: about 3.94M steps before any Bitcoin validation. Block 170's
   actual validation is 839,768 steps, of which script validation (one ECDSA check,
   constrained) is about 647k. `--direct` runs the client as a standalone executable,
   the way stwo-cairo's `cairo-prove` does.
2. **The memory floor was the preprocessed trace, sized for the largest program
   stwo-cairo supports.** Its `Seq` columns go to 2^25 rows for every proof, and the
   prover precomputes twiddles for 2^26-row components. That fixes about 8 GB of RSS for
   a 193k-step proof, and on wasm32 one Merkle layer of it is a single 2 GiB allocation,
   which is impossible there. `patches/stwo-cairo-zk.patch` adds a
   `CanonicalWithoutPedersenUpTo(k)` variant whose `Seq` columns and twiddles stop at
   2^k rows, and fails loudly if a component is larger. Block 170's largest components
   are 2^20 rows, so k = 20.
3. **WASM needed four small dependency fixes**, all in `prover/scripts/vendor.sh` and
   the patch: cairo-vm forced `no_std` on every wasm32 target (WASI has std);
   parking_lot_core needs its `nightly` feature to park threads with WASM atomics; two
   stwo-cairo witness generators unwrapped a dedicated rayon pool that cannot be built
   without threads; wasmtime 49 dropped the wasi-threads proposal, so threaded runs use
   wasmtime 36.0.2.

## Caveats

- **The bounded variant is this fork's.** Its preprocessed root differs from stock
  stwo-cairo's, so stock verifiers (including Cairo verifiers for recursion) will not
  accept these proofs. Prover and verifier here agree on k.
- **Direct mode moves the program check to the verifier.** Without the bootloader the
  proof does not output a program hash; the claim carries the program in public memory
  and `zk-bench` checks it word for word against the client executable before
  verifying. A light client that already holds the client bytecode could leave it out
  of the wire format; the 66 MB JSON is not a size floor.
- **The chain state input is trusted for now.** The fixture supplies the spent outputs'
  metadata (the UTXO set); Raito's utreexo mode, which proves those, is not wired up.
- **One laptop, three runs per cell**, under WSL2, with the host also in use. Prove times
  ranged up to about 20% around the median for the bounded runs; the WASM/native ratios
  come from interleaved runs in the same session.
- **Two blocks.** Block 170 has one signature. Segwit and taproot blocks, and blocks with
  thousands of inputs, will have components far above 2^20 rows, so they need a larger
  k (or splitting a block across proofs), and the WASM memory budget will bind sooner.

## Soundness findings in the Shinigami path of upstream Raito

Found while porting Raito's script adapter (`packages/consensus/src/validation/script.cairo`)
to the Shinigami fork; fixed on the `shinigami-provable` branch of the Raito clone, not
reported upstream yet.

1. Raito pins upstream Shinigami 1963116, which verifies ECDSA through Starknet secp256k1
   syscalls. In a bootloader/stwo proof a syscall's result comes from a hint, so the
   signature check is not constrained. The upstream client did execute block 170 under
   the bootloader (3,420,337 steps) without complaint.
2. `validate_script` leaves the input loop when the first input passes, so inputs after
   the first are never script-checked.
3. Soft-fork script flags are derived from `inputs[0].previous_output.block_height` (the
   height at which the spent output was created) instead of the height of the block
   being validated.

## Reproducing

WSL Ubuntu 24.04 with rustup, Scarb, wasi-sdk at `/opt/wasi-sdk`, wasmtime 49 and 36.

    cd zk && cargo test --features raito-fixture       # args: differential test vs Raito
    zk/prover/scripts/vendor.sh                         # patched cairo-vm + stwo-cairo
    cargo build --release --bin zk-bench                # in zk/prover (nightly-2025-07-14)
    zk/prover/scripts/build-wasm.sh                     # both WASM targets
    RUNS="fork-direct-bounded-170" zk/prover/scripts/native.sh
    RUNS="mt-bounded-170 st-bounded-170" zk/prover/scripts/wasm.sh

Companion commits (local, not pushed): Raito `shinigami-provable` at `a7d8eb4` (on
upstream 48c237a), and stwo-cairo `small-preprocessed` at `76035a6d` (on e8bc957), whose
diff from e8bc957 is exactly `prover/patches/stwo-cairo-zk.patch`.

The Raito client is built from `../raito` (branch `shinigami-provable`) with
`scarb --profile release build --package client --target-kinds executable
--no-default-features --features shinigami`; `--no-default-features` drops the
`syscalls` feature, under which Raito's SHA-256 is corelib's, computed by the
`sha256_process_block` syscall, i.e. by a hint the proof does not constrain.
