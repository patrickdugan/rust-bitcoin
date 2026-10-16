# bitcoin-zk-sync: ZeroSync-style header-chain sync for rust-bitcoin

A light client that learns the Bitcoin header chain from validity proofs instead of
replaying it, in the shape ZeroSync proposed ("ZeroSync: Introducing Validity Proofs to
Bitcoin", Linus et al., 2023) and Raito implements in Cairo 1:

1. **Proven history.** Each proof attests that a batch of headers validly extends a chain
   state, and publishes commitments to where the batch starts and ends.
2. **Trusted tip.** The client verifies the proofs, links them from the genesis state, and
   accepts a chain state and block MMR only if they hash to the final commitments.
3. **Following the chain.** Headers above the proven tip are validated natively with
   rust-bitcoin, under the same rules.
4. **SPV against proven history.** A transaction is checked against its block's Merkle
   root (rust-bitcoin's `MerkleBlock`), and the block header against the proven
   Merkle Mountain Range of block hashes.

## Pieces

| piece | where | what |
|---|---|---|
| `chain_segment` | `../../../raito/packages/chain_segment` (Raito fork) | Cairo program: validates headers on top of a chain state and block MMR; outputs the Blake2s digests of both, before and after, and the batch size |
| `bitcoin-zk-sync` | `zk/sync` (this crate, stable Rust, no prover dependencies) | Raito-compatible digests and MMR, inclusion proofs, native header validation, segment arguments and output decoding, linking, tip acceptance, extension, SPV |
| `zk-sync` | `zk/prover/sync` (nightly, stwo-cairo) | `prove` header ranges into segment proofs; `verify` them as the light client; `run` any argument file, for adversarial checks |

## What a segment proof states, and why it can be trusted

- **The program.** `zk-sync verify` hashes the public program words of each proof and
  requires them to equal the `chain_segment` bytecode; the STARK then shows that this
  program ran.
- **No unconstrained hints.** `chain_segment` is built without `allow-syscalls`, so the
  compiler rejects any syscall, and `zk-sync` refuses to load an executable with a
  `SystemCall` hint. This matters because segments are proven in direct mode: a syscall's
  result is a hint, and no AIR component constrains it. (Raito's own `assumevalid`
  program does hash through the `Sha256ProcessBlock` syscall, but declares the `system`
  builtin, and Raito's bootloader re-checks every SHA-256 syscall in Cairo
  (`verify_sha256`); that is sound under that bootloader only.)
- **Success.** The executable's entry code asserts that `main` did not panic, inside the
  proven program: a batch with one flipped nonce stops there (`ASSERT_EQ 0 != 1` at pc
  16), so it has no proof. The public output is then exactly the nine-felt `Output`.
- **Binding.** The output commits to the initial and final chain state (`ChainState`
  Blake2s digest, as Raito defines it) and block MMR. The client links outputs end to
  start from the genesis commitments and accepts a tip only if it hashes to the last one.
- **Rules.** Inside the proof, per header: link to the previous hash, time above the
  median of the last eleven, difficulty recomputed every 2016 blocks (not taken from
  `bits`), `bits` equal to that target, double-SHA-256 below the target, cumulative work.
  The one rule a proof cannot carry, time not too far in the future, needs the client's
  clock and is left to it.

The Rust side reproduces the Cairo commitments exactly: genesis chain-state digest
`6002eaa4…`, genesis leaf `5fd720d3…`, genesis MMR digest `21f9ae0b…` (Raito's own
vectors), Raito's MMR test vectors, and every honest segment's output.

## What the client checks for each proof

`stwo-cairo`'s Rust `verify_cairo` takes several things from the proof without checking
them; a five-lens adversarial review of this integration (each lens re-checked by a
skeptic) found that each one would let a dishonest prover make a valid proof say
something false. `zk-sync verify` therefore checks, before the STARK:

1. **Security parameters**: PoW 26 bits, blowup 2, 70 FRI queries, last layer degree 0,
   no channel salt. (Otherwise a prover picks `n_queries = 1`.)
2. **Preprocessed trace root**: equal to the pinned root for the bounded variant
   (`pins::PREPROCESSED_ROOT_K20`). (Otherwise the prover commits its own Seq and
   range-check tables, and e.g. memory addresses or u32 limbs stop being constrained.)
3. **Builtin segment slots**: exactly `pins::CHAIN_SEGMENT_BUILTINS` (output,
   range_check, bitwise), not whatever the executable file lists. (The verifier learns
   which pointer belongs to which builtin from the prover's layout; relabelling the
   bitwise segment as `range_check_96` frees every `&`, `^`, `|` in SHA-256.)
4. **Output location**: the output segment starts at the final `ap` and holds exactly the
   nine published felts. (Otherwise the published output need not be what the program
   wrote.)
5. **Program**: the public program words hash to `pins::CHAIN_SEGMENT_PROGRAM_ID`.

Then the STARK, then `link` from the genesis commitments, `accept` of the tip, a
mandatory **minimum-work** check (`--min-work`, the role of Core's `nMinimumChainWork`:
valid proofs from genesis show *a* valid chain, its work is what makes it *the* chain;
`verify` refuses to run without one unless told `--insecure-no-work-floor`), native
extension with the two-hour future-time rule, and SPV with the coinbase matched at leaf 0
(pinning the tree depth) and 64-byte transactions refused (CVE-2017-12842). SPV answers
come only from the proven MMR; headers followed natively above it can be dropped on a
reorg (`reset_to_proven`) without touching what was proven.

A second adversarial round on these fixes (three lenses, each re-checked) found no
critical issue; it walked every field `verify_cairo` reads and classified each as checked
by the verifier, pinned by the client, or prover-chosen but harmless. With the pins, a
verified proof means: the pinned `chain_segment` bytecode ran from pc 1 to its final
`jmp rel 0`, `main` returned without panicking, and the nine published felts are exactly
the `Output` it wrote. It also prompted pinning the builtin list, making the work floor
mandatory, separating proven from natively followed state, and rejecting (rather than
panicking on) a `tip.json` with more than eleven timestamps.

The review also found, and this branch fixes: the MMR digest skips an odd last root
(`chain_segment` now requires it to be `None` and the leaf count to equal height + 1);
Cairo's chain-state digest is non-standard Blake2s at exactly six timestamps (the Rust
side now mirrors Cairo's hasher call for call); non-canonical `nBits` and the BIP34/66/65
version rules (now enforced in Cairo and in Rust). It also refuted one of my claims:
Raito's `assumevalid` SHA-256 syscalls are re-checked by Raito's bootloader. The
stwo-cairo gaps 1 to 4 presumably affect any Rust-side verifier that calls `verify_cairo`
without these checks; that is not checked here.

## Results (2026-10-16)

Mainnet headers 1 to 200 proven in 25 segments of 8, verified by the light client,
extended natively to 2100, and Satoshi's block-170 payment to Hal Finney checked against
the proven MMR (`prover/scripts/sync-e2e.sh`). Laptop: Ryzen AI 9 365, WSL2 capped at
4.5 GB, 4 prover threads, bounded preprocessed trace k = 20, 96-bit parameters.

| step | result |
|---|---|
| prove one segment (8 headers, ~653k Cairo steps) | ~6.9 s, peak ~2.4 GB, proof 15 MB JSON |
| prove headers 1..200 (25 segments) | ~3 min |
| light client: load 25 proofs | 0.60 s |
| light client: shape checks + STARK verify, 25 proofs | 0.37 s |
| light client: link, accept tip 200, work check, extend to 2100, SPV | 1.2 s total, 34 MB |
| segment boundaries at heights 5 and 10 | prove and verify (six-timestamp digest) |
| adversarial: 10 tampered inputs | all rejected, each by the intended check |

**The same client in WebAssembly** (`zk-sync` built for `wasm32-wasip1`, under wasmtime
49, `prover/scripts/sync-wasm.sh`):

| step | result |
|---|---|
| light client, all of the above incl. work check and SPV | 1.5 s client time, 1.7 s wall with a warm module cache, 234 MB |
| prove segment 1..8 in WASM, one thread | 31.6 s, peak 2.6 GB |
| WASM proof vs native proof of the same segment | identical (SHA-256 `06e31644…`) |

## Limits

- **No recursion yet.** ZeroSync and Raito fold each step's proof into the next, so the
  client verifies one proof. Here the client verifies one proof per segment and links them
  outside Cairo: verification is linear in the number of segments. Raito's recursive
  `assumevalid` program needs the stwo verifier inside Cairo and the canonical
  preprocessed trace; at Raito's scale that is out of reach of this laptop (and of the
  4.5 GB WSL budget it now runs under).
- **Headers only.** The UTXO set is not proven (Raito's utreexo mode is the next step);
  SPV here proves inclusion, not that an output is unspent.
- **The bounded preprocessed trace** (`--max-log-rows`) is this fork's patch to
  stwo-cairo; stock verifiers do not accept those proofs.
- **Cost.** Header validation is about 81k Cairo steps per header (pure-Cairo double
  SHA-256), so segments are 8 headers to stay within 2^20-row components. Proving the
  ~940k mainnet headers this way would take ~118k segments; recursion, larger k on a
  bigger machine, and a cheaper hash path (Raito re-checks SHA-256 in its bootloader
  instead) are the levers.
- **Work is the trust anchor**, as for any SPV client. The demo's floor is the real work
  at height 200, which is small: early-chain headers are cheap to forge. A client should
  ship a recent minimum-work value (or checkpoint) and prefer the proven tip with most work.
- **Mainnet only.** Genesis, retarget rules and the BIP heights are mainnet's.
- **Known completeness gap.** Raito's retarget subtracts u32 timestamps; a negative
  epoch timespan (consensus-valid, clamped by Core) would make that segment unprovable.
  It cannot make an invalid chain provable, and mainnet history has no such epoch.
- **The new Cairo rules are unit-tested, and the MMR and nBits checks run in every
  proof, but the version rule only bites from height 227,931,** beyond the proven range.
