//! Values a light client pins instead of trusting the proof for them. Regenerate with
//! `zk-sync constants --executable chain_segment.executable.json --max-log-rows 20`
//! whenever the Cairo program or the prover configuration changes.

/// Blake2s over the `chain_segment` bytecode, felt by felt as eight little-endian u32
/// limbs (what `zk-sync verify` computes over a proof's public program).
/// Pinned 2026-10-16 from Raito fork `packages/chain_segment` (19,800 words).
pub const CHAIN_SEGMENT_PROGRAM_ID: &str = "f58bbd8f77fa1af93c8d1aa88f1bb1aa22d108731c34aaf851c860c65e1f79fb";

/// Root of the preprocessed-trace commitment for `CanonicalWithoutPedersenUpTo(20)`,
/// log blowup 1, Blake2s Merkle channel.
pub const PREPROCESSED_ROOT_K20: &str = "954bc5feaef41d719e063535db113b34445e4499e5541cfd512b8ff3d735805d";

/// The builtins `chain_segment`'s standalone entry point declares, in order. The
/// verifier learns which public segment belongs to which builtin only from the proof's
/// layout, so the client checks that layout against this list, not against whatever
/// executable file it is given.
pub const CHAIN_SEGMENT_BUILTINS: &[&str] = &["output", "range_check", "bitwise"];
