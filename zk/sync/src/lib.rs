//! ZeroSync-style sync for rust-bitcoin.
//!
//! A light client that learns the header chain from validity proofs instead of
//! replaying it: segment proofs of the Cairo `chain_segment` program each attest that a
//! batch of headers validly extends a committed chain state and block-hash MMR. Linked
//! from genesis, they yield a tip the client can check, extend natively, and query for
//! transaction inclusion. STARK verification itself lives in the prover workspace
//! (`zk/prover/sync`); this crate is the pure, `std`-only logic around it.

pub mod client;
pub mod digest;
pub mod header;
pub mod mmr;
pub mod pins;
pub mod segment;

pub use client::{genesis_mmr, genesis_state, link, ProvenChain, ProvenTip};
pub use digest::{chain_state_digest, header_leaf, Digest};
pub use mmr::{InclusionProof, Mmr, MmrTree};
pub use segment::{decode_output, segment_args, SegmentClaim};

/// Decode a flat file of 80-byte raw headers.
pub fn decode_headers(raw: &[u8]) -> Result<Vec<bitcoin::block::Header>, String> {
    if raw.len() % 80 != 0 {
        return Err(format!("{} bytes is not a whole number of headers", raw.len()));
    }
    raw.chunks_exact(80)
        .enumerate()
        .map(|(i, c)| bitcoin::encoding::decode_from_slice(c).map_err(|e| format!("header {i}: {e:?}")))
        .collect()
}
