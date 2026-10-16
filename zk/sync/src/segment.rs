//! Arguments and public output of the Cairo `chain_segment` program
//! (Raito fork, `packages/chain_segment`).

use bitcoin::block::Header;
use bitcoin_zk_args::{ChainState, Felt, Writer};

use crate::digest::Digest;
use crate::mmr::Mmr;

/// `Args { chain_state, block_mmr, blocks }` as Cairo serde felts. Each block is its
/// header with `TransactionData::MerkleRoot` (variant 0).
pub fn segment_args(state: &ChainState, mmr: &Mmr, headers: &[Header]) -> Vec<Felt> {
    let mut w = Writer::default();
    w.chain_state(state);
    // `MaybeBlake2sDigestSerde` reads each root as (high, low); (0, 0) is a gap.
    w.len(mmr.roots().len());
    for root in mmr.roots() {
        let (high, low) = root.map(|d| d.to_u128_halves()).unwrap_or((0, 0));
        w.uint(high);
        w.uint(low);
    }
    w.len(headers.len());
    for h in headers {
        w.header(h);
        w.uint(0);
        w.digest(h.merkle_root.to_byte_array());
    }
    w.felts
}

/// The program's `Output`: what one segment proof states.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SegmentClaim {
    pub initial_state: Digest,
    pub initial_mmr: Digest,
    pub final_state: Digest,
    pub final_mmr: Digest,
    pub n_blocks: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputError {
    WrongLength(usize),
    NotAU128,
    NotAU32,
}

fn felt_u128(f: &[u8; 32]) -> Result<u128, OutputError> {
    if f[..16].iter().any(|b| *b != 0) {
        return Err(OutputError::NotAU128);
    }
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&f[16..]);
    Ok(u128::from_be_bytes(lo))
}

/// Decode the public output of a `chain_segment` run: the serialized `Output`, nine felts.
///
/// There is no success flag to check. The executable's standalone entry code asserts that
/// `main` did not panic, and that assertion is part of the proven program: a run in which
/// any header fails validation stops at it (checked: one flipped nonce fails at pc 16 with
/// `ASSERT_EQ 0 != 1`), so no proof of it can exist.
pub fn decode_output(felts: &[[u8; 32]]) -> Result<SegmentClaim, OutputError> {
    if felts.len() != 9 {
        return Err(OutputError::WrongLength(felts.len()));
    }
    let u256 = |i: usize| -> Result<Digest, OutputError> {
        // Cairo serde of u256: low then high.
        Ok(Digest::from_u128_halves(felt_u128(&felts[i + 1])?, felt_u128(&felts[i])?))
    };
    let n_blocks = u32::try_from(felt_u128(&felts[8])?).map_err(|_| OutputError::NotAU32)?;
    Ok(SegmentClaim {
        initial_state: u256(0)?,
        initial_mmr: u256(2)?,
        final_state: u256(4)?,
        final_mmr: u256(6)?,
        n_blocks,
    })
}
