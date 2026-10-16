//! The light client: from verified segment claims to a trusted chain tip.
//!
//! 1. `link` checks that verified segment claims form one chain from genesis: each starts
//!    where the previous one ended, the first at the genesis commitments.
//! 2. `ProvenTip::accept` takes a chain state and MMR in the clear and keeps them only if
//!    they hash to the linked chain's final commitments.
//! 3. `ProvenTip::extend` validates newer headers natively, ZeroSync-style: the proof
//!    covers history, the client follows the tip.
//! 4. `ProvenTip::verify_tx` checks that a transaction is in a block of the chain: the
//!    transaction against the header's Merkle root (rust-bitcoin's `MerkleBlock`), the
//!    header against the block MMR.

use bitcoin::block::{Header, HeaderExt as _};
use bitcoin::transaction::TransactionExt as _;
use bitcoin::{BlockHash, Params, Transaction, Txid, Work};
use bitcoin_zk_args::ChainState;
use p2p::merkle_tree::MerkleBlock;

use crate::digest::{chain_state_digest, header_leaf, Digest};
use crate::header::{validate_and_apply, HeaderError};
use crate::mmr::{InclusionProof, Mmr, MmrError};
use crate::segment::SegmentClaim;

/// The chain state after the genesis block, Raito's `ChainState::default()`.
pub fn genesis_state(params: &Params) -> ChainState {
    let genesis = *bitcoin::constants::genesis_block(params).header();
    let time = genesis.time.to_u32();
    ChainState {
        block_height: 0,
        total_work: genesis.work(),
        best_block_hash: genesis.block_hash(),
        current_target: genesis.target(),
        epoch_start_time: time,
        prev_timestamps: vec![time],
    }
}

/// The block MMR after the genesis block.
pub fn genesis_mmr(params: &Params) -> Mmr {
    Mmr::default().add(header_leaf(bitcoin::constants::genesis_block(params).header()))
}

/// What a verified chain of segment proofs establishes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ProvenChain {
    pub height: u32,
    pub state: Digest,
    pub mmr: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    NoSegments,
    /// Segment `index` does not start where the chain so far ends.
    Broken { index: usize },
    EmptySegment { index: usize },
    HeightOverflow,
}

/// Link verified segment claims from genesis. The caller must have verified each claim's
/// STARK proof and pinned its program first; this only checks how the claims connect.
pub fn link(claims: &[SegmentClaim], params: &Params) -> Result<ProvenChain, LinkError> {
    if claims.is_empty() {
        return Err(LinkError::NoSegments);
    }
    let mut chain =
        ProvenChain { height: 0, state: chain_state_digest(&genesis_state(params)), mmr: genesis_mmr(params).digest() };
    for (index, c) in claims.iter().enumerate() {
        if c.initial_state != chain.state || c.initial_mmr != chain.mmr {
            return Err(LinkError::Broken { index });
        }
        if c.n_blocks == 0 {
            return Err(LinkError::EmptySegment { index });
        }
        let height = chain.height.checked_add(c.n_blocks).ok_or(LinkError::HeightOverflow)?;
        chain = ProvenChain { height, state: c.final_state, mmr: c.final_mmr };
    }
    Ok(chain)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TipError {
    /// Not a chain state `chain_segment` can produce (1 to 11 previous timestamps).
    MalformedState,
    StateMismatch,
    MmrMismatch,
    HeightMismatch { proven: u32, state: u32 },
    LeafCountMismatch { height: u32, leaves: u64 },
    InsufficientWork,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpvError {
    HeaderMismatch,
    BadMerkleBlock,
    TxNotMatched,
    /// The coinbase is not leaf 0, or is not a coinbase: the tree depth is not pinned.
    CoinbaseNotMatched,
    /// A transaction whose stripped serialization is 64 bytes can pose as an inner node
    /// of the Merkle tree (CVE-2017-12842); such proofs are refused.
    SixtyFourByteTransaction,
    /// The header is not at the claimed height of the proven MMR.
    Mmr(MmrError),
}

/// A chain tip the client trusts: proven up to `proven_height`, validated natively above.
///
/// The proven part and the natively followed part are kept apart: SPV answers come only
/// from the proven MMR, and a reorg above the proven tip is handled by `reset_to_proven`.
#[derive(Clone, Debug)]
pub struct ProvenTip {
    proven_state: ChainState,
    proven_mmr: Mmr,
    state: ChainState,
    mmr: Mmr,
}

impl ProvenTip {
    /// Keep `state` and `mmr` only if they are the ones `chain` commits to.
    pub fn accept(chain: &ProvenChain, state: ChainState, mmr: Mmr) -> Result<Self, TipError> {
        if !(1..=11).contains(&state.prev_timestamps.len()) {
            return Err(TipError::MalformedState);
        }
        if chain_state_digest(&state) != chain.state {
            return Err(TipError::StateMismatch);
        }
        if mmr.digest() != chain.mmr {
            return Err(TipError::MmrMismatch);
        }
        if state.block_height != chain.height {
            return Err(TipError::HeightMismatch { proven: chain.height, state: state.block_height });
        }
        if mmr.leaf_count() != u64::from(chain.height) + 1 {
            return Err(TipError::LeafCountMismatch { height: chain.height, leaves: mmr.leaf_count() });
        }
        Ok(ProvenTip { proven_state: state.clone(), proven_mmr: mmr.clone(), state, mmr })
    }

    /// The current tip: proven, plus whatever `extend` validated natively.
    pub fn state(&self) -> &ChainState { &self.state }

    pub fn proven_state(&self) -> &ChainState { &self.proven_state }

    pub fn proven_height(&self) -> u32 { self.proven_state.block_height }

    pub fn tip_hash(&self) -> BlockHash { self.state.best_block_hash }

    /// A valid header chain is only as good as the work in it: any chain from genesis
    /// with valid proofs passes `link` and `accept`, including a cheap low-difficulty
    /// fork. Like Bitcoin Core's `nMinimumChainWork`, require at least `min` total work
    /// in the proven part (and, between competing proven tips, prefer the one with more).
    pub fn require_work(&self, min: Work) -> Result<(), TipError> {
        if self.proven_state.total_work < min {
            return Err(TipError::InsufficientWork);
        }
        Ok(())
    }

    /// Validate `headers` natively on top of the tip and append them. All or nothing: on
    /// an error the tip is unchanged. With `now`, headers more than two hours in the
    /// future are refused.
    pub fn extend(&mut self, headers: &[Header], params: &Params, now: Option<u32>) -> Result<(), (usize, HeaderError)> {
        let (mut state, mut mmr) = (self.state.clone(), self.mmr.clone());
        for (i, h) in headers.iter().enumerate() {
            state = validate_and_apply(&state, h, params, now).map_err(|e| (i, e))?;
            mmr = mmr.add(header_leaf(h));
        }
        self.state = state;
        self.mmr = mmr;
        Ok(())
    }

    /// Drop the natively followed headers (e.g. on a reorg above the proven tip).
    pub fn reset_to_proven(&mut self) {
        self.state = self.proven_state.clone();
        self.mmr = self.proven_mmr.clone();
    }

    /// Check that `tx` is in the block `header`, and that `header` is block
    /// `header_proof.leaf_index` of the proven chain. Returns that height.
    ///
    /// `header_proof` is against the proven MMR (`proven_height() + 1` leaves).
    /// `merkle_block` must match both `tx` and the block's coinbase, and the full coinbase
    /// must be supplied: all leaves sit at one depth, so a real coinbase at index 0 pins
    /// the depth the server's (unauthenticated) transaction count implies. What is
    /// authenticated is `tx`'s txid; its witness is not covered by the Merkle root.
    pub fn verify_tx(
        &self,
        header: &Header,
        header_proof: &InclusionProof,
        merkle_block: &MerkleBlock,
        tx: &Transaction,
        coinbase: &Transaction,
    ) -> Result<u32, SpvError> {
        if merkle_block.header != *header {
            return Err(SpvError::HeaderMismatch);
        }
        if tx.base_size() == 64 || coinbase.base_size() == 64 {
            return Err(SpvError::SixtyFourByteTransaction);
        }
        let mut matches = Vec::new();
        let mut indexes = Vec::new();
        merkle_block.extract_matches(&mut matches, &mut indexes).map_err(|_| SpvError::BadMerkleBlock)?;
        let leaf = |txid: Txid| matches.iter().position(|m| *m == txid).map(|i| indexes[i]);
        if !coinbase.is_coinbase() || leaf(coinbase.compute_txid()) != Some(0) {
            return Err(SpvError::CoinbaseNotMatched);
        }
        if leaf(tx.compute_txid()).is_none() {
            return Err(SpvError::TxNotMatched);
        }
        self.proven_mmr.verify(&header_leaf(header), header_proof).map_err(SpvError::Mmr)?;
        Ok(header_proof.leaf_index as u32)
    }
}
