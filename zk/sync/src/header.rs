//! Native header-chain validation with rust-bitcoin, for extending a proven tip.
//!
//! The rules the Cairo `chain_segment` program enforces: the header links to the tip, its
//! version meets the BIP34/66/65 minimum for its height, its time is above the median of
//! the last eleven, its bits are exactly the required compact target (retargeting every
//! 2016 blocks), and its hash meets that target. Plus the one rule a proof cannot carry:
//! a time limit relative to the verifier's clock, applied when the caller passes `now`.

use bitcoin::block::{Header, HeaderExt as _};
use bitcoin::{BlockHash, CompactTarget, Params, Target};
use bitcoin_zk_args::ChainState;

/// Bitcoin Core's `MAX_FUTURE_BLOCK_TIME`.
pub const MAX_FUTURE_BLOCK_TIME: u32 = 2 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderError {
    DoesNotExtendTip { expected: BlockHash, got: BlockHash },
    BadVersion { height: u32, version: i32 },
    TimeNotAboveMedian { median: u32, time: u32 },
    TimeTooFarInFuture { time: u32, now: u32 },
    WrongBits { required: CompactTarget, got: CompactTarget },
    InsufficientWork,
}

/// Median of the previous timestamps, Bitcoin Core's `GetMedianTimePast`.
pub fn median_time_past(prev_timestamps: &[u32]) -> u32 {
    let mut sorted = prev_timestamps.to_vec();
    sorted.sort_unstable();
    sorted[sorted.len() / 2]
}

/// The compact target the next block must carry.
pub fn required_bits(state: &ChainState, params: &Params) -> CompactTarget {
    let last = state.current_target.to_compact_lossy();
    state.required_bits(last, params)
}

/// The minimum version for a block at `height` (`bad-version`).
pub fn min_version(height: u32, params: &Params) -> i32 {
    if height >= params.bip65_height.to_u32() {
        4
    } else if height >= params.bip66_height.to_u32() {
        3
    } else if height >= params.bip34_height.to_u32() {
        2
    } else {
        i32::MIN
    }
}

/// Validate `header` as the block after `state` and return the new state. With
/// `now` (Unix seconds), also reject a header more than two hours in the future.
pub fn validate_and_apply(
    state: &ChainState,
    header: &Header,
    params: &Params,
    now: Option<u32>,
) -> Result<ChainState, HeaderError> {
    if header.prev_blockhash != state.best_block_hash {
        return Err(HeaderError::DoesNotExtendTip { expected: state.best_block_hash, got: header.prev_blockhash });
    }
    let height = state.block_height + 1;
    let version = header.version.to_consensus();
    if version < min_version(height, params) {
        return Err(HeaderError::BadVersion { height, version });
    }
    let time = header.time.to_u32();
    let median = median_time_past(&state.prev_timestamps);
    if time <= median {
        return Err(HeaderError::TimeNotAboveMedian { median, time });
    }
    if let Some(now) = now {
        if u64::from(time) > u64::from(now) + u64::from(MAX_FUTURE_BLOCK_TIME) {
            return Err(HeaderError::TimeTooFarInFuture { time, now });
        }
    }
    let required = required_bits(state, params);
    if header.bits != required {
        return Err(HeaderError::WrongBits { required, got: header.bits });
    }
    header.validate_pow(Target::from(required)).map_err(|_| HeaderError::InsufficientWork)?;
    Ok(state.apply(header))
}
