//! Serialize rust-bitcoin blocks into the argument felts of Raito's `client` program.
//!
//! The layout follows the Cairo `Serde` derivations in Raito's `consensus` package
//! (`types/{chain_state,block,transaction}.cairo`) and the reference Python formatter
//! `scripts/data/format_args.py`. The output is the hex felt list that the Scarb runner,
//! cairo-vm's `user_args_file` and Raito's prover all accept.
//!
//! Two deliberate differences from Raito's Python generator, both invisible on blocks
//! whose coinbase witness reserved value is zero:
//! - the coinbase input carries the block's actual witness reserved value; Raito's
//!   generator always writes 32 zero bytes, which BIP-141 does not require;
//! - every field is encoded from its type, so there is no guessing a string's type from
//!   its contents (`format_args.py` reads an all-digit string as a decimal u256).

#[cfg(feature = "raito-fixture")]
pub mod fixture;

use std::collections::HashSet;

use bitcoin::block::{Checked, Header, HeaderExt as _};
use bitcoin::pow::CompactTargetExt as _;
use bitcoin::{Block, BlockHash, CompactTarget, OutPoint, Params, Target, Transaction, TxOut, Work};

/// One Cairo field element, big-endian. Values produced here are all below 2^252.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Felt(pub [u8; 32]);

impl Felt {
    pub fn from_u128(v: u128) -> Self {
        let mut b = [0u8; 32];
        b[16..].copy_from_slice(&v.to_be_bytes());
        Felt(b)
    }

    /// Big-endian bytes, at most 31 of them, right-aligned.
    fn from_be_slice(s: &[u8]) -> Self {
        assert!(s.len() <= 31);
        let mut b = [0u8; 32];
        b[32 - s.len()..].copy_from_slice(s);
        Felt(b)
    }

    /// Minimal `0x`-prefixed lowercase hex, the format Python's `hex()` produces.
    pub fn to_hex(&self) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::from("0x");
        let mut started = false;
        for byte in self.0 {
            for nibble in [byte >> 4, byte & 0xf] {
                if nibble != 0 || started {
                    started = true;
                    s.push(DIGITS[nibble as usize] as char);
                }
            }
        }
        if !started {
            s.push('0');
        }
        s
    }
}

/// Raito's `ChainState`: the minimum needed to validate the next header.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ChainState {
    pub block_height: u32,
    pub total_work: Work,
    pub best_block_hash: BlockHash,
    /// Target the next block must meet.
    pub current_target: Target,
    /// Timestamp of the first block of the current difficulty epoch.
    pub epoch_start_time: u32,
    /// Timestamps of the last (up to) eleven blocks, oldest first.
    pub prev_timestamps: Vec<u32>,
}

impl ChainState {
    /// The chain state after `header` is applied, mirroring Raito's `next_chain_state`.
    ///
    /// This trusts `header.bits`; whether those bits are the required target is checked
    /// inside the proven program, not here.
    pub fn apply(&self, header: &Header) -> ChainState {
        let block_height = self.block_height + 1;
        let time = header.time.to_u32();
        let mut prev_timestamps = self.prev_timestamps.clone();
        prev_timestamps.push(time);
        if prev_timestamps.len() > 11 {
            prev_timestamps.drain(..prev_timestamps.len() - 11);
        }
        ChainState {
            block_height,
            total_work: self.total_work + header.work(),
            best_block_hash: header.block_hash(),
            current_target: header.target(),
            epoch_start_time: if block_height % 2016 == 0 { time } else { self.epoch_start_time },
            prev_timestamps,
        }
    }

    /// The compact target Bitcoin Core requires for the block after this state.
    pub fn required_bits(&self, last_bits: CompactTarget, params: &Params) -> CompactTarget {
        let next_height = self.block_height + 1;
        if next_height % 2016 != 0 {
            return last_bits;
        }
        let last_time = *self.prev_timestamps.last().expect("non-empty");
        let timespan = i64::from(last_time) - i64::from(self.epoch_start_time);
        CompactTarget::from_next_work_required(last_bits, timespan, params)
    }
}

/// What a UTXO set knows about a spent output, beyond the `TxOut` itself.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SpentOutput {
    pub txout: TxOut,
    /// Height of the block that created the output.
    pub height: u32,
    /// Median time past of the block before the creating block (Raito's convention).
    pub median_time_past: u32,
    pub is_coinbase: bool,
}

/// Felt writer for Cairo `Serde`.
#[derive(Default)]
pub struct Writer {
    pub felts: Vec<Felt>,
}

impl Writer {
    pub fn uint(&mut self, v: u128) { self.felts.push(Felt::from_u128(v)); }

    fn bool(&mut self, v: bool) { self.uint(u128::from(v)); }

    /// `u256 { low, high }` from big-endian bytes.
    fn u256_be(&mut self, be: [u8; 32]) {
        let mut hi = [0u8; 16];
        let mut lo = [0u8; 16];
        hi.copy_from_slice(&be[..16]);
        lo.copy_from_slice(&be[16..]);
        self.uint(u128::from_be_bytes(lo));
        self.uint(u128::from_be_bytes(hi));
    }

    /// `Digest { value: [u32; 8] }`: internal byte order, read as big-endian words.
    pub fn digest(&mut self, internal: [u8; 32]) {
        for w in internal.chunks(4) {
            self.uint(u128::from(u32::from_be_bytes([w[0], w[1], w[2], w[3]])));
        }
    }

    /// `ByteArray { data: Array<bytes31>, pending_word, pending_word_len }`.
    fn byte_array(&mut self, bytes: &[u8]) {
        let full = bytes.len() / 31;
        self.uint(full as u128);
        for chunk in bytes.chunks_exact(31) {
            self.felts.push(Felt::from_be_slice(chunk));
        }
        let rest = &bytes[full * 31..];
        self.felts.push(Felt::from_be_slice(rest));
        self.uint(rest.len() as u128);
    }

    pub fn len(&mut self, n: usize) { self.uint(n as u128); }

    pub fn chain_state(&mut self, cs: &ChainState) {
        self.uint(u128::from(cs.block_height));
        self.u256_be(cs.total_work.to_be_bytes());
        self.digest(cs.best_block_hash.to_byte_array());
        self.u256_be(cs.current_target.to_be_bytes());
        self.uint(u128::from(cs.epoch_start_time));
        self.len(cs.prev_timestamps.len());
        for t in &cs.prev_timestamps {
            self.uint(u128::from(*t));
        }
    }

    pub fn header(&mut self, h: &Header) {
        self.uint(u128::from(h.version.to_consensus() as u32));
        self.uint(u128::from(h.time.to_u32()));
        self.uint(u128::from(h.bits.to_consensus()));
        self.uint(u128::from(h.nonce));
    }

    fn txout(&mut self, out: &TxOut, cached: bool) {
        self.uint(u128::from(out.amount.to_sat()));
        self.byte_array(out.script_pubkey.as_bytes());
        self.bool(cached);
    }

    fn coinbase_tx(&mut self, tx: &Transaction, spent_in_block: &HashSet<OutPoint>) {
        self.uint(u128::from(tx.version.to_u32()));
        self.bool(uses_witness(tx));
        self.len(1);
        let input = &tx.inputs[0];
        self.byte_array(input.script_sig.as_bytes());
        self.uint(u128::from(input.sequence.to_consensus_u32()));
        // Null outpoint with an empty prevout, exactly as Raito encodes it.
        self.digest([0u8; 32]);
        self.uint(u128::from(u32::MAX));
        self.txout(&TxOut { amount: bitcoin::Amount::ZERO, script_pubkey: Default::default() }, false);
        self.uint(0);
        self.uint(0);
        self.bool(false);
        // Witness reserved value: the real one when present, else 32 zero bytes.
        match input.witness.iter().next() {
            Some(reserved) if input.witness.len() == 1 => {
                self.len(1);
                self.byte_array(reserved);
            }
            _ => {
                self.len(1);
                self.byte_array(&[0u8; 32]);
            }
        }
        self.outputs(tx, spent_in_block);
        self.uint(u128::from(tx.lock_time.to_consensus_u32()));
    }

    fn outputs(&mut self, tx: &Transaction, spent_in_block: &HashSet<OutPoint>) {
        let txid = tx.compute_txid();
        self.len(tx.outputs.len());
        for (vout, out) in tx.outputs.iter().enumerate() {
            let cached = spent_in_block.contains(&OutPoint { txid, vout: vout as u32 });
            self.txout(out, cached);
        }
    }

    /// One block with full transaction data (`TransactionData::Transactions`).
    pub fn block<F>(&mut self, block: &Block<Checked>, mut spent: F) -> Result<(), MissingPrevout>
    where
        F: FnMut(&OutPoint) -> Option<SpentOutput>,
    {
        let txs = block.transactions();
        // Outputs created and spent inside this block are "cached" on both sides.
        let created: HashSet<OutPoint> = txs
            .iter()
            .flat_map(|tx| {
                let txid = tx.compute_txid();
                (0..tx.outputs.len()).map(move |vout| OutPoint { txid, vout: vout as u32 })
            })
            .collect();
        let spent_in_block: HashSet<OutPoint> = txs
            .iter()
            .skip(1)
            .flat_map(|tx| tx.inputs.iter().map(|i| i.previous_output))
            .filter(|op| created.contains(op))
            .collect();

        self.header(block.header());
        self.uint(1); // TransactionData::Transactions
        self.len(txs.len());
        self.coinbase_tx(&txs[0], &spent_in_block);
        for tx in &txs[1..] {
            self.uint(u128::from(tx.version.to_u32()));
            self.bool(uses_witness(tx));
            self.len(tx.inputs.len());
            for input in &tx.inputs {
                let op = input.previous_output;
                let prev = spent(&op).ok_or(MissingPrevout(op))?;
                self.byte_array(input.script_sig.as_bytes());
                self.uint(u128::from(input.sequence.to_consensus_u32()));
                self.digest(op.txid.to_byte_array());
                self.uint(u128::from(op.vout));
                self.txout(&prev.txout, spent_in_block.contains(&op));
                self.uint(u128::from(prev.height));
                self.uint(u128::from(prev.median_time_past));
                self.bool(prev.is_coinbase);
                self.len(input.witness.len());
                for item in input.witness.iter() {
                    self.byte_array(item);
                }
            }
            self.outputs(tx, &spent_in_block);
            self.uint(u128::from(tx.lock_time.to_consensus_u32()));
        }
        Ok(())
    }
}

/// A non-coinbase input whose spent output the caller could not supply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingPrevout(pub OutPoint);

/// Whether the transaction serializes with the segwit marker, which is how Raito's
/// generator decides `is_segwit`.
fn uses_witness(tx: &Transaction) -> bool { tx.inputs.iter().any(|i| !i.witness.is_empty()) }

/// Arguments for Raito's `client` executable: initial state, blocks, expected state.
/// Returns the felts and the expected chain state computed by rust-bitcoin.
pub fn client_args<F>(
    initial: &ChainState,
    blocks: &[Block<Checked>],
    mut spent: F,
) -> Result<(Vec<Felt>, ChainState), MissingPrevout>
where
    F: FnMut(&OutPoint) -> Option<SpentOutput>,
{
    let mut w = Writer::default();
    w.chain_state(initial);
    w.len(blocks.len());
    let mut state = initial.clone();
    for block in blocks {
        w.block(block, &mut spent)?;
        state = state.apply(block.header());
    }
    w.chain_state(&state);
    Ok((w.felts, state))
}

/// The JSON array of hex felts that `--arguments-file` / `user_args_file` expect.
pub fn to_args_json(felts: &[Felt]) -> String {
    let items: Vec<String> = felts.iter().map(|f| format!("\"{}\"", f.to_hex())).collect();
    format!("[{}]", items.join(", "))
}
