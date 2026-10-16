//! Raito's JSON fixtures (`packages/client/tests/data/full_*.json`) as rust-bitcoin types.
//!
//! A fixture holds the chain state before a block, the expected state after it, and the
//! metadata of every output the block spends. Only those two states and the prevouts are
//! taken from it; block bodies come from raw block bytes.

use std::collections::HashMap;

use bitcoin::{Amount, BlockHash, OutPoint, ScriptPubKeyBuf, Target, TxOut, Txid, Work};
use serde_json::Value;

use crate::{ChainState, SpentOutput};

pub struct Fixture {
    pub initial: ChainState,
    pub expected: ChainState,
    pub prevouts: HashMap<OutPoint, SpentOutput>,
}

impl Fixture {
    pub fn parse(json: &str) -> Result<Self, String> {
        let v: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
        Ok(Fixture {
            initial: chain_state(&v["chain_state"])?,
            expected: chain_state(&v["expected"])?,
            prevouts: prevouts(&v)?,
        })
    }
}

fn u32_of(v: &Value) -> Result<u32, String> {
    v.as_u64().and_then(|n| u32::try_from(n).ok()).ok_or_else(|| format!("not a u32: {v}"))
}

fn str_of(v: &Value) -> Result<&str, String> { v.as_str().ok_or_else(|| format!("not a string: {v}")) }

fn hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim_start_matches("0x");
    if s.len() % 2 != 0 {
        return Err(format!("odd-length hex: {s}"));
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string())).collect()
}

/// Decimal string to 32 big-endian bytes.
fn dec_be(s: &str) -> Result<[u8; 32], String> {
    let mut out = [0u8; 32];
    for d in s.bytes() {
        if !d.is_ascii_digit() {
            return Err(format!("not decimal: {s}"));
        }
        let mut carry = u32::from(d - b'0');
        for b in out.iter_mut().rev() {
            let v = u32::from(*b) * 10 + carry;
            *b = v as u8;
            carry = v >> 8;
        }
        if carry != 0 {
            return Err(format!("exceeds 256 bits: {s}"));
        }
    }
    Ok(out)
}

fn chain_state(v: &Value) -> Result<ChainState, String> {
    Ok(ChainState {
        block_height: u32_of(&v["block_height"])?,
        total_work: Work::from_be_bytes(dec_be(str_of(&v["total_work"])?)?),
        best_block_hash: str_of(&v["best_block_hash"])?.parse::<BlockHash>().map_err(|e| e.to_string())?,
        current_target: Target::from_be_bytes(dec_be(str_of(&v["current_target"])?)?),
        epoch_start_time: u32_of(&v["epoch_start_time"])?,
        prev_timestamps: v["prev_timestamps"]
            .as_array()
            .ok_or("prev_timestamps")?
            .iter()
            .map(u32_of)
            .collect::<Result<_, _>>()?,
    })
}

fn prevouts(v: &Value) -> Result<HashMap<OutPoint, SpentOutput>, String> {
    let mut m = HashMap::new();
    for block in v["blocks"].as_array().ok_or("blocks")? {
        let Some(txs) = block["data"]["transactions"].as_array() else { continue };
        for tx in txs.iter().skip(1) {
            for input in tx["inputs"].as_array().ok_or("inputs")? {
                let po = &input["previous_output"];
                let txid: Txid = str_of(&po["txid"])?.parse().map_err(|e| format!("{e}"))?;
                let sats = po["data"]["value"].as_u64().ok_or("value")?;
                let txout = TxOut {
                    amount: Amount::from_sat(sats).map_err(|e| e.to_string())?,
                    script_pubkey: ScriptPubKeyBuf::from_bytes(hex_bytes(str_of(&po["data"]["pk_script"])?)?),
                };
                let spent = SpentOutput {
                    txout,
                    height: u32_of(&po["block_height"])?,
                    median_time_past: u32_of(&po["median_time_past"])?,
                    is_coinbase: po["is_coinbase"].as_bool().ok_or("is_coinbase")?,
                };
                m.insert(OutPoint { txid, vout: u32_of(&po["vout"])? }, spent);
            }
        }
    }
    Ok(m)
}
