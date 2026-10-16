//! Differential test against Raito's own serializer.
//!
//! Data, all under `tests/data/` (see `tests/data/SOURCES.md`):
//! - `block_<h>.bin`: raw mainnet blocks, decoded here by rust-bitcoin;
//! - `full_<h-1>.json`: Raito's fixture for applying block `h` (its chain states and
//!   prevout metadata are the UTXO-set input this crate takes from the caller);
//! - `raito_felts_full_<h-1>.json`: Raito's `format_args.py` output for that fixture.
//!
//! The block bodies come only from the raw bytes, so a match means rust-bitcoin's
//! decoding plus this crate's encoding reproduces Raito's Cairo arguments exactly, and
//! the expected chain state computed by rust-bitcoin equals the one Raito fetched over RPC.

use std::path::PathBuf;

use bitcoin::Block;
use bitcoin_zk_args::fixture::Fixture;
use bitcoin_zk_args::{client_args, to_args_json};

fn data(name: &str) -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(name) }

fn check(height: u32) {
    let fixture = Fixture::parse(&std::fs::read_to_string(data(&format!("full_{}.json", height - 1))).unwrap()).unwrap();
    let raw = std::fs::read(data(&format!("block_{height}.bin"))).unwrap();
    let block: Block = bitcoin::encoding::decode_from_slice(&raw).unwrap();
    let block = block.validate().expect("merkle root and coinbase checks");

    let (felts, expected) = client_args(&fixture.initial, &[block], |op| fixture.prevouts.get(op).cloned()).unwrap();

    assert_eq!(expected, fixture.expected, "chain state transition");

    let ours: Vec<String> = felts.iter().map(|f| f.to_hex()).collect();
    let raito: Vec<String> = serde_json::from_str(
        &std::fs::read_to_string(data(&format!("raito_felts_full_{}.json", height - 1))).unwrap(),
    )
    .unwrap();
    if let Some(i) = ours.iter().zip(&raito).position(|(a, b)| a != b) {
        panic!("first difference at felt {i}: ours {} raito {}", ours[i], raito[i]);
    }
    assert_eq!(ours.len(), raito.len(), "felt count");
    assert!(to_args_json(&felts).starts_with("[\"0x"));
}

#[test]
fn block_170_first_p2pk_spend() { check(170); }

#[test]
fn block_2016_first_retarget_boundary() { check(2016); }
