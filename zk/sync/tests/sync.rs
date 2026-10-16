//! Vectors from the Cairo side (Raito `utils::mmr` tests and `chain_segment`'s
//! `genesis_commitments` test) and end-to-end client checks on real mainnet headers.
//! Proof verification is exercised in `zk/prover/sync`; here segment claims are built
//! from native replay, which is what an honest prover's outputs must equal.

use std::path::PathBuf;

use bitcoin::block::Header;
use bitcoin::{Block, Params, Txid};
use bitcoin_zk_sync::client::{LinkError, SpvError, TipError};
use bitcoin_zk_sync::header::{validate_and_apply, HeaderError};
use bitcoin_zk_sync::{
    chain_state_digest, decode_headers, genesis_mmr, genesis_state, header_leaf, link, Digest, Mmr, MmrTree,
    ProvenTip, SegmentClaim,
};
use p2p::merkle_tree::MerkleBlock;

fn data(path: &str) -> PathBuf { PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path) }

fn d(hex: &str) -> Digest { Digest::from_hex(hex).unwrap() }

fn headers() -> Vec<Header> {
    decode_headers(&std::fs::read(data("tests/data/headers_0_2100.bin")).unwrap()).unwrap()
}

#[test]
fn genesis_vectors_match_cairo() {
    let p = Params::MAINNET;
    assert_eq!(chain_state_digest(&genesis_state(&p)), d("6002eaa4410bd0b15e778656f84fc895fd091827e27ce697ba4231076c70c43b"));
    let genesis = *bitcoin::constants::genesis_block(&p).header();
    assert_eq!(header_leaf(&genesis), d("5fd720d341e64d17d3b8624b17979b0d0dad4fc17d891796a3a51a99d3f41599"));
    assert_eq!(genesis_mmr(&p).digest(), d("21f9ae0b68f0f6427ad73f82bf975f140d2f67abdf2fb93604b354a8b6d923ac"));
    assert_eq!(headers()[0], genesis);
}

#[test]
fn mmr_add_matches_cairo_test() {
    let leaf = d("c713e33d89122b85e2f646cc518c2e6ef88b06d3b016104faa95f84f878dab66");
    let m1 = Mmr::default().add(leaf);
    assert_eq!(m1.roots(), &[Some(leaf), None]);
    let m2 = m1.add(leaf);
    let r1 = d("693aa1ab81c6362fe339fc4c7f6d8ddb1e515701e58c5bb2fb54a193c8287fdc");
    assert_eq!(m2.roots(), &[None, Some(r1), None]);
    let m3 = m2.add(leaf);
    assert_eq!(m3.roots(), &[Some(leaf), Some(r1), None]);
    let m4 = m3.add(leaf);
    let r2 = d("488a5ed31744187c70a57c092e2c86742518ec5acea240726789d8b1af2b1e0d");
    assert_eq!(m4.roots(), &[None, None, Some(r2), None]);
}

#[test]
fn native_replay_from_genesis_and_rejections() {
    let p = Params::MAINNET;
    let hs = headers();
    let mut state = genesis_state(&p);
    for h in &hs[1..] {
        state = validate_and_apply(&state, h, &p, None).unwrap();
    }
    assert_eq!(state.block_height, 2100);
    assert_eq!(state.best_block_hash, hs[2100].block_hash());

    let s1 = validate_and_apply(&genesis_state(&p), &hs[1], &p, None).unwrap();
    // Skipping a header breaks the link.
    assert!(matches!(validate_and_apply(&s1, &hs[3], &p, None), Err(HeaderError::DoesNotExtendTip { .. })));
    // An easier target is refused before any PoW check.
    let mut easy = hs[2];
    easy.bits = bitcoin::CompactTarget::from_consensus(0x207fffff);
    assert!(matches!(validate_and_apply(&s1, &easy, &p, None), Err(HeaderError::WrongBits { .. })));
    // A changed nonce no longer meets the target.
    let mut bad = hs[2];
    bad.nonce ^= 1;
    assert_eq!(validate_and_apply(&s1, &bad, &p, None), Err(HeaderError::InsufficientWork));
}

#[test]
fn mmr_proofs_for_every_leaf() {
    let hs = headers();
    let mut tree = MmrTree::default();
    let mut mmr = Mmr::default();
    for h in &hs {
        tree.push(header_leaf(h));
        mmr = mmr.add(header_leaf(h));
    }
    assert_eq!(mmr.leaf_count(), hs.len() as u64);
    for (i, h) in hs.iter().enumerate() {
        let proof = tree.proof(i as u64).unwrap();
        mmr.verify(&header_leaf(h), &proof).unwrap();
        if !proof.siblings.is_empty() {
            let mut bad = proof.clone();
            bad.siblings[0].0[0] ^= 1;
            assert!(mmr.verify(&header_leaf(h), &bad).is_err());
        }
        // The right header at the wrong position fails.
        let mut moved = proof.clone();
        moved.leaf_index = (i as u64 + 1) % hs.len() as u64;
        assert!(mmr.verify(&header_leaf(h), &moved).is_err());
    }
}

/// Segment claims an honest prover's runs would output, from native replay.
fn honest_claims(hs: &[Header], to: usize, size: usize) -> (Vec<SegmentClaim>, bitcoin_zk_args::ChainState, Mmr) {
    let p = Params::MAINNET;
    let (mut state, mut mmr) = (genesis_state(&p), genesis_mmr(&p));
    let mut claims = Vec::new();
    let mut h = 1;
    while h <= to {
        let end = (h + size - 1).min(to);
        let (s0, m0) = (chain_state_digest(&state), mmr.digest());
        for header in &hs[h..=end] {
            mmr = mmr.add(header_leaf(header));
            state = validate_and_apply(&state, header, &p, None).unwrap();
        }
        claims.push(SegmentClaim {
            initial_state: s0,
            initial_mmr: m0,
            final_state: chain_state_digest(&state),
            final_mmr: mmr.digest(),
            n_blocks: (end - h + 1) as u32,
        });
        h = end + 1;
    }
    (claims, state, mmr)
}

/// Public output of a verified stwo proof of `chain_segment` on headers 1..=8 (captured
/// from `zk-sync run --prove`), as nine big-endian felts.
const PROVEN_OUTPUT_1_8: [&str; 9] = [
    "fd091827e27ce697ba4231076c70c43b",
    "6002eaa4410bd0b15e778656f84fc895",
    "0d2f67abdf2fb93604b354a8b6d923ac",
    "21f9ae0b68f0f6427ad73f82bf975f14",
    "255b5574f473a0f21f9d912bd624657a",
    "8f349e9272ce9908365a735a4cc307d5",
    "6a7694e660e1528f2b294023c4d4ff20",
    "3de556e36d301bc56cd7626b35619a8e",
    "08",
];

#[test]
fn proven_output_matches_native_replay() {
    let felts: Vec<[u8; 32]> = PROVEN_OUTPUT_1_8
        .iter()
        .map(|h| {
            let v = u128::from_str_radix(h, 16).unwrap();
            let mut f = [0u8; 32];
            f[16..].copy_from_slice(&v.to_be_bytes());
            f
        })
        .collect();
    let claim = bitcoin_zk_sync::decode_output(&felts).unwrap();
    let (claims, _, _) = honest_claims(&headers(), 8, 8);
    assert_eq!(claim, claims[0]);
    // A tenth felt (or a missing one) is not an `Output`.
    assert!(bitcoin_zk_sync::decode_output(&felts[..8]).is_err());
}

#[test]
fn link_accept_extend_and_spv() {
    let p = Params::MAINNET;
    let hs = headers();
    let (claims, state, mmr) = honest_claims(&hs, 200, 32);
    let chain = link(&claims, &p).unwrap();
    assert_eq!(chain.height, 200);

    // Reordered or missing segments do not link.
    let mut swapped = claims.clone();
    swapped.swap(1, 2);
    assert_eq!(link(&swapped, &p), Err(LinkError::Broken { index: 1 }));
    assert_eq!(link(&claims[1..], &p), Err(LinkError::Broken { index: 0 }));

    // The tip must be exactly what the chain commits to.
    let mut wrong = state.clone();
    wrong.total_work = wrong.total_work + wrong.total_work;
    assert_eq!(ProvenTip::accept(&chain, wrong, mmr.clone()).unwrap_err(), TipError::StateMismatch);
    let mut tip = ProvenTip::accept(&chain, state, mmr).unwrap();

    // Work floor: the proven tip carries the real chain's work at height 200, and a
    // client that expects more refuses it.
    let work_200 = tip.state().total_work;
    tip.require_work(work_200).unwrap();
    assert_eq!(tip.require_work(work_200 + work_200), Err(TipError::InsufficientWork));

    // Extending is all or nothing: a bad header at the end leaves the tip unchanged.
    let mut bad_tail = hs[201..=300].to_vec();
    bad_tail.last_mut().unwrap().nonce ^= 1;
    assert_eq!(tip.extend(&bad_tail, &p, None).unwrap_err().0, 99);
    assert_eq!(tip.state().block_height, 200);

    // Follow the chain natively past the proven part, across the first retarget.
    tip.extend(&hs[201..], &p, None).unwrap();
    assert_eq!(tip.state().block_height, 2100);
    assert_eq!(tip.tip_hash(), hs[2100].block_hash());

    // Satoshi to Hal Finney, block 170, checked against the proven MMR.
    let raw = std::fs::read(data("../args/tests/data/block_170.bin")).unwrap();
    let block: Block = bitcoin::encoding::decode_from_slice(&raw).unwrap();
    let block = block.validate().unwrap();
    let (coinbase, hal_tx) = (&block.transactions()[0], &block.transactions()[1]);
    let hal: Txid = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16".parse().unwrap();
    assert_eq!(hal_tx.compute_txid(), hal);
    let cb = coinbase.compute_txid();
    let merkle_block = MerkleBlock::from_block_with_predicate(&block, |t| *t == hal || *t == cb);
    // The server proves inclusion in the proven MMR (heights 0..=200), not in the part the
    // client followed natively.
    let mut tree = MmrTree::default();
    for h in &hs[..=200] {
        tree.push(header_leaf(h));
    }
    let proof = tree.proof(170).unwrap();
    assert_eq!(tip.verify_tx(block.header(), &proof, &merkle_block, hal_tx, coinbase), Ok(170));
    // A proof against the natively extended tree (2101 leaves) is not accepted.
    let mut full = MmrTree::default();
    for h in &hs {
        full.push(header_leaf(h));
    }
    assert!(matches!(
        tip.verify_tx(block.header(), &full.proof(170).unwrap(), &merkle_block, hal_tx, coinbase),
        Err(SpvError::Mmr(_))
    ));
    // Without the coinbase at leaf 0 the tree depth is not pinned.
    let hal_only = MerkleBlock::from_block_with_predicate(&block, |t| *t == hal);
    assert_eq!(tip.verify_tx(block.header(), &proof, &hal_only, hal_tx, coinbase), Err(SpvError::CoinbaseNotMatched));
    assert_eq!(
        tip.verify_tx(block.header(), &proof, &merkle_block, hal_tx, hal_tx),
        Err(SpvError::CoinbaseNotMatched)
    );
    // A matched transaction other than the one asked about does not count.
    let coinbase_only = MerkleBlock::from_block_with_predicate(&block, |t| *t == cb);
    assert_eq!(tip.verify_tx(block.header(), &proof, &coinbase_only, hal_tx, coinbase), Err(SpvError::TxNotMatched));
    // Right block, wrong position in the MMR.
    let wrong_pos = tree.proof(171).unwrap();
    assert!(matches!(tip.verify_tx(block.header(), &wrong_pos, &merkle_block, hal_tx, coinbase), Err(SpvError::Mmr(_))));

    // A reorg above the proven tip: drop what was followed natively, keep the proof.
    tip.reset_to_proven();
    assert_eq!(tip.state().block_height, 200);
    assert_eq!(tip.verify_tx(block.header(), &proof, &merkle_block, hal_tx, coinbase), Ok(170));
}

#[test]
fn malformed_tip_is_rejected_not_a_panic() {
    let p = Params::MAINNET;
    let hs = headers();
    let (claims, state, mmr) = honest_claims(&hs, 16, 8);
    let chain = link(&claims, &p).unwrap();
    let mut long = state.clone();
    long.prev_timestamps = vec![1; 40];
    assert_eq!(ProvenTip::accept(&chain, long, mmr.clone()).unwrap_err(), TipError::MalformedState);
    ProvenTip::accept(&chain, state, mmr).unwrap();
}

#[test]
fn version_and_future_time_rules() {
    let p = Params::MAINNET;
    let hs = headers();
    // Pretend the tip is at BIP34's height - 1: a version-1 header is then refused.
    let mut late = genesis_state(&p);
    late.block_height = p.bip34_height.to_u32() - 1;
    assert!(matches!(validate_and_apply(&late, &hs[1], &p, None), Err(HeaderError::BadVersion { .. })));
    // More than two hours ahead of the verifier's clock.
    let s1 = validate_and_apply(&genesis_state(&p), &hs[1], &p, None).unwrap();
    let t2 = hs[2].time.to_u32();
    assert!(matches!(validate_and_apply(&s1, &hs[2], &p, Some(t2 - 7201)), Err(HeaderError::TimeTooFarInFuture { .. })));
    validate_and_apply(&s1, &hs[2], &p, Some(t2 - 7200)).unwrap();
}
