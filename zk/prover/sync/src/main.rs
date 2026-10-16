//! `zk-sync`: ZeroSync-style header-chain proofs for rust-bitcoin.
//!
//!   zk-sync prove  --executable chain_segment.executable.json --headers headers.bin
//!                  --from A --to B --segment N --out DIR [--max-log-rows K]
//!       Replays headers 1..A natively, then proves headers A..=B in segments of N with
//!       the Cairo `chain_segment` program (direct mode). Writes one proof per segment and
//!       `tip.json`, the final chain state and block MMR in the clear.
//!
//!   zk-sync verify --executable chain_segment.executable.json --proofs DIR
//!                  [--max-log-rows K] [--headers headers.bin --extend-to T]
//!                  [--spv-block block.bin --txid TXID]
//!       The light client. For each proof: the public program must be exactly the
//!       `chain_segment` bytecode, the STARK must verify, and the public output must be a
//!       successful run. Then the claims are linked from genesis, `tip.json` is accepted
//!       only if it hashes to the proven commitments, newer headers are validated
//!       natively, and a transaction can be checked against the proven block MMR.
//!
//! Each command prints one JSON object with its timings and results.

use std::path::{Path, PathBuf};
use std::time::Instant;

use bitcoin::block::Header;
use bitcoin::{Block, BlockHash, Params, Target, Txid, Work};
use bitcoin_zk_args::{to_args_json, ChainState};
use bitcoin_zk_sync::header::validate_and_apply;
use bitcoin_zk_sync::{
    chain_state_digest, decode_headers, decode_output, genesis_mmr, genesis_state, header_leaf, link, segment_args,
    Digest, Mmr, MmrTree, ProvenTip, SegmentClaim,
};
use blake2::{Blake2s256, Digest as _};
use cairo_air::utils::{deserialize_proof_from_file, serialize_proof_to_file, ProofFormat};
use cairo_air::verifier::verify_cairo;
use cairo_air::{CairoProof, PreProcessedTraceVariant};
use cairo_lang_executable::executable::{EntryPointKind, Executable};
use cairo_lang_execute_utils::{program_and_hints_from_executable, user_args_from_flags};
use cairo_lang_runner::{Arg, CairoHintProcessor};
use cairo_vm::cairo_run::CairoRunConfig;
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::vm::runners::cairo_runner::CairoRunner;
use p2p::merkle_tree::MerkleBlock;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::PcsConfig;
use stwo::core::vcs::blake2_merkle::{Blake2sMerkleChannel, Blake2sMerkleHasher};
use stwo_cairo_adapter::adapter::adapt;
use stwo_cairo_adapter::PublicSegmentContext;
use stwo_cairo_prover::prover::{prove_cairo, ChannelHash, ProverParameters};

#[derive(Default)]
struct Opts {
    executable: PathBuf,
    headers: Option<PathBuf>,
    from: u32,
    to: u32,
    segment: u32,
    out: PathBuf,
    proofs: PathBuf,
    max_log_rows: Option<u32>,
    stop_after_execute: bool,
    extend_to: Option<u32>,
    spv_block: Option<PathBuf>,
    txid: Option<Txid>,
    args: Option<PathBuf>,
    prove: bool,
    min_work: Option<Work>,
    no_work_floor: bool,
}

fn parse(args: impl Iterator<Item = String>) -> Opts {
    let mut a = args;
    let mut o = Opts { segment: 16, out: "zk-sync-out".into(), ..Default::default() };
    while let Some(k) = a.next() {
        let mut v = || a.next().unwrap_or_else(|| panic!("{k} needs a value"));
        match k.as_str() {
            "--executable" => o.executable = v().into(),
            "--headers" => o.headers = Some(v().into()),
            "--from" => o.from = v().parse().expect("--from"),
            "--to" => o.to = v().parse().expect("--to"),
            "--segment" => o.segment = v().parse().expect("--segment"),
            "--out" => o.out = v().into(),
            "--proofs" => o.proofs = v().into(),
            "--max-log-rows" => o.max_log_rows = Some(v().parse().expect("--max-log-rows")),
            "--stop-after" if v() == "execute" => o.stop_after_execute = true,
            "--extend-to" => o.extend_to = Some(v().parse().expect("--extend-to")),
            "--spv-block" => o.spv_block = Some(v().into()),
            "--txid" => o.txid = Some(v().parse().expect("--txid")),
            "--args" => o.args = Some(v().into()),
            "--prove" => o.prove = true,
            "--insecure-no-work-floor" => o.no_work_floor = true,
            "--min-work" => {
                let be = Digest::from_hex(&format!("{:0>64}", v().trim_start_matches("0x"))).expect("--min-work hex");
                o.min_work = Some(Work::from_be_bytes(be.to_u256_be()));
            }
            _ => panic!("unknown argument {k}"),
        }
    }
    o
}

/// One JSON object of results.
#[derive(Default)]
struct Report(Vec<(String, String)>);

impl Report {
    fn num(&mut self, k: &str, v: f64) { self.0.push((k.into(), format!("{v:.3}"))); }
    fn int(&mut self, k: &str, v: u64) { self.0.push((k.into(), v.to_string())); }
    fn text(&mut self, k: &str, v: &str) { self.0.push((k.into(), format!("{v:?}"))); }
    fn raw(&mut self, k: &str, v: String) { self.0.push((k.into(), v)); }
    fn line(&self) -> String {
        let body: Vec<String> = self.0.iter().map(|(k, v)| format!("\"{k}\": {v}")).collect();
        format!("{{{}}}", body.join(", "))
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_default();
    let o = parse(args);
    let report = match cmd.as_str() {
        "prove" => prove(&o),
        "verify" => verify(&o),
        "run" => run_args(&o),
        "constants" => constants(&o),
        _ => panic!("usage: zk-sync prove|verify ... (see the module docs)"),
    };
    println!("{}", report.line());
}

fn variant(o: &Opts) -> PreProcessedTraceVariant {
    match o.max_log_rows {
        Some(k) => PreProcessedTraceVariant::CanonicalWithoutPedersenUpTo(k),
        None => PreProcessedTraceVariant::CanonicalWithoutPedersen,
    }
}

fn load_executable(path: &Path) -> Executable {
    let exe: Executable = serde_json::from_reader(std::fs::File::open(path).expect("executable")).expect("executable json");
    // The no-Pedersen preprocessed trace is only sound for programs without that builtin.
    let entry = standalone(&exe);
    assert!(
        !entry.builtins.iter().any(|b| matches!(b, cairo_vm::types::builtin_name::BuiltinName::pedersen)),
        "program uses Pedersen"
    );
    let builtins: Vec<&str> = entry.builtins.iter().map(|b| b.to_str()).collect();
    assert_eq!(builtins, bitcoin_zk_sync::pins::CHAIN_SEGMENT_BUILTINS, "executable builtins differ from the pinned list");
    // A syscall's result is a hint the proof does not constrain in direct mode.
    for (pc, hints) in &exe.program.hints {
        for h in hints {
            let s = serde_json::to_string(h).expect("hint json");
            assert!(!s.contains("SystemCall") && !s.contains("Cheatcode"), "program has a syscall hint at pc {pc}");
        }
    }
    exe
}

/// What `verify_cairo` reads from the proof without checking it, pinned here. Each one
/// would otherwise let a prover make a valid proof say something else (see the review
/// notes in zk/sync/README.md).
fn check_claim_shape(proof: &CairoProof<Blake2sMerkleHasher>, _exe: &Executable, root: &str) -> Result<(), String> {
    use cairo_vm::types::builtin_name::BuiltinName as B;
    // 1. Security parameters are ours, not the prover's: 96 bits as `prove_run` uses.
    let c = proof.stark_proof.config;
    let f = c.fri_config;
    if (c.pow_bits, f.log_blowup_factor, f.n_queries, f.log_last_layer_degree_bound) != (26, 1, 70, 0) {
        return Err(format!("unexpected PCS config {c:?}"));
    }
    if proof.channel_salt.is_some() {
        return Err("unexpected channel salt".into());
    }
    // 2. The preprocessed trace commitment is the one for our variant, not the prover's.
    let got = format!("{}", proof.stark_proof.commitments[0]);
    if got != root {
        return Err(format!("preprocessed root {got} is not {root}"));
    }
    // 3. Builtin segment slots are exactly the program's builtins: the verifier only
    //    learns from this pattern which builtin each pointer belongs to.
    let segs = &proof.claim.public_data.public_memory.public_segments;
    let has = |b: B| bitcoin_zk_sync::pins::CHAIN_SEGMENT_BUILTINS.contains(&b.to_str());
    let pattern = [
        (segs.pedersen.is_some(), has(B::pedersen)),
        (segs.range_check_128.is_some(), has(B::range_check)),
        (segs.ecdsa.is_some(), has(B::ecdsa)),
        (segs.bitwise.is_some(), has(B::bitwise)),
        (segs.ec_op.is_some(), has(B::ec_op)),
        (segs.keccak.is_some(), has(B::keccak)),
        (segs.poseidon.is_some(), has(B::poseidon)),
        (segs.range_check_96.is_some(), has(B::range_check96)),
        (segs.add_mod.is_some(), has(B::add_mod)),
        (segs.mul_mod.is_some(), has(B::mul_mod)),
    ];
    if pattern.iter().any(|(got, want)| got != want) {
        return Err(format!("builtin segments {pattern:?} (present, expected)"));
    }
    // 4. The public output is what the program wrote: it starts at the output pointer,
    //    which must be final ap (where the verifier places it), and spans exactly the
    //    published felts.
    let pd = &proof.claim.public_data;
    let out = &segs.output;
    let n = pd.public_memory.output.len() as u32;
    if out.start_ptr.value != pd.final_state.ap.0 || out.stop_ptr.value != out.start_ptr.value + n || n != 9 {
        return Err(format!(
            "output segment [{}, {}) with {n} felts, final ap {}",
            out.start_ptr.value, out.stop_ptr.value, pd.final_state.ap.0
        ));
    }
    Ok(())
}

/// The preprocessed root for this run's variant: the pinned constant for k = 20,
/// otherwise computed (a few seconds; prover code).
fn expected_root(o: &Opts) -> String {
    match o.max_log_rows {
        Some(20) if !bitcoin_zk_sync::pins::PREPROCESSED_ROOT_K20.is_empty() => {
            bitcoin_zk_sync::pins::PREPROCESSED_ROOT_K20.to_string()
        }
        _ => format!(
            "{}",
            stwo_cairo_prover::witness::preprocessed_trace::generate_preprocessed_commitment_root::<Blake2sMerkleChannel>(
                1,
                variant(o)
            )
        ),
    }
}

/// `zk-sync constants --executable E --max-log-rows K`: the values a client pins.
fn constants(o: &Opts) -> Report {
    let mut r = Report::default();
    let exe = load_executable(&o.executable);
    let (id, n) = program_id(bytecode_limbs(&exe).iter());
    r.text("program_id", &id.to_hex());
    r.int("program_words", n as u64);
    let t = Instant::now();
    let root = format!(
        "{}",
        stwo_cairo_prover::witness::preprocessed_trace::generate_preprocessed_commitment_root::<Blake2sMerkleChannel>(1, variant(o))
    );
    r.text("preprocessed_root", &root);
    r.num("root_s", t.elapsed().as_secs_f64());
    r
}

fn standalone(exe: &Executable) -> &cairo_lang_executable::executable::ExecutableEntryPoint {
    exe.entrypoints.iter().find(|e| matches!(e.kind, EntryPointKind::Standalone)).expect("standalone entry point")
}

fn load_headers(o: &Opts) -> Vec<Header> {
    let path = o.headers.as_ref().expect("--headers");
    decode_headers(&std::fs::read(path).expect("headers file")).expect("headers")
}

// ---------------------------------------------------------------------------- prove

fn prove(o: &Opts) -> Report {
    let p = Params::MAINNET;
    let mut r = Report::default();
    let exe = load_executable(&o.executable);
    let headers = load_headers(o);
    assert!(o.from >= 1 && o.from <= o.to && (o.to as usize) < headers.len(), "bad --from/--to");
    std::fs::create_dir_all(&o.out).expect("out dir");

    // Native replay up to the first proven block: the prover's view, not trusted by anyone.
    let (mut state, mut mmr) = (genesis_state(&p), genesis_mmr(&p));
    for h in &headers[1..o.from as usize] {
        mmr = mmr.add(header_leaf(h));
        state = validate_and_apply(&state, h, &p, None).expect("native replay");
    }

    let mut segments = Vec::new();
    let total = Instant::now();
    let mut start = o.from;
    while start <= o.to {
        let end = (start + o.segment - 1).min(o.to);
        let batch = &headers[start as usize..=end as usize];
        let (s0, m0) = (chain_state_digest(&state), mmr.digest());
        let felts = segment_args(&state, &mmr, batch);
        let name = format!("seg_{start:07}_{end:07}");
        let args_path = o.out.join(format!("{name}.args.json"));
        std::fs::write(&args_path, to_args_json(&felts)).expect("write args");

        let mut s = Report::default();
        s.text("segment", &name);
        let t = Instant::now();
        let runner = run_direct(&exe, &args_path);
        s.num("execute_s", t.elapsed().as_secs_f64());
        s.int("steps", runner.vm.get_current_step() as u64);

        // What the run must have output, from native replay.
        for h in batch {
            mmr = mmr.add(header_leaf(h));
            state = validate_and_apply(&state, h, &p, None).expect("native replay");
        }
        let expected = SegmentClaim {
            initial_state: s0,
            initial_mmr: m0,
            final_state: chain_state_digest(&state),
            final_mmr: mmr.digest(),
            n_blocks: batch.len() as u32,
        };

        if !o.stop_after_execute {
            let t = Instant::now();
            let proof = prove_run(runner, variant(o));
            s.num("prove_s", t.elapsed().as_secs_f64());
            let claim = decode_output(&output_felts(&proof)).expect("segment output");
            assert_eq!(claim, expected, "proven output disagrees with native replay");
            let proof_path = o.out.join(format!("{name}.proof.json"));
            serialize_proof_to_file(&proof, &proof_path, ProofFormat::Json).expect("write proof");
            s.int("proof_bytes", std::fs::metadata(&proof_path).map(|m| m.len()).unwrap_or(0));
        }
        eprintln!("{}", s.line());
        segments.push(s.line());
        start = end + 1;
    }
    write_tip(&o.out.join("tip.json"), &state, &mmr);
    r.int("segments", segments.len() as u64);
    r.int("proven_to", u64::from(state.block_height));
    r.text("tip", &state.best_block_hash.to_string());
    r.num("total_s", total.elapsed().as_secs_f64());
    peak_rss(&mut r);
    r.raw("per_segment", format!("[{}]", segments.join(", ")));
    r
}

/// The executable's standalone entry point under cairo-vm in proof mode (no bootloader).
fn run_direct(exe: &Executable, args_path: &Path) -> CairoRunner {
    let (program, string_to_hint) = program_and_hints_from_executable(exe, standalone(exe)).expect("program");
    let user_args = user_args_from_flags(Some(&args_path.to_path_buf()), &[]).expect("user args");
    let mut hint_processor = CairoHintProcessor {
        runner: None,
        user_args: vec![vec![Arg::Array(user_args)]],
        string_to_hint,
        starknet_state: Default::default(),
        run_resources: Default::default(),
        syscalls_used_resources: Default::default(),
        no_temporary_segments: false,
        markers: Default::default(),
        panic_traceback: Default::default(),
    };
    let config = CairoRunConfig {
        trace_enabled: true,
        relocate_mem: true,
        layout: LayoutName::all_cairo_stwo,
        disable_trace_padding: true,
        proof_mode: true,
        fill_holes: true,
        ..Default::default()
    };
    cairo_vm::cairo_run::cairo_run_program(&program, &config, &mut hint_processor).expect("cairo-vm run")
}

fn prove_run(runner: CairoRunner, variant: PreProcessedTraceVariant) -> CairoProof<Blake2sMerkleHasher> {
    let mut input = adapt(&runner).expect("adapt");
    // `adapt` assumes the bootloader's builtins; describe the program's own.
    let builtins: Vec<_> = runner.get_program().iter_builtins().copied().collect();
    input.public_segment_context = PublicSegmentContext::new(&builtins);
    drop(runner);
    let params = ProverParameters {
        channel_hash: ChannelHash::Blake2s,
        channel_salt: None,
        pcs_config: PcsConfig {
            pow_bits: 26,
            fri_config: FriConfig { log_last_layer_degree_bound: 0, log_blowup_factor: 1, n_queries: 70 },
        },
        preprocessed_trace: variant,
        store_polynomials_coefficients: false,
    };
    prove_cairo::<Blake2sMerkleChannel>(input, params).expect("prove")
}

/// `zk-sync run --executable E --args FILE [--prove] [--max-log-rows K]`: run any argument
/// file in proof mode and show the public output, what it decodes to, and (with `--prove`)
/// whether its proof verifies. For checking what a dishonest prover could get accepted.
fn run_args(o: &Opts) -> Report {
    let mut r = Report::default();
    let exe = load_executable(&o.executable);
    let args = o.args.as_ref().expect("--args");
    let (program, string_to_hint) = program_and_hints_from_executable(&exe, standalone(&exe)).expect("program");
    let user_args = user_args_from_flags(Some(args), &[]).expect("user args");
    let mut hint_processor = CairoHintProcessor {
        runner: None,
        user_args: vec![vec![Arg::Array(user_args)]],
        string_to_hint,
        starknet_state: Default::default(),
        run_resources: Default::default(),
        syscalls_used_resources: Default::default(),
        no_temporary_segments: false,
        markers: Default::default(),
        panic_traceback: Default::default(),
    };
    let config = CairoRunConfig {
        trace_enabled: true,
        relocate_mem: true,
        layout: LayoutName::all_cairo_stwo,
        disable_trace_padding: true,
        proof_mode: true,
        fill_holes: true,
        ..Default::default()
    };
    let runner = match cairo_vm::cairo_run::cairo_run_program(&program, &config, &mut hint_processor) {
        Ok(runner) => runner,
        Err(e) => {
            r.text("run", "failed");
            r.text("error", &format!("{e}").chars().take(300).collect::<String>());
            return r;
        }
    };
    r.text("run", "completed");
    r.int("steps", runner.vm.get_current_step() as u64);
    if !o.prove {
        return r;
    }
    let proof = prove_run(runner, variant(o));
    let out = output_felts(&proof);
    let hex: Vec<String> =
        out.iter().map(|f| format!("\"0x{}\"", f.iter().map(|b| format!("{b:02x}")).collect::<String>())).collect();
    r.raw("output", format!("[{}]", hex.join(", ")));
    r.text("decoded", &format!("{:?}", decode_output(&out)));
    r.text("shape", &format!("{:?}", check_claim_shape(&proof, &exe, &expected_root(o))));
    r.text("stark", &format!("{:?}", verify_cairo::<Blake2sMerkleChannel>(proof, variant(o)).map(|_| "verifies")));
    r
}

// ---------------------------------------------------------------------------- verify

/// Blake2s over the public program, felt by felt (eight little-endian u32 limbs each).
/// Pinning this to the `chain_segment` bytecode is what makes a proof about that program.
fn program_id<'a>(words: impl Iterator<Item = &'a [u32; 8]>) -> (Digest, usize) {
    let mut h = Blake2s256::new();
    let mut n = 0;
    for w in words {
        for limb in w {
            h.update(limb.to_le_bytes());
        }
        n += 1;
    }
    let out = h.finalize();
    let mut be = [0u8; 32];
    be.copy_from_slice(&out);
    (Digest::from_u256_be(be), n)
}

fn bytecode_limbs(exe: &Executable) -> Vec<[u32; 8]> {
    exe.program
        .bytecode
        .iter()
        .map(|b| {
            let bytes = cairo_vm::Felt252::from(b).to_bytes_le();
            let mut limbs = [0u32; 8];
            for (i, c) in bytes.chunks_exact(4).enumerate() {
                limbs[i] = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
            }
            limbs
        })
        .collect()
}

/// The public output section as big-endian felts.
fn output_felts(proof: &CairoProof<Blake2sMerkleHasher>) -> Vec<[u8; 32]> {
    proof
        .claim
        .public_data
        .public_memory
        .output
        .iter()
        .map(|(_, limbs)| {
            let mut be = [0u8; 32];
            for (i, l) in limbs.iter().enumerate() {
                be[28 - 4 * i..32 - 4 * i].copy_from_slice(&l.to_be_bytes());
            }
            be
        })
        .collect()
}

fn verify(o: &Opts) -> Report {
    let p = Params::MAINNET;
    let mut r = Report::default();
    let total = Instant::now();
    let exe = load_executable(&o.executable);
    let (expected_id, expected_len) = program_id(bytecode_limbs(&exe).iter());
    r.text("program_id", &expected_id.to_hex());
    // The executable file only stands in for the pinned program id, and must agree with it.
    let pin = bitcoin_zk_sync::pins::CHAIN_SEGMENT_PROGRAM_ID;
    if !pin.is_empty() {
        assert_eq!(expected_id.to_hex(), pin, "executable is not the pinned chain_segment program");
    }
    r.text("program_pinned", if pin.is_empty() { "no (pins.rs empty)" } else { "yes" });
    let root = expected_root(o);
    r.text("preprocessed_root", &root);

    let mut paths: Vec<PathBuf> = std::fs::read_dir(&o.proofs)
        .expect("--proofs dir")
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.to_string_lossy().ends_with(".proof.json"))
        .collect();
    paths.sort();

    let (mut load_s, mut stark_s) = (0.0, 0.0);
    let mut claims = Vec::new();
    for path in &paths {
        let t = Instant::now();
        let proof: CairoProof<Blake2sMerkleHasher> =
            deserialize_proof_from_file(path, ProofFormat::Json).expect("read proof");
        load_s += t.elapsed().as_secs_f64();

        let (id, n) = program_id(proof.claim.public_data.public_memory.program.iter().map(|(_, w)| w));
        assert!(
            id == expected_id && n == expected_len,
            "{}: public program is not chain_segment ({n} words, expected {expected_len})",
            path.display()
        );
        check_claim_shape(&proof, &exe, &root).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let claim = decode_output(&output_felts(&proof)).unwrap_or_else(|e| panic!("{}: {e:?}", path.display()));
        let t = Instant::now();
        verify_cairo::<Blake2sMerkleChannel>(proof, variant(o)).unwrap_or_else(|e| panic!("{}: {e:?}", path.display()));
        stark_s += t.elapsed().as_secs_f64();
        claims.push(claim);
    }
    r.int("proofs", claims.len() as u64);
    r.num("load_s", load_s);
    r.num("stark_verify_s", stark_s);

    let chain = link(&claims, &p).expect("segments do not link from genesis");
    let (state, mmr) = read_tip(&o.proofs.join("tip.json"));
    let mut tip = ProvenTip::accept(&chain, state, mmr).expect("tip.json does not match the proven commitments");
    r.int("proven_height", u64::from(tip.proven_height()));
    r.text("proven_tip", &tip.tip_hash().to_string());
    r.text("proven_total_work", &format!("{:?}", tip.proven_state().total_work));
    // Valid proofs from genesis only show *a* valid chain; its work is what makes it the
    // chain. Without a floor, the result is reported as unchecked.
    match o.min_work {
        Some(min) => {
            tip.require_work(min).expect("proven chain has less than --min-work");
            r.text("work_check", "passed");
        }
        None if o.no_work_floor => r.text("work_check", "skipped (--insecure-no-work-floor)"),
        None => panic!("a light client needs --min-work (or --insecure-no-work-floor to see what is proven without it)"),
    }

    if let Some(to) = o.extend_to {
        let headers = load_headers(o);
        let t = Instant::now();
        let from = tip.state().block_height as usize + 1;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs().min(u64::from(u32::MAX)) as u32)
            .ok();
        tip.extend(&headers[from..=to as usize], &p, now).unwrap_or_else(|(i, e)| panic!("header {}: {e:?}", from + i));
        r.num("extend_s", t.elapsed().as_secs_f64());
        r.int("tip_height", u64::from(tip.state().block_height));
        r.text("tip", &tip.tip_hash().to_string());
    }

    if let (Some(block_path), Some(txid)) = (&o.spv_block, o.txid) {
        // Server side: a Merkle proof for the transaction and an MMR proof for its block.
        let block: Block = bitcoin::encoding::decode_from_slice(&std::fs::read(block_path).expect("block")).expect("block");
        let block = block.validate().expect("block");
        let txs = block.transactions();
        let coinbase = &txs[0];
        let tx = txs.iter().find(|t| t.compute_txid() == txid).expect("txid in block");
        let cb = coinbase.compute_txid();
        let merkle_block = MerkleBlock::from_block_with_predicate(&block, |t| *t == txid || *t == cb);
        let headers = load_headers(o);
        let mut tree = MmrTree::default();
        for h in &headers[..=tip.proven_height() as usize] {
            tree.push(header_leaf(h));
        }
        let height = headers.iter().position(|h| h == block.header()).expect("block in headers file") as u64;
        let header_proof = tree.proof(height).expect("mmr proof");
        // Client side.
        let t = Instant::now();
        let got = tip.verify_tx(block.header(), &header_proof, &merkle_block, tx, coinbase).expect("spv");
        r.num("spv_s", t.elapsed().as_secs_f64());
        r.int("spv_height", u64::from(got));
        r.text("spv_txid", &txid.to_string());
    }

    r.num("total_s", total.elapsed().as_secs_f64());
    peak_rss(&mut r);
    r
}

// ---------------------------------------------------------------------------- tip.json

fn write_tip(path: &Path, s: &ChainState, mmr: &Mmr) {
    let hex = |b: [u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let roots: Vec<String> =
        mmr.roots().iter().map(|r| r.map(|d| format!("\"{}\"", d.to_hex())).unwrap_or("null".into())).collect();
    let ts: Vec<String> = s.prev_timestamps.iter().map(u32::to_string).collect();
    let json = format!(
        "{{\"block_height\": {}, \"total_work\": \"{}\", \"best_block_hash\": \"{}\", \"current_target\": \"{}\", \
         \"epoch_start_time\": {}, \"prev_timestamps\": [{}], \"mmr_roots\": [{}]}}",
        s.block_height,
        hex(s.total_work.to_be_bytes()),
        s.best_block_hash,
        hex(s.current_target.to_be_bytes()),
        s.epoch_start_time,
        ts.join(", "),
        roots.join(", ")
    );
    std::fs::write(path, json).expect("write tip");
}

fn read_tip(path: &Path) -> (ChainState, Mmr) {
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).expect("tip.json")).expect("tip json");
    let be = |s: &str| Digest::from_hex(s).expect("32-byte hex").to_u256_be();
    let state = ChainState {
        block_height: v["block_height"].as_u64().expect("height") as u32,
        total_work: Work::from_be_bytes(be(v["total_work"].as_str().expect("work"))),
        best_block_hash: v["best_block_hash"].as_str().expect("hash").parse::<BlockHash>().expect("hash"),
        current_target: Target::from_be_bytes(be(v["current_target"].as_str().expect("target"))),
        epoch_start_time: v["epoch_start_time"].as_u64().expect("epoch") as u32,
        prev_timestamps: v["prev_timestamps"].as_array().expect("ts").iter().map(|t| t.as_u64().expect("ts") as u32).collect(),
    };
    let roots = v["mmr_roots"]
        .as_array()
        .expect("roots")
        .iter()
        .map(|r| r.as_str().map(|s| Digest::from_hex(s).expect("root")))
        .collect();
    (state, Mmr::from_roots(roots).expect("mmr roots"))
}

fn peak_rss(r: &mut Report) {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else { return };
    if let Some(kib) = status.lines().find(|l| l.starts_with("VmHWM:")).and_then(|l| l.split_whitespace().nth(1)) {
        if let Ok(kib) = kib.parse::<f64>() {
            r.num("peak_rss_mib", kib / 1024.0);
        }
    }
}
