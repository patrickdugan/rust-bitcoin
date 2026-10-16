//! Prove Raito's `client` program on a block decoded by rust-bitcoin, timing each stage.
//!
//! The pipeline is Raito's own (`crates/raito-assumevalid/src/prove.rs`): the simple
//! bootloader runs the Cairo1 executable as a task under cairo-vm in proof mode, the run
//! is adapted for stwo-cairo, proven, and verified. What differs is the front end: the
//! program arguments come from `bitcoin_zk_args`, i.e. from rust-bitcoin types.
//!
//! Prints one JSON object with per-stage wall time, so native and WASM runs of the same
//! binary can be compared line by line.
//!
//! Two execution modes:
//! - bootloader (default, Raito's): the simple bootloader hashes the client program inside
//!   Cairo and outputs that hash, so the proof states its own program;
//! - `--direct` (`cairo-prove`'s): the client runs as a standalone executable, its
//!   bytecode sits in the proof's public memory, and the verifier compares it with the
//!   expected client natively (done in the verify stage below).
//!
//! Usage:
//!   zk-bench --executable client.executable.json --bootloader simple_bootloader_compiled.json
//!            --fixture full_169.json --block block_170.bin --out DIR [--direct]
//!            [--stop-after args|execute|adapt|prove] [--no-pedersen] [--pow-bits N]
//!            [--max-log-rows K]   (bounded preprocessed trace; this fork's stwo-cairo patch)

use std::path::PathBuf;
use std::time::Instant;

use bitcoin::Block;
use bitcoin_zk_args::fixture::Fixture;
use bitcoin_zk_args::{client_args, to_args_json};
use cairo_air::utils::{serialize_proof_to_file, ProofFormat};
use cairo_air::verifier::verify_cairo;
use cairo_air::PreProcessedTraceVariant;
use cairo_lang_executable::executable::{EntryPointKind, Executable};
use cairo_lang_execute_utils::{program_and_hints_from_executable, user_args_from_flags};
use cairo_lang_runner::{Arg, CairoHintProcessor};
use cairo_program_runner_lib::cairo_run_program;
use cairo_program_runner_lib::utils::get_cairo_run_config;
use cairo_vm::cairo_run::CairoRunConfig;
use cairo_vm::types::layout_name::LayoutName;
use cairo_vm::types::program::Program;
use cairo_vm::vm::runners::cairo_runner::CairoRunner;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::PcsConfig;
use stwo::core::vcs::blake2_merkle::Blake2sMerkleChannel;
use stwo_cairo_adapter::adapter::adapt;
use stwo_cairo_adapter::PublicSegmentContext;
use stwo_cairo_prover::prover::{prove_cairo, ChannelHash, ProverParameters};

struct Opts {
    executable: PathBuf,
    bootloader: PathBuf,
    fixture: PathBuf,
    block: PathBuf,
    out: PathBuf,
    stop_after: String,
    no_pedersen: bool,
    pow_bits: u32,
    direct: bool,
    max_log_rows: Option<u32>,
}

fn parse_opts() -> Opts {
    let mut a = std::env::args().skip(1);
    let mut o = Opts {
        executable: PathBuf::new(),
        bootloader: PathBuf::new(),
        fixture: PathBuf::new(),
        block: PathBuf::new(),
        out: PathBuf::from("zk-out"),
        stop_after: "verify".into(),
        no_pedersen: false,
        pow_bits: 26,
        direct: false,
        max_log_rows: None,
    };
    while let Some(k) = a.next() {
        let mut v = || a.next().unwrap_or_else(|| panic!("{k} needs a value"));
        match k.as_str() {
            "--executable" => o.executable = v().into(),
            "--bootloader" => o.bootloader = v().into(),
            "--fixture" => o.fixture = v().into(),
            "--block" => o.block = v().into(),
            "--out" => o.out = v().into(),
            "--stop-after" => o.stop_after = v(),
            "--pow-bits" => o.pow_bits = v().parse().expect("pow bits"),
            "--no-pedersen" => o.no_pedersen = true,
            "--direct" => o.direct = true,
            "--max-log-rows" => o.max_log_rows = Some(v().parse().expect("max log rows")),
            _ => panic!("unknown argument {k}"),
        }
    }
    o
}

/// Peak resident set size in MiB, where the platform reports it.
fn peak_rss_mib() -> Option<f64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
    let kib: f64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib / 1024.0)
}

struct Report(Vec<(String, String)>);

impl Report {
    fn num(&mut self, k: &str, v: f64) { self.0.push((k.into(), format!("{v:.3}"))); }
    fn int(&mut self, k: &str, v: u64) { self.0.push((k.into(), v.to_string())); }
    fn text(&mut self, k: &str, v: &str) { self.0.push((k.into(), format!("{v:?}"))); }
    fn print(&self) {
        let body: Vec<String> = self.0.iter().map(|(k, v)| format!("\"{k}\": {v}")).collect();
        println!("{{{}}}", body.join(", "));
    }
}

fn main() {
    // stwo / stwo-cairo report component sizes and phases through `tracing`;
    // `RUST_LOG=info` shows them on stderr.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let o = parse_opts();
    let mut r = Report(Vec::new());
    r.text("target", std::env::consts::ARCH);
    r.text("block", &o.block.display().to_string());
    std::fs::create_dir_all(&o.out).expect("create out dir");
    let total = Instant::now();

    // Stage 1: rust-bitcoin decode + validate + Raito argument serialization.
    let t = Instant::now();
    let fixture = Fixture::parse(&std::fs::read_to_string(&o.fixture).expect("fixture")).expect("parse fixture");
    let raw = std::fs::read(&o.block).expect("block");
    let block: Block = bitcoin::encoding::decode_from_slice(&raw).expect("decode block");
    let block = block.validate().expect("block structure");
    let (felts, expected) =
        client_args(&fixture.initial, &[block], |op| fixture.prevouts.get(op).cloned()).expect("prevouts");
    assert_eq!(expected, fixture.expected, "rust-bitcoin chain state disagrees with fixture");
    let args_path = o.out.join("args.json");
    std::fs::write(&args_path, to_args_json(&felts)).expect("write args");
    r.num("args_s", t.elapsed().as_secs_f64());
    r.int("arg_felts", felts.len() as u64);
    if o.stop_after == "args" {
        return finish(r, total);
    }

    // Stage 2: the client program under cairo-vm, proof mode.
    let t = Instant::now();
    let executable: Executable =
        serde_json::from_reader(std::fs::File::open(&o.executable).expect("executable")).expect("parse executable");
    let runner = if o.direct { run_direct(&executable, &args_path) } else { run_bootloaded(&o, &args_path) };
    r.text("mode", if o.direct { "direct" } else { "bootloader" });
    r.num("execute_s", t.elapsed().as_secs_f64());
    r.int("steps", runner.vm.get_current_step() as u64);
    if o.stop_after == "execute" {
        return finish(r, total);
    }

    // Stage 3: adapt the VM run for the prover.
    let t = Instant::now();
    let mut input = adapt(&runner).expect("adapt");
    if o.direct {
        // `adapt` at this revision assumes the bootloader's builtin list. A standalone
        // program passes only its own builtins, so describe those, as `cairo-prove` does;
        // otherwise the claim reads segment pointers into the wrong slots.
        let builtins: Vec<_> = runner.get_program().iter_builtins().copied().collect();
        input.public_segment_context = PublicSegmentContext::new(&builtins);
    }
    drop(runner);
    r.num("adapt_s", t.elapsed().as_secs_f64());
    if o.stop_after == "adapt" {
        return finish(r, total);
    }

    // Stage 4: prove. Production parameters from stwo-cairo (96-bit security). The
    // preprocessed trace follows `cairo-prove`: the Pedersen table only if the program
    // can use the Pedersen builtin. The bootloader declares it; for a direct run it is
    // read from the executable (this adapter revision hard-codes the bootloader's
    // segment context, so `input.public_segment_context` cannot tell).
    let uses_pedersen = !o.direct
        || executable
            .entrypoints
            .iter()
            .filter(|e| matches!(e.kind, EntryPointKind::Standalone))
            .any(|e| e.builtins.iter().any(|b| matches!(b, cairo_vm::types::builtin_name::BuiltinName::pedersen)));
    let variant = match (o.max_log_rows, o.no_pedersen || !uses_pedersen) {
        // This fork's bounded variant (vendored stwo-cairo patch): Seq columns and
        // twiddles only up to 2^k rows. Not accepted by stock stwo-cairo verifiers.
        (Some(k), true) => PreProcessedTraceVariant::CanonicalWithoutPedersenUpTo(k),
        (Some(_), false) => panic!("--max-log-rows needs a program without Pedersen"),
        (None, true) => PreProcessedTraceVariant::CanonicalWithoutPedersen,
        (None, false) => PreProcessedTraceVariant::Canonical,
    };
    let params = ProverParameters {
        channel_hash: ChannelHash::Blake2s,
        channel_salt: None,
        pcs_config: PcsConfig {
            pow_bits: o.pow_bits,
            fri_config: FriConfig { log_last_layer_degree_bound: 0, log_blowup_factor: 1, n_queries: 70 },
        },
        preprocessed_trace: variant,
        store_polynomials_coefficients: false,
    };
    r.text("preprocessed", &match variant {
        PreProcessedTraceVariant::Canonical => "canonical".to_string(),
        PreProcessedTraceVariant::CanonicalWithoutPedersen => "canonical_without_pedersen".to_string(),
        PreProcessedTraceVariant::CanonicalWithoutPedersenUpTo(k) => format!("canonical_without_pedersen_up_to_{k}"),
    });
    r.int("pow_bits", u64::from(o.pow_bits));
    let t = Instant::now();
    let proof = prove_cairo::<Blake2sMerkleChannel>(input, params).expect("prove");
    r.num("prove_s", t.elapsed().as_secs_f64());
    // CairoSerde is the input format of the Cairo (recursive) verifier, which requires
    // every builtin segment to be present, i.e. a bootloaded run. Direct runs use JSON.
    let (format, format_name) =
        if o.direct { (ProofFormat::Json, "json") } else { (ProofFormat::CairoSerde, "cairo_serde") };
    let proof_path = o.out.join("proof.json");
    serialize_proof_to_file(&proof, &proof_path, format).expect("write proof");
    r.text("proof_format", format_name);
    r.int("proof_bytes", std::fs::metadata(&proof_path).map(|m| m.len()).unwrap_or(0));
    if o.stop_after == "prove" {
        return finish(r, total);
    }

    // Stage 5: verify. In direct mode the claim must also carry exactly the client's
    // bytecode, or a valid proof could be about some other program.
    let t = Instant::now();
    if o.direct {
        let program = &proof.claim.public_data.public_memory.program;
        let expected: Vec<[u32; 8]> = executable.program.bytecode.iter().map(felt_limbs).collect();
        let got: Vec<[u32; 8]> = program.iter().map(|(_, v)| *v).collect();
        assert!(
            got.len() >= expected.len() && got[..expected.len()] == expected[..],
            "proof's public program does not match the client bytecode ({} vs {} words)",
            got.len(),
            expected.len()
        );
        r.int("public_program_words", got.len() as u64);
    }
    verify_cairo::<Blake2sMerkleChannel>(proof, variant).expect("verify");
    r.num("verify_s", t.elapsed().as_secs_f64());
    finish(r, total);
}

/// Raito's path: the simple bootloader runs the executable as a task and hashes it.
fn run_bootloaded(o: &Opts, args_path: &std::path::Path) -> CairoRunner {
    let program_input = format!(
        r#"{{"single_page": true, "tasks": [{{"type": "Cairo1Executable", "path": {:?}, "program_hash_function": "blake", "user_args_file": {:?}}}]}}"#,
        o.executable.display().to_string(),
        args_path.display().to_string(),
    );
    let bootloader = Program::from_bytes(&std::fs::read(&o.bootloader).expect("bootloader"), Some("main"))
        .expect("load bootloader");
    let config = get_cairo_run_config(&None, LayoutName::all_cairo_stwo, true, true, true, false).expect("run config");
    cairo_run_program(&bootloader, Some(program_input), config).expect("cairo-vm run")
}

/// `cairo-prove`'s path: the executable's standalone entry point, no bootloader.
fn run_direct(executable: &Executable, args_path: &std::path::Path) -> CairoRunner {
    let entry = executable
        .entrypoints
        .iter()
        .find(|e| matches!(e.kind, EntryPointKind::Standalone))
        .expect("standalone entry point");
    let (program, string_to_hint) = program_and_hints_from_executable(executable, entry).expect("program");
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
        // Complete builtin instances the program only partly read (e.g. a bitwise
        // instance whose `xor`/`or` outputs were never used); the adapter needs whole
        // instances. proving-utils sets the same for bootloader tasks.
        fill_holes: true,
        ..Default::default()
    };
    cairo_vm::cairo_run::cairo_run_program(&program, &config, &mut hint_processor).expect("cairo-vm run")
}

/// A bytecode word (reduced mod p, as the VM loads it) as eight little-endian u32 limbs,
/// the layout of `PubMemoryValue`.
fn felt_limbs(v: &num_bigint::BigInt) -> [u32; 8] {
    let bytes = cairo_vm::Felt252::from(v).to_bytes_le();
    let mut limbs = [0u32; 8];
    for (i, c) in bytes.chunks_exact(4).enumerate() {
        limbs[i] = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
    }
    limbs
}

fn finish(mut r: Report, total: Instant) {
    r.num("total_s", total.elapsed().as_secs_f64());
    if let Some(m) = peak_rss_mib() {
        r.num("peak_rss_mib", m);
    }
    r.print();
}
