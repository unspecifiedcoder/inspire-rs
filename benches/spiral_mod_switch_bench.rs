//! Spiral mod-switching bench: response wire-bytes BEFORE vs AFTER.
//!
//! Locked production cell shape (M005): 65,536 entries x 512 B at
//! `d = 2048`, single-CRT `q = DEFAULT_Q ≈ 2^60`, InsPIRe^2
//! (TwoPacking + InspiRING + seeded query + sticky session). The
//! bench builds a single shard of the locked shape (matches the
//! per-shard layout) then exercises the full
//! query → respond_seeded_inspiring → mod_switch → encode_packed
//! pipeline three times with three independent seeds, reporting
//! the median wire-byte count.
//!
//! # Why a custom harness instead of criterion
//!
//! The metric here is wire-bytes (a deterministic measurement, not
//! a wall-clock distribution). Three seeds suffice (per M005's
//! three-seed methodology) and the criterion overhead would dwarf
//! the bench. Output is plain stderr so an operator can `grep
//! WIRE_BYTES_RESULT` from a CI log.
//!
//! # Pass criteria
//!
//! - Mod-switched + tightly-encoded response wire-bytes <= 80% of
//!   the bincode baseline (>= 20% reduction). Target was 25%; some
//!   slack is allowed for serializer overhead.
//! - Decryption roundtrip recovers the original entry byte-for-byte
//!   under all three seeds. Wire-bytes savings without correctness
//!   are not a savings — bench BAILS HONESTLY if any seed fails to
//!   decrypt.

use rand::{rngs::StdRng, RngCore, SeedableRng};

use raven_inspire::math::GaussianSampler;
use raven_inspire::params::InspireParams;
use raven_inspire::pir::mod_switch::{
    encode_response_packed, extract_inspiring_mod_switched, mod_switch_response_checked,
    MOD_SWITCH_TARGET_45BIT,
};
use raven_inspire::pir::{query_seeded, respond_seeded_inspiring, setup};

const ENTRY_SIZE: usize = 512;
const SEEDS: [u64; 3] = [
    0xA5A5_A5A5_DEAD_BEEF,
    0x1234_5678_DEAD_FEED,
    0xC0FFEE_BABE_F00D,
];

fn run_one_seed(seed: u64) -> SeedResult {
    let mut rng = StdRng::seed_from_u64(seed);
    let params = InspireParams::secure_128_d2048();
    let mut sampler = GaussianSampler::new(params.sigma);

    let num_entries = params.ring_dim;
    let mut database = vec![0u8; num_entries * ENTRY_SIZE];
    rng.fill_bytes(&mut database);

    let (crs, encoded_db, rlwe_sk) =
        setup(&params, &database, ENTRY_SIZE, &mut sampler).expect("setup");

    let target_index = (rng.next_u64() % (num_entries as u64)) as u64;
    let (state, query) = query_seeded(
        &crs,
        target_index,
        &encoded_db.config,
        &rlwe_sk,
        &mut sampler,
    )
    .expect("query_seeded");

    let response = respond_seeded_inspiring(&crs, &encoded_db, &query).expect("respond");

    let baseline_bytes = response
        .to_binary()
        .expect("baseline bincode serialize")
        .len();

    let switched = mod_switch_response_checked(&crs.params, &response, MOD_SWITCH_TARGET_45BIT)
        .expect("mod_switch_response_checked at production cell");

    let switched_bincode_bytes = switched
        .to_binary()
        .expect("mod-switched bincode serialize")
        .len();

    let switched_packed_bytes = encode_response_packed(&switched)
        .expect("encode_response_packed for mod-switched response")
        .len();

    let extracted =
        extract_inspiring_mod_switched(&crs, &state, &switched, ENTRY_SIZE).expect("extract");

    let expected_start = (target_index as usize) * ENTRY_SIZE;
    let expected = &database[expected_start..expected_start + ENTRY_SIZE];
    let correct = extracted.as_slice() == expected;

    SeedResult {
        baseline_bytes,
        switched_bincode_bytes,
        switched_packed_bytes,
        correct,
    }
}

#[derive(Debug, Clone, Copy)]
struct SeedResult {
    baseline_bytes: usize,
    switched_bincode_bytes: usize,
    switched_packed_bytes: usize,
    correct: bool,
}

fn median3(mut values: [usize; 3]) -> usize {
    values.sort_unstable();
    values[1]
}

fn main() {
    eprintln!(
        "Spiral mod-switching bench: production cell d=2048, entries={}, entry_size={}",
        InspireParams::secure_128_d2048().ring_dim,
        ENTRY_SIZE
    );
    eprintln!(
        "Mod-switch target: 0x{:x} (45-bit NTT-friendly prime)",
        MOD_SWITCH_TARGET_45BIT
    );
    eprintln!();

    let mut results = Vec::new();
    for &seed in &SEEDS {
        eprintln!("seed=0x{seed:016x}: running pipeline...");
        let r = run_one_seed(seed);
        if !r.correct {
            eprintln!("seed=0x{seed:016x}: DECRYPT FAILED. M015 honest stop. Bench aborts.");
            std::process::exit(2);
        }
        eprintln!(
            "seed=0x{:016x}: baseline={} bytes, switched_bincode={} bytes, switched_packed={} bytes",
            seed, r.baseline_bytes, r.switched_bincode_bytes, r.switched_packed_bytes
        );
        results.push(r);
    }

    let baseline_med = median3([
        results[0].baseline_bytes,
        results[1].baseline_bytes,
        results[2].baseline_bytes,
    ]);
    let switched_bincode_med = median3([
        results[0].switched_bincode_bytes,
        results[1].switched_bincode_bytes,
        results[2].switched_bincode_bytes,
    ]);
    let switched_packed_med = median3([
        results[0].switched_packed_bytes,
        results[1].switched_packed_bytes,
        results[2].switched_packed_bytes,
    ]);

    let bincode_reduction =
        100.0 * (baseline_med as f64 - switched_bincode_med as f64) / baseline_med as f64;
    let packed_reduction =
        100.0 * (baseline_med as f64 - switched_packed_med as f64) / baseline_med as f64;

    eprintln!();
    eprintln!("=== 3-seed median results ===");
    eprintln!(
        "baseline (bincode of unswitched ServerResponse): {} bytes",
        baseline_med
    );
    eprintln!(
        "switched (bincode of mod-switched ServerResponse): {} bytes ({:.2}% reduction)",
        switched_bincode_med, bincode_reduction
    );
    eprintln!(
        "switched (encode_response_packed tight serializer):  {} bytes ({:.2}% reduction)",
        switched_packed_med, packed_reduction
    );
    eprintln!();

    println!(
        "WIRE_BYTES_RESULT baseline={} switched_bincode={} switched_packed={} bincode_reduction_pct={:.4} packed_reduction_pct={:.4}",
        baseline_med, switched_bincode_med, switched_packed_med, bincode_reduction, packed_reduction
    );

    if packed_reduction < 20.0 {
        eprintln!(
            "FAIL: packed_reduction ({:.2}%) < 20% target. M015 honest stop.",
            packed_reduction
        );
        std::process::exit(1);
    }

    eprintln!("PASS: packed wire-byte reduction >= 20% under 3-seed median.");
}
