//! End-to-end production-cell bench for the AVX-512-IFMA52 packing-
//! offline dispatch.
//!
//! Drives `respond_seeded_inspiring_cached_with_session` (the locked
//! production variant) against the production cell shapes:
//!
//! - 65 536 entries × 512 B (T2 / T3 cell).
//! - 131 072 entries × 32 B (T1 cell, scaled).
//!
//! Measurement: 3-seed median (sort + middle, NOT mean). The sister
//! crate / harness conditions are matched to the shipping
//! `INSPIRE_PRODUCTION_VARIANT_BENCH.md` methodology so the numbers
//! are comparable.
//!
//! Gating: `RAVEN_PACKING_OFFLINE_SIMD_BENCH=1` to opt into the
//! workload (the cell setup is multi-second per seed and would
//! otherwise dominate `cargo test` runtime).
//!
//! Skips on non-x86_64 hosts and on hosts lacking AVX-512-IFMA52
//! when the `simd-packing-offline` feature is enabled (since the
//! dispatch falls through to scalar there and the run would just
//! re-measure the scalar path under a misleading label).
//!
//! Output: per-call wall-time per seed + 3-seed median + total
//! speedup factor (set via env var across two cargo invocations,
//! one with and one without the feature flag).

use std::time::Instant;

use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, SecurityLevel};
use raven_inspire::{
    respond_seeded_inspiring_cached_with_session, setup, ClientSession, PackingMode,
    ServerInspiringCache, ServerSessionStore,
};

/// Number of warm-up calls before timing begins.
const WARMUP_CALLS: usize = 2;
/// Number of timed calls per seed (median over these locks against
/// per-call jitter).
const TIMED_CALLS: usize = 5;
/// Three independent RNG seeds drive the locked methodology.
const SEEDS: [u64; 3] = [0x5EED_0001, 0x5EED_0002, 0x5EED_0003];

fn median_of(mut samples: Vec<u128>) -> u128 {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn drive_one_cell(label: &str, entries: usize, entry_bytes: usize, params: InspireParams) {
    eprintln!("=== {label}: entries={entries}, entry_bytes={entry_bytes} ===");
    eprintln!(
        "    ring_dim={}, gadget=(base=2^20, len={}), feature={}",
        params.ring_dim,
        params.gadget_len,
        if cfg!(feature = "simd-packing-offline") {
            "simd-packing-offline"
        } else {
            "(scalar baseline)"
        }
    );

    // Per-seed median wall-time across TIMED_CALLS responder invocations.
    let mut per_seed_medians: Vec<u128> = Vec::with_capacity(SEEDS.len());

    for &seed in &SEEDS {
        let mut sampler = GaussianSampler::with_seed(params.sigma, seed);

        // Synthetic database: deterministic, byte-recoverable; the
        // decoded byte semantics aren't asserted here (correctness is
        // covered by the KAT + existing e2e tests). Bench measures
        // server wall-time only.
        let db: Vec<u8> = (0..entries * entry_bytes)
            .map(|i| ((i.wrapping_mul(0x9E37_79B9) >> 8) & 0xFF) as u8)
            .collect();

        let (crs, encoded_db, rlwe_sk) = setup(&params, &db, entry_bytes, &mut sampler)
            .expect("setup must succeed at production cell");

        let server_cache =
            ServerInspiringCache::new(&crs, &encoded_db).expect("server cache build must succeed");
        let session_store = ServerSessionStore::new();

        let mut session = ClientSession::new(crs.clone(), rlwe_sk, &mut sampler)
            .expect("client session must build");
        let _handle = session
            .register_with(&session_store)
            .expect("register must succeed")
            .expect("inspiring session must register a handle");

        // Pre-build a query at a representative index. The same query
        // is replayed across warmup + timed iterations to isolate
        // server-side wall-time from query construction noise.
        let target_idx = entries / 2 - 1;
        let (_state, mut query) = session
            .query_seeded(target_idx as u64, &encoded_db.config, &mut sampler)
            .expect("query_seeded must succeed");
        query.packing_mode = PackingMode::Inspiring;

        // Warmup: not measured; populates branch predictors + page-cache.
        for _ in 0..WARMUP_CALLS {
            let _r = respond_seeded_inspiring_cached_with_session(
                &crs,
                &encoded_db,
                &query,
                &server_cache,
                Some(&session_store),
            )
            .expect("respond must succeed (warmup)");
            std::hint::black_box(&_r);
        }

        // Timed loop: per-call wall in nanoseconds.
        let mut per_call_ns: Vec<u128> = Vec::with_capacity(TIMED_CALLS);
        for _ in 0..TIMED_CALLS {
            let t0 = Instant::now();
            let r = respond_seeded_inspiring_cached_with_session(
                &crs,
                &encoded_db,
                &query,
                &server_cache,
                Some(&session_store),
            )
            .expect("respond must succeed (timed)");
            let elapsed = t0.elapsed().as_nanos();
            std::hint::black_box(&r);
            per_call_ns.push(elapsed);
        }

        let seed_median = median_of(per_call_ns.clone());
        per_seed_medians.push(seed_median);

        eprintln!(
            "  seed=0x{seed:08X}: per-call samples (ns) = {per_call_ns:?}, median = {seed_median} ns ({:.3} ms)",
            seed_median as f64 / 1_000_000.0
        );
    }

    let median = median_of(per_seed_medians.clone());
    eprintln!(
        "  3-seed medians (ns) = {per_seed_medians:?}, overall median = {median} ns ({:.3} ms)",
        median as f64 / 1_000_000.0
    );
    eprintln!();
}

fn should_run() -> bool {
    if std::env::var("RAVEN_PACKING_OFFLINE_SIMD_BENCH")
        .ok()
        .as_deref()
        != Some("1")
    {
        eprintln!("SKIP: set RAVEN_PACKING_OFFLINE_SIMD_BENCH=1 to run");
        return false;
    }
    #[cfg(all(feature = "simd-packing-offline", target_arch = "x86_64"))]
    {
        if !is_x86_feature_detected!("avx512ifma") {
            eprintln!(
                "SKIP: simd-packing-offline feature is enabled but host lacks AVX-512-IFMA52"
            );
            return false;
        }
    }
    true
}

/// Production cell A: 65 536 entries × 512 B (T2 / T3 shape).
#[test]
#[ignore = "production cell bench; gated by RAVEN_PACKING_OFFLINE_SIMD_BENCH=1"]
fn bench_prod_cell_65536x512() {
    if !should_run() {
        return;
    }

    let mut params = InspireParams::secure_128_d2048();
    params.security_level = SecurityLevel::Bits128;
    drive_one_cell("prod-cell-65536x512", 65_536, 512, params);
}

/// Production cell B: 131 072 entries × 32 B (T1 shape, scaled).
#[test]
#[ignore = "production cell bench; gated by RAVEN_PACKING_OFFLINE_SIMD_BENCH=1"]
fn bench_prod_cell_131072x32() {
    if !should_run() {
        return;
    }

    let mut params = InspireParams::secure_128_d2048();
    params.security_level = SecurityLevel::Bits128;
    drive_one_cell("prod-cell-131072x32", 131_072, 32, params);
}
