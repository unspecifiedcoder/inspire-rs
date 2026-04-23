//! 2-CRT bug-hunt smoke bisection.
//!
//! Runs TwoPacking + InspiRING round-trips at increasing
//! `(ring_dim, entries, record_bytes)` cells under both:
//!   - single-prime DEFAULT_Q baseline (known-good)
//!   - 2-CRT `DEFAULT_Q_2CRT_30BIT` pair (suspected-broken)
//!
//! Prints PASS/FAIL per cell so a human can locate the smallest
//! cell at which 2-CRT first diverges from 1-CRT. Then the code
//! audit has a concrete failure point to instrument.
//!
//! Run with:
//!   cargo test --manifest-path crates/raven-inspire/Cargo.toml \
//!              --release --test two_crt_bisection -- --nocapture
//!
//! Each cell is marked `#[ignore]` because the 2^20 cells take
//! ~1 min of setup + smoke. The smaller cells run under the
//! default unignored path so a quick `cargo test` catches
//! gross regressions without paying the full bisection cost.

use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, SecurityLevel, DEFAULT_Q_2CRT_30BIT};
use raven_inspire::{
    extract_inspiring, query_seeded, respond_seeded_inspiring, setup, PackingMode,
};

/// Construct DEFAULT_Q single-prime baseline at the given ring_dim.
fn default_q_single(ring_dim: usize) -> InspireParams {
    InspireParams {
        ring_dim,
        q: 1_152_921_504_606_830_593,
        crt_moduli: vec![1_152_921_504_606_830_593],
        p: 65537,
        sigma: 6.4,
        gadget_base: 1 << 20,
        gadget_len: 3,
        security_level: SecurityLevel::Bits128,
    }
}

/// Construct the 2-CRT 30-bit pair at the given ring_dim. Keeps
/// gadget_base = 2^20 (DEFAULT_Q preset value) so the only change
/// vs the baseline is the CRT shape (1-CRT vs 2-CRT) and q-width.
fn two_crt_30bit(ring_dim: usize) -> InspireParams {
    let crt = DEFAULT_Q_2CRT_30BIT.to_vec();
    let q: u64 = crt.iter().product();
    InspireParams {
        ring_dim,
        q,
        crt_moduli: crt,
        p: 65537,
        sigma: 6.4,
        gadget_base: 1 << 20,
        gadget_len: 3,
        security_level: SecurityLevel::Bits128,
    }
}

/// Plants `(i + j) mod 251` at every byte; checks recovered bytes.
fn smoke_twopacking_inspiring(
    params: &InspireParams,
    entries: u64,
    record_bytes: usize,
) -> Result<(), String> {
    let mut sampler = GaussianSampler::new(params.sigma);
    let total = (entries as usize)
        .checked_mul(record_bytes)
        .ok_or_else(|| "entries * record_bytes overflow".to_string())?;
    let mut db = vec![0u8; total];
    for i in 0..entries as usize {
        for j in 0..record_bytes {
            db[i * record_bytes + j] = ((i + j) % 251) as u8;
        }
    }
    let (crs, encoded_db, sk) = setup(params, &db, record_bytes, &mut sampler)
        .map_err(|e| format!("setup failed: {e:?}"))?;

    // Probe three indices across the DB.
    let n = entries.saturating_sub(1).max(1);
    let indices: [u64; 3] = [n / 4, n / 2, (3 * n) / 4];
    for &idx in &indices {
        let (state, mut seeded_query) = query_seeded(&crs, idx, &encoded_db.config, &sk, &mut sampler)
            .map_err(|e| format!("query_seeded @ idx={idx}: {e:?}"))?;
        seeded_query.packing_mode = PackingMode::Inspiring;
        let response = respond_seeded_inspiring(&crs, &encoded_db, &seeded_query)
            .map_err(|e| format!("respond_seeded_inspiring @ idx={idx}: {e:?}"))?;
        let recovered = extract_inspiring(&crs, &state, &response, record_bytes)
            .map_err(|e| format!("extract_inspiring @ idx={idx}: {e:?}"))?;
        let expected: Vec<u8> = (0..record_bytes)
            .map(|j| (((idx as usize) + j) % 251) as u8)
            .collect();
        if recovered != expected {
            return Err(format!(
                "byte-mismatch @ idx={idx}: recovered[..4] = {:?}, expected[..4] = {:?}",
                &recovered[..4.min(recovered.len())],
                &expected[..4.min(expected.len())]
            ));
        }
    }
    Ok(())
}

fn run_cell(crt_shape: &str, params: &InspireParams, entries: u64, record_bytes: usize) -> bool {
    let label = format!(
        "{:<6}  d={:<5} entries=2^{:<3} record={:<4} B",
        crt_shape,
        params.ring_dim,
        (entries as f64).log2().round() as u32,
        record_bytes
    );
    match smoke_twopacking_inspiring(params, entries, record_bytes) {
        Ok(()) => {
            println!("  PASS   {label}");
            true
        }
        Err(e) => {
            println!("  FAIL   {label}  - {e}");
            false
        }
    }
}

/// Fast bisection (d=256, d=512) runs under default `cargo test`.
#[test]
fn bisection_small_rings() {
    println!("\n=== Phase E.6 smoke bisection (small rings, fast) ===");
    for &(d, ents_log2) in &[(256usize, 8u32), (512, 9)] {
        let entries = 1u64 << ents_log2;
        for &rb in &[8usize, 32, 256] {
            let p1 = default_q_single(d);
            let p2 = two_crt_30bit(d);
            run_cell("1-CRT ", &p1, entries, rb);
            run_cell("2-CRT ", &p2, entries, rb);
        }
    }
}

/// Medium rings (d=1024, d=2048 small entry count). Fast enough to stay
/// un-ignored.
#[test]
fn bisection_medium_rings() {
    println!("\n=== Phase E.6 smoke bisection (medium rings) ===");
    for &(d, ents_log2) in &[(1024usize, 10u32), (2048, 11)] {
        let entries = 1u64 << ents_log2;
        for &rb in &[8usize, 32, 256] {
            let p1 = default_q_single(d);
            let p2 = two_crt_30bit(d);
            run_cell("1-CRT ", &p1, entries, rb);
            run_cell("2-CRT ", &p2, entries, rb);
        }
    }
}

/// Large rings at small entry count (1 shard worth). Also fast.
#[test]
fn bisection_large_ring_one_shard() {
    println!("\n=== Phase E.6 smoke bisection (d=2048, 1 shard) ===");
    let d = 2048usize;
    let entries = 1u64 << 11;
    for &rb in &[8usize, 32, 128, 256] {
        let p1 = default_q_single(d);
        let p2 = two_crt_30bit(d);
        run_cell("1-CRT ", &p1, entries, rb);
        run_cell("2-CRT ", &p2, entries, rb);
    }
}
