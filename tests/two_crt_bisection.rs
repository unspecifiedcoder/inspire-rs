//! Round-trips at increasing `(ring_dim, entries, record_bytes)` cells under
//! both the single-prime and the 2-CRT modulus, reporting per cell, so the
//! smallest diverging cell can be read off.

use raven_inspire::math::GaussianSampler;
use raven_inspire::params::{InspireParams, SecurityLevel, DEFAULT_Q_2CRT_30BIT};
use raven_inspire::{
    extract_inspiring, query_seeded, respond_seeded_inspiring, setup, PackingMode,
};

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

/// Same gadget_base as the baseline, so CRT shape and q-width are the only
/// variables.
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

fn smoke_twopacking_inspiring(
    params: &InspireParams,
    entries: u64,
    record_bytes: usize,
) -> Result<(), String> {
    let mut sampler = GaussianSampler::with_seed(params.sigma, 0);
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

    let n = entries.saturating_sub(1).max(1);
    let indices: [u64; 3] = [n / 4, n / 2, (3 * n) / 4];
    for &idx in &indices {
        let (state, mut seeded_query) =
            query_seeded(&crs, idx, &encoded_db.config, &sk, &mut sampler)
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

fn run_cell(
    crt_shape: &str,
    params: &InspireParams,
    entries: u64,
    record_bytes: usize,
    failures: &mut Vec<String>,
) {
    let label = format!(
        "{:<6}  d={:<5} entries=2^{:<3} record={:<4} B",
        crt_shape,
        params.ring_dim,
        (entries as f64).log2().round() as u32,
        record_bytes
    );
    match smoke_twopacking_inspiring(params, entries, record_bytes) {
        Ok(()) => println!("  PASS   {label}"),
        Err(e) => {
            println!("  FAIL   {label}  - {e}");
            failures.push(format!("{label}  - {e}"));
        }
    }
    assert!(
        failures.is_empty(),
        "cells failed to round-trip: {failures:#?}"
    );
}

#[test]
fn bisection_small_rings() {
    println!("\n=== smoke bisection (small rings, fast) ===");
    let mut failures: Vec<String> = Vec::new();
    for &(d, ents_log2) in &[(256usize, 8u32), (512, 9)] {
        let entries = 1u64 << ents_log2;
        for &rb in &[8usize, 32, 256] {
            let p1 = default_q_single(d);
            let p2 = two_crt_30bit(d);
            run_cell("1-CRT ", &p1, entries, rb, &mut failures);
            run_cell("2-CRT ", &p2, entries, rb, &mut failures);
        }
    }
    assert!(
        failures.is_empty(),
        "cells failed to round-trip: {failures:#?}"
    );
}

#[test]
fn bisection_medium_rings() {
    println!("\n=== smoke bisection (medium rings) ===");
    let mut failures: Vec<String> = Vec::new();
    for &(d, ents_log2) in &[(1024usize, 10u32), (2048, 11)] {
        let entries = 1u64 << ents_log2;
        for &rb in &[8usize, 32, 256] {
            let p1 = default_q_single(d);
            let p2 = two_crt_30bit(d);
            run_cell("1-CRT ", &p1, entries, rb, &mut failures);
            run_cell("2-CRT ", &p2, entries, rb, &mut failures);
        }
    }
    assert!(
        failures.is_empty(),
        "cells failed to round-trip: {failures:#?}"
    );
}

#[test]
fn bisection_large_ring_one_shard() {
    println!("\n=== smoke bisection (d=2048, 1 shard) ===");
    let mut failures: Vec<String> = Vec::new();
    let d = 2048usize;
    let entries = 1u64 << 11;
    for &rb in &[8usize, 32, 128, 256] {
        let p1 = default_q_single(d);
        let p2 = two_crt_30bit(d);
        run_cell("1-CRT ", &p1, entries, rb, &mut failures);
        run_cell("2-CRT ", &p2, entries, rb, &mut failures);
    }
    assert!(
        failures.is_empty(),
        "cells failed to round-trip: {failures:#?}"
    );
}
